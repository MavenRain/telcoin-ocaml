(* Chunk-36 stage 7: the epoch lifecycle.

   Everything here is about the transition, not about one block's fields: which
   block of a closing output carries the commitment, what the engine refuses
   once it has carried it, and what [begin_epoch] must reset before the next
   epoch's first output.

   The fixtures stand on the PINNED pre-fork consensus registry and a committee
   of REAL testnet validator execution addresses, because a closing block runs
   the epoch-close system calls: [applyIncentives] is handed the withdrawal
   records and must succeed for the block to finish at all. They are this
   suite's own rather than shared, so that the cost of building a registry world
   and four BLS committees is paid by this executable and not by the other
   forty-four. *)

open Tn_types
open Tn_vertex
open Tn_consensus
module Bf = Block_fixtures
module Cb = Tn_execution.Consensus_block
module Nonempty = Tn_std.Nonempty
module Output = Tn_batch.Output
module Engine = Tn_engine.Engine
module Config = Tn_engine.Config
module Anchor = Tn_engine.Anchor
module Executed_block = Tn_engine.Executed_block
module Block_header = Tn_evm.Block_header
module Hash32 = Tn_evm.Hash32
module System_contracts = Tn_evm.System_contracts
module Withdrawal = Tn_evm.Withdrawal
module U256 = Tn_state.U256
module World = Tn_state.World_state

(* Totalise an option under a named expectation; Result.fold keeps both arms
   lazy, where Option.fold's ~none is eager. *)
let get what o =
  Result.fold ~ok:Fun.id
    ~error:(fun msg -> Alcotest.fail msg)
    (Option.to_result ~none:what o)

let nth what l n = get what (List.nth_opt l n)
let mk_addr c = get "address" (Units.Address.of_bytes (String.make 20 c))
let ts n = get "timestamp" (Units.Timestamp.of_sec n)
let round n = get "round" (Round.of_int n)
let w0 = Units.Worker_id.zero
let fee n = Units.Base_fee.of_int64 (Int64.of_int n)

(* ---------- committees, certificates and committed output ---------- *)

type chain = {
  cmt : Committee.t;
  chain_certify : Header.t -> Certificate.t;
  chain_address_of : Authority_id.t -> Units.Address.t option;
  chain_parents : Digests.Header_digest.t list;
}

let build_chain ~seed addresses =
  let seeded =
    List.mapi
      (fun i address ->
        (Tn_crypto.Secret_key.derive (Int64.of_int (seed + i)), address))
      addresses
  in
  let sks = List.map fst seeded in
  let authorities =
    List.map
      (fun (sk, address) ->
        Authority.make
          ~protocol_key:(Tn_crypto.Secret_key.public_key sk)
          ~execution_address:address)
      seeded
  in
  let cmt =
    Result.fold ~ok:Fun.id
      ~error:(fun e ->
        Alcotest.failf "committee: %s" (Committee.error_to_string e))
      (Committee.create ~epoch:Units.Epoch.zero authorities)
  in
  let sk_of id =
    get "secret key"
      (List.find_opt
         (fun sk ->
           Authority_id.equal
             (Authority_id.of_public_key (Tn_crypto.Secret_key.public_key sk))
             id)
         sks)
  in
  let seats = Committee.authorities cmt in
  let seat_ids = List.map Authority.id seats in
  {
    cmt;
    chain_certify =
      (fun header ->
        let votes =
          List.map (fun id -> Vote.sign (sk_of id) ~voter:id header) seat_ids
        in
        Result.fold ~ok:Fun.id
          ~error:(fun e ->
            Alcotest.failf "certify: %s" (Certificate.error_to_string e))
          (Certificate.assemble cmt header votes));
    chain_address_of =
      (fun id ->
        List.find_map
          (fun a ->
            if Authority_id.equal (Authority.id a) id then
              Some (Authority.execution_address a)
            else None)
          seats);
    chain_parents = List.map Certificate.digest (Certificate.genesis cmt);
  }

let seat ch i = nth "seat" (Committee.authorities ch.cmt) i
let leader ch i = Authority.id (seat ch i)
let leader_address ch i = Authority.execution_address (seat ch i)

let batch ?(base_fee = fee 0) txs =
  Batch.make
    ~transactions:(List.map Tn_evm.Tx_envelope.encode_2718 txs)
    ~epoch:Units.Epoch.zero ~beneficiary:Units.Address.zero
    ~base_fee_per_gas:base_fee ~worker_id:w0

(* One committed output. [entries] is (author, its batches) in header order with
   the LEADER LAST, which is the shape [Sub_dag] commits and the reason [at] (the
   leader's creation time) is the output's commit timestamp. *)
let output_on ch ~at ~r entries =
  let bodies = List.concat_map (fun (_, bs) -> bs) entries in
  let n = List.length entries in
  let headers_rev, _ =
    List.fold_left
      (fun (acc, parents) (i, (author, bs)) ->
        let created_at =
          if i = n - 1 then ts at else ts (Int64.of_int (10 + i))
        in
        let header =
          Header.make ~author ~round:(round (r + i)) ~epoch:Units.Epoch.zero
            ~created_at
            ~payload:(List.map (fun b -> (Batch.digest b, w0)) bs)
            ~parents
        in
        (header :: acc, [ Header.digest header ]))
      ([], ch.chain_parents)
      (List.mapi (fun i entry -> (i, entry)) entries)
  in
  let sequence =
    get "certificates"
      (Nonempty.of_list (List.rev_map ch.chain_certify headers_rev))
  in
  let sub_dag =
    Sub_dag.create ~sequence ~scores:(Reputation_scores.fresh ch.cmt)
      ~previous:None
  in
  let consensus =
    Cb.create ~parent_hash:Cb.genesis_parent ~sub_dag
      ~number:(Cb.Number.succ Cb.Number.genesis)
  in
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "attach: %s" (Output.error_to_string e))
    (Output.attach ~consensus
       ~lookup:(fun d ->
         List.find_opt
           (fun b -> Digests.Batch_digest.equal (Batch.digest b) d)
           bodies)
       ~address_of:ch.chain_address_of)

(* ---------- the registry world a closing block needs ---------- *)

let registry = System_contracts.consensus_registry_address

let u256_short s =
  get "word" (U256.of_hex (String.make (64 - String.length s) '0' ^ s))

let u256_hex s = get "word" (U256.of_hex s)

let registry_world =
  let entry =
    Tn_state.Genesis_account.make ~nonce:Tn_state.Nonce.zero
      ~balance:(u256_short Registry_genesis.balance_hex)
      ~code:(Some (Bf.hex Registry_genesis.code_hex))
      ~storage:
        (List.map
           (fun (s, v) -> (u256_hex s, u256_hex v))
           Registry_genesis.storage_hex)
  in
  Bf.get_ok (World.of_genesis_alloc [ (registry, entry) ])

let close_world = System_contracts.predeploy registry_world

(* The five testnet validator execution addresses, verbatim from
   chain-configs/testnet/committee.yaml, as in test_epoch_close.ml. Whichever of
   them leads a closing output, its withdrawal names a validator the fixture
   registry knows. *)
let validator_addresses =
  List.map
    (fun h -> get "validator address" (Units.Address.of_bytes (Bf.hex h)))
    [
      "0033a370616805b1fd275b7ffab83fc41d665ccb";
      "89dab9f6fdc569c1bcdbd6493f25b7040b55dc79";
      "3518b301b86ceb53b5a3dff62e55cd43ef59d024";
      "efaacf04b92298a88200aa50aa6bb7bfce587b17";
      "7489025dfbaad94f2366d88a62989147d9c8b5d3";
    ]

(* Two committees over the SAME validator addresses and DIFFERENT protocol keys,
   so a leader of [chain_next] is an authority [chain_now] cannot resolve at all.
   That is what makes the committee row of T-28 readable: the sentinel leader
   exists in exactly one of them. *)
let chain_now = build_chain ~seed:300 validator_addresses
let chain_next = build_chain ~seed:400 validator_addresses

(* ---------- engines ---------- *)

let genesis_hash = Tn_keccak.digest "chunk 36 epoch genesis sentinel"
let ancestor_hash = Tn_keccak.digest "chunk 36 epoch ancestor sentinel"
let chain_id = get "chain id" (U256.of_int 0x7e5)
let basefee_address = mk_addr '\xbe'

(* [boundary] is the whole lever: a boundary before every commit timestamp makes
   the first output close the epoch, and one after them all makes none of them
   close it. *)
let engine_with ?(chain = chain_now) ?(world = close_world) ~boundary () =
  Engine.create
    (Config.create
       ~anchor:
         (Anchor.of_genesis ~hash:genesis_hash
            ~base_fee:(get "base fee" (U256.of_int 77))
            ~gas_limit:30_000_007)
       ~ancestors:[ ancestor_hash ] ~world ~chain_id ~basefee_address
       ~epoch_boundary:boundary ~committee:chain.cmt)

let executed engine output =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "execute: %s" (Engine.error_to_string e))
    (Engine.execute engine output)

(* The rendered error, or ["ok"] when there was none: a string comparison rather
   than an eight-arm match on the error sum, and it names the two timestamps the
   refusal is about. *)
let outcome r =
  Result.fold ~ok:(fun _ -> "ok") ~error:Engine.error_to_string r

let sealed_message =
  "epoch sealed: the closing block is built and the next committee has not \
   been installed"

let not_advanced ~proposed ~closed_at =
  Printf.sprintf
    "epoch boundary %Ld does not advance past the timestamp %Ld at which the \
     last epoch closed"
    proposed closed_at

let extra_data block = Block_header.extra_data (Executed_block.header block)

let withdrawals block =
  Block_header.withdrawals (Executed_block.header block)

let amount_at block address =
  List.fold_left
    (fun acc w ->
      if Units.Address.equal (Withdrawal.address w) address then
        acc + Withdrawal.amount w
      else acc)
    0 (withdrawals block)

(* ================================================================== *)
(* T-26: one commitment per closing output, and then nothing.          *)
(* ================================================================== *)

(* Long past the boundary below, so this output closes the epoch. Three batches
   under one certificate, the last of them carrying a real transfer, so the
   closing block is a FULL block and not the empty one T-20..T-25 build. The
   first two batches differ only in their declared base fee, which is the
   cheapest way to give two empty batches two digests. *)
let gas_price = 100
let tx_last = Bf.legacy_envelope ~signer:41 ~gas_price ~gas_limit:21_000 ()

let out_three_closing =
  output_on chain_now ~at:1_700_000_500L ~r:9
    [
      ( leader chain_now 0,
        [ batch []; batch ~base_fee:(fee 1) []; batch ~base_fee:(fee 2) [ tx_last ] ] );
    ]

(* An ordinary output after it, which a sealed engine must refuse. *)
let out_after_close =
  output_on chain_now ~at:1_700_000_600L ~r:20
    [ (leader chain_now 1, [ batch ~base_fee:(fee 3) [] ]) ]

let boundary_past = ts 1L
let closing_world = Bf.fund close_world [ tx_last ]

let t26 () =
  let engine = engine_with ~world:closing_world ~boundary:boundary_past () in
  let after, blocks = executed engine out_three_closing in
  Alcotest.(check int) "a three-batch closing output makes exactly three blocks"
    3 (List.length blocks);
  Alcotest.(check (list int))
    "and only the LAST of them carries the 32-byte commitment"
    [ 0; 0; 32 ]
    (List.map (fun b -> String.length (extra_data b)) blocks);
  Alcotest.(check (list int))
    "with the withdrawal records on that block and no other" [ 0; 0; 1 ]
    (List.map (fun b -> List.length (withdrawals b)) blocks);
  Alcotest.(check int) "the closing block pays this output's own leader"
    1
    (amount_at (nth "block 3" blocks 2) (leader_address chain_now 0));
  Alcotest.(check bool) "the engine is sealed behind it" true
    (Engine.is_sealed after);
  Alcotest.(check string) "and the next output is refused, not executed"
    sealed_message
    (outcome (Engine.execute after out_after_close))

(* ================================================================== *)
(* T-27: the closing block is a BLOCK, not a receipt for the epoch.    *)
(* ================================================================== *)

(* The same output on an engine whose boundary nothing here reaches: every block
   is open, and the last one is the same block the closing run built except for
   its boundary. *)
let boundary_far = ts 2_000_000_000L

let t27 () =
  let closing =
    engine_with ~world:closing_world ~boundary:boundary_past ()
  in
  let _, closed = executed closing out_three_closing in
  let last_closed = nth "closing block" closed 2 in
  Alcotest.(check int) "the closing block executed its own batch" 1
    (List.length (Executed_block.transactions last_closed));
  Alcotest.(check bool) "so it burned gas" true
    (Block_header.gas_used (Executed_block.header last_closed) > 0);
  Alcotest.(check int) "having skipped nothing" 0
    (List.length (Executed_block.skipped last_closed));
  let open_engine =
    engine_with ~world:closing_world ~boundary:boundary_far ()
  in
  let _, opened = executed open_engine out_three_closing in
  let last_open = nth "open block" opened 2 in
  Alcotest.(check int) "the control run is three blocks too" 3
    (List.length opened);
  Alcotest.(check int) "and its last block carries no commitment" 0
    (String.length (extra_data last_open));
  Alcotest.(check string)
    "the closing block's transactions root is the open block's, byte for byte"
    (Bf.to_hex
       (Hash32.to_bytes
          (Block_header.transactions_root (Executed_block.header last_open))))
    (Bf.to_hex
       (Hash32.to_bytes
          (Block_header.transactions_root (Executed_block.header last_closed))))

(* ================================================================== *)
(* T-28: begin_epoch clears the counts and installs the committee.     *)
(* ================================================================== *)

let began engine ~boundary ~committee =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "begin_epoch: %s" (Engine.error_to_string e))
    (Engine.begin_epoch engine ~boundary ~committee)

let boundary_first = ts 1_000_000_000L
let boundary_second = ts 1_200_000_000L

(* Two outputs before the reset and one after it, all led by SEAT 0, all
   committed before the boundary in force at the time, so all three are skips
   and the counts are the only thing that moves. *)
let out_early_one = output_on chain_now ~at:900_000_001L ~r:1 [ (leader chain_now 0, []) ]
let out_early_two = output_on chain_now ~at:900_000_002L ~r:5 [ (leader chain_now 0, []) ]
let out_late = output_on chain_now ~at:1_100_000_000L ~r:9 [ (leader chain_now 0, []) ]

(* The closing output is led by seat 1, so seat 0's amount is exactly what the
   post-reset outputs gave it and nothing else. *)
let out_close_now =
  output_on chain_now ~at:1_300_000_000L ~r:13 [ (leader chain_now 1, []) ]

(* A closing output led by an authority of the OTHER committee. *)
let out_close_next =
  output_on chain_next ~at:1_300_000_000L ~r:13 [ (leader chain_next 0, []) ]

let close_only engine output =
  let _, blocks = executed engine output in
  Alcotest.(check int) "a closing empty output makes exactly one block" 1
    (List.length blocks);
  nth "close block" blocks 0

let t28 () =
  (* The counts row. *)
  let engine = engine_with ~boundary:boundary_first () in
  let engine =
    List.fold_left
      (fun e output -> fst (executed e output))
      engine [ out_early_one; out_early_two ]
  in
  let engine =
    began engine ~boundary:boundary_second ~committee:chain_now.cmt
  in
  let engine = fst (executed engine out_late) in
  let block = close_only engine out_close_now in
  Alcotest.(check int)
    "the leader of two pre-reset and one post-reset output is owed 1, not 3" 1
    (amount_at block (leader_address chain_now 0));
  Alcotest.(check int) "and the closing output's own leader is owed 1" 1
    (amount_at block (leader_address chain_now 1));
  (* The committee row: SENTINEL first. *)
  let installed =
    began
      (engine_with ~boundary:boundary_first ())
      ~boundary:boundary_second ~committee:chain_next.cmt
  in
  let sentinel = close_only installed out_close_next in
  Alcotest.(check int)
    "a leader of the INSTALLED next committee gets a withdrawal" 1
    (amount_at sentinel (leader_address chain_next 0));
  (* The NEGATIVE row: the same leader, the same output, the old committee. *)
  let stale =
    began
      (engine_with ~boundary:boundary_first ())
      ~boundary:boundary_second ~committee:chain_now.cmt
  in
  let negative = close_only stale out_close_next in
  Alcotest.(check int)
    "the same leader under the OLD committee resolves to no address" 0
    (List.length (withdrawals negative))

(* ================================================================== *)
(* T-29: the next boundary must strictly advance.                      *)
(* ================================================================== *)

let out_close_late =
  output_on chain_now ~at:1_700_000_500L ~r:9 [ (leader chain_now 0, []) ]

let out_next_epoch =
  output_on chain_now ~at:1_700_000_600L ~r:20
    [ (leader chain_now 1, [ batch ~base_fee:(fee 5) [] ]) ]

let t29 () =
  let sealed =
    fst (executed (engine_with ~boundary:boundary_past ()) out_close_late)
  in
  Alcotest.(check bool) "the epoch is sealed at the closing commit timestamp"
    true (Engine.is_sealed sealed);
  Alcotest.(check string) "a boundary EQUAL to it is refused"
    (not_advanced ~proposed:1_700_000_500L ~closed_at:1_700_000_500L)
    (outcome
       (Engine.begin_epoch sealed
          ~boundary:(ts 1_700_000_500L)
          ~committee:chain_now.cmt));
  Alcotest.(check string) "and one before it is refused"
    (not_advanced ~proposed:1_700_000_400L ~closed_at:1_700_000_500L)
    (outcome
       (Engine.begin_epoch sealed
          ~boundary:(ts 1_700_000_400L)
          ~committee:chain_now.cmt));
  Alcotest.(check bool) "a refusal leaves the engine sealed" true
    (Engine.is_sealed sealed);
  let running = began sealed ~boundary:boundary_far ~committee:chain_now.cmt in
  Alcotest.(check bool) "a boundary that advances reopens the epoch" false
    (Engine.is_sealed running);
  let _, blocks = executed running out_next_epoch in
  Alcotest.(check int) "and the next output builds its block" 1
    (List.length blocks);
  Alcotest.(check (list int)) "with EMPTY extra data: it does not re-close" [ 0 ]
    (List.map (fun b -> String.length (extra_data b)) blocks)

let () =
  Alcotest.run "engine_epoch"
    [
      ( "commitment",
        [
          Alcotest.test_case
            "T-26 one commitment per closing output, then sealed" `Quick t26;
          Alcotest.test_case "T-27 the closing block still executes its batch"
            `Quick t27;
        ] );
      ( "lifecycle",
        [
          Alcotest.test_case
            "T-28 begin_epoch clears the counts and installs the committee"
            `Quick t28;
          Alcotest.test_case "T-29 the next boundary must strictly advance"
            `Quick t29;
        ] );
    ]
