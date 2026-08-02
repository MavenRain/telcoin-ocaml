(* Chunk-37 stage 4: the driver core - watermark, fold, fail-stop.

   [Tn_driver.Driver] is the pure two-chain fold: mint-and-attach through the
   subscriber, execute through the real engine, and advance the forwarding
   watermark only AFTER the execute succeeds (H7). Fixtures are hand-built
   sub-DAGs over a real committee with DISTINCT execution addresses (no sim:
   the core is provable before injection exists), driven from a [Chain_spec]
   whose boundary sits far past every commit timestamp, so nothing here
   closes the epoch (the close is stage 5's fixture proof). The Continuity
   classifier was dropped (design patch P1): a driver that mints its own
   numbers always hands the engine the next contiguous output, so T4.5 keeps
   only its watermark half. T4.7 is reshaped by patch P7: every transaction
   in the port is a placeholder - dropped by the decode layer before the
   block, per test_engine_txskip T-35, one notch stricter than P7's
   "recorded as SKIPPED" prose - so a zero fee credit cannot distinguish the
   spec's basefee address from any other; chain id is tested through the
   config accessor and the drop is asserted honestly. *)

open Tn_types
open Tn_vertex
open Tn_consensus
module Bf = Block_fixtures
module Cb = Tn_execution.Consensus_block
module Nonempty = Tn_std.Nonempty
module Output = Tn_batch.Output
module Driver = Tn_driver.Driver
module Outcome = Tn_driver.Outcome
module Batch_store = Tn_driver.Batch_store
module Chain_spec = Tn_driver.Chain_spec
module Epoch_duration = Tn_driver.Chain_spec.Epoch_duration
module Address_book = Tn_driver.Address_book
module Engine = Tn_engine.Engine
module Config = Tn_engine.Config
module Anchor = Tn_engine.Anchor
module Block_number = Tn_engine.Block_number
module Executed_block = Tn_engine.Executed_block
module Recent_hashes = Tn_engine.Recent_hashes
module Rewards_counter = Tn_evm.Rewards_counter
module Block_header = Tn_evm.Block_header
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

(* Whether [needle] occurs in [haystack], for error-string assertions. *)
let mentions needle haystack =
  let n = String.length needle in
  List.exists
    (fun start ->
      String.equal needle
        (String.of_seq (Seq.take n (Seq.drop start (String.to_seq haystack)))))
    (List.init (Stdlib.max 0 (String.length haystack - n + 1)) Fun.id)

(* Four validators, each with its own execution address, so an id resolved to
   the WRONG seat's address cannot pass (no constant-valued fixture). *)
let member_addresses =
  [ mk_addr '\xa0'; mk_addr '\xa1'; mk_addr '\xa2'; mk_addr '\xa3' ]

let committee, sk_of =
  let sks =
    List.init 4 (fun i -> Tn_crypto.Secret_key.derive (Int64.of_int i))
  in
  let authorities =
    List.mapi
      (fun i sk ->
        Authority.make
          ~protocol_key:(Tn_crypto.Secret_key.public_key sk)
          ~execution_address:(nth "member address" member_addresses i))
      sks
  in
  let committee =
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
  (committee, sk_of)

let ids = List.map Authority.id (Committee.authorities committee)
let id0 = nth "id0" ids 0
let id1 = nth "id1" ids 1
let book = Address_book.of_committee committee
let address_of = Address_book.find book
let addr_of id = get "seat address" (Address_book.find book id)
let ts n = get "timestamp" (Units.Timestamp.of_sec n)
let round n = get "round" (Round.of_int n)
let genesis_parents = List.map Certificate.digest (Certificate.genesis committee)

let certify header =
  let votes = List.map (fun id -> Vote.sign (sk_of id) ~voter:id header) ids in
  Result.fold ~ok:Fun.id
    ~error:(fun e ->
      Alcotest.failf "certify: %s" (Certificate.error_to_string e))
    (Certificate.assemble committee header votes)

(* One committed sub-DAG. [entries] is (author, payload) in header order with
   the LEADER LAST, which is the shape [Sub_dag] commits and the reason [at]
   (the leader's creation time) is the output's commit timestamp. *)
let sub_dag_on ~r ~at entries =
  let n = List.length entries in
  let headers_rev, _ =
    List.fold_left
      (fun (acc, parents) (i, (author, payload)) ->
        let created_at =
          if i = n - 1 then ts at else ts (Int64.of_int (10 + i))
        in
        let header =
          Header.make ~author ~round:(round (r + i)) ~epoch:Units.Epoch.zero
            ~created_at ~payload ~parents
        in
        (header :: acc, [ Header.digest header ]))
      ([], genesis_parents)
      (List.mapi (fun i entry -> (i, entry)) entries)
  in
  let sequence =
    get "certificates" (Nonempty.of_list (List.rev_map certify headers_rev))
  in
  Sub_dag.create ~sequence
    ~scores:(Reputation_scores.fresh committee)
    ~previous:None

let w0 = Units.Worker_id.zero
let fee n = Units.Base_fee.of_int64 (Int64.of_int n)

(* Distinct transaction lists, so all four digests differ. The bytes are
   placeholders (the engine records them as skipped, risk R4): what the
   driver underwrites is threading and ordering, not transaction validity. *)
let body_of txs c =
  Batch.make ~transactions:txs ~epoch:Units.Epoch.zero ~beneficiary:(mk_addr c)
    ~base_fee_per_gas:(fee 7) ~worker_id:w0

let body_a = body_of [ "\x01" ] '\xb1'
let body_b = body_of [ "\x02"; "\x03" ] '\xb2'
let body_c = body_of [ "\x04" ] '\xb3'
let body_d = body_of [ "\x05" ] '\xb4'
let bodies = Batch_store.of_bodies [ body_a; body_b; body_c; body_d ]
let payload b = [ (Batch.digest b, w0) ]

(* ---------- the spec the driver cold-starts from ---------- *)

let u256_int n = get "u256" (U256.of_int n)
let u256_hex s = get "word" (U256.of_hex s)

let registry_entry =
  Tn_state.Genesis_account.make ~nonce:Tn_state.Nonce.zero
    ~balance:
      (get "balance"
         (U256.of_hex
            (String.make (64 - String.length Registry_genesis.balance_hex) '0'
           ^ Registry_genesis.balance_hex)))
    ~code:(Some (Bf.hex Registry_genesis.code_hex))
    ~storage:
      (List.map
         (fun (s, v) -> (u256_hex s, u256_hex v))
         Registry_genesis.storage_hex)

let genesis_hash = Tn_keccak.digest "chunk-37 driver genesis sentinel"
let basefee_address = mk_addr '\xbe'
let duration_28800 = get "epoch duration" (Epoch_duration.of_secs 28800)

(* Genesis at second 1 with a 28800 s epoch puts the boundary at 28801, far
   past every fixture commit (55..61 s): nothing in this file closes the
   epoch, so every advance is a mid-epoch one (the close is stage 5's). *)
let spec =
  Result.fold ~ok:Fun.id
    ~error:(fun e ->
      Alcotest.failf "chain spec: %s" (Chain_spec.error_to_string e))
    (Chain_spec.create ~chain_id:(u256_int 2017) ~basefee_address ~genesis_hash
       ~genesis_base_fee:(u256_int 7) ~genesis_gas_limit:30_000_000
       ~genesis_timestamp:(ts 1L) ~epoch_duration:duration_28800
       ~registry:registry_entry ~extra_alloc:[] ())

let driver0 () = Driver.create spec ~committee

let step_ok what d sd =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "%s: %s" what (Outcome.error_to_string e))
    (Driver.step d sd ~bodies ~address_of)

let fold_ok what d sds =
  match Driver.fold d sds ~bodies ~address_of with
  | Outcome.Advance { driver; advances } -> (driver, advances)
  | Outcome.Sealed { driver = _; advances = _; rest } ->
      Alcotest.failf
        "%s: sealed with %d outputs unconsumed under the 28800 s epoch" what
        (List.length rest)
  | Outcome.Halted { advances = _; error } ->
      Alcotest.failf "%s: %s" what (Outcome.error_to_string error)

let block_numbers blocks =
  List.map (fun b -> Block_number.to_int (Executed_block.number b)) blocks

(* The two-output, two-batch-each stream most cases fold. *)
let o1 () = sub_dag_on ~r:1 ~at:55L [ (id0, payload body_a); (id1, payload body_b) ]
let o2 () = sub_dag_on ~r:3 ~at:56L [ (id0, payload body_c); (id1, payload body_d) ]

(* T4.1: two successive two-batch outputs yield two blocks each, numbered
   1,2 then 3,4, and every block's parent hash is its predecessor's hash -
   ACROSS the output boundary, not merely within one output (H13: the engine
   is threaded, never re-created). *)
let test_numbers_and_links () =
  let _, advances = fold_ok "fold" (driver0 ()) [ o1 (); o2 () ] in
  Alcotest.(check (list (list int)))
    "execution numbers continue across the output boundary"
    [ [ 1; 2 ]; [ 3; 4 ] ]
    (List.map (fun a -> block_numbers a.Outcome.blocks) advances);
  let all_blocks = List.concat_map (fun a -> a.Outcome.blocks) advances in
  let (_ : Tn_keccak.t) =
    List.fold_left
      (fun expected b ->
        Alcotest.(check string) "block links to its predecessor's hash"
          (Tn_keccak.to_hex expected)
          (Tn_keccak.to_hex (Block_header.parent_hash (Executed_block.header b)));
        Executed_block.hash b)
      genesis_hash all_blocks
  in
  ()

(* T4.2: an EMPTY non-closing output returns blocks = [] yet the driver's
   engine shows the leader's count incremented by one (H14): the chain
   advanced even though execution was skipped, so the engine MUST be the
   post-call one. *)
let test_empty_output_credits_leader () =
  let d0 = driver0 () in
  Alcotest.(check int) "no leader counts before the first output" 0
    (List.length (Rewards_counter.address_counts (Engine.rewards (Driver.engine d0))));
  let d1, adv =
    step_ok "empty output" d0 (sub_dag_on ~r:1 ~at:55L [ (id0, []) ])
  in
  Alcotest.(check int) "an empty non-closing output produces no block" 0
    (List.length adv.Outcome.blocks);
  Alcotest.(check bool) "and does not close the epoch" false
    adv.Outcome.closes_epoch;
  Alcotest.(check (list (pair string int)))
    "the leader's count advanced to one, nobody else's"
    [ (Units.Address.to_bytes (addr_of id0), 1) ]
    (List.map
       (fun (a, c) -> (Units.Address.to_bytes a, c))
       (Rewards_counter.address_counts (Engine.rewards (Driver.engine d1))))

(* T4.3: fold over [good; good; bad] halts with EXACTLY the two good
   advances and the error naming the missing body; the Halted arm carries no
   driver AT ALL (a compile-time fact: [Outcome.Halted] has no driver
   field), so resuming past the violation is unrepresentable. G6: the last
   advance IS the watermark a restart would resume from - number 2, the
   last SUCCESSFULLY executed output. *)
let test_fold_fail_stop () =
  let missing = body_of [ "\x0f" ] '\xbf' in
  let sds =
    [
      o1 ();
      o2 ();
      sub_dag_on ~r:5 ~at:57L [ (id0, payload missing); (id1, []) ];
    ]
  in
  match Driver.fold (driver0 ()) sds ~bodies ~address_of with
  | Outcome.Advance { driver = _; advances } ->
      Alcotest.failf "fold returned Ok with %d advances despite the bad output"
        (List.length advances)
  | Outcome.Sealed { driver = _; advances = _; rest = _ } ->
      Alcotest.fail "fold sealed despite the bad output and the 28800 s epoch"
  | Outcome.Halted { advances; error } ->
      Alcotest.(check int) "the prefix is exactly the two good advances" 2
        (List.length advances);
      let last = nth "last advance" advances (List.length advances - 1) in
      Alcotest.(check int)
        "the last advance is the last successfully executed output" 2
        (Cb.Number.to_int (Cb.number last.Outcome.consensus));
      Alcotest.(check bool) "the error names the missing body's digest" true
        (mentions
           (Digests.Batch_digest.to_hex (Batch.digest missing))
           (Outcome.error_to_string error))

(* T4.4: for every advance the minted consensus block and the attached
   output are the SAME step's pair: digest (consensus) = output_digest
   (output), so the two things a shell persists cannot be mismatched (D6).
   The middle output references ONE digest under TWO headers, so the pairing
   holds on the duplicate-resolution path too and the store demonstrably
   answered twice through the whole driver (G8). *)
let test_advance_pairing () =
  let dup = sub_dag_on ~r:3 ~at:56L [ (id0, payload body_a); (id1, payload body_a) ] in
  let _, advances =
    fold_ok "fold"
      (driver0 ())
      [ o1 (); dup; sub_dag_on ~r:5 ~at:57L [ (id1, []) ] ]
  in
  Alcotest.(check int) "three advances" 3 (List.length advances);
  List.iter
    (fun a ->
      Alcotest.(check string) "consensus and output are the same step's pair"
        (Digests.Output_digest.to_hex (Cb.digest a.Outcome.consensus))
        (Digests.Output_digest.to_hex (Output.output_digest a.Outcome.output)))
    advances;
  let dup_advance = nth "dup advance" advances 1 in
  let entries = Output.certified dup_advance.Outcome.output in
  Alcotest.(check int) "the duplicate output kept both certified entries" 2
    (List.length entries);
  Alcotest.(check bool) "and the store answered the same body for both" true
    (List.for_all
       (fun (_, bs) -> List.length bs = 1 && List.for_all (Batch.equal body_a) bs)
       entries)

(* T4.5 (watermark half; the classify half is void with Continuity, patch
   P1): the watermark starts at the consensus genesis number and, after
   folding three outputs, reads 3 - it advances with successful execution
   and with nothing else. *)
let test_watermark () =
  let d0 = driver0 () in
  Alcotest.(check int) "cold start forwards nothing" 0
    (Cb.Number.to_int (Driver.last_forwarded d0));
  let d3, _ =
    fold_ok "fold" d0
      [ o1 (); o2 (); sub_dag_on ~r:5 ~at:57L [ (id0, []) ] ]
  in
  Alcotest.(check int) "after three outputs the watermark reads 3" 3
    (Cb.Number.to_int (Driver.last_forwarded d3))

(* T4.6: the BLOCKHASH window after output 2 still contains output 1's block
   hashes (H13): the window rolls across outputs rather than resetting to
   the genesis window. *)
let test_window_rolls () =
  let d, advances = fold_ok "fold" (driver0 ()) [ o1 (); o2 () ] in
  let window = Recent_hashes.to_list (Engine.recent_hashes (Driver.engine d)) in
  let first = nth "first advance" advances 0 in
  Alcotest.(check int) "output 1 produced two blocks" 2
    (List.length first.Outcome.blocks);
  List.iter
    (fun b ->
      Alcotest.(check bool) "output 1's block hash is still in the window" true
        (List.exists (Tn_keccak.equal (Executed_block.hash b)) window))
    first.Outcome.blocks

(* T4.7 (as reshaped by P7): Driver.create wires Chain_spec.engine_config -
   the chain id and basefee address read back off the engine's config equal
   the spec's OWN accessors (never literals re-derived here), and the first
   block's parent hash is the spec's genesis anchor hash. The fee-credit
   field cannot be probed by balance: every transaction in the port is a
   placeholder recorded as SKIPPED, so the honest assertion is the skip
   recording itself plus a ZERO credit at the basefee address. *)
let test_spec_wiring () =
  let d0 = driver0 () in
  let cfg = Engine.config (Driver.engine d0) in
  Alcotest.(check string) "the engine's chain id is the spec's"
    (U256.to_hex (Chain_spec.chain_id spec))
    (U256.to_hex (Config.chain_id cfg));
  Alcotest.(check string) "the engine's basefee address is the spec's"
    (String.escaped (Units.Address.to_bytes (Chain_spec.basefee_address spec)))
    (String.escaped (Units.Address.to_bytes (Config.basefee_address cfg)));
  let _, adv =
    step_ok "one-batch output" d0
      (sub_dag_on ~r:1 ~at:55L [ (id0, payload body_a) ])
  in
  let block = nth "first block" adv.Outcome.blocks 0 in
  Alcotest.(check string) "the first block builds on the spec's genesis hash"
    (Tn_keccak.to_hex (Anchor.hash (Chain_spec.anchor spec)))
    (Tn_keccak.to_hex (Block_header.parent_hash (Executed_block.header block)));
  Alcotest.(check int) "no placeholder transaction executed" 0
    (List.length (Executed_block.transactions block));
  Alcotest.(check int)
    "and none was even recorded skipped: the undecodable placeholder is \
     dropped BEFORE the block (test_engine_txskip T-35), tightening P7's \
     'recorded as SKIPPED' to what the tree does"
    0
    (List.length (Executed_block.skipped block));
  Alcotest.(check string)
    "so the basefee address's credit is zero (why chain id is asserted \
     through the accessor instead, P7)"
    (U256.to_hex (World.balance (Chain_spec.world spec) basefee_address))
    (U256.to_hex (World.balance (Executed_block.world block) basefee_address))

let () =
  Alcotest.run "driver"
    [
      ( "core",
        [
          Alcotest.test_case "numbers and links continue across outputs" `Quick
            test_numbers_and_links;
          Alcotest.test_case "an empty output still credits the leader" `Quick
            test_empty_output_credits_leader;
          Alcotest.test_case "fold is fail-stop with the good prefix" `Quick
            test_fold_fail_stop;
          Alcotest.test_case "each advance pairs its own consensus and output"
            `Quick test_advance_pairing;
          Alcotest.test_case "the watermark advances only with execution"
            `Quick test_watermark;
          Alcotest.test_case "the BLOCKHASH window rolls across outputs" `Quick
            test_window_rolls;
          Alcotest.test_case "create wires the spec, not literals" `Quick
            test_spec_wiring;
        ] );
    ]
