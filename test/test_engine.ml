(* Chunk-36 stage 4: the tn_engine skeleton and the skipped-output path.

   The engine folds committed consensus output that a driver has already
   attached bodies and certificate addresses to, so the fixtures here build a
   real committee, real certificates and a real committed sub-DAG, then hand
   [Output.attach]'s result to the engine, exactly as a node would.

   The committee's four members have DISTINCT execution addresses, which is
   what makes the leader-count rows readable: with the usual all-zero addresses
   every authority's count would merge into one record, and a member that never
   led would be indistinguishable from one that led twice. *)

open Tn_types
open Tn_vertex
open Tn_consensus
module Cb = Tn_execution.Consensus_block
module Nonempty = Tn_std.Nonempty
module Output = Tn_batch.Output
module Engine = Tn_engine.Engine
module Config = Tn_engine.Config
module Anchor = Tn_engine.Anchor
module Block_number = Tn_engine.Block_number
module Recent_hashes = Tn_engine.Recent_hashes
module Rewards_counter = Tn_evm.Rewards_counter
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

(* Four validators, each with its own execution address. *)
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

(* Committee order is ascending authority id, not creation order, and the
   leader counts resolve through the COMMITTEE's execution addresses, so the
   members are read back off the committee rather than paired with the list
   they were built from. *)
let members = Committee.authorities committee
let ids = List.map Authority.id members
let id0 = nth "id0" ids 0
let id1 = nth "id1" ids 1
let member_address i = Authority.execution_address (nth "member" members i)
let addr_a = member_address 0
let addr_b = member_address 1
let addr_c = member_address 2
let addr_d = member_address 3

(* The authority table the driver injects: the same addresses the committee
   carries, so a leader's count and its withdrawal address agree. *)
let address_of id =
  List.find_map
    (fun a ->
      if Authority_id.equal (Authority.id a) id then
        Some (Authority.execution_address a)
      else None)
    members

let ts n = get "timestamp" (Units.Timestamp.of_sec n)
let round n = get "round" (Round.of_int n)
let genesis_parents = List.map Certificate.digest (Certificate.genesis committee)

let certify header =
  let votes = List.map (fun id -> Vote.sign (sk_of id) ~voter:id header) ids in
  Result.fold ~ok:Fun.id
    ~error:(fun e ->
      Alcotest.failf "certify: %s" (Certificate.error_to_string e))
    (Certificate.assemble committee header votes)

(* One leader-only header with an EMPTY payload: no batches, so the plan is
   Skip for as long as the output does not close the epoch. *)
let empty_output ~author ~r ~at =
  let header =
    Header.make ~author ~round:(round r) ~epoch:Units.Epoch.zero
      ~created_at:(ts at) ~payload:[] ~parents:genesis_parents
  in
  let sub_dag =
    Sub_dag.create
      ~sequence:(Nonempty.singleton (certify header))
      ~scores:(Reputation_scores.fresh committee)
      ~previous:None
  in
  let consensus =
    Cb.create ~parent_hash:Cb.genesis_parent ~sub_dag
      ~number:(Cb.Number.succ Cb.Number.genesis)
  in
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "attach: %s" (Output.error_to_string e))
    (Output.attach ~consensus ~lookup:(fun _ -> None) ~address_of)

(* Leader A (id0) leads the first and third outputs, leader B (id1) the
   second. Every one of them is empty, so every one of them is a Skip. *)
let skip_a1 = empty_output ~author:id0 ~r:1 ~at:55L
let skip_b = empty_output ~author:id1 ~r:2 ~at:56L
let skip_a2 = empty_output ~author:id0 ~r:3 ~at:57L

(* The configured chain. {!Tn_keccak.digest} is the only producer of a hash in
   this port, so the genesis sentinel is the hash of a string nothing else in
   the fixture hashes: not the empty hash, and not any header's hash. The world
   holds one funded account, so "the world did not move" is an assertion about
   something rather than about two empty maps. *)
let genesis_hash = Tn_keccak.digest "chunk 36 genesis sentinel"
let ancestor_hash = Tn_keccak.digest "chunk 36 ancestor sentinel"
let funded = mk_addr '\xf0'
let sentinel_balance = get "balance" (U256.of_int 0x2b)
let world0 = World.of_alloc [ (funded, sentinel_balance) ]
let chain_id = get "chain id" (U256.of_int 0x7e5)
let basefee_address = mk_addr '\xbe'

(* Far past every fixture's commit timestamp, so no output here closes the
   epoch and every plan is a Skip. *)
let boundary = ts 10_000L

let config =
  Config.create
    ~anchor:
      (Anchor.of_genesis ~hash:genesis_hash
         ~base_fee:(get "base fee" (U256.of_int 77))
         ~gas_limit:30_000_000)
    ~ancestors:[ ancestor_hash ] ~world:world0 ~chain_id ~basefee_address
    ~epoch_boundary:boundary ~committee

let engine0 = Engine.create config

let executed engine output =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "execute: %s" (Engine.error_to_string e))
    (Engine.execute engine output)

(* Fold a list of outputs, keeping the engine and discarding the blocks, which
   is sound here only because every output in this suite is a Skip. *)
let fold_skips engine outputs =
  List.fold_left
    (fun engine output -> fst (executed engine output))
    engine outputs

let keccak =
  Alcotest.testable
    (fun ppf h -> Format.pp_print_string ppf (Tn_keccak.to_hex h))
    Tn_keccak.equal

(* T-01: an empty, non-closing output produces no block and moves nothing: not
   the tip, not the height, not the anchor, not the world, not the BLOCKHASH
   window. *)
let t01 () =
  (* Named first, so that a Skip falling through to a block-building arm is a
     failed assertion rather than an unnamed abort: no Skip output ever reaches
     the arms this stage leaves unbuilt. *)
  Alcotest.(check bool) "a skip is not an error" true
    (Result.is_ok (Engine.execute engine0 skip_a1));
  let after, blocks = executed engine0 skip_a1 in
  Alcotest.(check int) "a skip produces no block" 0 (List.length blocks);
  Alcotest.(check bool) "a skip leaves the tip unset" true
    (Option.is_none (Engine.tip after));
  Alcotest.(check int) "a skip leaves the height at the anchor's" 0
    (Block_number.to_int (Engine.height after));
  Alcotest.(check bool) "a skip leaves the anchor hash where it was" true
    (Tn_keccak.equal
       (Anchor.hash (Engine.anchor after))
       (Anchor.hash (Engine.anchor engine0)));
  Alcotest.(check bool) "a skip leaves the world where it was" true
    (World.equal (Engine.world after) (Engine.world engine0));
  Alcotest.(check (list keccak))
    "a skip leaves the BLOCKHASH window where it was"
    (Recent_hashes.to_list (Engine.recent_hashes engine0))
    (Recent_hashes.to_list (Engine.recent_hashes after));
  Alcotest.(check (list keccak))
    "the window starts at the anchor hash, then its ancestors"
    [ genesis_hash; ancestor_hash ]
    (Recent_hashes.to_list (Engine.recent_hashes after))

let withdrawals_of engine =
  Result.fold ~ok:Fun.id
    ~error:(fun e ->
      Alcotest.failf "withdrawals: %s" (Rewards_counter.error_to_string e))
    (Rewards_counter.generate_withdrawals (Engine.rewards engine))

(* The amount an address is owed, and zero for an address with no record at
   all, which is the row that tells "never led" from "led once". *)
let amount_for engine address =
  List.fold_left
    (fun acc w ->
      if Units.Address.equal (Tn_evm.Withdrawal.address w) address then
        acc + Tn_evm.Withdrawal.amount w
      else acc)
    0 (withdrawals_of engine)

let has_record engine address =
  List.exists
    (fun w -> Units.Address.equal (Tn_evm.Withdrawal.address w) address)
    (withdrawals_of engine)

(* T-02: a skip is block-neutral and tip-neutral but NOT rewards-neutral.
   Leader A leads two skipped outputs and leader B one, and the counts an epoch
   would pay out say so. NEGATIVE ROW: member D never led, and has no
   withdrawal record at all.

   The design's row runs the second output as a CLOSING one and reads A's
   amount off the closing block's withdrawals; that block is a later stage's,
   so the same counts are read here off the engine, which is the only place
   they exist before an epoch closes. *)
let t02 () =
  let after = fold_skips engine0 [ skip_a1; skip_b; skip_a2 ] in
  Alcotest.(check int) "the leader of two skipped outputs is owed 2" 2
    (amount_for after addr_a);
  Alcotest.(check int) "the leader of one skipped output is owed 1" 1
    (amount_for after addr_b);
  Alcotest.(check bool)
    "a member that never led has no withdrawal record at all" false
    (has_record after addr_d);
  Alcotest.(check bool) "and neither has the third member" false
    (has_record after addr_c);
  Alcotest.(check int) "an engine that folded nothing owes nobody" 0
    (amount_for engine0 addr_a)

(* ================================================================== *)
(* Chunk-36 stage 5: the Batch_blocks fold.                            *)
(* ================================================================== *)

(* Everything above runs on outputs with no batches at all. From here the
   outputs carry real batch bodies, so the engine's per-block work is what is
   under test: chaining, the threaded world, the rolling BLOCKHASH window, the
   once-per-output EIP-4788 write, and the all-or-nothing return.

   The EVM fixtures are [Block_fixtures]', qualified rather than opened so this
   file's own [get]/[nth] keep their meaning. *)

module Bf = Block_fixtures
module Block_execution = Tn_evm.Block_execution
module Block_header = Tn_evm.Block_header
module Block_roots = Tn_evm.Block_roots
module Executed_block = Tn_engine.Executed_block
module Hash32 = Tn_evm.Hash32
module Opcode = Tn_evm.Opcode
module Transaction = Tn_evm.Transaction
module Tx_envelope = Tn_evm.Tx_envelope

let w0 = Units.Worker_id.zero
let worker n = get "worker id" (Units.Worker_id.of_int n)
let fee n = Units.Base_fee.of_int64 (Int64.of_int n)
let word n = get "word" (U256.of_int n)
let word_hex v = Bf.to_hex (U256.to_be_bytes v)
let keccak_hex h = Bf.to_hex (Tn_keccak.to_bytes h)
let addr_hex a = Bf.to_hex (Units.Address.to_bytes a)

(* Is [needle] anywhere in [haystack]? Consumed as a sequence rather than
   sliced, so no range is computed and none can be out of bounds. *)
let mentions needle haystack =
  let n = String.length needle in
  List.exists
    (fun start ->
      String.equal needle
        (String.of_seq (Seq.take n (Seq.drop start (String.to_seq haystack)))))
    (List.init (Stdlib.max 0 (String.length haystack - n + 1)) Fun.id)

(* A batch of already-signed envelopes, and one of raw wire bytes for the
   payloads the drop layer is supposed to discard. The base fee varies because
   it is the cheapest way to give two otherwise identical batches two digests,
   and because a block reads its own batch's fee. *)
let batch ?(base_fee = fee 0) ?(w = w0) txs =
  Batch.make
    ~transactions:(List.map Tx_envelope.encode_2718 txs)
    ~epoch:Units.Epoch.zero ~beneficiary:Units.Address.zero
    ~base_fee_per_gas:base_fee ~worker_id:w

let raw_batch ?(base_fee = fee 0) ?(w = w0) txs =
  Batch.make ~transactions:txs ~epoch:Units.Epoch.zero
    ~beneficiary:Units.Address.zero ~base_fee_per_gas:base_fee ~worker_id:w

(* One committee's worth of everything an output needs. The suite needs more
   than one, because the withdrawal ordering row is ABOUT a committee whose
   execution addresses are deliberately not in creation order. *)
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

(* The suite's standing chain is the one the skip cases already built. *)
let main_chain =
  {
    cmt = committee;
    chain_certify = certify;
    chain_address_of = address_of;
    chain_parents = genesis_parents;
  }

(* Every authority of [ch] holding [address]: a list rather than a lookup,
   because a committee with two members at one execution address is exactly
   what the summing row is about. *)
let ids_at ch address =
  List.filter_map
    (fun a ->
      if Units.Address.equal (Authority.execution_address a) address then
        Some (Authority.id a)
      else None)
    (Committee.authorities ch.cmt)

(* One committed output. [entries] is (author, its batches) in header order
   with the LEADER LAST, which is the shape [Sub_dag] commits and the reason
   [at] (the leader's creation time) is the output's commit timestamp. *)
let output_on ch ~at ~r entries =
  let bodies = List.concat_map (fun (_, bs) -> List.map fst bs) entries in
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
            ~payload:(List.map (fun (b, w) -> (Batch.digest b, w)) bs)
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
    Sub_dag.create ~sequence
      ~scores:(Reputation_scores.fresh ch.cmt)
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

(* One certificate's worth, which is most of the cases. *)
let single ?(author = id0) ~at ~r bs = output_on main_chain ~at ~r [ (author, bs) ]

(* Far past every commit timestamp below, so nothing here closes the epoch and
   every non-empty output plans as Batch_blocks. *)
let boundary_far = ts 2_000_000_000L

let engine_on ?(ancestors = [ ancestor_hash ]) ?(chain = main_chain) world =
  Engine.create
    (Config.create
       ~anchor:
         (Anchor.of_genesis ~hash:genesis_hash
            ~base_fee:(get "base fee" (U256.of_int 77))
            ~gas_limit:30_000_000)
       ~ancestors ~world ~chain_id ~basefee_address ~epoch_boundary:boundary_far
       ~committee:chain.cmt)

let header_at blocks i = Executed_block.header (nth "block" blocks i)

let numbers blocks =
  List.map (fun b -> Block_header.number (Executed_block.header b)) blocks

let hashes blocks = List.map Executed_block.hash blocks

(* ---------- contracts that read the BLOCKHASH window ---------- *)

(* PUSH delta; NUMBER; SUB; BLOCKHASH; PUSH1 slot; SSTORE. SSTORE pops the key
   first, so the slot is pushed last; SUB pops the top first, so NUMBER is
   pushed after the delta. Slot [slot] then holds BLOCKHASH(number - delta). *)
let relative_read ~width ~delta ~slot =
  Bf.bytes_of
    [
      Bf.push_int ~width delta;
      Bf.op Opcode.Number;
      Bf.op Opcode.Sub;
      Bf.op Opcode.Blockhash;
      Bf.push1 slot;
      Bf.op Opcode.Sstore;
    ]

(* The same, at an ABSOLUTE height, which is how a block asks for its own. *)
let absolute_read ~number ~slot =
  Bf.bytes_of
    [
      Bf.push1 number;
      Bf.op Opcode.Blockhash;
      Bf.push1 slot;
      Bf.op Opcode.Sstore;
    ]

let contract parts = Bf.bytes_of (parts @ [ Bf.op Opcode.Stop ])

(* ---------- the standing transactions and worlds ---------- *)

let call address = Transaction.Call address

(* Every batch below sets a base fee, and the executor refuses a transaction
   whose gas price is under it, so the fixtures bid well over the highest fee
   any batch here carries. A tx priced under its block's base fee is not an
   error, it is a SKIP, which is exactly the shape that would quietly empty a
   block the case is trying to read storage out of. *)
let gas_price = 100
let transfer ~signer =
  Bf.legacy_envelope ~signer ~gas_price:gas_price ~gas_limit:21_000 ()
let tx_a = transfer ~signer:41
let tx_b = transfer ~signer:42
let tx_c = transfer ~signer:43
let tx_d = transfer ~signer:44
let world_abcd = Bf.fund World.empty [ tx_a; tx_b; tx_c; tx_d ]

(* T-04: the first block is number ONE off the CONFIGURED genesis hash, which
   is a sentinel: the keccak of a string nothing else in the fixture hashes,
   so neither zero nor any header's hash can pass for it. *)
let out_one = single ~at:1_700_000_123L ~r:1 [ (batch [ tx_a ], w0) ]

let t04 () =
  let _, blocks = executed (engine_on world_abcd) out_one in
  Alcotest.(check int) "one batch makes one block" 1 (List.length blocks);
  Alcotest.(check (list int)) "numbered 1, off a genesis anchor at 0" [ 1 ]
    (numbers blocks);
  Alcotest.(check keccak) "with the configured genesis hash as its parent"
    genesis_hash
    (Block_header.parent_hash (header_at blocks 0))

(* T-05: three blocks in one output chain by number and by parent hash. *)
let out_three =
  output_on main_chain ~at:1_700_000_123L ~r:1
    [
      (id0, [ (batch [ tx_a ], w0); (batch ~base_fee:(fee 1) [ tx_b ], w0) ]);
      (id1, [ (batch ~base_fee:(fee 2) [ tx_c ], w0) ]);
    ]

let t05 () =
  let _, blocks = executed (engine_on world_abcd) out_three in
  Alcotest.(check int) "three batches make three blocks" 3 (List.length blocks);
  Alcotest.(check (list int)) "numbered 1, 2, 3" [ 1; 2; 3 ] (numbers blocks);
  Alcotest.(check (list keccak))
    "and each block's parent is the block before it"
    (genesis_hash :: List.filteri (fun i _ -> i < 2) (hashes blocks))
    (List.map
       (fun b -> Block_header.parent_hash (Executed_block.header b))
       blocks)

(* T-06/T-07: the world threads. Block 1 credits the spender the SENTINEL
   0x2b, which is exactly what block 2's transfer needs on top of its gas, so
   an engine that re-runs every block against the pre-output world leaves the
   second transaction unaffordable and the builder skips it. *)
let sentinel_value = 0x2b
let payee = mk_addr '\xd0'

let tx_spend =
  Bf.legacy_envelope ~signer:45 ~gas_price ~gas_limit:21_000
    ~value:sentinel_value ~kind:(call payee) ()

let spender = Bf.sender_of tx_spend

let tx_credit =
  Bf.legacy_envelope ~signer:46 ~gas_price ~gas_limit:21_000
    ~value:sentinel_value ~kind:(call spender) ()

let world_thread =
  World.of_alloc
    [
      (Bf.sender_of tx_credit, word 1_000_000_000);
      (* Gas money and not one wei more: the sentinel is the whole difference
         between a block that can pay and one that cannot. *)
      (spender, word (21_000 * gas_price));
    ]

let out_thread =
  single ~at:1_700_000_123L ~r:1
    [ (batch [ tx_credit ], w0); (batch ~base_fee:(fee 1) [ tx_spend ], w0) ]

let t06 () =
  let _, blocks = executed (engine_on world_thread) out_thread in
  Alcotest.(check int) "two batches make two blocks" 2 (List.length blocks);
  let b1 = nth "block 1" blocks 0 and b2 = nth "block 2" blocks 1 in
  Alcotest.(check int) "block 2 spends what block 1 credited" 1
    (List.length (Executed_block.transactions b2));
  Alcotest.(check int) "and skips nothing" 0
    (List.length (Executed_block.skipped b2));
  Alcotest.(check string) "the sentinel reached the payee"
    (word_hex (word sentinel_value))
    (word_hex (World.balance (Executed_block.world b2) payee));
  Alcotest.(check bool) "and the two blocks root different states" false
    (String.equal
       (Block_roots.state_root (Executed_block.world b1))
       (Block_roots.state_root (Executed_block.world b2)))

let out_credit = single ~at:1_700_000_123L ~r:1 [ (batch [ tx_credit ], w0) ]

let out_spend =
  single ~author:id1 ~at:1_700_000_124L ~r:5 [ (batch [ tx_spend ], w0) ]

let t07 () =
  let after_credit, _ = executed (engine_on world_thread) out_credit in
  let _, blocks = executed after_credit out_spend in
  let b = nth "block" blocks 0 in
  Alcotest.(check int) "the second output's block executes its transfer" 1
    (List.length (Executed_block.transactions b));
  Alcotest.(check int) "having skipped nothing" 0
    (List.length (Executed_block.skipped b));
  Alcotest.(check string) "the sentinel reached the payee across the outputs"
    (word_hex (word sentinel_value))
    (word_hex (World.balance (Executed_block.world b) payee))

(* T-08: every block of one output carries the OUTPUT's commit timestamp, not
   a parent timestamp plus one. *)
let t08 () =
  let _, blocks = executed (engine_on world_abcd) out_three in
  let committed =
    Int64.to_int (Units.Timestamp.to_sec (Output.committed_at out_three))
  in
  Alcotest.(check int) "the fixture's commit timestamp is the sentinel"
    1_700_000_123 committed;
  Alcotest.(check (list int)) "and all three headers carry it unchanged"
    [ committed; committed; committed ]
    (List.map
       (fun b -> Block_header.timestamp (Executed_block.header b))
       blocks)

(* T-09: commit timestamps are only NON-decreasing, so two outputs sharing one
   are both accepted. There is no timestamp error path to reach. *)
let out_same_a = single ~at:1_700_000_123L ~r:1 [ (batch [ tx_a ], w0) ]

let out_same_b =
  single ~author:id1 ~at:1_700_000_123L ~r:7
    [ (batch ~base_fee:(fee 3) [ tx_b ], w0) ]

let t09 () =
  let after_a, _ = executed (engine_on world_abcd) out_same_a in
  Alcotest.(check bool)
    "an output committed at the same second as the last is not refused" true
    (Result.is_ok (Engine.execute after_a out_same_b));
  let _, blocks = executed after_a out_same_b in
  Alcotest.(check (list int)) "and its block carries that same timestamp"
    [ 1_700_000_123 ]
    (List.map
       (fun b -> Block_header.timestamp (Executed_block.header b))
       blocks)

(* T-10: execution order is certificate-major, batch-minor, by POSITION. The
   four base fees are distinct so the (beneficiary, fee) walk pins the whole
   permutation, and the digest-sorted order is asserted to DIFFER from the
   positional one so a sort would actually change something. *)
let order_batches =
  List.map
    (fun (tx, f) -> batch ~base_fee:(fee f) [ tx ])
    [ (tx_a, 19); (tx_b, 11); (tx_c, 17); (tx_d, 13) ]

let out_order =
  output_on main_chain ~at:1_700_000_123L ~r:1
    [
      ( id0,
        List.filteri
          (fun i _ -> i < 2)
          (List.map (fun b -> (b, w0)) order_batches) );
      ( id1,
        List.filteri
          (fun i _ -> i >= 2)
          (List.map (fun b -> (b, w0)) order_batches) );
    ]

let t10 () =
  let _, blocks = executed (engine_on world_abcd) out_order in
  let expected =
    List.concat_map
      (fun (address, bs) ->
        List.map
          (fun b ->
            ( addr_hex address,
              word_hex
                (U256.of_u64_bits
                   (Units.Base_fee.to_int64 (Batch.base_fee_per_gas b))) ))
          bs)
      (Output.certified out_order)
  in
  Alcotest.(check int) "four batches make four blocks" 4 (List.length blocks);
  Alcotest.(check (list (pair string string)))
    "the (beneficiary, base fee) walk is the certified walk" expected
    (List.map
       (fun b ->
         let h = Executed_block.header b in
         ( addr_hex (Block_header.beneficiary h),
           word_hex (Block_header.base_fee_per_gas h) ))
       blocks);
  let digests = List.map Batch.digest order_batches in
  Alcotest.(check bool)
    "and digest order is NOT positional order, so a sort would show" false
    (List.equal Digests.Batch_digest.equal digests
       (List.sort Digests.Batch_digest.compare digests))

(* T-11: the header difficulty is the PACKED batch position, not the flat
   index. Worker 3 on the second batch is the sentinel that tells the two
   apart. *)
let out_packed =
  single ~at:1_700_000_123L ~r:1
    [
      (batch [ tx_a ], w0);
      (batch ~base_fee:(fee 1) ~w:(worker 3) [ tx_b ], worker 3);
    ]

let t11 () =
  let _, blocks = executed (engine_on world_abcd) out_packed in
  Alcotest.(check string) "block 1 packs batch 0, worker 0" (word_hex U256.zero)
    (word_hex (Block_header.difficulty (header_at blocks 0)));
  Alcotest.(check string) "block 2 packs (1 lsl 16) lor 3"
    (word_hex (word ((1 lsl 16) lor 3)))
    (word_hex (Block_header.difficulty (header_at blocks 1)))

(* T-12: the EIP-4788 consensus-root write happens once per OUTPUT, on the
   first batch only, while the EIP-2935 blockhashes write happens on every
   block. Read off the carried Pre_block token, so nothing is re-run. *)
let root_disposition b =
  match
    Block_execution.Pre_block.consensus_root (Executed_block.pre_block b)
  with
  | Block_execution.Pre_block.Root_skipped_at_genesis -> "skipped at genesis"
  | Block_execution.Pre_block.Root_skipped_after_first_batch ->
      "skipped after the first batch"
  | Block_execution.Pre_block.Root_written _ -> "written"

let hash_disposition b =
  match Block_execution.Pre_block.blockhashes (Executed_block.pre_block b) with
  | Block_execution.Pre_block.Hash_skipped_at_genesis -> "skipped at genesis"
  | Block_execution.Pre_block.Hash_written _ -> "written"

let t12 () =
  let _, blocks = executed (engine_on world_abcd) out_three in
  Alcotest.(check (list string))
    "the consensus root is written once, on the first batch"
    [
      "written";
      "skipped after the first batch";
      "skipped after the first batch";
    ]
    (List.map root_disposition blocks);
  Alcotest.(check (list string)) "the blockhashes write runs on every block"
    [ "written"; "written"; "written" ]
    (List.map hash_disposition blocks)

(* T-13: the window is seeded from the genesis hash and rolls between blocks.
   Block 1 reads its parent and finds the SENTINEL genesis hash; block 3 reads
   height 2 and finds block 2; block 2 reads height 2, its own, and finds
   zero, because the hash is pushed only after the header is assembled. *)
let parent_reader = mk_addr '\xc1'
let self_reader = mk_addr '\xc2'

let tx_parent =
  Bf.legacy_envelope ~signer:51 ~gas_price ~gas_limit:200_000
    ~kind:(call parent_reader) ()

let tx_self2 =
  Bf.legacy_envelope ~signer:52 ~gas_price ~gas_limit:200_000
    ~kind:(call self_reader) ()

let tx_self3 =
  Bf.legacy_envelope ~signer:53 ~gas_price ~gas_limit:200_000
    ~kind:(call self_reader) ()

let world_window =
  Bf.with_code
    (Bf.with_code
       (Bf.fund World.empty [ tx_parent; tx_self2; tx_self3 ])
       parent_reader
       (contract [ relative_read ~width:1 ~delta:1 ~slot:1 ]))
    self_reader
    (contract [ absolute_read ~number:2 ~slot:2 ])

let out_window =
  single ~at:1_700_000_123L ~r:1
    [
      (batch [ tx_parent ], w0);
      (batch ~base_fee:(fee 1) [ tx_self2 ], w0);
      (batch ~base_fee:(fee 2) [ tx_self3 ], w0);
    ]

let t13 () =
  let _, blocks = executed (engine_on world_window) out_window in
  Alcotest.(check int) "three blocks" 3 (List.length blocks);
  Alcotest.(check (list int))
    "every block ran its reader: a skipped call would empty the slots it reads"
    [ 1; 1; 1 ]
    (List.map (fun b -> List.length (Executed_block.transactions b)) blocks);
  let b1 = nth "block 1" blocks 0
  and b2 = nth "block 2" blocks 1
  and b3 = nth "block 3" blocks 2 in
  Alcotest.(check string) "block 1's BLOCKHASH(0) is the genesis sentinel"
    (keccak_hex genesis_hash)
    (word_hex (Bf.slot (Executed_block.world b1) parent_reader 1));
  Alcotest.(check string) "block 2's BLOCKHASH(2), its own height, is zero"
    (word_hex U256.zero)
    (word_hex (Bf.slot (Executed_block.world b2) self_reader 2));
  Alcotest.(check string) "block 3's BLOCKHASH(2) is block 2's hash"
    (keccak_hex (Executed_block.hash b2))
    (word_hex (Bf.slot (Executed_block.world b3) self_reader 2))

(* T-14: the window survives the output boundary, and it truncates at the
   depth limit BEHAVIOURALLY. [Block_hashes.of_recent] re-truncates, so a
   dropped cap is invisible through a BLOCKHASH read; the [depth] assertion is
   what kills it. The deep run uses EMPTY batches so 260 blocks cost almost
   nothing. *)
let out_first = single ~at:1_700_000_123L ~r:1 [ (batch [ tx_a ], w0) ]

let out_reads_parent =
  single ~author:id1 ~at:1_700_000_124L ~r:9 [ (batch [ tx_parent ], w0) ]

let deep_batches = List.init 260 (fun i -> raw_batch ~base_fee:(fee (i + 1)) [])

let out_deep =
  single ~at:1_700_000_123L ~r:1 (List.map (fun b -> (b, w0)) deep_batches)

let deep_reader = mk_addr '\xc3'

let tx_deep =
  Bf.legacy_envelope ~signer:54 ~gas_price ~gas_limit:400_000
    ~kind:(call deep_reader) ()

let out_deep_read =
  single ~author:id1 ~at:1_700_000_200L ~r:400 [ (batch [ tx_deep ], w0) ]

let t14 () =
  let world =
    Bf.with_code
      (Bf.fund World.empty [ tx_a; tx_parent ])
      parent_reader
      (contract [ relative_read ~width:1 ~delta:1 ~slot:1 ])
  in
  let after_first, first = executed (engine_on world) out_first in
  let _, second = executed after_first out_reads_parent in
  Alcotest.(check string)
    "output two's first block reads output one's last block"
    (keccak_hex (Executed_block.hash (nth "block 1" first 0)))
    (word_hex
       (Bf.slot (Executed_block.world (nth "block 2" second 0)) parent_reader 1));
  let deep_world =
    Bf.with_code
      (Bf.fund World.empty [ tx_deep ])
      deep_reader
      (contract
         [
           relative_read ~width:2 ~delta:256 ~slot:1;
           relative_read ~width:2 ~delta:257 ~slot:2;
         ])
  in
  let after_deep, deep = executed (engine_on deep_world) out_deep in
  Alcotest.(check int) "260 empty batches make 260 blocks" 260
    (List.length deep);
  Alcotest.(check int) "and the window holds exactly the depth limit" 256
    (Recent_hashes.depth (Engine.recent_hashes after_deep));
  let _, reading = executed after_deep out_deep_read in
  let read_world = Executed_block.world (nth "reading block" reading 0) in
  Alcotest.(check string) "BLOCKHASH(current - 256) is block 5's hash"
    (keccak_hex (Executed_block.hash (nth "block 5" deep 4)))
    (word_hex (Bf.slot read_world deep_reader 1));
  Alcotest.(check string) "BLOCKHASH(current - 257) is zero"
    (word_hex U256.zero)
    (word_hex (Bf.slot read_world deep_reader 2))

(* T-15: the window PREPENDS. Three configured ancestors sit behind the anchor,
   so an appending push does not merely read zero, it reads the wrong real
   hash, which is the failure mode with no symptom. *)
let anc_one = Tn_keccak.digest "chunk 36 ancestor one"
let anc_two = Tn_keccak.digest "chunk 36 ancestor two"
let anc_three = Tn_keccak.digest "chunk 36 ancestor three"
let triple_reader = mk_addr '\xc4'

let tx_triple =
  Bf.legacy_envelope ~signer:55 ~gas_price ~gas_limit:400_000
    ~kind:(call triple_reader) ()

let world_triple =
  Bf.with_code
    (Bf.fund World.empty [ tx_a; tx_b; tx_c; tx_triple ])
    triple_reader
    (contract
       [
         relative_read ~width:1 ~delta:1 ~slot:1;
         relative_read ~width:1 ~delta:2 ~slot:2;
         relative_read ~width:1 ~delta:3 ~slot:3;
       ])

let out_four =
  output_on main_chain ~at:1_700_000_123L ~r:1
    [
      ( id0,
        [
          (batch [ tx_a ], w0);
          (batch ~base_fee:(fee 1) [ tx_b ], w0);
          (batch ~base_fee:(fee 2) [ tx_c ], w0);
        ] );
      (id1, [ (batch ~base_fee:(fee 3) [ tx_triple ], w0) ]);
    ]

let t15 () =
  let engine =
    engine_on ~ancestors:[ anc_one; anc_two; anc_three ] world_triple
  in
  let _, blocks = executed engine out_four in
  Alcotest.(check int) "four blocks" 4 (List.length blocks);
  Alcotest.(check int) "and block 4 ran its reader" 1
    (List.length (Executed_block.transactions (nth "block 4" blocks 3)));
  let world = Executed_block.world (nth "block 4" blocks 3) in
  Alcotest.(check (list string)) "block 4 reads blocks 3, 2 and 1, newest first"
    (List.map keccak_hex
       (List.filteri (fun i _ -> i > 0) (List.rev (hashes blocks))))
    [
      word_hex (Bf.slot world triple_reader 1);
      word_hex (Bf.slot world triple_reader 2);
      word_hex (Bf.slot world triple_reader 3);
    ]

(* ---- chunk-38 stage 1: the window's two total projections ---- *)

(* S1.3: [newest] is the anchor's own hash and [ancestors] is everything strictly
   below it, so [newest :: ancestors] rebuilds the window exactly. An [ancestors]
   that handed back the whole list would give a resumed [Config.create] a window
   one entry too long, shifting every BLOCKHASH answer by one. *)
let s13 () =
  let w =
    Recent_hashes.of_genesis genesis_hash
      ~ancestors:[ anc_one; anc_two; anc_three ]
  in
  Alcotest.(check keccak) "newest is the anchor's own hash" genesis_hash
    (Recent_hashes.newest w);
  Alcotest.(check (list keccak))
    "ancestors are exactly the three, newest first"
    [ anc_one; anc_two; anc_three ]
    (Recent_hashes.ancestors w);
  Alcotest.(check (list keccak))
    "newest :: ancestors is the window"
    (Recent_hashes.to_list w)
    (Recent_hashes.newest w :: Recent_hashes.ancestors w);
  Alcotest.(check int) "and nothing was invented or dropped" 4
    (Recent_hashes.depth w)

(* S1.4: past the depth limit the split still accounts for every held hash - the
   anti-vacuity guard on S1.3, which an unbounded window would also satisfy. *)
let s14 () =
  let deep =
    List.fold_left Recent_hashes.push
      (Recent_hashes.of_genesis genesis_hash ~ancestors:[])
      (List.init
         (Tn_evm.Block_hashes.depth_limit + 10)
         (fun i -> Tn_keccak.digest ("chunk 38 s1.4/" ^ string_of_int i)))
  in
  Alcotest.(check int) "the window is capped at the depth limit"
    Tn_evm.Block_hashes.depth_limit (Recent_hashes.depth deep);
  Alcotest.(check int) "and newest plus ancestors accounts for every entry"
    (Recent_hashes.depth deep)
    (1 + List.length (Recent_hashes.ancestors deep))

(* T-03: the leader count advances once per OUTPUT, not once per block. The
   three-block output is led by ONE authority, so an engine that counted blocks
   would owe that leader three for it; a second output from the same leader
   separates once-per-output (2) from once-per-block (4). The counts are read
   off the engine rather than off a closing block's withdrawals, which is where
   T-02 already established they live before an epoch closes. *)
let leader_address_of output =
  get "leader address"
    (address_of
       (Sub_dag.leader_author (Cb.sub_dag (Output.consensus output))))

let t03 () =
  let after_three, blocks = executed (engine_on world_abcd) out_three in
  let leader = leader_address_of out_three in
  Alcotest.(check int) "the fixture output really is three blocks" 3
    (List.length blocks);
  Alcotest.(check int)
    "a three-block output advances its leader's count by exactly one" 1
    (amount_for after_three leader);
  Alcotest.(check bool) "the other certificate's author did not lead it" false
    (has_record after_three (leader_address_of out_one));
  let after = fst (executed after_three skip_b) in
  Alcotest.(check int)
    "a second output from the same leader makes it 2, not 4" 2
    (amount_for after leader)

(* T-16: the chain id and the base-fee address are READ FROM THE CONFIG, not
   defaulted. Both rows are sentinels: 0x7e5 is not the trivial 1 a hard-coded
   environment would carry, and the configured base-fee address is not the
   governance safe, so a substitution shows up as a credit at the wrong
   address rather than merely as a different number. *)
let chain_id_reader = mk_addr '\xc5'

let tx_chain_id =
  Bf.legacy_envelope ~signer:56 ~gas_price ~gas_limit:200_000
    ~kind:(call chain_id_reader) ()

let world_chain_id =
  Bf.with_code
    (Bf.fund World.empty [ tx_chain_id ])
    chain_id_reader
    (contract
       [ Bf.op Opcode.Chainid; Bf.push1 0; Bf.op Opcode.Sstore ])

let out_chain_id =
  single ~at:1_700_000_123L ~r:1
    [ (batch ~base_fee:(fee 5) [ tx_chain_id ], w0) ]

let governance_safe = Tn_evm.System_contracts.governance_safe_address

let t16 () =
  let _, blocks = executed (engine_on world_chain_id) out_chain_id in
  let block = nth "block" blocks 0 in
  let world = Executed_block.world block in
  Alcotest.(check int) "the reader ran: a skipped call would read nothing" 1
    (List.length (Executed_block.transactions block));
  Alcotest.(check bool) "the fixture's chain id is not the trivial default"
    false
    (U256.equal chain_id U256.one);
  Alcotest.(check string) "CHAINID answers the CONFIGURED chain id"
    (word_hex chain_id)
    (word_hex (Bf.slot world chain_id_reader 0));
  Alcotest.(check bool)
    "the configured base-fee address is not the governance safe" false
    (Units.Address.equal basefee_address governance_safe);
  Alcotest.(check bool)
    "the base fee and the gas penalty are credited to the CONFIGURED address"
    true
    (U256.compare (World.balance world basefee_address) U256.zero > 0);
  Alcotest.(check string) "and the governance safe is left untouched"
    (word_hex U256.zero)
    (word_hex (World.balance world governance_safe))

(* T-17: the nonce and the consensus root are OUTPUT-level facts. Every block
   of one output carries the same pair, and a different output carries a
   different one, so a value derived per certificate or per batch disagrees
   within the output rather than merely looking odd. *)
let nonce_of b =
  Units.Sequence_number.to_int64 (Block_header.nonce (Executed_block.header b))

let beacon_of b =
  Digests.Output_digest.to_hex
    (Block_header.parent_beacon_block_root (Executed_block.header b))

let t17 () =
  let _, blocks = executed (engine_on world_abcd) out_three in
  let expected_nonce = Units.Sequence_number.to_int64 (Output.nonce out_three) in
  let expected_beacon =
    Digests.Output_digest.to_hex (Output.output_digest out_three)
  in
  Alcotest.(check int) "three blocks to disagree with each other" 3
    (List.length blocks);
  Alcotest.(check (list int64))
    "all three headers carry the OUTPUT's nonce"
    [ expected_nonce; expected_nonce; expected_nonce ]
    (List.map nonce_of blocks);
  Alcotest.(check (list string))
    "and all three carry the output digest as the beacon root"
    [ expected_beacon; expected_beacon; expected_beacon ]
    (List.map beacon_of blocks);
  let _, other = executed (engine_on world_abcd) out_same_b in
  let b = nth "the other output's first block" other 0 in
  Alcotest.(check bool) "a DIFFERENT output carries a different nonce" false
    (Int64.equal (nonce_of b) expected_nonce);
  Alcotest.(check bool) "and a different beacon root" false
    (String.equal (beacon_of b) expected_beacon)

(* T-18: tip and height count BLOCKS, not outputs. *)
let out_skip_after = output_on main_chain ~at:1_700_000_200L ~r:20 [ (id0, []) ]

let t18 () =
  let after_three, blocks = executed (engine_on world_abcd) out_three in
  Alcotest.(check int) "a three-block output advances the height by three" 3
    (Block_number.to_int (Engine.height after_three));
  Alcotest.(check (list keccak)) "and the tip is the third block"
    [ Executed_block.hash (nth "block 3" blocks 2) ]
    (Option.to_list (Option.map Executed_block.hash (Engine.tip after_three)));
  let after_skip, none = executed after_three out_skip_after in
  Alcotest.(check int) "a skip after it produces no block" 0 (List.length none);
  Alcotest.(check int) "leaves the height at three" 3
    (Block_number.to_int (Engine.height after_skip));
  Alcotest.(check (list keccak)) "and leaves the tip on the third block"
    [ Executed_block.hash (nth "block 3" blocks 2) ]
    (Option.to_list (Option.map Executed_block.hash (Engine.tip after_skip)))

(* T-19: an output is all or nothing. The third batch's transaction asks for
   more gas than the whole block has, which is fatal rather than skippable, and
   nothing of the first two blocks survives it. *)
let tx_greedy =
  Bf.legacy_envelope ~signer:56 ~gas_price ~gas_limit:40_000_000 ()
let world_fatal = Bf.fund World.empty [ tx_a; tx_b; tx_c; tx_greedy ]

let out_fatal =
  single ~at:1_700_000_123L ~r:1
    [
      (batch [ tx_a ], w0);
      (batch ~base_fee:(fee 1) [ tx_b ], w0);
      (batch ~base_fee:(fee 2) [ tx_greedy ], w0);
    ]

let out_after_fatal =
  single ~author:id1 ~at:1_700_000_130L ~r:30
    [ (batch ~base_fee:(fee 4) [ tx_c ], w0) ]

let t19 () =
  let engine = engine_on world_fatal in
  let refused =
    Result.fold
      ~ok:(fun _ -> "the fatal output was accepted")
      ~error:Engine.error_to_string (Engine.execute engine out_fatal)
  in
  Alcotest.(check bool) "the fatal third batch fails the whole output" true
    (mentions "block 3" refused);
  let _, blocks = executed engine out_after_fatal in
  Alcotest.(check int) "the re-run produces one block" 1 (List.length blocks);
  Alcotest.(check (list int)) "numbered 1, not 3" [ 1 ] (numbers blocks);
  Alcotest.(check keccak) "off the genesis anchor again" genesis_hash
    (Block_header.parent_hash (header_at blocks 0));
  Alcotest.(check bool)
    "and the failed output's beneficiary was never credited" false
    (Bf.present (Executed_block.world (nth "block" blocks 0)) addr_a)

(* T-33, T-34 and T-35, the three shapes of the builder's skip stance, live in
   [test_engine_txskip.ml], which is the executable the chunk's build graph
   gives them. *)

(* T-36: withdrawals are RAW COUNTS in ascending execution-address order. The
   sentinel addresses are 0x03, 0x01, 0x02 in CREATION order, so a fold that
   preserved creation order would be visibly wrong. *)
let sentinel_addresses =
  [ mk_addr '\x03'; mk_addr '\x01'; mk_addr '\x02'; mk_addr '\x04' ]

let reward_chain = build_chain ~seed:100 sentinel_addresses

(* Two members at ONE address, which must sum into a single record. *)
let shared_addresses =
  [ mk_addr '\x05'; mk_addr '\x06'; mk_addr '\x05'; mk_addr '\x07' ]

let shared_chain = build_chain ~seed:200 shared_addresses

let lead_empty chain engine leaders =
  fst
    (List.fold_left
       (fun (engine, r) author ->
         let output =
           output_on chain
             ~at:(Int64.of_int (1_700_000_100 + r))
             ~r
             [ (author, []) ]
         in
         (fst (executed engine output), r + 1))
       (engine, 1) leaders)

let owed engine =
  List.map
    (fun w ->
      (addr_hex (Tn_evm.Withdrawal.address w), Tn_evm.Withdrawal.amount w))
    (withdrawals_of engine)

let t36 () =
  let at3 = get "0x03" (List.nth_opt sentinel_addresses 0) in
  let at1 = get "0x01" (List.nth_opt sentinel_addresses 1) in
  let at2 = get "0x02" (List.nth_opt sentinel_addresses 2) in
  let leader_at address =
    get "leader" (List.nth_opt (ids_at reward_chain address) 0)
  in
  let after =
    lead_empty reward_chain
      (engine_on ~chain:reward_chain World.empty)
      [
        leader_at at3;
        leader_at at3;
        leader_at at3;
        leader_at at1;
        leader_at at2;
        leader_at at2;
      ]
  in
  Alcotest.(check (list (pair string int)))
    "raw counts, in ascending execution-address order"
    [ (addr_hex at1, 1); (addr_hex at2, 2); (addr_hex at3, 3) ]
    (owed after);
  let shared = get "shared address" (List.nth_opt shared_addresses 0) in
  let both = ids_at shared_chain shared in
  Alcotest.(check int) "the shared-address committee really seats two there" 2
    (List.length both);
  let after_shared =
    lead_empty shared_chain (engine_on ~chain:shared_chain World.empty) both
  in
  Alcotest.(check (list (pair string int)))
    "two authorities at one address sum into one record"
    [ (addr_hex shared, 2) ]
    (owed after_shared);
  let producing =
    output_on reward_chain ~at:1_700_000_300L ~r:40
      [ (leader_at at3, [ (raw_batch [], w0) ]) ]
  in
  let produced, blocks =
    executed (engine_on ~chain:reward_chain World.empty) producing
  in
  Alcotest.(check int) "the empty batch still produced its block" 1
    (List.length blocks);
  Alcotest.(check (list bool)) "and no withdrawal address holds a balance yet"
    [ false; false; false ]
    (List.map (Bf.present (Engine.world produced)) [ at1; at2; at3 ])

(* T-37: the engine is a pure function of (state, output) -- folding one output
   twice from one engine value gives identical block hashes, state root and
   world, so no hidden mutable state is carried across a fold. Telcoin
   RE-EXECUTES after a crash and never reuses stored receipts, which is why that
   matters. The scope, stated honestly: both folds run in ONE process, so this
   pins referential transparency and NOT cross-process reproducibility. A
   container-iteration order that is stable within a process would survive this
   assertion; catching that needs a second process, which this suite has no
   harness for. *)
let t37 () =
  let engine = engine_on world_abcd in
  let first, blocks_one = executed engine out_three in
  let second, blocks_two = executed engine out_three in
  Alcotest.(check (list keccak))
    "re-executing one output from one state gives the same block hashes"
    (hashes blocks_one) (hashes blocks_two);
  Alcotest.(check string) "and the same final state root"
    (Bf.to_hex (Block_roots.state_root (Engine.world first)))
    (Bf.to_hex (Block_roots.state_root (Engine.world second)));
  Alcotest.(check bool) "and an equal world" true
    (World.equal (Engine.world first) (Engine.world second))

(* ================================================================== *)
(* Chunk-36 stage 6: the close-epoch empty block.                      *)
(* ================================================================== *)

(* An empty output that DOES close the epoch plans as a [Close_block] rather
   than a [Skip], and the one block it produces has no batch behind it: four of
   its header fields have nowhere to come from and are the engine's to
   synthesise. Every one of the four is a decision that a plausible alternative
   would get wrong, so each has its own case below.

   The closing arm runs the epoch-close system calls, so these fixtures stand
   on the PINNED pre-fork registry: real bytecode, and a committee whose
   execution addresses are the real testnet validators, because
   [applyIncentives] is handed the withdrawal records and must succeed for the
   block to finish at all. *)

module System_contracts = Tn_evm.System_contracts

let registry = System_contracts.consensus_registry_address
let u256_short s = get "word" (U256.of_hex (String.make (64 - String.length s) '0' ^ s))
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

(* The registry, the two EIP predeploys, and nothing else. *)
let close_world = System_contracts.predeploy registry_world

(* The five testnet validator execution addresses, verbatim from
   chain-configs/testnet/committee.yaml, as in test_epoch_close.ml. Whichever
   of them leads the closing output, its withdrawal names a validator the
   fixture registry knows. *)
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

let close_chain = build_chain ~seed:300 validator_addresses
let close_leader = nth "close leader" (List.map Authority.id (Committee.authorities close_chain.cmt)) 0

(* A boundary BEFORE every commit timestamp here, which is the only difference
   between this section's outputs and the [Skip]s of T-01: [boundary_far] above
   is the same lever pointed the other way. *)
let boundary_past = ts 1L

(* The anchor's two inherited fields are SENTINELS. 77 is not a plausible
   default, and 30_000_007 is not [Batch.max_batch_gas], so a close block that
   recomputed either instead of reading the parent would read differently. *)
let closing_engine ?(base_fee = 77) ?(gas_limit = 30_000_007) ?(world = close_world)
    ?(boundary = boundary_past) () =
  Engine.create
    (Config.create
       ~anchor:
         (Anchor.of_genesis ~hash:genesis_hash
            ~base_fee:(get "base fee" (U256.of_int base_fee))
            ~gas_limit)
       ~ancestors:[ ancestor_hash ] ~world ~chain_id ~basefee_address
       ~epoch_boundary:boundary ~committee:close_chain.cmt)

(* One empty output, committed long after the boundary. *)
let out_close = output_on close_chain ~at:1_700_000_500L ~r:9 [ (close_leader, []) ]

let digest_hex d = Bf.to_hex (Tn_crypto.Digest.to_bytes d)
let batch_digest_hex d = digest_hex (Digests.Batch_digest.to_digest d)
let output_digest_hex d = digest_hex (Digests.Output_digest.to_digest d)

(* The one block, with the count asserted where it is produced: a closing
   output that built two blocks, or none, would otherwise reach the field
   assertions as a silent [nth] failure. *)
let close_block_of engine =
  let after, blocks = executed engine out_close in
  Alcotest.(check int) "a closing empty output makes exactly one block" 1
    (List.length blocks);
  (after, nth "the close block" blocks 0)

(* T-20: the ommers slot of a block with no batch holds the ZERO batch digest,
   which is the absent-value constant and not the digest of anything. The
   output digest is right there in the same spec, so the classic swap is one
   character away. *)
let t20 () =
  let _, block = close_block_of (closing_engine ()) in
  let ommers = Block_header.ommers_hash (Executed_block.header block) in
  Alcotest.(check string) "the close block's ommers slot is the ZERO batch digest"
    (batch_digest_hex Digests.Batch_digest.zero)
    (batch_digest_hex ommers);
  Alcotest.(check bool) "which is not the output digest" false
    (String.equal
       (output_digest_hex (Output.output_digest out_close))
       (batch_digest_hex ommers))

(* T-21: prev_randao on this path is the RAW output digest. Every batch block
   XORs the batch digest in; the close block has no batch digest, and XORing
   the zero one in would be an identity that nothing here could see, so the
   assertion is against the output digest itself. *)
let t21 () =
  let _, block = close_block_of (closing_engine ()) in
  let mix = Block_header.mix_hash (Executed_block.header block) in
  Alcotest.(check string)
    "the close block's prev_randao is the raw output digest, un-XORed"
    (output_digest_hex (Output.output_digest out_close))
    (word_hex mix);
  Alcotest.(check bool) "and is not the zero word" false (U256.is_zero mix)

(* T-22: the base fee is the PARENT's, copied. The sentinel row reads a genesis
   fee nothing would guess; the negative row is the one that matters, because
   an EIP-1559 chain would raise a zero parent fee to the protocol floor and
   this chain has no fee market to do it with. *)
let t22 () =
  let _, block = close_block_of (closing_engine ()) in
  Alcotest.(check string) "the close block inherits the parent's base fee"
    (word_hex (word 77))
    (word_hex (Block_header.base_fee_per_gas (Executed_block.header block)));
  let _, zeroed = close_block_of (closing_engine ~base_fee:0 ()) in
  let inherited = Block_header.base_fee_per_gas (Executed_block.header zeroed) in
  Alcotest.(check string) "and a zero parent base fee stays zero" (word_hex U256.zero)
    (word_hex inherited);
  Alcotest.(check bool) "not raised to Base_fee.min_protocol's seven" false
    (String.equal (word_hex (word 7)) (word_hex inherited))

(* T-23: the gas limit is the PARENT's too, not the per-epoch batch cap the
   batch blocks carry. The sentinel is seven over [max_batch_gas], so the two
   sources are told apart by a value neither could produce by accident. *)
let t23 () =
  let _, block = close_block_of (closing_engine ()) in
  let limit = Block_header.gas_limit (Executed_block.header block) in
  Alcotest.(check int) "the close block inherits the parent's gas limit" 30_000_007
    limit;
  Alcotest.(check bool) "and does not read Batch.max_batch_gas" false
    (limit = Int64.to_int (Batch.max_batch_gas Units.Epoch.zero))

(* T-24: the packed difficulty word is zero, which is batch 0 of worker 0, so
   the close block IS a first batch: the EIP-4788 consensus-root write runs on
   it exactly as it would on a real output's first block. A position that said
   "some later batch" would silently skip that write. *)
let t24 () =
  let _, block = close_block_of (closing_engine ()) in
  Alcotest.(check string)
    "the close block packs batch 0 of worker 0" (word_hex U256.zero)
    (word_hex (Block_header.difficulty (Executed_block.header block)));
  Alcotest.(check string) "so it is a first batch and writes the consensus root"
    "written" (root_disposition block)

(* T-25: the close block carries the epoch commitment and executes nothing. The
   first row is a control: the same engine, one output earlier, DID execute a
   transaction, so "no gas" is a fact about this block rather than about a
   fixture that could never execute anything. The skipped list is asserted too:
   a close block handed transactions it then rejected would still show zero gas
   and an empty transaction list, and only the skip count tells the two
   apart. *)
let out_before_close =
  output_on close_chain ~at:1_700_000_123L ~r:1 [ (close_leader, [ (batch [ tx_a ], w0) ]) ]

let t25 () =
  (* The boundary sits BETWEEN the two outputs' commit timestamps, so the first
     is an ordinary batch build and only the second closes the epoch. A boundary
     before both would seal the engine on the first output, and the control row
     below would never reach its close block. *)
  let engine =
    closing_engine
      ~world:(Bf.fund close_world [ tx_a ])
      ~boundary:(ts 1_700_000_200L) ()
  in
  let after, blocks = executed engine out_before_close in
  Alcotest.(check bool) "the fixture's batch block did execute a transaction" true
    (Block_header.gas_used (header_at blocks 0) > 0);
  let _, block = close_block_of after in
  let header = Executed_block.header block in
  Alcotest.(check int) "the close block burns no gas" 0 (Block_header.gas_used header);
  Alcotest.(check int) "and carries no transactions" 0
    (List.length (Executed_block.transactions block));
  Alcotest.(check int) "having attempted none: nothing was even skipped" 0
    (List.length (Executed_block.skipped block));
  Alcotest.(check string) "so its transactions root is the empty-trie root"
    (Bf.to_hex Tn_trie.Trie.empty_root)
    (Bf.to_hex (Hash32.to_bytes (Block_header.transactions_root header)))

(* ================================================================== *)
(* Chunk-38 stage 4: the engine's persistence seam.                    *)
(* ================================================================== *)

(* [chain_id] and [basefee_address] are the only two facts [resume] is told
   again, because they are configuration and not state; the suite hands back
   the very ones every engine here was created with. *)
let round_trip e = Engine.resume ~chain_id ~basefee_address (Engine.snapshot e)

(* A committee as two comparable projections: which epoch it is for and who is
   in it. Hex rather than an opaque testable, so a failure names WHICH member
   moved instead of only that one did. *)
let committee_shape c =
  ( Units.Epoch.to_int (Committee.epoch c),
    List.map
      (fun a -> Authority_id.to_hex (Authority.id a))
      (Committee.authorities c) )

(* The leader counts as rows a failure can be read off. *)
let counts e =
  List.map
    (fun (a, n) -> (addr_hex a, n))
    (Rewards_counter.address_counts (Engine.rewards e))

(* The phase as (which arm, the timestamp that arm carries). A tag rather than
   a bare timestamp: "sealed at t" and "running to t" are different engines,
   and only the tag tells them apart. *)
let phase_shape e =
  match Engine.phase e with
  | Engine.Running { boundary; committee = _ } ->
      ("running", Units.Timestamp.to_sec boundary)
  | Engine.Sealed { closed_at; committee = _ } ->
      ("sealed", Units.Timestamp.to_sec closed_at)

(* Every answer BLOCKHASH can get out of this engine's window, from one request
   past the far edge up to the block being built. Read through
   [Block_hashes.lookup] - the function the interpreter's host seam calls - so
   this is what the OPCODE would see and not merely what the list holds. *)
let window_answers e =
  let w = Recent_hashes.window (Engine.recent_hashes e) in
  let current = 1 + Block_number.to_int (Anchor.number (Engine.anchor e)) in
  let floor = current - Tn_evm.Block_hashes.depth_limit - 1 in
  List.map
    (fun requested ->
      word_hex
        (Tn_evm.Block_hashes.lookup w ~current:(word current)
           ~requested:(word requested)))
    (List.init (current - floor + 1) (fun i -> floor + i))

(* S4.1: the round trip moves nothing. Every field a resumed engine is supposed
   to carry is read off both sides and compared, on a freshly CREATED engine, so
   the assertion is about the seam and not about a fold. *)
let s41 () =
  let original = engine0 in
  let resumed = round_trip original in
  Alcotest.(check keccak)
    "the anchor hash survives"
    (Anchor.hash (Engine.anchor original))
    (Anchor.hash (Engine.anchor resumed));
  Alcotest.(check int) "and so does its number"
    (Block_number.to_int (Anchor.number (Engine.anchor original)))
    (Block_number.to_int (Anchor.number (Engine.anchor resumed)));
  Alcotest.(check bool) "the world is the same state" true
    (World.equal (Engine.world original) (Engine.world resumed));
  Alcotest.(check (list keccak))
    "the window is carried whole, in order"
    (Recent_hashes.to_list (Engine.recent_hashes original))
    (Recent_hashes.to_list (Engine.recent_hashes resumed));
  Alcotest.(check (list (pair string int)))
    "the leader counts are carried" (counts original) (counts resumed);
  Alcotest.(check (pair int (list string)))
    "the committee is the same epoch and the same membership"
    (committee_shape (Engine.committee original))
    (committee_shape (Engine.committee resumed));
  Alcotest.(check bool) "and a running engine resumes running"
    (Engine.is_sealed original) (Engine.is_sealed resumed)

(* T-14's 260-block run, folded for its WINDOW rather than for its blocks: past
   the depth limit the window is full, so a seam that truncated it would move
   answers a short fixture never asks for. *)
let deep_engine = fst (executed (engine_on world0) out_deep)

(* S4.2: the window crosses the seam at full depth. *)
let s42 () =
  let resumed = round_trip deep_engine in
  Alcotest.(check int) "the original window is full"
    Tn_evm.Block_hashes.depth_limit
    (Recent_hashes.depth (Engine.recent_hashes deep_engine));
  Alcotest.(check int) "and the resumed one holds exactly as many"
    (Recent_hashes.depth (Engine.recent_hashes deep_engine))
    (Recent_hashes.depth (Engine.recent_hashes resumed));
  Alcotest.(check (list keccak))
    "hash for hash, in order"
    (Recent_hashes.to_list (Engine.recent_hashes deep_engine))
    (Recent_hashes.to_list (Engine.recent_hashes resumed))

(* S4.3: SEMANTIC window agreement, the assertion that makes the window
   non-decorative. The second row is the anti-vacuity guard: a fixture too
   short for the window to be load-bearing fails here rather than banking a
   pass on a window of zeroes.

   Declared vacuity verdict: no transaction in this suite reaches a BLOCKHASH
   through a real close-epoch resume, so this proves agreement at the host-seam
   function the interpreter calls, not end to end through the opcode. *)
let s43 () =
  let original = deep_engine in
  let resumed = round_trip original in
  let answers = window_answers original in
  Alcotest.(check int) "the sweep covers the whole window and one past it"
    (Tn_evm.Block_hashes.depth_limit + 2)
    (List.length answers);
  Alcotest.(check bool)
    "and at least a full window of those answers is a real hash" true
    (List.length (List.filter (fun a -> a <> word_hex U256.zero) answers)
    >= Tn_evm.Block_hashes.depth_limit);
  Alcotest.(check (list string))
    "every BLOCKHASH the window can be asked agrees across the seam" answers
    (window_answers resumed)

(* The sealed engine of the close section, folded through the same fixture
   T-20..T-25 use. A function rather than a value: [close_block_of] asserts as
   it goes, and an assertion at module initialisation would take the whole
   executable down instead of one case. *)
let sealed_engine () = fst (close_block_of (closing_engine ()))

(* One more empty output, after the one that closed the epoch. *)
let out_after_close =
  output_on close_chain ~at:1_700_000_600L ~r:10 [ (close_leader, []) ]

(* S4.4: the phase round trip. The three [begin_epoch] probes straddle
   [closed_at], and the fold probe is what makes the mutation bite
   SEMANTICALLY: a resumed engine seated Running would carry the same frontier
   and answer all three probes alike, and only folding an output the original
   refuses tells the two arms apart. *)
let s44 () =
  let original = sealed_engine () in
  let resumed = round_trip original in
  Alcotest.(check (pair string int64))
    "the fixture engine really is sealed, at the closing output's commit time"
    ("sealed", 1_700_000_500L) (phase_shape original);
  Alcotest.(check (pair string int64))
    "and the seam carries the arm and its timestamp" (phase_shape original)
    (phase_shape resumed);
  let probe e at =
    Result.is_ok
      (Engine.begin_epoch e ~boundary:(ts at) ~committee:close_chain.cmt)
  in
  let probes = [ 1_700_000_499L; 1_700_000_500L; 1_700_000_501L ] in
  Alcotest.(check (list bool))
    "the original refuses a boundary below and at closed_at, accepts above"
    [ false; false; true ]
    (List.map (probe original) probes);
  Alcotest.(check (list bool))
    "and the resumed engine answers the same three"
    (List.map (probe original) probes)
    (List.map (probe resumed) probes);
  let folds e =
    Result.fold ~ok:(fun _ -> "folded") ~error:Engine.error_to_string
      (Engine.execute e out_after_close)
  in
  Alcotest.(check bool) "the original refuses the next output as Epoch_sealed"
    true
    (mentions "epoch sealed" (folds original));
  Alcotest.(check string) "and the resumed engine refuses it identically"
    (folds original) (folds resumed)

(* S4.5: the reconstructed config. The fixture is SEALED and was created with
   [boundary_past], so a config reporting the phase's frontier and one
   reporting the boundary the engine was created with are far apart. *)
let s45 () =
  let original = sealed_engine () in
  let resumed = round_trip original in
  let cfg = Engine.config resumed in
  Alcotest.(check int64)
    "the boundary reported is the phase's frontier, not the created one"
    1_700_000_500L
    (Units.Timestamp.to_sec (Config.epoch_boundary cfg));
  Alcotest.(check int64) "which the created engine's config does not report"
    1L
    (Units.Timestamp.to_sec (Config.epoch_boundary (Engine.config original)));
  Alcotest.(check keccak) "the anchor is the persisted one"
    (Anchor.hash (Engine.anchor original))
    (Anchor.hash (Config.anchor cfg));
  Alcotest.(check (list keccak))
    "and the ancestors are everything strictly BELOW the window's newest"
    (Recent_hashes.ancestors (Engine.recent_hashes original))
    (Config.ancestors cfg)

(* ---- S4.6: continuation equality ---- *)

(* The boundary sits BETWEEN the head outputs and the tail's last one, so the
   tail closes the epoch and its closing block's withdrawals_root commits the
   counts the HEAD accumulated. That is what makes losing the counts across the
   seam a visible block hash rather than an invisible field. *)
let resume_boundary = ts 1_700_000_450L

(* Empty batches, so a block is produced without funding anything; distinct
   base fees, so no two batches share a digest. *)
let head_outputs =
  [
    output_on close_chain ~at:1_700_000_100L ~r:1
      [ (close_leader, [ (raw_batch ~base_fee:(fee 1) [], w0) ]) ];
    output_on close_chain ~at:1_700_000_200L ~r:2 [ (close_leader, []) ];
    output_on close_chain ~at:1_700_000_300L ~r:3
      [ (close_leader, [ (raw_batch ~base_fee:(fee 2) [], w0) ]) ];
  ]

let tail_outputs =
  [
    output_on close_chain ~at:1_700_000_400L ~r:4
      [ (close_leader, [ (raw_batch ~base_fee:(fee 3) [], w0) ]) ];
    output_on close_chain ~at:1_700_000_500L ~r:5 [ (close_leader, []) ];
  ]

(* Fold outputs, keeping the engine and the block hashes in production order.
   The hashes are gathered newest-last by reversing once at the end rather than
   appending inside the fold. *)
let fold_outputs engine outputs =
  let final, produced_rev =
    List.fold_left
      (fun (e, acc) output ->
        let next, blocks = executed e output in
        ( next,
          List.fold_left
            (fun acc b -> keccak_hex (Executed_block.hash b) :: acc)
            acc blocks ))
      (engine, []) outputs
  in
  (final, List.rev produced_rev)

let s46 () =
  let after_head, head_blocks =
    fold_outputs
      (closing_engine ~boundary:resume_boundary ())
      head_outputs
  in
  let resumed = round_trip after_head in
  let original_end, original_hashes = fold_outputs after_head tail_outputs in
  let resumed_end, resumed_hashes = fold_outputs resumed tail_outputs in
  Alcotest.(check bool) "the head really accumulated leader credit" true
    (List.exists (fun (_, n) -> n > 0) (counts after_head));
  Alcotest.(check bool) "and it really produced blocks" true
    (List.length head_blocks > 0);
  Alcotest.(check bool) "the tail really closes the epoch" true
    (Engine.is_sealed original_end);
  Alcotest.(check bool) "and it really produced blocks to compare" true
    (List.length original_hashes > 0);
  Alcotest.(check (list string))
    "the same tail folded through the seam produces the same blocks"
    original_hashes resumed_hashes;
  Alcotest.(check bool) "and leaves the same world" true
    (World.equal (Engine.world original_end) (Engine.world resumed_end))

(* ---- S4.7: the resume-side normalization guard ---- *)

(* [Engine.persisted] is a transparent record, so [snapshot] is only its
   INTENDED producer: nothing stops a hand-built value whose window's newest
   entry disagrees with the anchor's own hash, and [build_block] reads
   BLOCKHASH out of one field and [parent_hash] out of the other in the same
   block. [resume] therefore re-seats the window from the anchor instead of
   trusting it, and this pins that post-fact on a deliberately skewed pair.
   The fixture is [deep_engine], so the ancestors sit at the depth cap and a
   re-seat that truncated or reordered them would also show here. *)
let s47 () =
  let p = Engine.snapshot deep_engine in
  let anchor_hash = Anchor.hash p.Engine.anchor in
  let bogus = Tn_keccak.digest "chunk 38 skewed-newest sentinel" in
  Alcotest.(check bool)
    "the sentinel really disagrees with the anchor's hash" false
    (Tn_keccak.equal bogus anchor_hash);
  let kept_ancestors = Recent_hashes.ancestors p.Engine.hashes in
  let skewed =
    {
      p with
      Engine.hashes = Recent_hashes.of_genesis bogus ~ancestors:kept_ancestors;
    }
  in
  let resumed = Engine.resume ~chain_id ~basefee_address skewed in
  Alcotest.(check keccak)
    "resume re-seats the window's newest entry from the anchor" anchor_hash
    (Recent_hashes.newest (Engine.recent_hashes resumed));
  Alcotest.(check (list keccak))
    "and keeps the persisted ancestors below it, in order" kept_ancestors
    (Recent_hashes.ancestors (Engine.recent_hashes resumed));
  Alcotest.(check (list keccak))
    "so the skew is gone: the window is the honest engine's, hash for hash"
    (Recent_hashes.to_list (Engine.recent_hashes deep_engine))
    (Recent_hashes.to_list (Engine.recent_hashes resumed))

let () =
  Alcotest.run "engine"
    [
      ( "skip",
        [
          Alcotest.test_case "T-01 a skip moves no chain state" `Quick t01;
          Alcotest.test_case "T-02 a skip still advances the leader count"
            `Quick t02;
          Alcotest.test_case
            "T-03 the leader count advances per output, not per block" `Quick
            t03;
        ] );
      ( "chain",
        [
          Alcotest.test_case
            "T-04 the first block is number one off the genesis sentinel" `Quick
            t04;
          Alcotest.test_case
            "T-05 number and parent hash chain within one output" `Quick t05;
          Alcotest.test_case "T-18 tip and height count blocks, not outputs"
            `Quick t18;
          Alcotest.test_case "T-19 an output is all or nothing" `Quick t19;
          Alcotest.test_case "T-37 re-execution is byte-identical" `Quick t37;
        ] );
      ( "world",
        [
          Alcotest.test_case "T-06 the world threads block to block" `Quick t06;
          Alcotest.test_case "T-07 the world threads across outputs" `Quick t07;
        ] );
      ( "header",
        [
          Alcotest.test_case "T-08 every block carries the commit timestamp"
            `Quick t08;
          Alcotest.test_case "T-09 equal commit timestamps are accepted" `Quick
            t09;
          Alcotest.test_case "T-10 execution order is certificate-major" `Quick
            t10;
          Alcotest.test_case "T-11 the difficulty is the packed batch position"
            `Quick t11;
          Alcotest.test_case
            "T-12 the consensus root is written once per output" `Quick t12;
          Alcotest.test_case
            "T-16 the chain id and base-fee address come from the config" `Quick
            t16;
          Alcotest.test_case
            "T-17 the nonce and beacon root are output-level" `Quick t17;
        ] );
      ( "window",
        [
          Alcotest.test_case "T-13 the window is seeded and rolls" `Quick t13;
          Alcotest.test_case
            "T-14 the window persists and truncates at the depth limit" `Quick
            t14;
          Alcotest.test_case "T-15 the window prepends, never appends" `Quick
            t15;
          Alcotest.test_case "S1.3 newest and ancestors split the window" `Quick
            s13;
          Alcotest.test_case "S1.4 the split holds at the depth limit" `Quick
            s14;
        ] );
      ( "builder",
        [
          Alcotest.test_case "T-36 withdrawals are raw counts in address order"
            `Quick t36;
        ] );
      ( "close",
        [
          Alcotest.test_case "T-20 the ommers slot is the zero batch digest"
            `Quick t20;
          Alcotest.test_case "T-21 the mix hash is the raw output digest" `Quick
            t21;
          Alcotest.test_case
            "T-22 the base fee is the parent's, and zero stays zero" `Quick t22;
          Alcotest.test_case "T-23 the gas limit is the parent's" `Quick t23;
          Alcotest.test_case
            "T-24 the close block is a first batch and writes the root" `Quick
            t24;
          Alcotest.test_case "T-25 the close block executes nothing" `Quick t25;
        ] );
      ( "resume",
        [
          Alcotest.test_case "S4.1 the round trip carries every moving field"
            `Quick s41;
          Alcotest.test_case "S4.2 a full window crosses the seam whole" `Quick
            s42;
          Alcotest.test_case "S4.3 the window agrees at the BLOCKHASH seam"
            `Quick s43;
          Alcotest.test_case "S4.4 a sealed engine resumes sealed" `Quick s44;
          Alcotest.test_case "S4.5 the resumed config reports the frontier"
            `Quick s45;
          Alcotest.test_case "S4.6 the same tail continues identically" `Quick
            s46;
          Alcotest.test_case
            "S4.7 a skewed persisted resumes agreeing with its anchor" `Quick
            s47;
        ] );
    ]
