(* Chunk-36: the engine's BUILDER stance on a transaction the executor refuses.

   These are the three shapes that a "no block" or "whole output errors" reading
   of the skip class would get wrong, and they are their own executable because
   the design's build graph gives them one: a cross-worker duplicate, a batch
   whose every transaction is refused, and a batch with nothing executable in it
   at all. None of the three is an error and none of the three costs a block.

   The fixtures are this suite's own rather than shared, so that the cost of
   building a BLS committee is paid by this executable and not by every other
   one in the directory. *)

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
module Block_number = Tn_engine.Block_number
module Executed_block = Tn_engine.Executed_block
module Block_execution = Tn_evm.Block_execution
module Block_header = Tn_evm.Block_header
module Block_roots = Tn_evm.Block_roots
module Hash32 = Tn_evm.Hash32
module Tx_envelope = Tn_evm.Tx_envelope
module U256 = Tn_state.U256
module World = Tn_state.World_state

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

(* Four validators with distinct execution addresses, so a leader and its
   withdrawal address agree and no two authorities merge into one record. *)
let member_addresses =
  [ mk_addr '\xa0'; mk_addr '\xa1'; mk_addr '\xa2'; mk_addr '\xa3' ]

let committee, sk_of =
  let sks = List.init 4 (fun i -> Tn_crypto.Secret_key.derive (Int64.of_int i)) in
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

let members = Committee.authorities committee
let ids = List.map Authority.id members
let id0 = nth "id0" ids 0

let address_of id =
  List.find_map
    (fun a ->
      if Authority_id.equal (Authority.id a) id then
        Some (Authority.execution_address a)
      else None)
    members

let genesis_parents = List.map Certificate.digest (Certificate.genesis committee)

let certify header =
  let votes = List.map (fun id -> Vote.sign (sk_of id) ~voter:id header) ids in
  Result.fold ~ok:Fun.id
    ~error:(fun e ->
      Alcotest.failf "certify: %s" (Certificate.error_to_string e))
    (Certificate.assemble committee header votes)

let batch ?(base_fee = fee 0) txs =
  Batch.make
    ~transactions:(List.map Tx_envelope.encode_2718 txs)
    ~epoch:Units.Epoch.zero ~beneficiary:Units.Address.zero
    ~base_fee_per_gas:base_fee ~worker_id:w0

(* Raw wire bytes rather than signed envelopes: the payloads the drop layer is
   supposed to discard before a block ever sees them. *)
let raw_batch ?(base_fee = fee 0) txs =
  Batch.make ~transactions:txs ~epoch:Units.Epoch.zero
    ~beneficiary:Units.Address.zero ~base_fee_per_gas:base_fee ~worker_id:w0

(* One committed output under a single certificate, which is all three cases
   here need. *)
let single ~at ~r bs =
  let header =
    Header.make ~author:id0 ~round:(round r) ~epoch:Units.Epoch.zero
      ~created_at:(ts at)
      ~payload:(List.map (fun b -> (Batch.digest b, w0)) bs)
      ~parents:genesis_parents
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
    (Output.attach ~consensus
       ~lookup:(fun d ->
         List.find_opt
           (fun b -> Digests.Batch_digest.equal (Batch.digest b) d)
           bs)
       ~address_of)

let genesis_hash = Tn_keccak.digest "chunk 36 txskip genesis sentinel"
let ancestor_hash = Tn_keccak.digest "chunk 36 txskip ancestor sentinel"
let chain_id = get "chain id" (U256.of_int 0x7e5)
let basefee_address = mk_addr '\xbe'

(* Far past every commit timestamp below, so nothing here closes the epoch and
   every output plans as a batch build. *)
let boundary_far = ts 2_000_000_000L

let engine_on world =
  Engine.create
    (Config.create
       ~anchor:
         (Anchor.of_genesis ~hash:genesis_hash
            ~base_fee:(get "base fee" (U256.of_int 77))
            ~gas_limit:30_000_000)
       ~ancestors:[ ancestor_hash ] ~world ~chain_id ~basefee_address
       ~epoch_boundary:boundary_far ~committee)

let executed engine output =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "execute: %s" (Engine.error_to_string e))
    (Engine.execute engine output)

(* Every batch below sets a base fee and the executor refuses a transaction
   priced under it, so the fixtures bid well over the highest fee here. *)
let gas_price = 100

let transfer ~signer =
  Bf.legacy_envelope ~signer ~gas_price ~gas_limit:21_000 ()

let tx_a = transfer ~signer:41
let world_a = Bf.fund World.empty [ tx_a ]

(* T-33: the same signed transaction in two batches. The second occurrence is
   refused on its nonce, recorded, and skipped: the normal cross-worker
   duplicate telcoin logs and continues past. *)
let out_duplicate =
  single ~at:1_700_000_123L ~r:1 [ batch [ tx_a ]; batch ~base_fee:(fee 1) [ tx_a ] ]

let t33 () =
  (* Named first, so an engine that took the executor's refusing stance fails an
     assertion rather than aborting unnamed inside the totaliser. *)
  Alcotest.(check bool) "a duplicate across batches is not an error" true
    (Result.is_ok (Engine.execute (engine_on world_a) out_duplicate));
  let _, blocks = executed (engine_on world_a) out_duplicate in
  Alcotest.(check int) "and both batches still get their block" 2
    (List.length blocks);
  let b2 = nth "block 2" blocks 1 in
  Alcotest.(check int) "the duplicate reaches no block" 0
    (List.length (Executed_block.transactions b2));
  Alcotest.(check int) "and is recorded as one skip" 1
    (List.length (Executed_block.skipped b2));
  Alcotest.(check int) "at its INPUT position" 0
    (Block_execution.Invalid_tx.index
       (nth "skip" (Executed_block.skipped b2) 0))

(* T-34: a batch whose only transaction is refused still produces its block. *)
let tx_broke = transfer ~signer:57
let out_all_rejected = single ~at:1_700_000_123L ~r:1 [ batch [ tx_broke ] ]

let t34 () =
  let _, blocks = executed (engine_on World.empty) out_all_rejected in
  Alcotest.(check int) "a wholly-rejected batch still produces one block" 1
    (List.length blocks);
  let b = nth "block" blocks 0 in
  Alcotest.(check int) "with no transactions in it" 0
    (List.length (Executed_block.transactions b));
  Alcotest.(check int) "one skip recorded" 1
    (List.length (Executed_block.skipped b));
  Alcotest.(check int) "and no gas used" 0
    (Block_header.gas_used (Executed_block.header b));
  Alcotest.(check string) "over the empty transactions root"
    (Bf.to_hex (Block_roots.transactions_root []))
    (Bf.to_hex
       (Hash32.to_bytes
          (Block_header.transactions_root (Executed_block.header b))))

(* T-35: an empty BATCH is not a SKIP. The undecodable payload is dropped BEFORE
   the block, so nothing is even skipped, and the block is still built. *)
let out_empty_batch =
  single ~at:1_700_000_123L ~r:1 [ raw_batch [ "\xde\xad\xbe\xef" ] ]

let t35 () =
  let after, blocks = executed (engine_on World.empty) out_empty_batch in
  Alcotest.(check int)
    "an output whose batch has nothing executable is not a skip" 1
    (List.length blocks);
  let b = nth "block" blocks 0 in
  Alcotest.(check int) "the block carries no transactions" 0
    (List.length (Executed_block.transactions b));
  Alcotest.(check int) "and nothing was skipped either: the drop layer ran" 0
    (List.length (Executed_block.skipped b));
  Alcotest.(check int) "and the height advanced, which a skip would not have" 1
    (Block_number.to_int (Engine.height after))

let () =
  Alcotest.run "engine_txskip"
    [
      ( "builder",
        [
          Alcotest.test_case "T-33 a cross-batch duplicate is skipped, not fatal"
            `Quick t33;
          Alcotest.test_case "T-34 a wholly-rejected batch still produces a block"
            `Quick t34;
          Alcotest.test_case "T-35 an empty batch is not a skip" `Quick t35;
        ] );
    ]
