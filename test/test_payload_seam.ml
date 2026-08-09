(* Chunk-34 stage 4: the payload seam (Tn_batch.Output / Block_plan /
   Batch_payload), tests T32-T38 of the chunk design.

   A real committee, real certificates and a real committed sub-DAG feed
   [Output.attach], so the seam is exercised over exactly the shapes the
   consensus layer produces: two headers (leader last) carrying batch
   digests, resolved against in-test batch bodies through the injected
   [lookup]/[address_of] dependencies. *)

open Tn_types
open Tn_vertex
open Tn_consensus
module Cb = Tn_execution.Consensus_block
module Nonempty = Tn_std.Nonempty
module Output = Tn_batch.Output
module Plan = Tn_batch.Block_plan
module Payload = Tn_batch.Batch_payload
module F = Batch_fixtures

let hex = Tx_vectors.hex

(* Totalise an option under a named expectation; Result.fold keeps both
   arms lazy (Option.fold's ~none is eager, so Alcotest.fail there would
   always fire). *)
let get what o =
  Result.fold ~ok:Fun.id
    ~error:(fun msg -> Alcotest.fail msg)
    (Option.to_result ~none:what o)

let nth what l n = get what (List.nth_opt l n)

(* The fixed 4-validator committee, test_consensus.ml's pattern. *)
let committee, sk_of =
  let sks =
    List.init 4 (fun i -> Tn_crypto.Secret_key.derive (Int64.of_int i))
  in
  let authorities =
    List.map
      (fun sk ->
        Authority.make
          ~protocol_key:(Tn_crypto.Secret_key.public_key sk)
          ~execution_address:Units.Address.zero)
      sks
  in
  let committee =
    Result.fold ~ok:Fun.id
      ~error:(fun e -> Alcotest.failf "committee: %s" (Committee.error_to_string e))
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
let id2 = nth "id2" ids 2
let id3 = nth "id3" ids 3
let mk_addr c = get "address" (Units.Address.of_bytes (String.make 20 c))
let addr_a = mk_addr '\xa0'
let addr_b = mk_addr '\xa1'

(* The injected authority execution-address table: every committee member
   resolves, to a DISTINCT address (the committee's own execution
   addresses are all zero, so a spec whose beneficiary came from the batch
   or the committee instead of this table cannot pass). *)
let table =
  [
    (id0, addr_a);
    (id1, addr_b);
    (id2, mk_addr '\xa2');
    (id3, mk_addr '\xa3');
  ]

let address_of id =
  List.find_map
    (fun (k, v) -> if Authority_id.equal k id then Some v else None)
    table

let worker n =
  Units.Worker_id.of_int n |> Option.value ~default:Units.Worker_id.zero

let w0 = Units.Worker_id.zero
let w3 = worker 3
let ts n = get "timestamp" (Units.Timestamp.of_sec n)
let round n = get "round" (Round.of_int n)
let fee7 = Units.Base_fee.min_protocol
let fee9 = Units.Base_fee.of_int64 9L

let mk_batch ?(fee = fee7) ?(w = w0) txs =
  Batch.make ~transactions:txs ~epoch:Units.Epoch.zero
    ~beneficiary:Units.Address.zero ~base_fee_per_gas:fee ~worker_id:w

(* Three distinct batches; bB differs in fee AND worker so T35 can pin
   that the spec reads the batch's own fields, not a shared constant. *)
let batch_a = mk_batch [ hex F.f1_encoded ]
let batch_b = mk_batch ~fee:fee9 ~w:w3 [ hex F.f4a_encoded ]
let batch_c = mk_batch [ hex F.f2_encoded ]
let d_a = Batch.digest batch_a
let d_b = Batch.digest batch_b
let d_c = Batch.digest batch_c

let lookup d =
  List.find_opt
    (fun b -> Digests.Batch_digest.equal (Batch.digest b) d)
    [ batch_a; batch_b; batch_c ]

let mk_header ~author ~r ~created_at ~payload ~parents =
  Header.make ~latest_execution_block:Tn_types.Block_num_hash.zero ~author ~round:(round r) ~epoch:Units.Epoch.zero
    ~created_at ~payload ~parents

let certify header =
  let votes =
    List.map (fun id -> Vote.sign (sk_of id) ~voter:id header) ids
  in
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "certify: %s" (Certificate.error_to_string e))
    (Certificate.assemble committee header votes)

let genesis_parents = List.map Certificate.digest (Certificate.genesis committee)

(* Wrap headers (leader LAST) into a consensus block at height one. *)
let consensus_of headers =
  let certs = Nonempty.map certify headers in
  let sub_dag =
    Sub_dag.create ~sequence:certs
      ~scores:(Reputation_scores.fresh committee)
      ~previous:None
  in
  Cb.create ~parent_hash:Cb.genesis_parent ~sub_dag
    ~number:(Cb.Number.succ Cb.Number.genesis)

(* The standing 2-header output: payloads [(dA,0); (dB,3)] under id0's
   certificate, [(dC,0)] under the leader id1's. Leader created_at 55 is
   the commit timestamp. *)
let header_1 =
  mk_header ~author:id0 ~r:1 ~created_at:(ts 10L)
    ~payload:[ (d_a, w0); (d_b, w3) ]
    ~parents:genesis_parents

let header_2 =
  mk_header ~author:id1 ~r:2 ~created_at:(ts 55L)
    ~payload:[ (d_c, w0) ]
    ~parents:[ Header.digest header_1 ]

let consensus_32 = consensus_of (Nonempty.cons header_1 [ header_2 ])

let attach_ok consensus =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "attach: %s" (Output.error_to_string e))
    (Output.attach ~consensus ~lookup ~address_of)

let out_32 = attach_ok consensus_32

let attach_outcome consensus ~lookup ~address_of =
  Result.fold
    ~ok:(fun (_ : Output.t) -> "attached")
    ~error:Output.error_to_string
    (Output.attach ~consensus ~lookup ~address_of)

let plan_ok output ~closes_epoch =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "plan: %s" (Plan.error_to_string e))
    (Plan.plan output ~closes_epoch)

let batch_specs plan =
  match plan with
  | Plan.Batch_blocks specs -> Nonempty.to_list specs
  | Plan.Skip -> Alcotest.fail "expected Batch_blocks, got Skip"
  | Plan.Close_block _ -> Alcotest.fail "expected Batch_blocks, got Close_block"

let digest_list = List.equal Digests.Batch_digest.equal

let certified_equal =
  List.equal (fun (addr, batches) (addr', batches') ->
      Units.Address.equal addr addr' && List.equal Batch.equal batches batches')

let root_bytes consensus =
  Tn_crypto.Digest.to_bytes (Digests.Output_digest.to_digest (Cb.digest consensus))

let batch_digest_bytes d =
  Tn_crypto.Digest.to_bytes (Digests.Batch_digest.to_digest d)

(* The test's own XOR oracle for T35, written over the codec's total byte
   writer; the library code under test never flows through here. *)
let xor_oracle a b =
  Seq.map2
    (fun x y ->
      Tn_codec.Bcs.encode Tn_codec.Bcs.u8 (Char.code x lxor Char.code y))
    (String.to_seq a) (String.to_seq b)
  |> List.of_seq |> String.concat ""

(* T32: attach walks headers in commit order: flat digests [dA; dB; dC],
   certified groups per header with the table's addresses, leader address
   = the LAST header's author's. *)
let t32 () =
  Alcotest.(check bool)
    "batch_digests = [dA; dB; dC]" true
    (digest_list (Output.batch_digests out_32) [ d_a; d_b; d_c ]);
  Alcotest.(check bool)
    "certified groups per header, table addresses" true
    (certified_equal (Output.certified out_32)
       [ (addr_a, [ batch_a; batch_b ]); (addr_b, [ batch_c ]) ]);
  Alcotest.(check bool)
    "leader address is the leader author's table entry" true
    (Units.Address.equal (Output.leader_address out_32) addr_b)

(* T33: a digest lookup cannot supply fails the WHOLE attach with that
   digest (TN's fatal MissingFetchedBatch, never a silent skip); an
   unresolvable author fails with Unknown_authority. *)
let t33 () =
  let lookup_missing d =
    if Digests.Batch_digest.equal d d_b then None else lookup d
  in
  Alcotest.(check string)
    "missing dB is Missing_batch dB"
    (Output.error_to_string (Output.Missing_batch d_b))
    (attach_outcome consensus_32 ~lookup:lookup_missing ~address_of);
  let address_missing id =
    if Authority_id.equal id id0 then None else address_of id
  in
  Alcotest.(check string)
    "unresolvable author is Unknown_authority"
    (Output.error_to_string (Output.Unknown_authority id0))
    (attach_outcome consensus_32 ~lookup ~address_of:address_missing)

(* T34: one digest under two certificates resolves TWICE (subscriber
   clone semantics): twice in certified, twice in the flat digests. *)
let t34 () =
  let h1 =
    mk_header ~author:id0 ~r:1 ~created_at:(ts 10L)
      ~payload:[ (d_a, w0) ] ~parents:genesis_parents
  in
  let h2 =
    mk_header ~author:id1 ~r:2 ~created_at:(ts 20L)
      ~payload:[ (d_a, w0) ] ~parents:[ Header.digest h1 ]
  in
  let out = attach_ok (consensus_of (Nonempty.cons h1 [ h2 ])) in
  Alcotest.(check bool)
    "dA appears twice in batch_digests" true
    (digest_list (Output.batch_digests out) [ d_a; d_a ]);
  Alcotest.(check bool)
    "dA's batch appears under both certificates" true
    (certified_equal (Output.certified out)
       [ (addr_a, [ batch_a ]); (addr_b, [ batch_a ]) ])

(* T35: every consensus-derived spec field, on the standing output. *)
let t35 () =
  let specs = batch_specs (plan_ok out_32 ~closes_epoch:false) in
  Alcotest.(check int) "three specs, one per batch" 3 (List.length specs);
  let s0 = nth "spec 0" specs 0 in
  let s1 = nth "spec 1" specs 1 in
  let sub_dag = Cb.sub_dag consensus_32 in
  Alcotest.(check bool) "s0 batch is bA" true
    (Batch.equal (Plan.Spec.batch s0) batch_a);
  Alcotest.(check bool) "s0 digest is dA" true
    (Digests.Batch_digest.equal (Plan.Spec.batch_digest s0) d_a);
  Alcotest.(check bool)
    "beneficiary is the certificate address, not the batch's" true
    (Units.Address.equal (Plan.Spec.beneficiary s0) addr_a);
  Alcotest.(check bool) "s0 base fee is bA's own (7)" true
    (Units.Base_fee.equal (Plan.Spec.base_fee s0) fee7);
  Alcotest.(check bool) "s1 base fee is bB's own (9)" true
    (Units.Base_fee.equal (Plan.Spec.base_fee s1) fee9);
  Alcotest.(check int64) "gas limit is the 30M cap regardless of content"
    30_000_000L (Plan.Spec.gas_limit s0);
  Alcotest.(check int64) "s1 gas limit is the same cap" 30_000_000L
    (Plan.Spec.gas_limit s1);
  Alcotest.(check bool) "nonce is the sub-DAG sequence number" true
    (Units.Sequence_number.equal (Plan.Spec.nonce s0)
       (Sub_dag.sequence_number sub_dag));
  Alcotest.(check bool) "consensus root is the output digest" true
    (Digests.Output_digest.equal (Plan.Spec.consensus_root s0)
       (Cb.digest consensus_32));
  Alcotest.(check bool) "timestamp is the commit timestamp" true
    (Units.Timestamp.equal (Plan.Spec.timestamp s0)
       (Sub_dag.commit_timestamp sub_dag));
  Alcotest.(check bool) "s0 position: batch index 0" true
    (Option.equal Int.equal
       (Tn_evm.Batch_position.batch_index (Plan.Spec.position s0))
       (Some 0));
  Alcotest.(check bool) "s0 position: worker 0" true
    (Option.equal Units.Worker_id.equal
       (Tn_evm.Batch_position.worker_id (Plan.Spec.position s0))
       (Some w0));
  Alcotest.(check bool) "s0 position is the first batch" true
    (Tn_evm.Batch_position.is_first_batch (Plan.Spec.position s0));
  Alcotest.(check bool) "s1 position: batch index 1 (global)" true
    (Option.equal Int.equal
       (Tn_evm.Batch_position.batch_index (Plan.Spec.position s1))
       (Some 1));
  Alcotest.(check bool) "s1 position: worker 3 (the batch's own)" true
    (Option.equal Units.Worker_id.equal
       (Tn_evm.Batch_position.worker_id (Plan.Spec.position s1))
       (Some w3));
  Alcotest.(check bool) "s1 position word is shifted past the worker bits"
    true
    (not (Tn_evm.Batch_position.is_first_batch (Plan.Spec.position s1)));
  let root = root_bytes consensus_32 in
  Alcotest.(check bool) "s0 mix_hash = output digest XOR dA" true
    (String.equal (Plan.Spec.mix_hash s0)
       (xor_oracle root (batch_digest_bytes d_a)));
  Alcotest.(check bool) "s1 mix_hash = output digest XOR dB" true
    (String.equal (Plan.Spec.mix_hash s1)
       (xor_oracle root (batch_digest_bytes d_b)));
  Alcotest.(check bool) "two batches of one output mix differently" true
    (not (String.equal (Plan.Spec.mix_hash s0) (Plan.Spec.mix_hash s1)));
  Alcotest.(check bool) "no spec closes a non-closing output" false
    (List.exists Plan.Spec.closes_epoch specs)

(* An empty output: one leader-only header with an empty payload. *)
let out_empty =
  attach_ok
    (consensus_of
       (Nonempty.singleton
          (mk_header ~author:id0 ~r:1 ~created_at:(ts 55L) ~payload:[]
             ~parents:genesis_parents)))

(* T36: no batches + not closing = no block at all; + closing = exactly
   one empty block, leader beneficiary, mix_hash = the bare output
   digest. *)
let t36 () =
  (match plan_ok out_empty ~closes_epoch:false with
  | Plan.Skip -> ()
  | Plan.Close_block _ -> Alcotest.fail "expected Skip, got Close_block"
  | Plan.Batch_blocks _ -> Alcotest.fail "expected Skip, got Batch_blocks");
  match plan_ok out_empty ~closes_epoch:true with
  | Plan.Skip -> Alcotest.fail "expected Close_block, got Skip"
  | Plan.Batch_blocks _ -> Alcotest.fail "expected Close_block, got Batch_blocks"
  | Plan.Close_block close ->
      Alcotest.(check bool) "close beneficiary is the leader's address" true
        (Units.Address.equal
           (Plan.Close_spec.beneficiary close)
           (Output.leader_address out_empty));
      Alcotest.(check bool) "close mix_hash is the bare output digest" true
        (String.equal
           (Plan.Close_spec.mix_hash close)
           (Tn_crypto.Digest.to_bytes
              (Digests.Output_digest.to_digest
                 (Output.output_digest out_empty))));
      Alcotest.(check bool) "close consensus root is the output digest" true
        (Digests.Output_digest.equal
           (Plan.Close_spec.consensus_root close)
           (Output.output_digest out_empty));
      Alcotest.(check bool) "close nonce is the output nonce" true
        (Units.Sequence_number.equal
           (Plan.Close_spec.nonce close)
           (Output.nonce out_empty));
      Alcotest.(check bool) "close timestamp is the commit timestamp" true
        (Units.Timestamp.equal
           (Plan.Close_spec.timestamp close)
           (Output.committed_at out_empty))

(* T37: only the LAST spec of a closing output closes the epoch, and the
   boundary recompute is committed_at >= boundary (equality closes). *)
let t37 () =
  let specs = batch_specs (plan_ok out_32 ~closes_epoch:true) in
  Alcotest.(check (list bool))
    "only the last spec closes" [ false; false; true ]
    (List.map Plan.Spec.closes_epoch specs);
  Alcotest.(check bool) "committed_at = boundary closes (>=, not >)" true
    (Output.closes_epoch out_32 ~epoch_boundary:(ts 55L));
  Alcotest.(check bool) "committed_at past the boundary closes" true
    (Output.closes_epoch out_32 ~epoch_boundary:(ts 54L));
  Alcotest.(check bool) "committed_at before the boundary does not" false
    (Output.closes_epoch out_32 ~epoch_boundary:(ts 56L))

(* T-41: the plan-side companion the chunk-36 engine leans on. The engine
   attaches the epoch commitment to the LAST block of a closing output by
   SPLITTING the spec list at its last element, so it never consults
   [Spec.closes_epoch] on a leading spec and a planner that flagged one would go
   unnoticed there. This is the case that notices. It counts the flags rather
   than reading a position, and identifies the flagged spec by folding to the
   last element, so neither the count nor the identity comes from an index. *)
let t41 () =
  let specs = batch_specs (plan_ok out_32 ~closes_epoch:true) in
  Alcotest.(check int) "the fixture is a three-batch output" 3
    (List.length specs);
  Alcotest.(check int) "exactly ONE spec closes the epoch" 1
    (List.length (List.filter Plan.Spec.closes_epoch specs));
  let last = List.fold_left (fun _ spec -> Some spec) None specs in
  Alcotest.(check bool) "and it is the last one" true
    (Option.fold ~none:false ~some:Plan.Spec.closes_epoch last);
  Alcotest.(check (list bool))
    "so the flags read false, false, true, in that order"
    [ false; false; true ]
    (List.map Plan.Spec.closes_epoch specs);
  Alcotest.(check int) "and a non-closing output flags nothing at all" 0
    (List.length
       (List.filter Plan.Spec.closes_epoch
          (batch_specs (plan_ok out_32 ~closes_epoch:false))))

(* T38: the drop layer. Kept: F1, the 0x00-tagged F1 (stripped to its
   untagged twin), and F4a, in batch order; dropped: undecodable junk
   (TN drops it too), the nonce-2^62 F2 and the well-formed 4844 F6
   (TN executes then skips them, so block content agrees). *)
let t38 () =
  let batch =
    mk_batch
      [
        hex F.f1_encoded;
        "\x01\x02\x03";
        "\x00" ^ hex F.f1_encoded;
        hex F.f2_encoded;
        hex F.f6_encoded;
        hex F.f4a_encoded;
      ]
  in
  let kept = Payload.executable_txs batch in
  Alcotest.(check int) "exactly three transactions survive" 3
    (List.length kept);
  let hashes = List.map Tn_evm.Tx_envelope.hash kept in
  Alcotest.(check bool) "kept hashes are [F1; F1; F4a], in batch order" true
    (List.equal String.equal hashes
       [ hex F.f1_tx_hash; hex F.f1_tx_hash; hex F.f4a_tx_hash ]);
  let stripped = nth "stripped tagged F1" kept 1 in
  Alcotest.(check bool)
    "the stripped tagged legacy hashes as the untagged encoding" true
    (String.equal
       (Tn_evm.Tx_envelope.hash stripped)
       (Tn_evm.Tx_envelope.hash_of_2718 (hex F.f1_encoded)))

(* ================================================================== *)
(* Chunk-36 stage 3: the skip class, one layer below the drop layer.   *)
(* ================================================================== *)

(* T38's [executable_txs] drops what cannot be decoded or recovered, BEFORE
   the block runs. What survives it can still be refused by the executor, and
   a batch that duplicates another worker's transaction is normal operation
   rather than an incident, so the builder's fold skips it and continues:
   [Tn_evm.Block_execution.run_transactions_skipping_invalid]. These three
   cases live here, beside the drop layer they complete, rather than in
   test_block_execution.ml, whose UNTOUCHED green suite is what proves the new
   fold was added additively and cost [run_transactions] nothing.

   Every fixture is Block_fixtures', qualified rather than opened so this
   file's own [get]/[hex]/[nth] keep their meaning. *)

module Bf = Block_fixtures
module Block_execution = Tn_evm.Block_execution
module Block_roots = Tn_evm.Block_roots
module Bloom = Tn_evm.Bloom
module World_state = Tn_state.World_state

(* One legacy transfer per signer index, all at nonce zero, all cheap enough
   that three of them fit any block limit these cases set. *)
let transfer ~signer = Bf.legacy_envelope ~signer ~gas_limit:21_000 ()

let pre_of world ~context =
  Result.fold ~ok:Fun.id
    ~error:(fun e ->
      Alcotest.failf "pre-block: %s" (Block_execution.error_to_string e))
    (Block_execution.apply_pre_block world ~context)

(* Polymorphic in what the fold returns, so the strict path's [outcome] and the
   builder path's [outcome * Invalid_tx.t list] share one totaliser. *)
let exec_ok what result =
  Result.fold ~ok:Fun.id
    ~error:(fun e ->
      Alcotest.failf "%s: %s" what (Block_execution.error_to_string e))
    result

let refused what result =
  Result.fold
    ~ok:(fun _ -> Alcotest.fail what)
    ~error:Block_execution.error_to_string result

(* T-30: a batch of [good; the same transaction again; good2] builds ONE block
   of two transactions and two receipts, with one Invalid_tx recorded at INPUT
   position 1. The strict fold on the very same list still refuses at the same
   index, with the same rendering it refused with before this stage. *)
let t30 () =
  let good = transfer ~signer:71 in
  let good2 = transfer ~signer:72 in
  let world = Bf.fund World_state.empty [ good; good2 ] in
  let context = Bf.context () in
  let pre = pre_of world ~context in
  let batch = [ good; good; good2 ] in
  let result =
    Block_execution.run_transactions_skipping_invalid pre ~context batch
  in
  Alcotest.(check bool) "a duplicate does not stop the block" true
    (Result.is_ok result);
  let outcome, skipped = exec_ok "the skipping fold" result in
  Alcotest.(check int) "two transactions reach the block" 2
    (List.length (Block_execution.transactions outcome));
  Alcotest.(check int) "and two receipts" 2
    (List.length (Block_execution.receipts outcome));
  Alcotest.(check int) "exactly one skip is recorded" 1 (List.length skipped);
  let record = nth "the skip record" skipped 0 in
  Alcotest.(check int) "the skip reports its INPUT position" 1
    (Block_execution.Invalid_tx.index record);
  Alcotest.(check string) "and says why it was skipped"
    "transaction 1 skipped: nonce mismatch (expected 1, got 0)"
    (Block_execution.Invalid_tx.to_string record);
  Alcotest.(check string) "the strict fold still refuses the same list"
    "transaction 1 rejected: nonce mismatch (expected 1, got 0)"
    (refused "the strict fold accepted a duplicate"
       (Block_execution.run_transactions pre ~context batch))

(* T-31: the skipped transaction is in no root, no bloom and no gas. Both
   blocks are built here, so neither side is an assumed constant: the block
   from [good; duplicate; good2] must be byte-identical, in every field the
   header commits to, to the block from [good; good2] at the same context. *)
let t31 () =
  let good = transfer ~signer:73 in
  let good2 = transfer ~signer:74 in
  let world = Bf.fund World_state.empty [ good; good2 ] in
  let context = Bf.context () in
  let pre = pre_of world ~context in
  let skipped_block, skips =
    exec_ok "the skipping fold"
      (Block_execution.run_transactions_skipping_invalid pre ~context
         [ good; good; good2 ])
  in
  let clean_block =
    exec_ok "the two-transaction fold"
      (Block_execution.run_transactions pre ~context [ good; good2 ])
  in
  Alcotest.(check int) "the fixture really did skip one" 1 (List.length skips);
  (* Not vacuous: an empty block agrees with neither. *)
  let empty_block =
    exec_ok "the empty fold" (Block_execution.run_transactions pre ~context [])
  in
  Alcotest.(check bool) "the roots under test are not the empty ones" false
    (String.equal
       (Block_roots.transactions_root_of
          (Block_execution.transactions clean_block))
       (Block_roots.transactions_root_of
          (Block_execution.transactions empty_block)));
  Alcotest.(check string) "transactions root ignores the skipped envelope"
    (Block_roots.transactions_root_of
       (Block_execution.transactions clean_block))
    (Block_roots.transactions_root_of
       (Block_execution.transactions skipped_block));
  Alcotest.(check string) "receipts root ignores it"
    (Block_roots.receipts_root (Block_execution.receipts clean_block))
    (Block_roots.receipts_root (Block_execution.receipts skipped_block));
  Alcotest.(check bool) "the logs bloom ignores it" true
    (Bloom.equal
       (Block_execution.logs_bloom clean_block)
       (Block_execution.logs_bloom skipped_block));
  Alcotest.(check int) "the skip burns no block gas"
    (Block_execution.gas_used clean_block)
    (Block_execution.gas_used skipped_block);
  Alcotest.(check string) "and commits no state"
    (Block_roots.state_root (Block_execution.world clean_block))
    (Block_roots.state_root (Block_execution.world skipped_block))

(* T-32: Gas_limit_above_available is telcoin's own pre-check, not an
   InvalidTx, so it stays FATAL in the builder fold too. The batch skips one
   transaction before reaching it, so the index the error reports is also the
   proof that the counter counts INPUTS: a success counter would say 1. *)
let t32_fatal () =
  let good = transfer ~signer:75 in
  let greedy = Bf.legacy_envelope ~signer:76 ~gas_limit:100_001 () in
  let world = Bf.fund World_state.empty [ good; greedy ] in
  let context = Bf.context ~gas_limit:100_000 () in
  let pre = pre_of world ~context in
  let result =
    Block_execution.run_transactions_skipping_invalid pre ~context
      [ good; good; greedy ]
  in
  Alcotest.(check bool) "the gas-limit pre-check is fatal, not a skip" true
    (Result.is_error result);
  Alcotest.(check string) "it names the INPUT position and the REMAINDER"
    "transaction 2 wants 100001 gas but only 79000 remain in the block"
    (refused "the greedy transaction was skipped" result)

let () =
  Alcotest.run "payload_seam"
    [
      ( "output",
        [
          Alcotest.test_case "T32 attach ordering + grouping" `Quick t32;
          Alcotest.test_case "T33 attach failures" `Quick t33;
          Alcotest.test_case "T34 duplicate digest resolves twice" `Quick t34;
        ] );
      ( "plan",
        [
          Alcotest.test_case "T35 spec fields + mix_hash XOR" `Quick t35;
          Alcotest.test_case "T36 empty-output plan" `Quick t36;
          Alcotest.test_case "T37 close on last spec + >= boundary" `Quick t37;
          Alcotest.test_case
            "T-41 the plan flags the LAST spec and no other" `Quick t41;
        ] );
      ( "payload",
        [ Alcotest.test_case "T38 executable_txs drop layer" `Quick t38 ] );
      ( "skip",
        [
          Alcotest.test_case "T30 an InvalidTx is skipped, not fatal" `Quick t30;
          Alcotest.test_case "T31 a skip enters no root and no gas" `Quick t31;
          Alcotest.test_case "T32 Gas_limit_above_available stays fatal" `Quick
            t32_fatal;
        ] );
    ]
