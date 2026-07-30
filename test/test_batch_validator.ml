(* Chunk-34 stage 3: [Tn_batch.Batch_validator] against the oracle-signed
   fixtures (batch_fixtures.ml), tests T19-T31 of the chunk design.

   Every outcome is asserted through [error_to_string], so each check pins
   the ARM and its payload values at once (the display strings embed the
   exact expected/found fields, the batch digest, or the offending tx
   hash), and the renderer itself is exercised on every reachable arm. *)

open Tn_types
module Bv = Tn_batch.Batch_validator
module Validator = Tn_batch.Batch_validator.Validator
module F = Batch_fixtures
module V = Tx_shape_vectors

let hex = Tx_vectors.hex

(* Totalise the option-returning Units constructors, test_batch.ml's
   pattern: a silently defaulted value cannot hide, every constructed
   field is re-observed through an exact expected string below. *)
let epoch n = Units.Epoch.of_int n |> Option.value ~default:Units.Epoch.zero

let worker n =
  Units.Worker_id.of_int n |> Option.value ~default:Units.Worker_id.zero

let fee = Units.Base_fee.of_int64

(* The standing snapshot all fixtures were minted against: worker 1,
   epoch 0, base fee 7 (the protocol floor). *)
let expected_worker = worker 1
let expected_epoch = Units.Epoch.zero
let expected_fee = Units.Base_fee.min_protocol

let validator =
  Validator.make ~worker_id:expected_worker ~epoch:expected_epoch
    ~base_fee_per_gas:expected_fee

(* A batch that passes every rule unless a field is overridden: one F1
   legacy tx, the snapshot's epoch/worker/fee. *)
let mk ?(txs = [ hex F.f1_encoded ]) ?(ep = expected_epoch)
    ?(w = expected_worker) ?(f = expected_fee) () =
  Batch.make ~transactions:txs ~epoch:ep ~beneficiary:Units.Address.zero
    ~base_fee_per_gas:f ~worker_id:w

let outcome result =
  Result.fold ~ok:(fun _valid -> "valid") ~error:Bv.error_to_string result

let run batch = outcome (Validator.validate validator (Batch.Sealed.seal batch))

(* The Recover_transaction rendering for a given batch: rule 5 carries the
   BATCH digest, so the expectation is recomputed per batch. *)
let recover_msg batch message =
  "Failed to decode transaction for batch 0x"
  ^ Digests.Batch_digest.to_hex (Batch.digest batch)
  ^ ": " ^ message

(* Four bytes whose first byte (0xde) opens an untagged-legacy RLP list
   that immediately truncates: fails rule 5 at decode, never recovery. *)
let junk = hex "deadbeef"

(* ---- T19: happy path, and the Valid witness rounds back ---- *)

let t19 () =
  let b = mk () in
  let result = Validator.validate validator (Batch.Sealed.seal b) in
  Alcotest.(check string) "sealed F1 batch validates" "valid" (outcome result);
  Alcotest.(check bool) "Valid.batch rounds back" true
    (Result.map (fun v -> Batch.equal (Validator.Valid.batch v) b) result
    |> Result.value ~default:false);
  Alcotest.(check bool) "Valid.digest is the verified digest" true
    (Result.map
       (fun v ->
         Digests.Batch_digest.equal (Validator.Valid.digest v) (Batch.digest b))
       result
    |> Result.value ~default:false)

(* ---- T20: rule 1, a dishonest digest claim ---- *)

let t20 () =
  let b = mk () in
  let wrong =
    Digests.Batch_digest.of_digest (Tn_crypto.Digest.hash "not the preimage")
  in
  Alcotest.(check string) "wrong digest claim is Invalid_digest"
    "Invalid digest for sealed batch."
    (outcome (Validator.validate validator (Batch.Sealed.claim ~batch:b ~digest:wrong)))

(* ---- T21: rule 2, with the exact Rust payload fields ---- *)

let t21 () =
  Alcotest.(check string) "worker 2 against expected 1"
    "Invalid worker id, expected 1 got 2"
    (run (mk ~w:(worker 2) ()))

(* ---- T22: rule 3, both payload directions, snapshot not a constant ---- *)

let t22 () =
  Alcotest.(check string) "epoch 1 against expected 0"
    "Invalid epoch, expected epoch 0 got epoch 1"
    (run (mk ~ep:(epoch 1) ()));
  (* A nonzero snapshot distinguishes "compare with the snapshot" from
     "compare with zero": epoch-1 validator, epoch-0 batch, and the
     epoch-1 happy pair. *)
  let validator_e1 =
    Validator.make ~worker_id:expected_worker ~epoch:(epoch 1)
      ~base_fee_per_gas:expected_fee
  in
  Alcotest.(check string) "epoch 0 against expected 1"
    "Invalid epoch, expected epoch 1 got epoch 0"
    (outcome (Validator.validate validator_e1 (Batch.Sealed.seal (mk ()))));
  Alcotest.(check string) "epoch 1 against expected 1 passes" "valid"
    (outcome
       (Validator.validate validator_e1
          (Batch.Sealed.seal (mk ~ep:(epoch 1) ()))))

(* ---- T23: rule 4, the empty list and the exact byte boundary ---- *)

let t23 () =
  let f3 = hex F.f3_encoded in
  Alcotest.(check int) "F3 is exactly 1000 encoded bytes" 1000
    (String.length f3);
  Alcotest.(check string) "the empty batch" "Batch contains no transactions"
    (run (mk ~txs:[] ()));
  Alcotest.(check string) "1001 x F3 is one tx over the byte cap"
    "Peer's transactions exceed max byte size: 1001000"
    (run (mk ~txs:(List.init 1001 (fun _i -> f3)) ()));
  Alcotest.(check string) "1000 x F3 sits exactly at the cap and validates"
    "valid"
    (run (mk ~txs:(List.init 1000 (fun _i -> f3)) ()))

(* ---- T24: rule 5 is decode AND recovery, digest payload is the batch's ---- *)

let t24 () =
  let b_junk = mk ~txs:[ junk ] () in
  Alcotest.(check string) "undecodable bytes carry the BATCH digest"
    (recover_msg b_junk "failed to decode signed transaction")
    (run b_junk);
  (* r = 0 decodes fine and dies only in recovery (the in-tree
     unrecoverable-signature exhibit; stage 2's T17 pins its class). *)
  let b_r0 = mk ~txs:[ hex V.r_zero_v27 ] () in
  Alcotest.(check string) "r = 0 fails rule 5 at recovery, not decode"
    (recover_msg b_r0 "invalid transaction signature")
    (run b_r0);
  let b_high_s = mk ~txs:[ hex F.f8_encoded ] () in
  Alcotest.(check string) "F8 high-s twin fails rule 5 at recovery"
    (recover_msg b_high_s "invalid transaction signature")
    (run b_high_s)

(* ---- T25: rule 5 reports the FIRST failure in list order ---- *)

let t25 () =
  let f8 = hex F.f8_encoded in
  let b1 = mk ~txs:[ junk; f8 ] () in
  Alcotest.(check string) "decode failure first in list order"
    (recover_msg b1 "failed to decode signed transaction")
    (run b1);
  let b2 = mk ~txs:[ f8; junk ] () in
  Alcotest.(check string) "signature failure first in list order"
    (recover_msg b2 "invalid transaction signature")
    (run b2)

(* ---- T26: rule 6 carries the OFFENDING TX hash, not the batch digest ---- *)

let t26 () =
  Alcotest.(check string) "F6 fires Invalid_tx_4844 with its own tx hash"
    ("Proposed batch contains blob transaction. Tx hash: 0x" ^ F.f6_tx_hash)
    (run (mk ~txs:[ hex F.f6_encoded ] ()))

(* ---- T27: the EIP-7702 gap, pinned as TN behaviour ---- *)

let t27 () =
  Alcotest.(check string)
    "a valid type-4 tx passes batch validation (TN has no 7702 filter)"
    "valid"
    (run (mk ~txs:[ hex Eip7702_vectors.type4_encoded_2718_hex ] ()))

(* ---- T28: rule 7, cap equality, one-over, and the u64 overflow arm ---- *)

let t28 () =
  let f4a = hex F.f4a_encoded
  and f4b = hex F.f4b_encoded
  and f5 = hex F.f5_encoded in
  Alcotest.(check string) "2 x 15M = the 30M cap exactly passes" "valid"
    (run (mk ~txs:[ f4a; f4a ] ()));
  Alcotest.(check string) "one gas unit over the cap"
    "Peer's batch total possible gas (30000001) is greater than batch's gas \
     limit (30000000)"
    (run (mk ~txs:[ f4a; f4b ] ()));
  Alcotest.(check string) "2 x 2^63 overflows the u64 sum, not the cap arm"
    "Overflow calculating max possible gas."
    (run (mk ~txs:[ f5; f5 ] ()))

(* ---- T29: rule 8 is strict equality, both directions ---- *)

let t29 () =
  Alcotest.(check string) "fee 8 against expected 7"
    "Invalid base fee, expected 7 got 8"
    (run (mk ~f:(fee 8L) ()));
  Alcotest.(check string) "fee 6 against expected 7"
    "Invalid base fee, expected 7 got 6"
    (run (mk ~f:(fee 6L) ()))

(* ---- T30: the order matrix, all 7 adjacent rule pairs ---- *)

let t30 () =
  let f3 = hex F.f3_encoded
  and f4a = hex F.f4a_encoded
  and f4b = hex F.f4b_encoded
  and f6 = hex F.f6_encoded in
  (* 1 before 2: wrong digest claim on a wrong-worker batch. *)
  let b12 = mk ~w:(worker 2) () in
  let wrong = Digests.Batch_digest.of_digest (Tn_crypto.Digest.hash "flip") in
  Alcotest.(check string) "digest before worker id"
    "Invalid digest for sealed batch."
    (outcome
       (Validator.validate validator
          (Batch.Sealed.claim ~batch:b12 ~digest:wrong)));
  (* 2 before 3. *)
  Alcotest.(check string) "worker id before epoch"
    "Invalid worker id, expected 1 got 2"
    (run (mk ~w:(worker 2) ~ep:(epoch 1) ()));
  (* 3 before 4. *)
  Alcotest.(check string) "epoch before byte size"
    "Invalid epoch, expected epoch 0 got epoch 1"
    (run (mk ~ep:(epoch 1) ~txs:(List.init 1001 (fun _i -> f3)) ()));
  (* 4 before 5. *)
  Alcotest.(check string) "byte size before decode"
    "Peer's transactions exceed max byte size: 1001004"
    (run (mk ~txs:(junk :: List.init 1001 (fun _i -> f3)) ()));
  (* 5 before 6. *)
  let b56 = mk ~txs:[ junk; f6 ] () in
  Alcotest.(check string) "decode before the 4844 filter"
    (recover_msg b56 "failed to decode signed transaction")
    (run b56);
  (* 6 before 7: F6 + 30M of valid gas. *)
  Alcotest.(check string) "the 4844 filter before the gas cap"
    ("Proposed batch contains blob transaction. Tx hash: 0x" ^ F.f6_tx_hash)
    (run (mk ~txs:[ f6; f4a; f4a ] ()));
  (* 7 before 8. *)
  Alcotest.(check string) "the gas cap before the base fee"
    "Peer's batch total possible gas (30000001) is greater than batch's gas \
     limit (30000000)"
    (run (mk ~txs:[ f4a; f4b ] ~f:(fee 8L) ()))

(* ---- T31: the penalty map, all 12 arms against the pinned severities ---- *)

let penalty_name p =
  match p with
  | Bv.Mild -> "mild"
  | Bv.Medium -> "medium"
  | Bv.Severe -> "severe"
  | Bv.Fatal -> "fatal"

let t31 () =
  let check_penalty label expected e =
    Alcotest.(check string) label expected (penalty_name (Bv.penalty e))
  in
  check_penalty "Invalid_digest is Fatal" "fatal" Bv.Invalid_digest;
  check_penalty "Canonical_chain is Mild" "mild"
    (Bv.Canonical_chain { block_hash = Tn_keccak.empty });
  check_penalty "Empty_batch is Fatal" "fatal" Bv.Empty_batch;
  check_penalty "Header_max_gas_exceeds_gas_limit is Fatal" "fatal"
    (Bv.Header_max_gas_exceeds_gas_limit
       { total_possible_gas = 30_000_001L; gas_limit = 30_000_000L });
  check_penalty "Calculate_max_possible_gas is Fatal" "fatal"
    Bv.Calculate_max_possible_gas;
  check_penalty "Header_transaction_bytes_exceeds_max is Fatal" "fatal"
    (Bv.Header_transaction_bytes_exceeds_max 1_000_001);
  check_penalty "Recover_transaction is Severe" "severe"
    (Bv.Recover_transaction
       { digest = Batch.digest (mk ()); message = "m" });
  check_penalty "Invalid_base_fee is Fatal" "fatal"
    (Bv.Invalid_base_fee
       { expected_base_fee = expected_fee; base_fee = fee 8L });
  check_penalty "Invalid_worker_id is Fatal" "fatal"
    (Bv.Invalid_worker_id
       { expected_worker_id = expected_worker; worker_id = worker 2 });
  check_penalty "Invalid_tx_4844 is Medium" "medium"
    (Bv.Invalid_tx_4844 Tn_keccak.empty);
  check_penalty "Gas_overflow is Fatal" "fatal" Bv.Gas_overflow;
  check_penalty "Invalid_epoch is Medium" "medium"
    (Bv.Invalid_epoch { expected = expected_epoch; found = epoch 1 })

let () =
  Alcotest.run "batch_validator"
    [
      ( "rules",
        [
          Alcotest.test_case "T19 happy path" `Quick t19;
          Alcotest.test_case "T20 rule 1 digest" `Quick t20;
          Alcotest.test_case "T21 rule 2 worker payloads" `Quick t21;
          Alcotest.test_case "T22 rule 3 epoch payloads" `Quick t22;
          Alcotest.test_case "T23 rule 4 empty + byte boundary" `Quick t23;
          Alcotest.test_case "T24 rule 5 decode + recovery" `Quick t24;
          Alcotest.test_case "T25 rule 5 first failure" `Quick t25;
          Alcotest.test_case "T26 rule 6 exact identity" `Quick t26;
          Alcotest.test_case "T27 the 7702 gap pinned" `Quick t27;
          Alcotest.test_case "T28 rule 7 boundary + overflow" `Quick t28;
          Alcotest.test_case "T29 rule 8 strict equality" `Quick t29;
        ] );
      ( "order and penalty",
        [
          Alcotest.test_case "T30 order matrix, 7 adjacent pairs" `Quick t30;
          Alcotest.test_case "T31 penalty map total" `Quick t31;
        ] );
    ]
