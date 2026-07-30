(* Chunk-34 stage 1: [Tn_types.Batch] against the oracle golden vectors
   (batch_vectors.ml, V1-V7), tests T1-T9 of the chunk design.

   The preimage rows are the byte-exact output of the pinned Rust oracle
   (bcs 0.1.6 + the alloy Address serde), so a green T1 is wire evidence,
   not round-trip self-consistency. The blake3 column stays inert until
   tn_crypto_blst lands; T7 pins the stub-seam digest formula (seam hash of
   domain ^ preimage) instead. *)

open Tn_types
module Bcs = Tn_codec.Bcs
module V = Batch_vectors

(* Hex of a byte string, for comparing computed preimages against the
   oracle's hex rows. *)
let to_hex s =
  String.fold_left
    (fun acc c -> acc ^ Printf.sprintf "%02x" (Char.code c))
    "" s

(* Totalise the option-returning Units constructors. A wrong default cannot
   hide a fixture typo: every constructed value is pinned byte-for-byte
   against the oracle hex in T1, so a silently defaulted field would fail
   there. *)
let epoch n = Units.Epoch.of_int n |> Option.value ~default:Units.Epoch.zero

let worker n =
  Units.Worker_id.of_int n |> Option.value ~default:Units.Worker_id.zero

let address s =
  Units.Address.of_bytes s |> Option.value ~default:Units.Address.zero

let ts s = Units.Timestamp.of_sec s |> Option.value ~default:Units.Timestamp.zero
let fee7 = Units.Base_fee.of_int64 7L

(* The vector batches, constructed field-by-field (NOT via Batch.default, so
   T3 checks the default against V1 independently). *)
let v1 =
  Batch.make ~transactions:[] ~epoch:Units.Epoch.zero
    ~beneficiary:Units.Address.zero ~base_fee_per_gas:fee7
    ~worker_id:Units.Worker_id.zero

let v2 =
  Batch.make ~transactions:[ V.v2_tx ] ~epoch:Units.Epoch.zero
    ~beneficiary:Units.Address.zero ~base_fee_per_gas:fee7
    ~worker_id:Units.Worker_id.zero

let v3 =
  Batch.make ~transactions:V.v3_txs ~epoch:Units.Epoch.zero
    ~beneficiary:Units.Address.zero ~base_fee_per_gas:fee7
    ~worker_id:Units.Worker_id.zero

let v4 =
  Batch.make ~transactions:[] ~epoch:(epoch V.v4_epoch)
    ~beneficiary:Units.Address.zero ~base_fee_per_gas:fee7
    ~worker_id:Units.Worker_id.zero

let v5 =
  Batch.make ~transactions:V.v5_txs ~epoch:(epoch V.v5_epoch)
    ~beneficiary:(address V.v5_beneficiary)
    ~base_fee_per_gas:(Units.Base_fee.of_int64 V.v5_base_fee)
    ~worker_id:(worker V.v5_worker_id)

let v6 = Batch.with_received_at v5 (ts V.v6_received_at_sec)

let v7 =
  Batch.make ~transactions:[ V.v7_tx ] ~epoch:Units.Epoch.zero
    ~beneficiary:Units.Address.zero ~base_fee_per_gas:fee7
    ~worker_id:Units.Worker_id.zero

let check_preimage name b expected_hex =
  Alcotest.(check string) name expected_hex (to_hex (Batch.preimage b))

(* T1: the seven preimage rows, byte-exact. *)
let t1 () =
  check_preimage "V1-default" v1 V.v1_preimage;
  check_preimage "V2-one-tx" v2 V.v2_preimage;
  check_preimage "V3-two-tx" v3 V.v3_preimage;
  check_preimage "V4-epoch7" v4 V.v4_preimage;
  check_preimage "V5-full" v5 V.v5_preimage;
  check_preimage "V6-skip-proof" v6 V.v6_preimage;
  check_preimage "V7-uleb128-128" v7 V.v7_preimage

(* T2: received_at contributes zero preimage bytes (the V6 skip-proof,
   mirroring TN's own regression test validator.rs:326-332). *)
let t2 () =
  Alcotest.(check string) "preimage (with_received_at v5) = preimage v5"
    (to_hex (Batch.preimage v5))
    (to_hex (Batch.preimage v6))

(* T3: Batch.default is V1. *)
let t3 () =
  Alcotest.(check string) "default preimage is V1" V.v1_preimage
    (to_hex (Batch.preimage Batch.default));
  Alcotest.(check bool) "default equals the constructed V1" true
    (Batch.equal Batch.default v1)

(* T4: a 128-byte tx length takes the two-byte canonical ULEB128 80 01. *)
let t4 () =
  Alcotest.(check bool) "V7 preimage starts 01 80 01" true
    (String.starts_with ~prefix:"018001" (to_hex (Batch.preimage v7)))

(* T5: codec round-trip and decode exactness. *)
let roundtrip name expected b =
  Result.fold
    ~ok:(fun decoded ->
      Alcotest.(check bool) (name ^ " decodes back") true
        (Batch.equal decoded expected))
    ~error:(fun e -> Alcotest.failf "%s: %s" name (Bcs.error_to_string e))
    (Bcs.decode Batch.codec (Batch.preimage b))

let t5 () =
  roundtrip "V1" v1 v1;
  roundtrip "V2" v2 v2;
  roundtrip "V3" v3 v3;
  roundtrip "V4" v4 v4;
  roundtrip "V5" v5 v5;
  roundtrip "V7" v7 v7;
  (* Decode applies the serde-skip default: V6's preimage yields V5's value,
     received_at reset to None ... *)
  roundtrip "V6 decodes to V5" v5 v6;
  (* ... so the decoded value is NOT V6 (whose received_at is Some 123). *)
  Result.fold
    ~ok:(fun decoded ->
      Alcotest.(check bool) "V6 round-trip drops received_at" false
        (Batch.equal decoded v6))
    ~error:(fun e -> Alcotest.failf "V6: %s" (Bcs.error_to_string e))
    (Bcs.decode Batch.codec (Batch.preimage v6));
  (* Exactness: one trailing byte is Trailing_bytes, never tolerated. *)
  let plen = String.length (Batch.preimage v1) in
  Result.fold
    ~ok:(fun (_ : Batch.t) -> Alcotest.fail "accepted a trailing byte")
    ~error:(fun e ->
      Alcotest.(check string) "trailing-bytes arm"
        (Bcs.error_to_string
           (Bcs.Trailing_bytes { consumed = plen; total = plen + 1 }))
        (Bcs.error_to_string e))
    (Bcs.decode Batch.codec (Batch.preimage v1 ^ "\x00"));
  (* A 19-byte beneficiary forgery (length prefix 0x13) must be rejected:
     alloy's Address deserializer refuses any width but 20. *)
  let forged =
    "\x00" ^ "\x00\x00\x00\x00" ^ "\x13" ^ String.make 19 '\x00'
    ^ "\x07\x00\x00\x00\x00\x00\x00\x00" ^ "\x00\x00"
  in
  Alcotest.(check bool) "19-byte beneficiary rejected" true
    (Result.is_error (Bcs.decode Batch.codec forged))

(* T6: equal covers all six fields, received_at included (the Rust derive,
   sealed_batch.rs:62), even though the preimages coincide. *)
let t6 () =
  Alcotest.(check bool) "equal includes received_at" false (Batch.equal v5 v6);
  Alcotest.(check bool) "reflexive on V5" true (Batch.equal v5 v5);
  Alcotest.(check bool) "reflexive on V6" true (Batch.equal v6 v6)

(* T7: the stub-era digest formula, recomputed in-test through the seam. *)
let stub_digest b =
  Digests.Batch_digest.of_digest
    (Tn_crypto.Digest.hash (Digests.Batch_digest.domain ^ Batch.preimage b))

let t7 () =
  Alcotest.(check bool) "V1 digest is seam hash of domain ^ preimage" true
    (Digests.Batch_digest.equal (Batch.digest v1) (stub_digest v1));
  Alcotest.(check bool) "V4 digest is seam hash of domain ^ preimage" true
    (Digests.Batch_digest.equal (Batch.digest v4) (stub_digest v4));
  Alcotest.(check bool) "V1 and V4 digests differ" false
    (Digests.Batch_digest.equal (Batch.digest v1) (Batch.digest v4))

(* T8: Sealed seal / claim / split. *)
let t8 () =
  let sealed = Batch.Sealed.seal v5 in
  Alcotest.(check bool) "seal computes the digest" true
    (Digests.Batch_digest.equal (Batch.Sealed.digest sealed) (Batch.digest v5));
  let wrong = Digests.Batch_digest.of_digest (Tn_crypto.Digest.hash "wrong") in
  let claimed = Batch.Sealed.claim ~batch:v5 ~digest:wrong in
  Alcotest.(check bool) "claim stores the claim unverified" true
    (Digests.Batch_digest.equal (Batch.Sealed.digest claimed) wrong);
  Alcotest.(check bool) "the wrong claim is not silently corrected" false
    (Digests.Batch_digest.equal (Batch.Sealed.digest claimed)
       (Batch.digest v5));
  let b, d = Batch.Sealed.split sealed in
  Alcotest.(check bool) "split returns the batch" true (Batch.equal b v5);
  Alcotest.(check bool) "split returns the digest" true
    (Digests.Batch_digest.equal d (Batch.digest v5));
  Alcotest.(check bool) "seal equals an honest claim" true
    (Batch.Sealed.equal sealed
       (Batch.Sealed.claim ~batch:v5 ~digest:(Batch.digest v5)));
  Alcotest.(check bool) "a wrong claim differs from seal" false
    (Batch.Sealed.equal sealed claimed)

(* T9: the fork-blind bounds and the protocol base-fee floor. *)
let t9 () =
  Alcotest.(check int64) "max_batch_gas epoch 0" 30_000_000L
    (Batch.max_batch_gas Units.Epoch.zero);
  Alcotest.(check int64) "max_batch_gas is fork-blind at epoch 7" 30_000_000L
    (Batch.max_batch_gas (epoch 7));
  Alcotest.(check int) "max_batch_size epoch 0" 1_000_000
    (Batch.max_batch_size Units.Epoch.zero);
  Alcotest.(check int) "max_batch_size is fork-blind at epoch 7" 1_000_000
    (Batch.max_batch_size (epoch 7));
  Alcotest.(check bool) "min_protocol base fee is 7 wei" true
    (Units.Base_fee.equal Units.Base_fee.min_protocol
       (Units.Base_fee.of_int64 7L));
  Alcotest.(check string) "min_protocol prints unsigned" "7"
    (Units.Base_fee.to_string Units.Base_fee.min_protocol)

let () =
  Alcotest.run "batch"
    [
      ( "golden vectors",
        [
          Alcotest.test_case "T1 preimage V1-V7" `Quick t1;
          Alcotest.test_case "T2 received_at excluded (V6 skip-proof)" `Quick
            t2;
          Alcotest.test_case "T3 default = V1" `Quick t3;
          Alcotest.test_case "T4 uleb128 two-byte length" `Quick t4;
          Alcotest.test_case "T5 codec round-trip + exactness" `Quick t5;
        ] );
      ( "semantics",
        [
          Alcotest.test_case "T6 equal includes received_at" `Quick t6;
          Alcotest.test_case "T7 digest = stub hash of domain ^ preimage"
            `Quick t7;
          Alcotest.test_case "T8 Sealed seal/claim/split" `Quick t8;
          Alcotest.test_case "T9 constants" `Quick t9;
        ] );
    ]
