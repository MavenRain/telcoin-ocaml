(* Chunk-34 stage 2: [Tn_batch.Tx_shape] against the divergence exhibits
   (tx_shape_vectors.ml), the oracle-signed fixtures (batch_fixtures.ml) and
   the whole existing signed-tx corpus (tx_vectors.ml + eip7702_vectors.ml),
   tests T10-T18 of the chunk design.

   The boundary under test is TN's: alloy decode_2718_exact then CHECKED
   recovery. Acceptance rows are wire evidence (oracle-encoded bytes);
   rejection rows are the empirically pinned gap-closure exhibits. *)

module Tx_shape = Tn_batch.Tx_shape
module Envelope = Tn_evm.Tx_envelope
module Address = Tn_types.Units.Address
module V = Tx_shape_vectors
module F = Batch_fixtures

let hex = Tx_vectors.hex
let to_hex = Tx_vectors.to_hex

(* ---- result projections (combinators only, no two-arm matches) ---- *)

let accepts input = Tx_shape.decode input |> Result.is_ok

let rejects_failed input =
  Tx_shape.decode input
  |> Result.fold
       ~ok:(fun _t -> false)
       ~error:(fun e ->
         match e with
         | Tx_shape.Failed_to_decode -> true
         | Tx_shape.Empty_input | Tx_shape.Invalid_signature -> false)

let rejects_empty input =
  Tx_shape.decode input
  |> Result.fold
       ~ok:(fun _t -> false)
       ~error:(fun e ->
         match e with
         | Tx_shape.Empty_input -> true
         | Tx_shape.Failed_to_decode | Tx_shape.Invalid_signature -> false)

let hash_hex input =
  Tx_shape.decode input
  |> Result.map (fun t -> Tn_keccak.to_hex (Tx_shape.hash t))
  |> Result.value ~default:"<decode rejected>"

let gas_of input =
  Tx_shape.decode input
  |> Result.map Tx_shape.gas_limit
  |> Result.value ~default:(-1L)

let signer_hex input =
  Tx_shape.decode input
  |> Fun.flip Result.bind Tx_shape.recover_signer
  |> Result.map (fun a -> to_hex (Address.to_bytes a))
  |> Result.value ~default:"<recovery rejected>"

let recovery_invalid input =
  Tx_shape.decode input
  |> Fun.flip Result.bind Tx_shape.recover_signer
  |> Result.fold
       ~ok:(fun _a -> false)
       ~error:(fun e ->
         match e with
         | Tx_shape.Invalid_signature -> true
         | Tx_shape.Empty_input | Tx_shape.Failed_to_decode -> false)

let composed_invalid input =
  Tx_shape.decode_and_recover input
  |> Result.fold
       ~ok:(fun _t -> false)
       ~error:(fun e ->
         match e with
         | Tx_shape.Invalid_signature -> true
         | Tx_shape.Empty_input | Tx_shape.Failed_to_decode -> false)

(* ---- T10: differential vs Tx_envelope over the whole fixture corpus ---- *)

let check_corpus name encoded_hex tx_hash_hex =
  let bytes = hex encoded_hex in
  let envelope = Envelope.decode_2718 bytes in
  let shape = Tx_shape.decode bytes in
  Alcotest.(check bool)
    (name ^ ": acceptance agrees with Tx_envelope")
    (Result.is_ok envelope) (Result.is_ok shape);
  Alcotest.(check bool) (name ^ ": corpus row accepts") true (Result.is_ok shape);
  let envelope_gas =
    Result.map
      (fun e -> Int64.of_int (Tn_evm.Tx_payload.gas_limit (Envelope.payload e)))
      envelope
    |> Result.value ~default:(-1L)
  in
  Alcotest.(check int64) (name ^ ": gas_limit agrees") envelope_gas (gas_of bytes);
  let envelope_hash =
    Result.map (fun e -> to_hex (Envelope.hash e)) envelope
    |> Result.value ~default:"<envelope rejected>"
  in
  Alcotest.(check string) (name ^ ": hash agrees") envelope_hash (hash_hex bytes);
  Alcotest.(check string)
    (name ^ ": hash is the oracle tx hash")
    tx_hash_hex (hash_hex bytes)

let t10 () =
  List.iter
    (fun (c : Tx_vectors.case) -> check_corpus c.name c.encoded_2718 c.tx_hash)
    Tx_vectors.cases;
  check_corpus "eip7702_type4" Eip7702_vectors.type4_encoded_2718_hex
    Eip7702_vectors.type4_tx_hash_hex

(* ---- T11: exhibit 24, the 0x00-tagged legacy form + the list guard ---- *)

let t11 () =
  let tagged = hex V.exhibit24_tagged and untagged = hex V.exhibit24_untagged in
  Alcotest.(check bool) "0x00-tagged legacy accepts" true (accepts tagged);
  Alcotest.(check bool) "untagged twin accepts" true (accepts untagged);
  Alcotest.(check string) "tagged and untagged share one tx hash"
    (hash_hex untagged) (hash_hex tagged);
  Alcotest.(check string) "that hash is keccak of the UNTAGGED bytes"
    (Tn_keccak.to_hex (Tn_keccak.digest untagged))
    (hash_hex tagged);
  Alcotest.(check bool) "0x00 followed by a non-list rejects" true
    (rejects_failed (hex V.exhibit24_zero_nonlist))

(* ---- T12: exhibit 25 stays rejected (agreement with decode_2718_exact) ---- *)

let t12 () =
  Alcotest.(check bool) "the unwrapped typed control accepts" true
    (accepts (hex V.typed_1559_control));
  Alcotest.(check bool) "short outer-string wrap rejects" true
    (rejects_failed (hex V.exhibit25_short));
  Alcotest.(check bool) "long 0xb8 outer-string wrap rejects" true
    (rejects_failed (hex V.exhibit25_long))

(* ---- T13: exhibit 26, the full-u64 nonce ---- *)

let t13 () =
  Alcotest.(check bool) "nonce 2^62 accepts (full u64, no narrowing)" true
    (accepts (hex V.exhibit26_nonce));
  Alcotest.(check bool) "a nine-byte nonce rejects" true
    (rejects_failed (hex V.nonce_nine_bytes))

(* ---- T14: full-u64 gas_limit, with the exact bits observable ---- *)

let t14 () =
  Alcotest.(check bool) "gas_limit 2^62 accepts" true
    (accepts (hex V.gas_two_pow_62));
  Alcotest.(check int64) "the accessor answers the full u64 bits"
    4611686018427387904L
    (gas_of (hex V.gas_two_pow_62))

(* ---- T15: the canonicity battery ---- *)

let t15 () =
  Alcotest.(check bool) "16-byte fee control accepts" true
    (accepts (hex V.fee_sixteen_bytes_control));
  Alcotest.(check bool) "17-byte fee scalar rejects" true
    (rejects_failed (hex V.fee_seventeen_bytes));
  Alcotest.(check bool) "leading-zero scalar rejects" true
    (rejects_failed (hex V.nonce_leading_zero));
  Alcotest.(check bool) "trailing byte rejects" true
    (rejects_failed (hex V.trailing_byte));
  Alcotest.(check bool) "non-canonical single byte rejects" true
    (rejects_failed (hex V.nonce_non_canonical));
  Alcotest.(check bool) "19-byte address rejects" true
    (rejects_failed (hex V.address_nineteen));
  Alcotest.(check bool) "y_parity 0x00 rejects" true
    (rejects_failed (hex V.parity_zero_byte));
  Alcotest.(check bool) "y_parity 0x02 rejects" true
    (rejects_failed (hex V.parity_two));
  Alcotest.(check bool) "legacy v = 0 rejects" true
    (rejects_failed (hex V.legacy_v_zero));
  Alcotest.(check bool) "legacy v = 1 rejects" true
    (rejects_failed (hex V.legacy_v_one));
  Alcotest.(check bool) "legacy v = 29 rejects" true
    (rejects_failed (hex V.legacy_v_twenty_nine));
  Alcotest.(check bool) "empty input is Empty_input, not Failed_to_decode" true
    (rejects_empty "")

(* ---- T16: type-3 decode: structure, classifier, hash ---- *)

let t16 () =
  let crafted = hex V.blob4844 and f6 = hex F.f6_encoded in
  Alcotest.(check bool) "well-formed 14-item type-3 accepts" true
    (accepts crafted);
  Alcotest.(check bool) "crafted type-3 classifies as EIP-4844" true
    (Tx_shape.decode crafted
    |> Result.map Tx_shape.is_eip4844
    |> Result.value ~default:false);
  Alcotest.(check string) "crafted type-3 hash = keccak of the raw bytes"
    (Tn_keccak.to_hex (Tn_keccak.digest crafted))
    (hash_hex crafted);
  Alcotest.(check bool) "oracle-signed F6 accepts" true (accepts f6);
  Alcotest.(check bool) "F6 classifies as EIP-4844" true
    (Tx_shape.decode f6
    |> Result.map Tx_shape.is_eip4844
    |> Result.value ~default:false);
  Alcotest.(check string) "F6 hash is the oracle tx hash" F.f6_tx_hash
    (hash_hex f6);
  Alcotest.(check bool) "a legacy tx does not classify as EIP-4844" false
    (Tx_shape.decode (hex V.exhibit24_untagged)
    |> Result.map Tx_shape.is_eip4844
    |> Result.value ~default:true);
  Alcotest.(check bool) "a 13-item type-3 body rejects" true
    (rejects_failed (hex V.blob4844_thirteen));
  Alcotest.(check bool) "a 15-item type-3 body rejects" true
    (rejects_failed (hex V.blob4844_fifteen))

(* ---- T17: the recovery gate ---- *)

let t17 () =
  let f1 = hex F.f1_encoded in
  Alcotest.(check string) "F1 recovers the oracle-pinned signer" F.signer
    (signer_hex f1);
  (* Agreement with the existing recovery path over the same bytes. *)
  let via_envelope =
    Envelope.decode_2718 f1
    |> Result.fold
         ~ok:(fun e ->
           Tn_evm.Tx_recovery.recover_signer e
           |> Result.map (fun a -> to_hex (Address.to_bytes a))
           |> Result.value ~default:"<envelope recovery rejected>")
         ~error:(fun _e -> "<envelope decode rejected>")
  in
  Alcotest.(check string) "Tx_recovery agrees on F1's signer" F.signer
    via_envelope;
  Alcotest.(check bool) "decode_and_recover passes F1" true
    (Tx_shape.decode_and_recover f1 |> Result.is_ok);
  (* Every minted fixture recovers the one oracle signer: transcription
     insurance for the stage-3 rows as much as a recovery test. *)
  List.iter
    (fun (label, encoded) ->
      Alcotest.(check string)
        (label ^ " recovers the oracle-pinned signer")
        F.signer
        (signer_hex (hex encoded)))
    [
      ("F2", F.f2_encoded);
      ("F3", F.f3_encoded);
      ("F4a", F.f4a_encoded);
      ("F4b", F.f4b_encoded);
      ("F5", F.f5_encoded);
    ];
  (* The high-s twin: decodes, then the strict EIP-2 gate rejects it, on
     both the split and the composed paths (checked recovery, R1 closed). *)
  let f8 = hex F.f8_encoded in
  Alcotest.(check bool) "F8 high-s twin still decodes" true (accepts f8);
  Alcotest.(check bool) "recover_signer rejects F8 as Invalid_signature" true
    (recovery_invalid f8);
  Alcotest.(check bool) "decode_and_recover rejects F8 too" true
    (composed_invalid f8);
  (* r = 0 decodes and is unrecoverable. *)
  let r0 = hex V.r_zero_v27 in
  Alcotest.(check bool) "r = 0 decodes" true (accepts r0);
  Alcotest.(check bool) "r = 0 recovery is Invalid_signature" true
    (recovery_invalid r0)

(* ---- T18: the EIP-4844 signing preimage, pinned through recovery ---- *)

let t18 () =
  let f6 = hex F.f6_encoded in
  Alcotest.(check string)
    "F6 recovers its oracle-pinned signer (pins keccak(0x03 || rlp(11)))"
    F.signer (signer_hex f6);
  Alcotest.(check bool) "decode_and_recover passes F6" true
    (Tx_shape.decode_and_recover f6 |> Result.is_ok)

let () =
  Alcotest.run "tx_shape"
    [
      ( "wire boundary",
        [
          Alcotest.test_case "T10 differential vs Tx_envelope corpus" `Quick t10;
          Alcotest.test_case "T11 exhibit 24 accept + list guard" `Quick t11;
          Alcotest.test_case "T12 exhibit 25 stays rejected" `Quick t12;
          Alcotest.test_case "T13 exhibit 26 nonce full-u64" `Quick t13;
          Alcotest.test_case "T14 gas_limit full-u64" `Quick t14;
          Alcotest.test_case "T15 canonicity battery" `Quick t15;
          Alcotest.test_case "T16 type-3 decode" `Quick t16;
        ] );
      ( "recovery",
        [
          Alcotest.test_case "T17 recovery gate" `Quick t17;
          Alcotest.test_case "T18 4844 signing preimage" `Quick t18;
        ] );
    ]
