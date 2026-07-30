(* Divergence-exhibit byte strings for the chunk-34 [Tn_batch.Tx_shape]
   boundary, shared by the chunk's test executables the way batch_vectors.ml
   is. Not listed in test/dune's (names ...): dune links it into every test
   binary.

   The exhibit rows are verbatim from the chunk-34 ground-truth gap closures
   (telcoin-ocaml-chunk34-ground-truth.md, gaps 4a/4b/4c), which pinned them
   EMPIRICALLY against the vendored pinned crates (alloy-consensus 1.8.3 /
   alloy-eips 1.8.3 / alloy-rlp 0.3.13, the exact telcoin-network @ 5dbb764e
   Cargo.lock versions): the 0x00-tagged legacy form decodes on TN's
   decode_2718_exact path (exhibit 24, re-encoding drops the tag so tagged
   and untagged share one tx hash), the outer-string wrap is REJECTED on that
   path with UnexpectedType(0) (exhibit 25; only the p2p-only network_decode
   accepts it), and full-u64 nonce/gas scalars decode (exhibit 26).

   All signatures in this file are the inert r = s = 1 pair: these rows pin
   DECODE verdicts only, and a recovery-level fixture must be genuinely
   signed (see batch_fixtures.ml). Hand-assembly comments follow the house
   fixture convention; every list header is the 0xc0/0xf7 form over the
   summed item bytes, written beside the row it covers. *)

let zeros_40 = String.make 40 '0'

(* ---- exhibit 24: 0x00-tagged legacy (gap 4a, alloy ACCEPTS) ----

   Legacy list, payload 33 = 0x21 bytes so header 0xe1: nonce 01,
   gas_price 07, gas_limit 82 5208 (21000), to 94 + 20 zero bytes, value 80,
   data 80, v 82 0fe5 (4069: chain 2017, parity 0), r 01, s 01. *)
let exhibit24_untagged =
  "e10107825208" ^ "94" ^ zeros_40 ^ "8080820fe50101"

let exhibit24_tagged = "00" ^ exhibit24_untagged

(* The canonical typed 1559 control (the ground truth's raw2): 02 then a
   12-item list, payload 36 = 0x24 so header 0xe4: chain 82 07e1, nonce 01,
   priority 01, fee 07, gas 82 5208, to 94 + 20 zeros, value 80, data 80,
   access c0, y_parity 80, r 01, s 01. *)
let typed_1559_control =
  "02e48207e1010107825208" ^ "94" ^ zeros_40 ^ "8080c0800101"

(* 0x00 followed by a NON-list (the typed control): alloy's typed_decode(0)
   demands the legacy grammar on the remainder, whose first byte 0x02 is an
   RLP single-byte STRING, so this must reject; the naive strip-and-recurse
   would wrongly accept it. *)
let exhibit24_zero_nonlist = "00" ^ typed_1559_control

(* ---- exhibit 25: outer RLP string wrap (gap 4b, alloy REJECTS) ----

   Short form: the 38-byte typed control wrapped once as an RLP string,
   header 0xa6 = 0x80 + 38. *)
let exhibit25_short = "a6" ^ typed_1559_control

(* Long form: a 104-byte typed 1559 envelope (the 12-item list above with
   64 bytes of 0xaa calldata: payload 101 = 0x65, list header f8 65, plus
   the type byte) wrapped as an RLP long string, header b8 68. *)
let typed_1559_long =
  "02f8658207e1010107825208" ^ "94" ^ zeros_40 ^ "80" ^ "b840"
  ^ String.concat "" (List.init 64 (fun _i -> "aa"))
  ^ "c0800101"

let exhibit25_long = "b868" ^ typed_1559_long

(* ---- exhibit 26: full-u64 nonce and gas_limit (gap 4c) ----

   Legacy with nonce 88 4000000000000000 (= 2^62, eight bytes): payload
   41 = 0x29 so header 0xe9. TN decodes the full u64 and batch validation
   never reads the nonce. *)
let exhibit26_nonce =
  "e9" ^ "884000000000000000" ^ "07825208" ^ "94" ^ zeros_40
  ^ "8080820fe50101"

(* A NINE-byte nonce 89 400000000000000000 must reject (u64 overflow):
   payload 42 = 0x2a so header 0xea. *)
let nonce_nine_bytes =
  "ea" ^ "89400000000000000000" ^ "07825208" ^ "94" ^ zeros_40
  ^ "8080820fe50101"

(* gas_limit 88 4000000000000000 (= 2^62) in an otherwise minimal legacy:
   payload 39 = 0x27 so header 0xe7. The accessor must answer the full u64
   bits, 4611686018427387904L. *)
let gas_two_pow_62 =
  "e7" ^ "0107" ^ "884000000000000000" ^ "94" ^ zeros_40
  ^ "8080820fe50101"

(* ---- the T15 canonicity battery (every row rejects; the controls accept) ---- *)

(* A 17-byte max_fee scalar (91 then 01 + 16 zero bytes) in the 1559 body:
   payload 53 = 0x35 so header 0xf5. alloy: u128 Overflow. *)
let fee_seventeen_bytes =
  "02f58207e10101" ^ "9101" ^ String.make 32 '0' ^ "825208" ^ "94" ^ zeros_40
  ^ "8080c0800101"

(* Its 16-byte control (90 then 01 + 15 zero bytes), payload 52 = 0x34. *)
let fee_sixteen_bytes_control =
  "02f48207e10101" ^ "9001" ^ String.make 30 '0' ^ "825208" ^ "94" ^ zeros_40
  ^ "8080c0800101"

(* A leading-zero nonce scalar 82 0001: payload 35 = 0x23 so header 0xe3. *)
let nonce_leading_zero =
  "e3" ^ "820001" ^ "07825208" ^ "94" ^ zeros_40 ^ "8080820fe50101"

(* One trailing byte after a valid envelope (decode_2718_exact rejects). *)
let trailing_byte = exhibit24_untagged ^ "00"

(* A non-canonical single byte 81 01 in the nonce slot (it had to be the
   bare 01): payload 34 = 0x22 so header 0xe2. *)
let nonce_non_canonical =
  "e2" ^ "8101" ^ "07825208" ^ "94" ^ zeros_40 ^ "8080820fe50101"

(* A 19-byte [to] (93 then 19 zero bytes): payload 32 = 0x20 so header
   0xe0. TxKind demands empty or exactly 20. *)
let address_nineteen =
  "e0" ^ "0107825208" ^ "93" ^ String.make 38 '0' ^ "8080820fe50101"

(* Typed y_parity written 00 (leading zero) and 02 (not a bool): the typed
   control with its parity item replaced. *)
let parity_zero_byte =
  "02e48207e1010107825208" ^ "94" ^ zeros_40 ^ "8080c0" ^ "00" ^ "0101"

let parity_two =
  "02e48207e1010107825208" ^ "94" ^ zeros_40 ^ "8080c0" ^ "02" ^ "0101"

(* Legacy v in {0, 1, 29}: none is 27/28 or an EIP-155 fold, so all three
   reject (Custom("invalid parity value")). Payload 31 = 0x1f so header
   0xdf; v items 80 (zero), 01, 1d. *)
let legacy_v_zero =
  "df" ^ "0107825208" ^ "94" ^ zeros_40 ^ "8080" ^ "80" ^ "0101"

let legacy_v_one =
  "df" ^ "0107825208" ^ "94" ^ zeros_40 ^ "8080" ^ "01" ^ "0101"

let legacy_v_twenty_nine =
  "df" ^ "0107825208" ^ "94" ^ zeros_40 ^ "8080" ^ "1d" ^ "0101"

(* A structurally valid pre-155 legacy (v = 1b = 27) whose r is the scalar
   ZERO (80): decodes, and recovery must answer Invalid_signature (the curve
   rejects r = 0). Payload 31 = 0x1f so header 0xdf. *)
let r_zero_v27 =
  "df" ^ "0107825208" ^ "94" ^ zeros_40 ^ "8080" ^ "1b" ^ "80" ^ "01"

(* ---- crafted type-3 (EIP-4844) shape rows, decode-level ----

   Well-formed 14-item signed body, payload 71 = 0x47 so header f8 47:
   chain 82 07e1, nonce 01, priority 01, fee 07, gas 82 5208, to 94 + 20
   zeros, value 80, data 80, access c0, max_fee_per_blob_gas 01,
   blob_versioned_hashes e1 a0 + 32 bytes of 0x11 (one hash), y_parity 80,
   r 01, s 01. *)
let blob_hash_32 = String.concat "" (List.init 32 (fun _i -> "11"))

let blob4844 =
  "03f8478207e1010107825208" ^ "94" ^ zeros_40 ^ "8080c001" ^ "e1a0"
  ^ blob_hash_32 ^ "800101"

(* Thirteen items: max_fee_per_blob_gas dropped, payload 70 = 0x46. *)
let blob4844_thirteen =
  "03f8468207e1010107825208" ^ "94" ^ zeros_40 ^ "8080c0" ^ "e1a0"
  ^ blob_hash_32 ^ "800101"

(* Fifteen items: one trailing extra scalar, payload 72 = 0x48. *)
let blob4844_fifteen =
  "03f8488207e1010107825208" ^ "94" ^ zeros_40 ^ "8080c001" ^ "e1a0"
  ^ blob_hash_32 ^ "80010101"
