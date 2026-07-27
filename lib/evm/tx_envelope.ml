(* The signed transaction envelope: signing pre-image, EIP-2718 consensus bytes,
   transaction hash and the strict decoder. A port of alloy-consensus 1.8.3
   [src/transaction/rlp.rs:24-113] with the legacy overrides at
   [src/transaction/legacy.rs:113-235], and alloy-eips 1.8.3
   [src/eip2718.rs:84-151] for the routing.

   The signature tail is [v], then [r], then [s], in the SAME list as the body
   fields (alloy-primitives 1.5.7 [src/signature/sig.rs:358-370]); the list
   header covers body and signature together, which [Rlp.encode_list] computes
   from the concatenated chunks. Legacy carries no type byte and no outer
   header; typed prepends exactly one raw byte, via the shared
   {!Eip2718.frame}. *)

module W = Tn_state.U256
module Rlp = Tn_rlp.Rlp
module Address = Tn_types.Units.Address

type t = { payload : Tx_payload.t; signature : Tx_signature.t }

let make ~payload ~signature = { payload; signature }
let payload t = t.payload
let signature t = t.signature

(* ------------------------------------------------------------------ *)
(* Field encoders                                                      *)
(* ------------------------------------------------------------------ *)

(* Numbers are SCALARS: leading zeros stripped, zero as [0x80]. This is [r] and
   [s] too — a signature whose [r] is below [2^248] makes a shorter envelope and
   a different hash, and the fixed 32-byte layout exists only in the recovery
   input, never on the wire. *)
let enc_word w = Rlp.encode_scalar (W.to_be_bytes w)
let enc_nonce n = Rlp.encode_nat (Tn_state.Nonce.to_int n)

(* [TxKind] (alloy-primitives [src/common.rs:84-99]): the field is ALWAYS
   present, a creation writes an empty string, and the zero address writes
   [0x94] then twenty zero bytes rather than [0x80]. *)
let enc_kind kind =
  match kind with
  | Transaction.Call addr -> Rlp.encode_bytes (Address.to_bytes addr)
  | Transaction.Create -> Rlp.encode_bytes ""

(* One list, no extra nesting (the [RlpEncodableWrapper] derive is a pure
   delegate, alloy-eip2930 0.2.3 [src/lib.rs:15-25,36-40]); addresses and keys
   are FIXED width with zeros preserved; no sort and no dedup, because alloy
   iterates verbatim and canonicalising would change the transaction hash. *)
let enc_access_list access_list =
  List.map
    (fun (addr, keys) ->
      Rlp.encode_list
        [
          Rlp.encode_bytes (Address.to_bytes addr);
          Rlp.encode_list (List.map (fun key -> Rlp.encode_bytes (W.to_be_bytes key)) keys);
        ])
    access_list
  |> Rlp.encode_list

(* The four fields every layout shares, in their common wire position:
   gas_limit, to, value, input. *)
let common_chunks p =
  [
    Rlp.encode_nat (Tx_payload.gas_limit p);
    enc_kind (Tx_payload.kind p);
    enc_word (Tx_payload.value p);
    Rlp.encode_bytes (Tx_payload.data p);
  ]

(* The body fields, in wire order: 6 for legacy, 8 for type 1, 9 for type 2.
   Note that type 2 writes the TIP cap before the FEE cap. *)
let body_chunks p =
  match Tx_payload.variant p with
  | Tx_payload.Legacy { gas_price; chain_id = _ } ->
      (enc_nonce (Tx_payload.nonce p) :: enc_word gas_price :: common_chunks p)
  | Tx_payload.Eip2930 { chain_id; gas_price } ->
      (enc_word chain_id :: enc_nonce (Tx_payload.nonce p) :: enc_word gas_price
       :: common_chunks p)
      @ [ enc_access_list (Tx_payload.access_list p) ]
  | Tx_payload.Eip1559 { chain_id; max_priority_fee_per_gas; max_fee_per_gas } ->
      (enc_word chain_id :: enc_nonce (Tx_payload.nonce p)
      :: enc_word max_priority_fee_per_gas :: enc_word max_fee_per_gas :: common_chunks p)
      @ [ enc_access_list (Tx_payload.access_list p) ]

(* ------------------------------------------------------------------ *)
(* Signing payload and consensus envelope                              *)
(* ------------------------------------------------------------------ *)

(* The EIP-155 tail is [chain_id, 0x80, 0x80] and is OMITTED ENTIRELY without a
   chain id ([legacy.rs:85-107,328-343]). The two trailing items are the NUMBER
   zero — [Rlp.encode_nat 0] is [0x80] — and writing literal [0x00] bytes would
   change the digest and therefore every recovered address. *)
let signing_tail p =
  match Tx_payload.variant p with
  | Tx_payload.Legacy { chain_id; gas_price = _ } ->
      Option.fold ~none:[]
        ~some:(fun id -> [ enc_word id; Rlp.encode_nat 0; Rlp.encode_nat 0 ])
        chain_id
  | Tx_payload.Eip2930 _ | Tx_payload.Eip1559 _ -> []

let signing_payload p =
  Eip2718.frame ~type_byte:(Tx_payload.type_byte p)
    (Rlp.encode_list (body_chunks p @ signing_tail p))

let signature_hash p = Tn_keccak.to_bytes (Tn_keccak.digest (signing_payload p))

(* Legacy writes the EIP-155 [v]; typed writes the raw y-parity as an RLP BOOL,
   which is [0x01] for true and [0x80] for false — never [0x00], which alloy
   would reject as a leading zero. [Rlp.encode_nat] gives exactly that, and it
   is the same trick {!Receipt_envelope} uses for the EIP-658 status. *)
let signature_tail p sg =
  let scalars = [ enc_word (Tx_signature.r sg); enc_word (Tx_signature.s sg) ] in
  match Tx_payload.variant p with
  | Tx_payload.Legacy { chain_id; gas_price = _ } ->
      enc_word (Tx_signature.to_eip155_value ~parity:(Tx_signature.parity sg) ~chain_id)
      :: scalars
  | Tx_payload.Eip2930 _ | Tx_payload.Eip1559 _ ->
      Rlp.encode_nat (if Tx_signature.parity sg then 1 else 0) :: scalars

let encode_2718 t =
  Eip2718.frame ~type_byte:(Tx_payload.type_byte t.payload)
    (Rlp.encode_list (body_chunks t.payload @ signature_tail t.payload t.signature))

let hash_of_2718 bytes = Tn_keccak.to_bytes (Tn_keccak.digest bytes)
let hash t = hash_of_2718 (encode_2718 t)

(* ------------------------------------------------------------------ *)
(* Decoding                                                            *)
(* ------------------------------------------------------------------ *)

type error =
  | Rlp of Tn_rlp.Rlp.error
  | Empty_input
  | Zero_type_byte
  | Unknown_type_byte of int
  | Outer_string
  | Unexpected_string
  | Unexpected_list
  | Field_count of { expected : int; got : int }
  | Leading_zero_scalar
  | Scalar_too_wide
  | Unrepresentable_scalar
  | Fixed_width of { expected : int; got : int }
  | Invalid_bool
  | Invalid_parity_value

let error_to_string e =
  match e with
  | Rlp err -> "rlp: " ^ Tn_rlp.Rlp.error_to_string err
  | Empty_input -> "empty input"
  | Zero_type_byte -> "0x00-tagged legacy envelope (non-canonical framing)"
  | Unknown_type_byte b -> Printf.sprintf "unknown transaction type byte 0x%02x" b
  | Outer_string -> "envelope is an RLP string, not a list (non-canonical framing)"
  | Unexpected_string -> "byte string where a list was required"
  | Unexpected_list -> "list where a byte string was required"
  | Field_count { expected; got } -> Printf.sprintf "expected %d fields, got %d" expected got
  | Leading_zero_scalar -> "integer field with a leading zero byte"
  | Scalar_too_wide -> "integer field wider than its type"
  | Unrepresentable_scalar -> "u64 field above the native int range"
  | Fixed_width { expected; got } ->
      Printf.sprintf "expected a %d-byte string, got %d bytes" expected got
  | Invalid_bool -> "y_parity is neither 0x80 nor 0x01"
  | Invalid_parity_value -> "invalid legacy v (parity value)"

let ( let* ) = Result.bind

(* Result-aware map: the first failure wins and the rest is not evaluated. No
   loop keyword, no mutation. *)
let traverse f xs =
  List.fold_left
    (fun acc x -> Result.bind acc (fun ys -> Result.map (fun y -> y :: ys) (f x)))
    (Ok []) xs
  |> Result.map List.rev

(* Read one item off the front of a decoded list. Both list constructors are
   named, so neither arm is a wildcard; [short] is the error an exhausted list
   reports, sized by the caller from the arity it expected. *)
let take short reader items =
  match items with
  | [] -> Error short
  | item :: rest -> Result.map (fun v -> (v, rest)) (reader item)

(* The list must be exhausted: a longer list is the same [Field_count] a shorter
   one raises, which is also how alloy detects both (a consumed-bytes comparison
   against the header's declared payload). *)
let finish short items = match items with [] -> Ok () | _ :: _ -> Error short

(* An integer field: an RLP scalar of at most [max_bytes] bytes with no leading
   zero. [max_bytes] is 8 for a chain id, nonce or gas limit, 16 for a gas price,
   a fee cap or a legacy [v], and 32 for a value or for [r]/[s] — alloy's [u64],
   [u128] and [U256] respectively. *)
let read_word ~max_bytes item =
  match item with
  | Tn_rlp.Rlp.List _ -> Error Unexpected_list
  | Tn_rlp.Rlp.Str s ->
      if String.length s > max_bytes then Error Scalar_too_wide
      else if String.length s > 0 && Char.equal s.[0] '\000' then Error Leading_zero_scalar
      else
        (* [max_bytes] never exceeds 32, so the left-padded string is exactly the
           width [of_be_bytes] accepts and the default is unreachable. *)
        Ok
          (Option.value ~default:W.zero
             (W.of_be_bytes (String.make (32 - String.length s) '\000' ^ s)))

(* A [u64] field as a native [int]. The port's one value narrowing: OCaml's
   [int] is 63 bits, so the top quarter of the [u64] range is rejected rather
   than truncated. *)
let read_int item =
  let* w = read_word ~max_bytes:8 item in
  Option.fold ~none:(Error Unrepresentable_scalar) ~some:Result.ok (W.to_int w)

let read_nonce item =
  let* i = read_int item in
  (* [read_int] yields a non-negative [int], which is exactly what [of_int]
     accepts, so the default is unreachable. *)
  Ok (Option.value ~default:Tn_state.Nonce.zero (Tn_state.Nonce.of_int i))

(* The typed y_parity is an RLP BOOL: [0x80] is false and [0x01] is true. A
   literal [0x00] is caught one step earlier by the leading-zero rule, which is
   exactly where alloy catches it ([alloy-rlp/src/decode.rs:48-57] over
   [decode.rs:214-233]). *)
let read_parity item =
  let* w = read_word ~max_bytes:1 item in
  if W.is_zero w then Ok false
  else if W.equal w W.one then Ok true
  else Error Invalid_bool

let read_bytes item =
  match item with
  | Tn_rlp.Rlp.Str s -> Ok s
  | Tn_rlp.Rlp.List _ -> Error Unexpected_list

let read_fixed n item =
  let* s = read_bytes item in
  if String.length s = n then Ok s
  else Error (Fixed_width { expected = n; got = String.length s })

(* [TxKind] decode (alloy-primitives [src/common.rs:101-116]): an empty string is
   a creation, anything else must be exactly an address. *)
let read_kind item =
  let* s = read_bytes item in
  if String.length s = 0 then Ok Transaction.Create
  else if String.length s = Address.length then
    (* Exactly [Address.length] bytes, the width [of_bytes] accepts, so the
       default is unreachable. *)
    Ok (Transaction.Call (Option.value ~default:Address.zero (Address.of_bytes s)))
  else Error (Fixed_width { expected = Address.length; got = String.length s })

(* A storage key is a FIXED 32-byte string with zeros preserved, not a scalar. *)
let read_key item =
  let* s = read_fixed 32 item in
  (* Exactly 32 bytes by the check above, so the default is unreachable. *)
  Ok (Option.value ~default:W.zero (W.of_be_bytes s))

let read_keys item =
  match item with
  | Tn_rlp.Rlp.Str _ -> Error Unexpected_string
  | Tn_rlp.Rlp.List keys -> traverse read_key keys

let read_access_item item =
  match item with
  | Tn_rlp.Rlp.Str _ -> Error Unexpected_string
  | Tn_rlp.Rlp.List fields ->
      let short = Field_count { expected = 2; got = List.length fields } in
      let* addr, fields = take short (read_fixed Address.length) fields in
      let* keys, fields = take short read_keys fields in
      let* () = finish short fields in
      (* Exactly [Address.length] bytes by [read_fixed], so unreachable. *)
      Ok (Option.value ~default:Address.zero (Address.of_bytes addr), keys)

let read_access_list item =
  match item with
  | Tn_rlp.Rlp.Str _ -> Error Unexpected_string
  | Tn_rlp.Rlp.List items -> traverse read_access_item items

(* --- the three per-type readers, positional and wildcard-free --- *)

let read_legacy items =
  let short = Field_count { expected = 9; got = List.length items } in
  let* nonce, items = take short read_nonce items in
  let* gas_price, items = take short (read_word ~max_bytes:16) items in
  let* gas_limit, items = take short read_int items in
  let* kind, items = take short read_kind items in
  let* value, items = take short (read_word ~max_bytes:32) items in
  let* data, items = take short read_bytes items in
  let* v, items = take short (read_word ~max_bytes:16) items in
  let* r, items = take short (read_word ~max_bytes:32) items in
  let* s, items = take short (read_word ~max_bytes:32) items in
  let* () = finish short items in
  (* The chain id is not a field: it is folded into [v], and recovering it is
     the one place a legacy envelope can fail after its structure is sound. *)
  let* parity, chain_id =
    Option.fold ~none:(Error Invalid_parity_value) ~some:Result.ok
      (Tx_signature.of_eip155_value v)
  in
  Ok
    (make
       ~payload:(Tx_payload.legacy ~nonce ~gas_price ~gas_limit ~kind ~value ~data ~chain_id)
       ~signature:(Tx_signature.make ~parity ~r ~s))

let read_eip2930 items =
  let short = Field_count { expected = 11; got = List.length items } in
  let* chain_id, items = take short (read_word ~max_bytes:8) items in
  let* nonce, items = take short read_nonce items in
  let* gas_price, items = take short (read_word ~max_bytes:16) items in
  let* gas_limit, items = take short read_int items in
  let* kind, items = take short read_kind items in
  let* value, items = take short (read_word ~max_bytes:32) items in
  let* data, items = take short read_bytes items in
  let* access_list, items = take short read_access_list items in
  let* parity, items = take short read_parity items in
  let* r, items = take short (read_word ~max_bytes:32) items in
  let* s, items = take short (read_word ~max_bytes:32) items in
  let* () = finish short items in
  Ok
    (make
       ~payload:
         (Tx_payload.eip2930 ~chain_id ~nonce ~gas_price ~gas_limit ~kind ~value ~data
            ~access_list)
       ~signature:(Tx_signature.make ~parity ~r ~s))

let read_eip1559 items =
  let short = Field_count { expected = 12; got = List.length items } in
  let* chain_id, items = take short (read_word ~max_bytes:8) items in
  let* nonce, items = take short read_nonce items in
  let* max_priority_fee_per_gas, items = take short (read_word ~max_bytes:16) items in
  let* max_fee_per_gas, items = take short (read_word ~max_bytes:16) items in
  let* gas_limit, items = take short read_int items in
  let* kind, items = take short read_kind items in
  let* value, items = take short (read_word ~max_bytes:32) items in
  let* data, items = take short read_bytes items in
  let* access_list, items = take short read_access_list items in
  let* parity, items = take short read_parity items in
  let* r, items = take short (read_word ~max_bytes:32) items in
  let* s, items = take short (read_word ~max_bytes:32) items in
  let* () = finish short items in
  Ok
    (make
       ~payload:
         (Tx_payload.eip1559 ~chain_id ~nonce ~max_priority_fee_per_gas ~max_fee_per_gas
            ~gas_limit ~kind ~value ~data ~access_list)
       ~signature:(Tx_signature.make ~parity ~r ~s))

(* The envelope must be a LIST. A string here is the [0xb8 || len || list]
   framing alloy accepts through its unrestored-cursor fallback and this port
   refuses; see the interface. *)
let decode_body bytes reader =
  let* item = Result.map_error (fun e -> Rlp e) (Tn_rlp.Rlp.decode_exact bytes) in
  match item with
  | Tn_rlp.Rlp.Str _ -> Error Outer_string
  | Tn_rlp.Rlp.List items -> reader items

(* Routing, alloy-eips [src/eip2718.rs:84-125]: a leading byte at or below [0x7f]
   is a type flag and is stripped; anything else is the untagged legacy form.
   The dispatch is on an [int], written as a chain of equalities so that no arm
   is a wildcard. *)
let decode_2718 input =
  if String.length input = 0 then Error Empty_input
  else
    let b = Char.code input.[0] in
    if b > 0x7f then decode_body input read_legacy
    else
      let rest = String.sub input 1 (String.length input - 1) in
      if b = 0 then Error Zero_type_byte
      else if b = 1 then decode_body rest read_eip2930
      else if b = 2 then decode_body rest read_eip1559
      else Error (Unknown_type_byte b)
