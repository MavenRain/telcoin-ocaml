(* The TN-mirror batch-transaction decoder. Field grammars transcribed from
   the vendored pinned sources (telcoin-network @ 5dbb764e Cargo.lock):

   - dispatch: alloy-eips-1.8.3/src/eip2718.rs:87-89,118-125 (a first byte
     at or below TX_TYPE_BYTE_MAX = 0x7f is consumed as a type flag;
     eip2718.rs:12), exactness at eip2718.rs:144-151;
   - typed bodies must be RLP lists:
     alloy-consensus-1.8.3/src/transaction/rlp.rs:150-154, with the
     consumed-length check at rlp.rs:160-165 (ListLengthMismatch);
   - legacy fields: alloy-consensus-1.8.3/src/transaction/legacy.rs:180-235
     (the v/chain-id fold at legacy.rs:199-234, Custom("invalid parity
     value") at 406-422);
   - eip2930 fields: alloy-consensus-1.8.3/src/transaction/eip2930.rs:109-125;
   - eip1559 fields: alloy-consensus-1.8.3/src/transaction/eip1559.rs:142-158;
   - eip7702 fields: alloy-consensus-1.8.3/src/transaction/eip7702.rs:129-144,
     authorization item shape per alloy-eip7702 auth_list.rs (chain_id U256,
     nonce u64, y_parity a one-byte scalar);
   - eip4844 fields: alloy-consensus-1.8.3/src/transaction/eip4844.rs:889-907
     (chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit,
     to, value, input, access_list, max_fee_per_blob_gas,
     blob_versioned_hashes), signing preimage 0x03 || rlp(those 11) per
     eip4844.rs:909-917 (encode_for_signing);
   - scalar canonicity: alloy-rlp-0.3.13/src/decode.rs:67-79,208-233 (any
     leading 0x00 is LeadingZero, wider than the type is Overflow).

   Every failure collapses into one arm because reth does exactly that:
   recover_raw_transaction's map_err discards the alloy error
   (reth d6324d63 rpc-eth-types/src/utils.rs:41). *)

module Rlp = Tn_rlp.Rlp
module Address = Tn_types.Units.Address

type error = Empty_input | Failed_to_decode | Invalid_signature

let error_to_string e =
  match e with
  | Empty_input -> "empty raw transaction data"
  | Failed_to_decode -> "failed to decode signed transaction"
  | Invalid_signature -> "invalid transaction signature"

let ( let* ) = Result.bind

(* The five decodable type classes; the constructor IS the canonical type
   byte (alloy TxType), so [type_prefix] below is the one place the mapping
   is written. *)
type kind = Legacy | Eip2930 | Eip1559 | Eip4844 | Eip7702

(* Legacy signing evidence recovered from [v] (legacy.rs:406-422): pre-155
   [v] is 27/28 and the signing list has six items; EIP-155 [v] folds a chain
   id and the signing list appends [chain_id, 0, 0]. Typed transactions carry
   the parity directly. *)
type chain = Pre155 | Eip155 of string | Typed

type t = {
  kind : kind;
  fields : Rlp.item list;
      (* the full signed list, exactly as decoded; canonical decode makes
         re-encoding it byte-identical to the (untagged) wire form *)
  gas_limit : int64; (* full u64 as raw bits *)
  chain : chain;
  parity : int; (* 0 or 1 *)
  r : string; (* minimal big-endian scalar bytes, at most 32 *)
  s : string; (* minimal big-endian scalar bytes, at most 32 *)
}

(* ---- total byte-string helpers (no indexing, no partial accessors) ---- *)

(* First byte (as an int) and the remainder, or [None] on the empty string. *)
let uncons str =
  Seq.uncons (String.to_seq str)
  |> Option.map (fun (c, rest) -> (Char.code c, String.of_seq rest))

let leading_zero str =
  Seq.uncons (String.to_seq str)
  |> Option.fold ~none:false ~some:(fun (c, _) -> Char.equal c '\x00')

(* Big-endian bytes (at most 8 of them) as raw u64 bits. *)
let int64_of_be str =
  String.fold_left
    (fun acc c -> Int64.add (Int64.shift_left acc 8) (Int64.of_int (Char.code c)))
    0L str

(* Big-endian bytes as an unbounded integer, for the legacy [v] fold. *)
let z_of_be str =
  String.fold_left
    (fun acc c -> Z.add (Z.mul acc (Z.of_int 256)) (Z.of_int (Char.code c)))
    Z.zero str

(* Minimal big-endian bytes of a non-negative [Z.t]: [Z.to_bits] is
   little-endian with possible trailing zeros, so reverse and strip. Zero is
   the empty string, which is exactly the RLP scalar-zero payload. *)
let minimal_be_of_z z =
  Z.to_bits z |> String.to_seq |> List.of_seq |> List.rev
  |> List.fold_left
       (fun acc c ->
         match acc with
         | [] -> if Char.equal c '\x00' then [] else [ c ]
         | _ :: _ -> c :: acc)
       []
  |> List.rev |> List.to_seq |> String.of_seq

(* [Int.max 0] keeps [String.make] total; every caller already bounds the
   input at 32 bytes via [read_scalar ~max:32]. *)
let pad32 str = String.make (Int.max 0 (32 - String.length str)) '\x00' ^ str
let u64_max = Z.sub (Z.shift_left Z.one 64) Z.one

(* ---- item readers: alloy's typed layer over the structural [Rlp] tree ---- *)

(* An integer field: a byte string of at most [max] bytes with no leading
   zero (decode.rs:208-233). The validated minimal bytes are the value. *)
let read_scalar ~max item =
  match item with
  | Rlp.List _ -> Error Failed_to_decode
  | Rlp.Str str ->
      if String.length str > max || leading_zero str then Error Failed_to_decode
      else Ok str

(* A fixed-width byte string: leading zeros preserved, exact length demanded
   (decode.rs:59-65). *)
let read_fixed n item =
  match item with
  | Rlp.List _ -> Error Failed_to_decode
  | Rlp.Str str -> if String.length str = n then Ok str else Error Failed_to_decode

(* Calldata: any byte string. *)
let read_bytes item =
  match item with Rlp.List _ -> Error Failed_to_decode | Rlp.Str str -> Ok str

(* [TxKind]: an empty string (create) or exactly an address
   (alloy-primitives src/common.rs:101-116). *)
let read_kind item =
  match item with
  | Rlp.List _ -> Error Failed_to_decode
  | Rlp.Str str ->
      if String.length str = 0 || String.length str = Address.length then Ok ()
      else Error Failed_to_decode

(* The typed y_parity is the RLP bool: empty payload is false, [0x01] is
   true; a literal [0x00] payload and everything else reject
   (decode.rs:48-57 behind the leading-zero rule). *)
let read_parity item =
  match item with
  | Rlp.List _ -> Error Failed_to_decode
  | Rlp.Str "" -> Ok 0
  | Rlp.Str "\x01" -> Ok 1
  | Rlp.Str _ -> Error Failed_to_decode

(* Result-aware iteration: first failure wins, values are discarded (this
   decoder validates shape; the observables are extracted by the callers). *)
let check_all reader items =
  List.fold_left
    (fun acc item -> Result.bind acc (fun () -> Result.map (fun _ -> ()) (reader item)))
    (Ok ()) items

(* An access-list entry: [address, [storage_key, ...]], the address 20 bytes
   fixed and every key 32 bytes fixed. *)
let read_keys item =
  match item with
  | Rlp.Str _ -> Error Failed_to_decode
  | Rlp.List keys -> check_all (read_fixed 32) keys

let read_access_entry item =
  match item with
  | Rlp.Str _ -> Error Failed_to_decode
  | Rlp.List [ addr; keys ] ->
      let* _ = read_fixed Address.length addr in
      read_keys keys
  | Rlp.List _ -> Error Failed_to_decode

let read_access_list item =
  match item with
  | Rlp.Str _ -> Error Failed_to_decode
  | Rlp.List entries -> check_all read_access_entry entries

(* One signed authorization: a six-item list whose widths belong to the
   AUTHORIZATION layer (auth_list.rs): chain_id a full U256 (32), nonce u64
   (8), y_parity a ONE-BYTE SCALAR (a parity of 2 decodes and only no-ops at
   authority recovery), r/s 32. *)
let read_authorization item =
  match item with
  | Rlp.Str _ -> Error Failed_to_decode
  | Rlp.List [ auth_chain; auth_addr; auth_nonce; auth_parity; auth_r; auth_s ] ->
      let* _ = read_scalar ~max:32 auth_chain in
      let* _ = read_fixed Address.length auth_addr in
      let* _ = read_scalar ~max:8 auth_nonce in
      let* _ = read_scalar ~max:1 auth_parity in
      let* _ = read_scalar ~max:32 auth_r in
      let* _ = read_scalar ~max:32 auth_s in
      Ok ()
  | Rlp.List _ -> Error Failed_to_decode

let read_authorization_list item =
  match item with
  | Rlp.Str _ -> Error Failed_to_decode
  | Rlp.List auths -> check_all read_authorization auths

(* EIP-4844 blob versioned hashes: a list of fixed 32-byte strings; an empty
   list DECODES (its rejection is validation's, not the decoder's). *)
let read_blob_hashes item =
  match item with
  | Rlp.Str _ -> Error Failed_to_decode
  | Rlp.List hashes -> check_all (read_fixed 32) hashes

(* ---- the five signed-list readers, positional and wildcard-free ---- *)

(* Legacy: nine items (legacy.rs:180-234). The nonce and gas_limit are FULL
   u64 scalars held as wire bytes: this is where the exhibit-26 class (values
   in [2^62, 2^64)) is accepted, with no native-int narrowing. [v] is a u128
   scalar folded into parity + chain id: 27/28 pre-155, at-least-35 EIP-155
   with (v - 35) / 2 at most u64::MAX, everything else Custom("invalid
   parity value") (legacy.rs:406-422). *)
let read_legacy_signed items =
  match items with
  | [ nonce; gas_price; gas_limit; to_; value; data; v; r; s ] ->
      let* _ = read_scalar ~max:8 nonce in
      let* _ = read_scalar ~max:16 gas_price in
      let* gas_bytes = read_scalar ~max:8 gas_limit in
      let* () = read_kind to_ in
      let* _ = read_scalar ~max:32 value in
      let* _ = read_bytes data in
      let* v_bytes = read_scalar ~max:16 v in
      let* r_bytes = read_scalar ~max:32 r in
      let* s_bytes = read_scalar ~max:32 s in
      let vz = z_of_be v_bytes in
      let* parity, chain =
        if Z.equal vz (Z.of_int 27) then Ok (0, Pre155)
        else if Z.equal vz (Z.of_int 28) then Ok (1, Pre155)
        else if Z.geq vz (Z.of_int 35) then
          let shifted = Z.sub vz (Z.of_int 35) in
          let chain_id = Z.div shifted (Z.of_int 2) in
          if Z.gt chain_id u64_max then Error Failed_to_decode
          else
            Ok
              ( (if Z.is_odd shifted then 1 else 0),
                Eip155 (minimal_be_of_z chain_id) )
        else Error Failed_to_decode
      in
      Ok
        {
          kind = Legacy;
          fields = items;
          gas_limit = int64_of_be gas_bytes;
          chain;
          parity;
          r = r_bytes;
          s = s_bytes;
        }
  | [] | _ :: _ -> Error Failed_to_decode

(* EIP-2930: eleven items (eip2930.rs:109-125 plus the signature tail). *)
let read_eip2930_signed items =
  match items with
  | [ chain_id; nonce; gas_price; gas_limit; to_; value; data; access; y_parity; r; s ]
    ->
      let* _ = read_scalar ~max:8 chain_id in
      let* _ = read_scalar ~max:8 nonce in
      let* _ = read_scalar ~max:16 gas_price in
      let* gas_bytes = read_scalar ~max:8 gas_limit in
      let* () = read_kind to_ in
      let* _ = read_scalar ~max:32 value in
      let* _ = read_bytes data in
      let* () = read_access_list access in
      let* parity = read_parity y_parity in
      let* r_bytes = read_scalar ~max:32 r in
      let* s_bytes = read_scalar ~max:32 s in
      Ok
        {
          kind = Eip2930;
          fields = items;
          gas_limit = int64_of_be gas_bytes;
          chain = Typed;
          parity;
          r = r_bytes;
          s = s_bytes;
        }
  | [] | _ :: _ -> Error Failed_to_decode

(* EIP-1559: twelve items (eip1559.rs:142-158 plus the signature tail). *)
let read_eip1559_signed items =
  match items with
  | [
   chain_id; nonce; priority; fee; gas_limit; to_; value; data; access; y_parity; r; s;
  ] ->
      let* _ = read_scalar ~max:8 chain_id in
      let* _ = read_scalar ~max:8 nonce in
      let* _ = read_scalar ~max:16 priority in
      let* _ = read_scalar ~max:16 fee in
      let* gas_bytes = read_scalar ~max:8 gas_limit in
      let* () = read_kind to_ in
      let* _ = read_scalar ~max:32 value in
      let* _ = read_bytes data in
      let* () = read_access_list access in
      let* parity = read_parity y_parity in
      let* r_bytes = read_scalar ~max:32 r in
      let* s_bytes = read_scalar ~max:32 s in
      Ok
        {
          kind = Eip1559;
          fields = items;
          gas_limit = int64_of_be gas_bytes;
          chain = Typed;
          parity;
          r = r_bytes;
          s = s_bytes;
        }
  | [] | _ :: _ -> Error Failed_to_decode

(* EIP-7702: thirteen items (eip7702.rs:129-144 plus the signature tail).
   [to] is a bare 20-byte address, never a create. *)
let read_eip7702_signed items =
  match items with
  | [
   chain_id;
   nonce;
   priority;
   fee;
   gas_limit;
   to_;
   value;
   data;
   access;
   auths;
   y_parity;
   r;
   s;
  ] ->
      let* _ = read_scalar ~max:8 chain_id in
      let* _ = read_scalar ~max:8 nonce in
      let* _ = read_scalar ~max:16 priority in
      let* _ = read_scalar ~max:16 fee in
      let* gas_bytes = read_scalar ~max:8 gas_limit in
      let* _ = read_fixed Address.length to_ in
      let* _ = read_scalar ~max:32 value in
      let* _ = read_bytes data in
      let* () = read_access_list access in
      let* () = read_authorization_list auths in
      let* parity = read_parity y_parity in
      let* r_bytes = read_scalar ~max:32 r in
      let* s_bytes = read_scalar ~max:32 s in
      Ok
        {
          kind = Eip7702;
          fields = items;
          gas_limit = int64_of_be gas_bytes;
          chain = Typed;
          parity;
          r = r_bytes;
          s = s_bytes;
        }
  | [] | _ :: _ -> Error Failed_to_decode

(* EIP-4844: fourteen items (eip4844.rs:889-907 plus the signature tail).
   [to] is a bare 20-byte address (a blob transaction cannot create), the
   blob fee cap is a u128 scalar and the versioned hashes are fixed 32s. *)
let read_eip4844_signed items =
  match items with
  | [
   chain_id;
   nonce;
   priority;
   fee;
   gas_limit;
   to_;
   value;
   data;
   access;
   blob_fee;
   blob_hashes;
   y_parity;
   r;
   s;
  ] ->
      let* _ = read_scalar ~max:8 chain_id in
      let* _ = read_scalar ~max:8 nonce in
      let* _ = read_scalar ~max:16 priority in
      let* _ = read_scalar ~max:16 fee in
      let* gas_bytes = read_scalar ~max:8 gas_limit in
      let* _ = read_fixed Address.length to_ in
      let* _ = read_scalar ~max:32 value in
      let* _ = read_bytes data in
      let* () = read_access_list access in
      let* _ = read_scalar ~max:16 blob_fee in
      let* () = read_blob_hashes blob_hashes in
      let* parity = read_parity y_parity in
      let* r_bytes = read_scalar ~max:32 r in
      let* s_bytes = read_scalar ~max:32 s in
      Ok
        {
          kind = Eip4844;
          fields = items;
          gas_limit = int64_of_be gas_bytes;
          chain = Typed;
          parity;
          r = r_bytes;
          s = s_bytes;
        }
  | [] | _ :: _ -> Error Failed_to_decode

(* ---- dispatch ---- *)

(* Every structural rejection collapses into the one arm reth keeps
   (utils.rs:41 map_err). Exhaustive so a new [Rlp] error variant forces a
   decision here rather than vanishing into a wildcard. *)
let of_rlp_error e =
  match e with
  | Rlp.Input_too_short | Rlp.Non_canonical_single_byte | Rlp.Non_canonical_size
  | Rlp.Leading_zero | Rlp.Overflow | Rlp.Trailing_bytes ->
      Failed_to_decode

(* The envelope body must be exactly one RLP LIST with nothing left over:
   rlp.rs:150-154 demands the list, eip2718.rs:144-151 demands exactness.
   In particular the outer-STRING framing [0xb8 || len || bytes] rejects
   here, agreeing with alloy's decode_2718_exact (the p2p-only
   network_decode is the only accepter of that wrap, and TN never calls
   it). *)
let decode_body bytes reader =
  let* item = Result.map_error of_rlp_error (Rlp.decode_exact bytes) in
  match item with
  | Rlp.Str _ -> Error Failed_to_decode
  | Rlp.List items -> reader items

(* eip2718.rs:87-89,118-125: a first byte at or below 0x7f is consumed as a
   type flag; type 0 routes to the LEGACY grammar on the remainder (exhibit
   24: the 0x00-tagged legacy form is TN-accepted); above 0x7f is the
   untagged legacy form. Types above 4 have no reader anywhere in the pinned
   envelope. Written as a chain of equalities so no arm is a wildcard. *)
let decode input =
  uncons input
  |> Option.fold ~none:(Error Empty_input) ~some:(fun (byte, rest) ->
         if byte > 0x7f then decode_body input read_legacy_signed
         else if byte = 0x00 then decode_body rest read_legacy_signed
         else if byte = 0x01 then decode_body rest read_eip2930_signed
         else if byte = 0x02 then decode_body rest read_eip1559_signed
         else if byte = 0x03 then decode_body rest read_eip4844_signed
         else if byte = 0x04 then decode_body rest read_eip7702_signed
         else Error Failed_to_decode)

(* ---- observables ---- *)

let type_prefix kind =
  match kind with
  | Legacy -> ""
  | Eip2930 -> "\x01"
  | Eip1559 -> "\x02"
  | Eip4844 -> "\x03"
  | Eip7702 -> "\x04"

(* The canonical EIP-2718 re-encoding. [Rlp] decoding is canonical, so
   re-encoding the decoded items reproduces the wire bytes exactly, except
   that a 0x00-tagged legacy input re-encodes UNTAGGED, which is precisely
   alloy's behaviour (the tagged and untagged forms share one tx hash). *)
let encode_canonical t = type_prefix t.kind ^ Rlp.encode (Rlp.List t.fields)
let hash t = Tn_keccak.digest (encode_canonical t)

let is_eip4844 t =
  match t.kind with
  | Eip4844 -> true
  | Legacy | Eip2930 | Eip1559 | Eip7702 -> false

let gas_limit t = t.gas_limit

(* The unsigned field list: the signed list minus its three signature
   items. *)
let unsigned_fields t =
  let n = List.length t.fields - 3 in
  List.filteri (fun i _ -> i < n) t.fields

(* The signing preimage, re-derived from the wire fields: the six-item list
   for pre-155 legacy, the nine-item [.. chain_id, 0, 0] list for EIP-155
   (legacy.rs:98-107 via the recovered chain id), and
   [ty || rlp(unsigned)] for every typed transaction, INCLUDING the
   EIP-4844 blob fields (eip4844.rs:909-917). *)
let signing_payload t =
  match t.chain with
  | Pre155 -> Rlp.encode (Rlp.List (unsigned_fields t))
  | Eip155 chain_bytes ->
      Rlp.encode
        (Rlp.List (unsigned_fields t @ [ Rlp.Str chain_bytes; Rlp.Str ""; Rlp.Str "" ]))
  | Typed -> type_prefix t.kind ^ Rlp.encode (Rlp.List (unsigned_fields t))

(* Checked recovery, the second half of reth's recover_raw_transaction: the
   EIP-2 strict high-s gate first (crypto.rs:246-251, strict >), then curve
   recovery and the keccak-truncate address. Both failures are the one arm
   reth reports. *)
let recover_signer t =
  let s32 = pad32 t.s in
  if Tn_evm.Secp256k1.s_is_high s32 then Error Invalid_signature
  else
    let msg = Tn_keccak.to_bytes (Tn_keccak.digest (signing_payload t)) in
    Tn_evm.Secp256k1.recover ~msg ~recid:t.parity ~r:(pad32 t.r) ~s:s32
    |> Fun.flip Option.bind Tn_evm.Public_key.to_address
    |> Option.to_result ~none:Invalid_signature

let decode_and_recover input =
  let* t = decode input in
  Result.map (fun _address -> t) (recover_signer t)
