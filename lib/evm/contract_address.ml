open Tn_types
module W = Tn_state.U256

type scheme =
  | From_nonce of Tn_state.Nonce.t
  | From_salt of { salt : W.t; init_code : string }

(* The minimal big-endian encoding of a non-negative integer: the shortest byte
   string whose value is [n], and the empty string for zero. Built by taking the
   eight bytes of a native integer most significant first and dropping the
   leading zeros, so there is no loop and no width to get wrong — [Nonce.t] is a
   native [int], which is narrower than the eight bytes laid out here, so the
   most significant byte is always zero and the encoding is always minimal. *)
let big_endian_minimal n =
  List.init 8 (fun i -> (n lsr (8 * (7 - i))) land 0xff)
  |> List.fold_left
       (fun kept byte -> match kept with [] when byte = 0 -> [] | _ -> byte :: kept)
       []
  |> List.rev_map Char.chr |> List.to_seq |> String.of_seq

(* One RLP item, for the two this module encodes and no others. A single byte
   below [0x80] is its own encoding; anything else takes a length prefix. Both
   items here are at most twenty bytes, so the long-form prefix that strings
   past fifty-five bytes need is unreachable and is not written. *)
let rlp_item bytes =
  if String.length bytes = 1 && Char.code bytes.[0] < 0x80 then bytes
  else String.make 1 (Char.chr (0x80 + String.length bytes)) ^ bytes

(* The RLP list of the two items. Their combined length cannot exceed thirty
   bytes — twenty-one for the address, nine for the widest nonce — so the header
   is always the short form. *)
let rlp_pair first second =
  let payload = rlp_item first ^ rlp_item second in
  String.make 1 (Char.chr (0xc0 + String.length payload)) ^ payload

(* The low twenty bytes of a digest, which is what both schemes take.
   [Address_word.of_word] discards the high twelve bytes of a word, so routing
   the digest through a word applies the truncation the consensus rule specifies
   rather than restating it. The default is unreachable: a digest is
   {!Tn_keccak.length} bytes, which is exactly the width [of_be_bytes] accepts —
   the same shape, and the same justification, as [Interpreter.word_of_digest]. *)
let address_of_digest digest =
  Tn_state.Address_word.of_word
    (Option.value ~default:W.zero (W.of_be_bytes (Tn_keccak.to_bytes digest)))

let derive ~creator scheme =
  let creator_bytes = Units.Address.to_bytes creator in
  address_of_digest
    (Tn_keccak.digest
       (match scheme with
       | From_nonce nonce ->
           rlp_pair creator_bytes (big_endian_minimal (Tn_state.Nonce.to_int nonce))
       | From_salt { salt; init_code } ->
           String.concat ""
             [
               "\xff";
               creator_bytes;
               W.to_be_bytes salt;
               Tn_keccak.to_bytes (Tn_keccak.digest init_code);
             ]))
