(* A checked 32-byte value: the representation is a plain string and the module
   boundary is what makes the width a fact rather than a hope. Every producer
   here either checks the length ([of_bytes]) or has it by construction
   ([of_keccak], [zero]). *)

type t = string

let length = 32
let of_bytes s = if String.length s = length then Some s else None

(* Total: [Tn_keccak.to_bytes] is exactly [Tn_keccak.length] bytes, which is the
   same 32. *)
let of_keccak k = Tn_keccak.to_bytes k
let zero = String.make length '\000'
let to_bytes t = t
let hex_digit n = String.get "0123456789abcdef" n

(* A pure [String.init] gather, as in [u256.ml:95-99]: output position [j] reads
   the nibble it needs rather than a buffer being written into twice. *)
let to_hex t =
  String.init (2 * length) (fun j ->
      let b = Char.code (String.get t (j / 2)) in
      let nibble = if j land 1 = 0 then b lsr 4 else b land 0x0f in
      hex_digit nibble)

let equal = String.equal
let compare = String.compare
