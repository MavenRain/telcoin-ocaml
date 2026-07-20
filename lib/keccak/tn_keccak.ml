module H = Digestif.KECCAK_256

type t = string

let length = H.digest_size
let digest s = H.to_raw_string (H.digest_string s)
let empty = digest ""
let to_bytes t = t

(* Rendered directly from the bytes rather than through [H.to_hex], which would
   need a round trip back through [H.of_raw_string_opt] and so an [Option.get].
   There is no partial function in this port. The shape is {!Tn_state.U256.to_hex}'s. *)
let hex_digit n = String.get "0123456789abcdef" n

let to_hex t =
  String.init (2 * String.length t) (fun j ->
      let b = Char.code (String.get t (j / 2)) in
      let nibble = if j land 1 = 0 then b lsr 4 else b land 0x0f in
      hex_digit nibble)

let equal = String.equal
