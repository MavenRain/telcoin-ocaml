module Address = Tn_types.Units.Address

let word_length = 32

(* Both conversions are the same operation at two widths: copy a byte string
   into a fixed-width buffer aligned at its {e low} end, padding with zeros on
   the left and dropping whatever does not fit on the left. Widening (address to
   word) only ever pads; narrowing (word to address) only ever drops, which is
   the truncation [Address::from_word] performs.

   [String.init] applies its function exactly on [0 .. length - 1] and the index
   into the source is range-checked here, so no read can leave the source. *)
let right_aligned ~length source =
  let shift = length - String.length source in
  String.init length (fun i ->
      let j = i - shift in
      if j >= 0 && j < String.length source then String.get source j else '\000')

(* [right_aligned] returns exactly [word_length] bytes and [of_be_bytes] accepts
   exactly that, so the default is unreachable. It is written as a default
   rather than an exception because the interface promises a total function, and
   a total function is what [ADDRESS] and its family need. *)
let to_word addr =
  Option.value ~default:U256.zero
    (U256.of_be_bytes (right_aligned ~length:word_length (Address.to_bytes addr)))

(* Likewise total: the low [Address.length] bytes of a 32-byte encoding are
   always a well-formed address, so [of_bytes] never declines. *)
let of_word word =
  Option.value ~default:Address.zero
    (Address.of_bytes
       (right_aligned ~length:Address.length (U256.to_be_bytes word)))
