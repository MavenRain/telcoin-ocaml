(* A 256-bit unsigned integer held as its canonical 32-byte big-endian encoding.
   Fixed width makes [String.compare] the correct unsigned ordering and the byte
   codec the identity, so the representation is canonical by construction: every
   operation below produces a 32-byte string and no two equal values differ. *)
type t = string

let width = 32
let zero = String.make width '\000'
let max_value = String.make width '\255'
let one = String.init width (fun i -> if i = width - 1 then '\001' else '\000')

(* The byte at position [i], most significant first. Safe for [i] in [0, width). *)
let byte t i = Char.code (String.get t i)

(* The byte positions from least significant (index [width-1]) to most (index 0)
   — the order the additive carry and borrow thread through. *)
let positions_lsb_first = List.init width (fun i -> width - 1 - i)

(* Assemble a 32-byte string from its bytes in big-endian (most-significant-first)
   order. Converting the list to an array once keeps the lookup total and O(1). *)
let of_be_list bytes_be =
  let arr = Array.of_list bytes_be in
  String.init width (fun i -> arr.(i))

(* Wrapping addition with the outgoing carry: fold the byte positions from least
   to most significant, threading the carry, prepending each result byte so the
   accumulator ends in big-endian order. The final carry is 1 exactly on
   256-bit overflow. *)
let add_carry a b =
  let carry, bytes_be =
    List.fold_left
      (fun (carry, acc) i ->
        let s = byte a i + byte b i + carry in
        (s lsr 8, Char.chr (s land 0xff) :: acc))
      (0, []) positions_lsb_first
  in
  (of_be_list bytes_be, carry)

(* Wrapping subtraction with the outgoing borrow. [d] lies in [-256, 255]; masking
   with [0xff] yields its value modulo 256 (OCaml [land] on the two's-complement
   representation), and the borrow is 1 exactly when the byte difference went
   negative. The final borrow is 1 exactly on underflow ([a < b]). *)
let sub_borrow a b =
  let borrow, bytes_be =
    List.fold_left
      (fun (borrow, acc) i ->
        let d = byte a i - byte b i - borrow in
        let next_borrow = if d < 0 then 1 else 0 in
        (next_borrow, Char.chr (d land 0xff) :: acc))
      (0, []) positions_lsb_first
  in
  (of_be_list bytes_be, borrow)

let add a b = fst (add_carry a b)
let sub a b = fst (sub_borrow a b)

let checked_add a b =
  let s, carry = add_carry a b in
  if carry = 0 then Some s else None

let checked_sub a b =
  let d, borrow = sub_borrow a b in
  if borrow = 0 then Some d else None

let of_int n =
  if n < 0 then None
  else
    Some
      (String.init width (fun i ->
           let shift = 8 * (width - 1 - i) in
           (* A native [int] is at most [Sys.int_size] bits; positions past that
              are always zero, and shifting by [>= Sys.int_size] is undefined, so
              guard it explicitly. *)
           if shift >= Sys.int_size then '\000'
           else Char.chr ((n lsr shift) land 0xff)))

let to_be_bytes t = t
let of_be_bytes s = if String.length s = width then Some s else None

let hex_digit n = String.get "0123456789abcdef" n

let to_hex t =
  String.init (2 * width) (fun j ->
      let b = byte t (j / 2) in
      let nibble = if j land 1 = 0 then b lsr 4 else b land 0x0f in
      hex_digit nibble)

let hex_value c =
  if c >= '0' && c <= '9' then Some (Char.code c - Char.code '0')
  else if c >= 'a' && c <= 'f' then Some (Char.code c - Char.code 'a' + 10)
  else if c >= 'A' && c <= 'F' then Some (Char.code c - Char.code 'A' + 10)
  else None

let of_hex s =
  if String.length s <> 2 * width then None
  else
    (* Each byte is the two hex digits at [2i, 2i+1], most significant first; a
       single bad digit collapses the whole parse to [None]. *)
    let bytes_be =
      List.init width (fun i ->
          Option.bind (hex_value (String.get s (2 * i))) (fun hi ->
              Option.map
                (fun lo -> Char.chr ((hi lsl 4) lor lo))
                (hex_value (String.get s ((2 * i) + 1)))))
    in
    List.fold_right
      (fun byte_opt acc ->
        Option.bind byte_opt (fun b -> Option.map (fun rest -> b :: rest) acc))
      bytes_be (Some [])
    |> Option.map of_be_list

let is_zero t = String.equal t zero
let equal = String.equal
let compare = String.compare
