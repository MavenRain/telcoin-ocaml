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

(* Accumulate the bytes most significant first, refusing as soon as the next
   digit would carry the value past [max_int]: [n * 256 + b <= max_int] exactly
   when [n <= (max_int - b) / 256], so the guard is checked before the multiply
   rather than after it, and nothing ever wraps. *)
let to_int t =
  List.fold_left
    (fun acc i ->
      Option.bind acc (fun n ->
          let b = byte t i in
          if n > (max_int - b) / 256 then None else Some ((n * 256) + b)))
    (Some 0)
    (List.init width (fun i -> i))

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

(* Bit [i] (least significant is 0) of a big-endian byte string of any length —
   the accessor the wide arithmetic below reads dividend and product bits with. *)
let nth_bit s i =
  let len = String.length s in
  (Char.code (String.get s (len - 1 - (i / 8))) lsr (i land 7)) land 1

(* Bit 255 — the most significant bit — of a 32-byte word, set iff the top byte
   is [>= 0x80]. This is the bit shifted out of the top by the division loop. *)
let msb_set t = byte t 0 >= 0x80

(* The bitwise operations map over the 32 bytes pairwise, so a canonical operand
   in yields a canonical result out with no carry to thread. *)
let logand a b = String.init width (fun i -> Char.chr (byte a i land byte b i))
let logor a b = String.init width (fun i -> Char.chr (byte a i lor byte b i))
let logxor a b = String.init width (fun i -> Char.chr (byte a i lxor byte b i))
let lognot a = String.init width (fun i -> Char.chr (byte a i lxor 0xff))

(* Build a word from a bit predicate: byte [j] (most significant is [0]) packs the
   eight bits at positions [8*(width-1-j) .. +7], most significant of the byte
   last. Total for any predicate; positions outside [0, 256) are simply never
   queried. *)
let of_bits f =
  String.init width (fun j ->
      let base = 8 * (width - 1 - j) in
      Char.chr
        (List.fold_left
           (fun acc k -> if f (base + k) then acc lor (1 lsl k) else acc)
           0
           [ 0; 1; 2; 3; 4; 5; 6; 7 ]))

let two_pow n = if n < 0 || n >= 256 then zero else of_bits (fun i -> i = n)

let of_byte n =
  String.init width (fun i ->
      if i = width - 1 then Char.chr (n land 0xff) else '\000')

(* Wrapping left shift by one bit: fold least-to-most significant, each byte's
   top bit carried into the next; the final carry falls off (mod [2^256]). *)
let shl1 t =
  let _, bytes_be =
    List.fold_left
      (fun (carry, acc) i ->
        let b = byte t i in
        (b lsr 7, Char.chr (((b lsl 1) lor carry) land 0xff) :: acc))
      (0, []) positions_lsb_first
  in
  of_be_list bytes_be

(* The byte at least-significant position [i] (index [0] is the low byte) — the
   order schoolbook multiplication accumulates its columns in. *)
let lsb a i = byte a (width - 1 - i)

(* The full 512-bit product as a 64-byte big-endian string: schoolbook long
   multiplication, one output column [k] at a time, threading the carry. Column
   [k] sums every partial product [a_i * b_j] with [i + j = k]; each column fits
   well inside a native int (at most 32 terms of at most [255*255], plus carry),
   so no intermediate overflow. *)
let mul_full a b =
  let indices = List.init width (fun i -> i) in
  let _, bytes_be =
    List.fold_left
      (fun (carry, acc) k ->
        let s =
          List.fold_left
            (fun s i ->
              let j = k - i in
              if j >= 0 && j < width then s + (lsb a i * lsb b j) else s)
            carry indices
        in
        (s lsr 8, Char.chr (s land 0xff) :: acc))
      (0, [])
      (List.init (2 * width) (fun k -> k))
  in
  let arr = Array.of_list bytes_be in
  String.init (2 * width) (fun i -> arr.(i))

let mul a b = String.sub (mul_full a b) width width

(* Reduce the [nbits]-bit integer whose bit [i] is [bit i] modulo [y] by binary
   long division, most significant bit first. The remainder is kept below [y]; at
   each step it is shifted left and the next dividend bit brought in, and [y] is
   subtracted when the shifted value reaches it. [top] captures the bit shifted
   out of the 256-bit remainder, so a remainder that grew past [2^255] before the
   shift still compares as [>= y]. Precondition: [y] is nonzero. *)
let umod_bits nbits bit y =
  List.fold_left
    (fun remainder i ->
      let top = msb_set remainder in
      let shifted = if bit i = 1 then logor (shl1 remainder) one else shl1 remainder in
      if top || compare shifted y >= 0 then sub shifted y else shifted)
    zero
    (List.init nbits (fun k -> nbits - 1 - k))

(* Quotient and remainder of [a / b] together, by the same long division as
   {!umod_bits} but also shifting the quotient bit in each step. Precondition:
   [b] is nonzero. *)
let udivmod a b =
  List.fold_left
    (fun (q, remainder) i ->
      let top = msb_set remainder in
      let shifted =
        if nth_bit a i = 1 then logor (shl1 remainder) one else shl1 remainder
      in
      let ge = top || compare shifted b >= 0 in
      ((if ge then logor (shl1 q) one else shl1 q),
       if ge then sub shifted b else shifted))
    (zero, zero)
    (List.init 256 (fun k -> 255 - k))

let udiv a b = if is_zero b then None else Some (fst (udivmod a b))
let urem a b = if is_zero b then None else Some (snd (udivmod a b))

let add_mod a b n =
  if is_zero n then None
  else
    let s, carry = add_carry a b in
    Some (umod_bits 257 (fun i -> if i = 256 then carry else nth_bit s i) n)

let mul_mod a b n =
  if is_zero n then None else Some (umod_bits 512 (nth_bit (mul_full a b)) n)

(* Square-and-multiply: fold the exponent's bits least significant first,
   squaring the running base each step and folding it into the accumulator on a
   set bit. All multiplication wraps mod [2^256]. *)
let pow a b =
  fst
    (List.fold_left
       (fun (acc, base) i ->
         ((if nth_bit b i = 1 then mul acc base else acc), mul base base))
       (one, a)
       (List.init 256 (fun i -> i)))

(* A shift amount below 256 as its native bit count, [None] once it reaches 256
   (where every EVM shift produces zero) — a value [< 256] has all but its low
   byte zero, so the count is that low byte. *)
let shift_bits shift =
  if compare shift (two_pow 8) >= 0 then None else Some (byte shift (width - 1))

let shl value shift =
  Option.fold ~none:zero
    ~some:(fun n -> of_bits (fun i -> i >= n && nth_bit value (i - n) = 1))
    (shift_bits shift)

let shr value shift =
  Option.fold ~none:zero
    ~some:(fun n -> of_bits (fun i -> i + n <= 255 && nth_bit value (i + n) = 1))
    (shift_bits shift)
