module W = Tn_state.U256

type word = W.t

let one = W.one
let zero = W.zero
let bool b = if b then one else zero

(* The signed view. A word is negative as a two's-complement 256-bit integer iff
   its top bit is set, i.e. it is at or above [2^255]; negation is wrapping
   subtraction from zero, and the magnitude is the value or its negation. *)
let sign_bit = W.two_pow 255
let is_negative x = W.compare x sign_bit >= 0
let neg x = W.sub zero x
let abs_signed x = if is_negative x then neg x else x

let add = W.add
let sub = W.sub
let mul = W.mul
let div a b = Option.value ~default:zero (W.udiv a b)
let modulo a b = Option.value ~default:zero (W.urem a b)
let addmod a b n = Option.value ~default:zero (W.add_mod a b n)
let mulmod a b n = Option.value ~default:zero (W.mul_mod a b n)
let exp = W.pow

(* Signed division divides the magnitudes and re-signs by the exclusive-or of the
   operand signs. The lone overflow case [-2^255 / -1] falls out unforced: the
   magnitude quotient is [2^255], and negating it wraps back to [2^255]. *)
let sdiv a b =
  if W.is_zero b then zero
  else
    let q = Option.value ~default:zero (W.udiv (abs_signed a) (abs_signed b)) in
    if is_negative a <> is_negative b then neg q else q

(* Signed remainder takes the sign of the dividend. *)
let smod a b =
  if W.is_zero b then zero
  else
    let r = Option.value ~default:zero (W.urem (abs_signed a) (abs_signed b)) in
    if is_negative a then neg r else r

let lt a b = bool (W.compare a b < 0)
let gt a b = bool (W.compare a b > 0)
let eq a b = bool (W.equal a b)
let iszero a = bool (W.is_zero a)

(* Signed comparison: a negative operand is below a non-negative one; within the
   same sign the unsigned order already agrees with the signed order. *)
let slt a b =
  let na = is_negative a and nb = is_negative b in
  if na <> nb then bool na else bool (W.compare a b < 0)

let sgt a b = slt b a

let logand = W.logand
let logor = W.logor
let logxor = W.logxor
let lognot = W.lognot

let shl shift value = W.shl value shift
let shr shift value = W.shr value shift

(* Arithmetic right shift fills with the sign bit. For a non-negative value that
   is the logical shift; for a negative one it is the complement of the logical
   shift of the complement, which also gives all-ones once the shift reaches 256. *)
let sar shift value =
  if is_negative value then W.lognot (W.shr (W.lognot value) shift)
  else W.shr value shift

(* The byte at big-endian index [i] (index [0] is most significant) of a word,
   and the index of the least-significant byte — read from the representation
   rather than written as a literal. *)
let byte_at w i = Char.code (String.get (W.to_be_bytes w) i)
let low_index = String.length (W.to_be_bytes zero) - 1

let thirty_two = W.two_pow 5

let byte i x =
  if W.compare i thirty_two >= 0 then zero
  else W.of_byte (byte_at x (byte_at i low_index))

(* Sign-extend from byte [b]: the sign bit sits at [8*b + 7]. Below it the bits of
   [x] are kept; above it they are cleared for a clear sign and set for a set one.
   For [b >= 31] the sign byte is the top byte (or beyond), so [x] is unchanged —
   the mask covers the whole word either way. *)
let signextend b x =
  if W.compare b thirty_two >= 0 then x
  else
    let bitpos = (8 * byte_at b low_index) + 7 in
    let mask_low = W.sub (W.two_pow (bitpos + 1)) one in
    if W.is_zero (W.logand x (W.two_pow bitpos)) then W.logand x mask_low
    else W.logor x (W.lognot mask_low)
