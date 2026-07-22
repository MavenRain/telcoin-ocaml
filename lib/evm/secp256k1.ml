(* secp256k1 over Z. The curve is y^2 = x^3 + 7 over the prime field of order
   [p]; signatures use the group of order [n]. Recovery reconstructs the point R
   from [r] and the parity [recid], then solves Q = r^{-1} (s R - z G) in the
   [u1 G + u2 R] form. All the standard domain parameters
   ({{:https://www.secg.org/sec2-v2.pdf} SEC 2}); [a = 0] is folded away. *)

let p =
  Z.of_string
    "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"

let n =
  Z.of_string
    "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"

let gx =
  Z.of_string
    "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

let gy =
  Z.of_string
    "0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"

(* For [p = 3 (mod 4)] a square root is the [(p + 1) / 4] power, so this exponent
   is precomputed once. *)
let sqrt_exp = Z.div (Z.succ p) (Z.of_int 4)

(* Field arithmetic mod [p]; [erem] keeps every result in [[0, p)]. *)
let fmod x = Z.erem x p
let fmul a b = fmod (Z.mul a b)
let fsub a b = fmod (Z.sub a b)
let fadd a b = fmod (Z.add a b)
let finv a = Z.invert a p (* callers pass a non-zero residue, so this is total *)

(* Scalar arithmetic mod [n]. *)
let nmod x = Z.erem x n

(* A curve point in affine coordinates, with the identity kept separate so the
   group laws stay total. *)
type point = Infinity | Affine of Z.t * Z.t

let g_point = Affine (gx, gy)

let two = Z.of_int 2
let three = Z.of_int 3

(* Point doubling. A vertical tangent (y = 0) meets the curve only at infinity. *)
let double = function
  | Infinity -> Infinity
  | Affine (x, y) ->
      if Z.equal y Z.zero then Infinity
      else
        let lambda = fmul (fmul three (fmul x x)) (finv (fmul two y)) in
        let x3 = fsub (fmul lambda lambda) (fmul two x) in
        let y3 = fsub (fmul lambda (fsub x x3)) y in
        Affine (x3, y3)

(* The group law. Equal x-coordinates mean either the same point (double) or a
   point and its inverse (whose sum is the identity). *)
let add p1 p2 =
  match (p1, p2) with
  | Infinity, _ -> p2
  | _, Infinity -> p1
  | Affine (x1, y1), Affine (x2, y2) ->
      if Z.equal x1 x2 then if Z.equal y1 y2 then double p1 else Infinity
      else
        let lambda = fmul (fsub y2 y1) (finv (fsub x2 x1)) in
        let x3 = fsub (fsub (fmul lambda lambda) x1) x2 in
        let y3 = fsub (fmul lambda (fsub x1 x3)) y1 in
        Affine (x3, y3)

(* [k * pt] by double-and-add over the bits of [k], low bit first. *)
let mul k pt =
  let rec go k acc base =
    if Z.equal k Z.zero then acc
    else
      let acc = if Z.equal (Z.logand k Z.one) Z.one then add acc base else acc in
      go (Z.shift_right k 1) acc (double base)
  in
  go k Infinity pt

(* A 32-byte big-endian string as a non-negative integer. *)
let z_of_be s =
  String.fold_left
    (fun acc c -> Z.add (Z.shift_left acc 8) (Z.of_int (Char.code c)))
    Z.zero s

(* The low 32 bytes of [z], big-endian; every coordinate here is below [p], so
   nothing above 256 bits is dropped. *)
let be32 z =
  String.init 32 (fun i ->
      Char.chr (Z.to_int (Z.logand (Z.shift_right z ((31 - i) * 8)) (Z.of_int 0xff))))

(* A square root of [a] mod [p], or [None] when [a] is not a quadratic residue —
   which is how an [r] that is no point's x-coordinate is rejected. *)
let sqrt_mod a =
  let cand = Z.powm a sqrt_exp p in
  if Z.equal (fmul cand cand) (fmod a) then Some cand else None

let recover ~msg ~recid ~r ~s =
  let z = z_of_be msg in
  let r = z_of_be r in
  let s = z_of_be s in
  if Z.leq r Z.zero || Z.geq r n || Z.leq s Z.zero || Z.geq s n then None
  else
    (* R has x-coordinate [r] (below [n < p], so a valid field element) and the
       y whose parity matches [recid]. *)
    let alpha = fadd (fmul (fmul r r) r) (Z.of_int 7) in
    Option.bind (sqrt_mod alpha) (fun y0 ->
        let y_is_odd = Z.equal (Z.logand y0 Z.one) Z.one in
        let want_odd = recid land 1 = 1 in
        let y = if Bool.equal y_is_odd want_odd then y0 else fsub Z.zero y0 in
        let big_r = Affine (r, y) in
        let rinv = Z.invert r n in
        let u1 = nmod (Z.mul (Z.sub Z.zero z) rinv) in
        let u2 = nmod (Z.mul s rinv) in
        match add (mul u1 g_point) (mul u2 big_r) with
        | Infinity -> None
        | Affine (qx, qy) -> Some (be32 qx ^ be32 qy))
