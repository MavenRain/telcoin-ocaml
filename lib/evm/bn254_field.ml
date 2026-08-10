(* The BN254 field tower. Fq is a canonical [Z.t] in [0, p), the secp256k1.ml
   template: every operation ends in [Z.erem], so a representative never drifts
   out of range and equality is representative equality. Fq2 is a pair of Fq
   coefficients over u^2 = -1, Fq6 a triple of Fq2 coefficients over v^3 = 9 + u,
   and Fq12 a pair of Fq6 coefficients over w^2 = v.

   Every function here is total. [Z.invert] is called only on a residue already
   proven non-zero, and [Z.powm] only on an exponent already proven
   non-negative; both guards return an option instead. Bytes are built through
   [Buffer.add_uint8],
   which takes an int and keeps its low 8 bits, so no byte value and no index
   can be out of range. *)

module Fq = struct
  type t = Z.t

  (* p, the base field modulus (ark-bn254 fields/fq.rs:4). In decimal:
     21888242871839275222246405745257275088696311157297823662689037894645226208583. *)
  let p =
    Z.of_string "0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47"

  (* Every coordinate on the precompile wire is one 32-byte big-endian word. *)
  let width = 32

  let fmod x = Z.erem x p
  let zero = Z.zero
  let one = Z.one
  let of_z x = fmod x
  let to_z a = a
  let equal a b = Z.equal a b
  let is_zero a = Z.equal a Z.zero
  let add a b = fmod (Z.add a b)
  let sub a b = fmod (Z.sub a b)
  let mul a b = fmod (Z.mul a b)
  let neg a = fmod (Z.sub Z.zero a)
  let square a = mul a a

  (* p is prime, so every non-zero residue is invertible; zero is the only
     element [Z.invert] could refuse, and it is excluded here. *)
  let inv a = if is_zero a then None else Some (Z.invert a p)

  (* [Z.powm] reads a negative exponent as an inverse power. This port never
     wants that reading, so a negative exponent is refused instead. *)
  let pow a e = if Z.sign e < 0 then None else Some (Z.powm a e p)

  (* A big-endian byte string as a non-negative integer, folded rather than
     indexed. *)
  let z_of_be s =
    String.fold_left
      (fun acc c -> Z.add (Z.shift_left acc 8) (Z.of_int (Char.code c)))
      Z.zero s

  (* Exactly 32 bytes AND a value below p. A wider or narrower word is
     malformed, and a value at or above p is non-canonical: arkworks rejects
     both rather than reducing (arkworks.rs:21-32). *)
  let of_be_bytes s =
    if String.length s <> width then None
    else
      let z = z_of_be s in
      if Z.lt z p then Some z else None

  (* The byte at position [i] is the [width - 1 - i]th base-256 digit. The
     buffer is local and nothing mutable escapes. *)
  let to_be_bytes a =
    let buf = Buffer.create width in
    List.iter
      (fun i ->
        Buffer.add_uint8 buf
          (Z.to_int
             (Z.logand (Z.shift_right a ((width - 1 - i) * 8)) (Z.of_int 0xff))))
      (List.init width Fun.id);
    Buffer.contents buf
end

module Fq2 = struct
  type t = { c0 : Fq.t; c1 : Fq.t }

  let make c0 c1 = { c0; c1 }
  let c0 x = x.c0
  let c1 x = x.c1
  let zero = { c0 = Fq.zero; c1 = Fq.zero }
  let one = { c0 = Fq.one; c1 = Fq.zero }
  let equal a b = Fq.equal a.c0 b.c0 && Fq.equal a.c1 b.c1
  let is_zero a = Fq.is_zero a.c0 && Fq.is_zero a.c1
  let add a b = { c0 = Fq.add a.c0 b.c0; c1 = Fq.add a.c1 b.c1 }
  let sub a b = { c0 = Fq.sub a.c0 b.c0; c1 = Fq.sub a.c1 b.c1 }
  let neg a = { c0 = Fq.neg a.c0; c1 = Fq.neg a.c1 }

  (* u^2 = -1, so (a0 + a1 u)(b0 + b1 u) = (a0 b0 - a1 b1) + (a0 b1 + a1 b0) u.
     The schoolbook form is kept: Karatsuba would agree in value, and value
     equality is what byte-exactness needs. *)
  let mul a b =
    {
      c0 = Fq.sub (Fq.mul a.c0 b.c0) (Fq.mul a.c1 b.c1);
      c1 = Fq.add (Fq.mul a.c0 b.c1) (Fq.mul a.c1 b.c0);
    }

  let square a = mul a a
  let conjugate a = { c0 = a.c0; c1 = Fq.neg a.c1 }
  let mul_by_fq k a = { c0 = Fq.mul k a.c0; c1 = Fq.mul k a.c1 }

  (* x^-1 = conjugate x / norm x, with norm x = c0^2 + c1^2 (the u term cancels
     because u^2 = -1). The norm is zero only at zero: a non-zero element with a
     zero norm would force -1 to be a square modulo p, which it is not. *)
  let inv a =
    let norm = Fq.add (Fq.square a.c0) (Fq.square a.c1) in
    Option.map
      (fun n -> { c0 = Fq.mul a.c0 n; c1 = Fq.neg (Fq.mul a.c1 n) })
      (Fq.inv norm)

  (* Square-and-multiply over the bits of [e], low bit first, the secp256k1.ml
     scalar-multiplication idiom. A negative exponent is refused, as Fq.pow. *)
  let pow x e =
    if Z.sign e < 0 then None
    else
      let rec go e acc base =
        if Z.equal e Z.zero then acc
        else
          let acc =
            if Z.equal (Z.logand e Z.one) Z.one then mul acc base else acc
          in
          go (Z.shift_right e 1) acc (square base)
      in
      Some (go e one x)

  (* The Frobenius coefficients of this level are 1 and -1, so raising to p^k is
     the identity on an even k and conjugation on an odd one. *)
  let frobenius k x = if k land 1 = 0 then x else conjugate x
end

(* xi = 9 + u, the non-residue of the Fq6 level: v cubes to it (ark-bn254
   fields/fq6.rs:14). Fq12 sits on top with w^2 = v (fields/fq12.rs:13), so xi is
   the only non-residue constant the two upper levels need. *)
let xi = Fq2.make (Fq.of_z (Z.of_int 9)) Fq.one

(* [Fq2.pow] refuses a negative exponent and nothing else. Every exponent below
   is a quotient of two non-negative integers, so the [None] arm is dead. It
   folds to zero, a value the frobenius-pins case rejects on sight if the arm is
   ever taken. *)
let xi_pow e = Option.fold ~none:Fq2.zero ~some:Fun.id (Fq2.pow xi e)

(* (p^k - 1) / d. p is 1 modulo 6, so p^k is too and the quotient is exact at
   both divisors used here, 3 and 6. Each call site passes a positive literal. *)
let frobenius_exponent k d =
  Z.div (Z.sub (Z.pow Fq.p k) Z.one) (Z.of_int d) (* @total-accessor *)

(* The Frobenius coefficient tables of the two upper levels, DERIVED rather than
   transcribed: entry k of FROBENIUS_COEFF_FP6_C1 is xi^((p^k - 1)/3), of
   FROBENIUS_COEFF_FP6_C2 is xi^(2(p^k - 1)/3), and of FROBENIUS_COEFF_FP12_C1 is
   xi^((p^k - 1)/6) (ark-bn254 fields/fq6.rs:16-90, fields/fq12.rs:15-88). The
   vendored tables are long literal arrays; deriving them keeps one transcribed
   constant in this file instead of thirty, and the frobenius-pins case checks
   entry 1 of each derived table against the vendored entry 1. *)
let frobenius_fp6_c1 = List.init 6 (fun k -> xi_pow (frobenius_exponent k 3))

let frobenius_fp6_c2 =
  List.init 6 (fun k -> xi_pow (Z.mul (Z.of_int 2) (frobenius_exponent k 3)))

let frobenius_fp12_c1 = List.init 12 (fun k -> xi_pow (frobenius_exponent k 6))

(* Entry [k] of a coefficient table, found by a fold over the list rather than
   by an index, so the read carries no partial accessor. An out-of-range [k]
   yields the identity; no caller reaches that case, because every call reduces
   [k] to the table length first. *)
let table_at tbl k =
  fst
    (List.fold_left
       (fun (found, j) v -> ((if Int.equal j k then v else found), j + 1))
       (Fq2.one, 0) tbl)

(* [k] reduced into [0, n) by repeated addition or subtraction. No division is
   involved, so nothing here can fail on a zero divisor, and the non-positive
   guard keeps the recursion terminating on any argument. Both call sites pass a
   positive literal length. *)
let rec table_index k n =
  match () with
  | () when n <= 0 -> 0
  | () when k < 0 -> table_index (k + n) n
  | () when k < n -> k
  | () -> table_index (k - n) n

module Fq6 = struct
  type t = { c0 : Fq2.t; c1 : Fq2.t; c2 : Fq2.t }

  let make c0 c1 c2 = { c0; c1; c2 }
  let zero = { c0 = Fq2.zero; c1 = Fq2.zero; c2 = Fq2.zero }
  let one = { c0 = Fq2.one; c1 = Fq2.zero; c2 = Fq2.zero }

  let equal a b =
    Fq2.equal a.c0 b.c0 && Fq2.equal a.c1 b.c1 && Fq2.equal a.c2 b.c2

  let add a b =
    {
      c0 = Fq2.add a.c0 b.c0;
      c1 = Fq2.add a.c1 b.c1;
      c2 = Fq2.add a.c2 b.c2;
    }

  let sub a b =
    {
      c0 = Fq2.sub a.c0 b.c0;
      c1 = Fq2.sub a.c1 b.c1;
      c2 = Fq2.sub a.c2 b.c2;
    }

  let neg a = { c0 = Fq2.neg a.c0; c1 = Fq2.neg a.c1; c2 = Fq2.neg a.c2 }

  (* Coefficient-wise scaling by one Fq2. The Fq12 Frobenius map needs it. *)
  let mul_by_fq2 k a =
    { c0 = Fq2.mul k a.c0; c1 = Fq2.mul k a.c1; c2 = Fq2.mul k a.c2 }

  (* Schoolbook, with v^3 folded to xi: each product that overruns degree 2 comes
     back scaled by xi. Karatsuba would agree in value, and value equality is
     what byte-exactness needs. *)
  let mul a b =
    {
      c0 =
        Fq2.add (Fq2.mul a.c0 b.c0)
          (Fq2.mul xi (Fq2.add (Fq2.mul a.c1 b.c2) (Fq2.mul a.c2 b.c1)));
      c1 =
        Fq2.add
          (Fq2.add (Fq2.mul a.c0 b.c1) (Fq2.mul a.c1 b.c0))
          (Fq2.mul xi (Fq2.mul a.c2 b.c2));
      c2 =
        Fq2.add
          (Fq2.add (Fq2.mul a.c0 b.c2) (Fq2.mul a.c1 b.c1))
          (Fq2.mul a.c2 b.c0);
    }

  let square a = mul a a

  (* Multiplication by v alone, the rotation (c0, c1, c2) to (xi c2, c0, c1).
     The Fq12 product uses it as its non-residue scaling. *)
  let mul_by_v a = { c0 = Fq2.mul xi a.c2; c1 = a.c0; c2 = a.c1 }

  (* The cubic-extension inverse: three cofactors s0, s1, s2 over the norm of
     [a]. Fq6 is a field, so the norm vanishes only at zero, and [Fq2.inv] turns
     that one case into [None]. *)
  let inv a =
    let s0 = Fq2.sub (Fq2.square a.c0) (Fq2.mul xi (Fq2.mul a.c1 a.c2)) in
    let s1 = Fq2.sub (Fq2.mul xi (Fq2.square a.c2)) (Fq2.mul a.c0 a.c1) in
    let s2 = Fq2.sub (Fq2.square a.c1) (Fq2.mul a.c0 a.c2) in
    let norm =
      Fq2.add (Fq2.mul a.c0 s0)
        (Fq2.mul xi (Fq2.add (Fq2.mul a.c2 s1) (Fq2.mul a.c1 s2)))
    in
    Option.map
      (fun n -> { c0 = Fq2.mul s0 n; c1 = Fq2.mul s1 n; c2 = Fq2.mul s2 n })
      (Fq2.inv norm)

  (* Raising to p^k: the Fq2 Frobenius map on each coefficient, then the two
     upper coefficients scaled by their table entries. *)
  let frobenius k a =
    let j = table_index k 6 in
    {
      c0 = Fq2.frobenius k a.c0;
      c1 = Fq2.mul (table_at frobenius_fp6_c1 j) (Fq2.frobenius k a.c1);
      c2 = Fq2.mul (table_at frobenius_fp6_c2 j) (Fq2.frobenius k a.c2);
    }
end

module Fq12 = struct
  type t = { c0 : Fq6.t; c1 : Fq6.t }

  let make c0 c1 = { c0; c1 }
  let one = { c0 = Fq6.one; c1 = Fq6.zero }
  let equal a b = Fq6.equal a.c0 b.c0 && Fq6.equal a.c1 b.c1
  let is_one a = equal a one

  (* w^2 = v, so the crossing term comes back multiplied by v, which is
     [Fq6.mul_by_v]. The shape is the Fq2 product two levels down. *)
  let mul a b =
    {
      c0 = Fq6.add (Fq6.mul a.c0 b.c0) (Fq6.mul_by_v (Fq6.mul a.c1 b.c1));
      c1 = Fq6.add (Fq6.mul a.c0 b.c1) (Fq6.mul a.c1 b.c0);
    }

  let square a = mul a a
  let conjugate a = { c0 = a.c0; c1 = Fq6.neg a.c1 }

  (* x^-1 = conjugate x over norm x, with norm x = c0^2 - v c1^2. Fq12 is a
     field, so the norm vanishes only at zero, and [Fq6.inv] reports that one
     case as [None]. *)
  let inv a =
    let norm = Fq6.sub (Fq6.square a.c0) (Fq6.mul_by_v (Fq6.square a.c1)) in
    Option.map
      (fun n -> { c0 = Fq6.mul a.c0 n; c1 = Fq6.neg (Fq6.mul a.c1 n) })
      (Fq6.inv norm)

  (* Raising to p^k: the Fq6 Frobenius map on both coefficients, then the upper
     one scaled by its table entry. Entry 6 of that table is -1, which is why
     conjugation is the same map as [frobenius 6]. *)
  let frobenius k a =
    {
      c0 = Fq6.frobenius k a.c0;
      c1 =
        Fq6.mul_by_fq2
          (table_at frobenius_fp12_c1 (table_index k 12))
          (Fq6.frobenius k a.c1);
    }

  (* The sparse product of the pairing line evaluation. The argument names index
     the six Fq2 slots of an Fq12 value: c0 is slot 0 of the lower Fq6, c3 and c4
     are slots 0 and 1 of the upper one, and the other three slots stay zero. The
     sparse element is built and then multiplied densely: the optimised routine
     agrees with it in value, and value equality is what byte-exactness needs. *)
  let mul_by_034 ~c0 ~c3 ~c4 a =
    mul a (make (Fq6.make c0 Fq2.zero Fq2.zero) (Fq6.make c3 c4 Fq2.zero))

  (* Square and multiply over the bits of [e], low bit first. A negative
     exponent is refused, as [Fq.pow] and [Fq2.pow] refuse one. *)
  let pow x e =
    if Z.sign e < 0 then None
    else
      let rec go e acc base =
        if Z.equal e Z.zero then acc
        else
          let acc =
            if Z.equal (Z.logand e Z.one) Z.one then mul acc base else acc
          in
          go (Z.shift_right e 1) acc (square base)
      in
      Some (go e one x)

  (* X, the BN parameter (ark-bn254 curves/mod.rs:18). It is positive, so the
     [None] arm of [pow] is dead below and folds to the identity. *)
  let bn_x = Z.of_string "4965661367192848881"
  let exp_x x = Option.fold ~none:one ~some:Fun.id (pow x bn_x)
end
