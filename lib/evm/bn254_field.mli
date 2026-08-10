(** The BN254 (alt_bn128) field tower, the algebra under the [0x06] ecAdd,
    [0x07] ecMul and [0x08] ecPairing precompiles.

    Ground truth is [ark-bn254] 0.5.0, the backend [revm-precompile] 32.1.0
    selects when its optional [bn] feature stays off. It builds the whole tower:
    the base field [Fq], its quadratic extension [Fq2 = Fq[u]/(u^2 + 1)], the
    cubic extension [Fq6 = Fq2[v]/(v^3 - (9 + u))] on top of that, and finally
    [Fq12 = Fq6[w]/(w^2 - v)], the field the pairing lands in.

    Two properties hold of every value here. Representation is CANONICAL: an
    [Fq] element is the representative in [[0, p)], and each operation reduces
    with [Z.erem], so equality is representative equality and the byte codec
    needs no separate normalisation step. Every function is TOTAL: no operation
    here can fail at run time. Where a mathematical operation is undefined the
    result is an option whose [None] arm carries a named meaning, stated per
    item below. *)

module Fq : sig
  type t
  (** An element of the base field, the canonical representative in [[0, p)]. *)

  val p : Z.t
  (** The base field modulus,
      [21888242871839275222246405745257275088696311157297823662689037894645226208583]
      ([ark-bn254] [fields/fq.rs:4]). Exposed because the wire format rejects a
      coordinate at or above it, and the tests pin that boundary. *)

  val zero : t
  (** The additive identity. *)

  val one : t
  (** The multiplicative identity. *)

  val of_z : Z.t -> t
  (** [of_z z] is [z] reduced modulo [p]. A negative [z] maps to its
      non-negative residue, so the result is always canonical. *)

  val to_z : t -> Z.t
  (** [to_z a] is the canonical representative of [a], an integer in
      [[0, p)]. *)

  val of_be_bytes : string -> t option
  (** [of_be_bytes s] decodes one 32-byte big-endian coordinate word. It is
      [None] in exactly two cases: [s] is not exactly 32 bytes long, or the
      value it encodes is [p] or above. The second case is the one that matters
      on the wire: arkworks REJECTS a non-canonical coordinate rather than
      reducing it ([arkworks.rs:21-32]), and the precompile turns that rejection
      into a failed call. *)

  val to_be_bytes : t -> string
  (** [to_be_bytes a] is [a] as exactly 32 big-endian bytes, zero-padded on the
      left. It is the inverse of {!of_be_bytes} on every element. *)

  val equal : t -> t -> bool
  (** [equal a b] is [true] when [a] and [b] are the same field element. *)

  val is_zero : t -> bool
  (** [is_zero a] is [equal a zero]. *)

  val add : t -> t -> t
  (** [add a b] is the field sum. *)

  val sub : t -> t -> t
  (** [sub a b] is the field difference, canonical even when [b] exceeds [a]:
      [sub zero one] is [p - 1], never a negative integer. *)

  val mul : t -> t -> t
  (** [mul a b] is the field product. *)

  val neg : t -> t
  (** [neg a] is the additive inverse, [zero] at [zero]. *)

  val square : t -> t
  (** [square a] is [mul a a]. *)

  val inv : t -> t option
  (** [inv a] is the multiplicative inverse of [a], and [None] at [zero], the
      one element with no inverse. Every other residue is invertible because [p]
      is prime. *)

  val pow : t -> Z.t -> t option
  (** [pow a e] is [a] to the power [e], and [None] when [e] is negative. A
      negative exponent is refused rather than read as an inverse power: totality
      is carried by the type, so a caller cannot reach a partial operation by
      forgetting a precondition. *)
end

module Fq2 : sig
  type t
  (** An element of [Fq2 = Fq[u]/(u^2 + 1)], written [c0 + c1 * u]. The
      non-residue is [-1] ([ark-bn254] [fields/fq2.rs:13]). *)

  val make : Fq.t -> Fq.t -> t
  (** [make c0 c1] is [c0 + c1 * u]. *)

  val c0 : t -> Fq.t
  (** [c0 x] is the coefficient of [1] in [x]. *)

  val c1 : t -> Fq.t
  (** [c1 x] is the coefficient of [u] in [x]. *)

  val zero : t
  (** The additive identity. *)

  val one : t
  (** The multiplicative identity. *)

  val equal : t -> t -> bool
  (** [equal a b] is [true] when both coefficients agree. *)

  val is_zero : t -> bool
  (** [is_zero a] is [equal a zero]. *)

  val add : t -> t -> t
  (** [add a b] is the coefficient-wise sum. *)

  val sub : t -> t -> t
  (** [sub a b] is the coefficient-wise difference. *)

  val neg : t -> t
  (** [neg a] is the additive inverse. *)

  val mul : t -> t -> t
  (** [mul a b] is the extension product, which folds [u^2] to [-1]. *)

  val square : t -> t
  (** [square a] is [mul a a]. *)

  val inv : t -> t option
  (** [inv a] is the multiplicative inverse of [a], and [None] at [zero]. The
      norm [c0^2 + c1^2] vanishes only at zero, because [-1] is not a square
      modulo [p]. *)

  val conjugate : t -> t
  (** [conjugate x] negates the [u] coefficient. It is the Frobenius map
      [x |-> x^p] on this level. *)

  val mul_by_fq : Fq.t -> t -> t
  (** [mul_by_fq k x] scales both coefficients of [x] by [k]. The pairing's line
      evaluation needs this scaling. *)

  val pow : t -> Z.t -> t option
  (** [pow x e] is [x] to the power [e] by square-and-multiply, and [None] when [e]
      is negative, as {!Fq.pow}. The Frobenius coefficient tables of the higher
      levels are derived with it. *)

  val frobenius : int -> t -> t
  (** [frobenius k x] is [x] to the power [p^k]. Only the parity of [k] matters
      here: the map is the identity on an even [k] and {!conjugate} on an odd
      one, because the two Frobenius coefficients of [Fq2] are [1] and [-1]. *)
end

module Fq6 : sig
  type t
  (** An element of [Fq6 = Fq2[v]/(v^3 - xi)], written [c0 + c1 * v + c2 * v^2].
      The non-residue is [xi = 9 + u] ([ark-bn254] [fields/fq6.rs:14]). *)

  val make : Fq2.t -> Fq2.t -> Fq2.t -> t
  (** [make c0 c1 c2] is [c0 + c1 * v + c2 * v^2]. *)

  val zero : t
  (** The additive identity. *)

  val one : t
  (** The multiplicative identity. *)

  val equal : t -> t -> bool
  (** [equal a b] is [true] when all three coefficients agree. *)

  val add : t -> t -> t
  (** [add a b] is the coefficient-wise sum. *)

  val sub : t -> t -> t
  (** [sub a b] is the coefficient-wise difference. *)

  val neg : t -> t
  (** [neg a] is the additive inverse. *)

  val mul : t -> t -> t
  (** [mul a b] is the extension product, which folds [v^3] to [xi]. *)

  val square : t -> t
  (** [square a] is [mul a a]. *)

  val inv : t -> t option
  (** [inv a] is the multiplicative inverse of [a], and [None] at [zero]. [Fq6]
      is a field, so [zero] is the one element with no inverse. *)

  val mul_by_v : t -> t
  (** [mul_by_v a] is [mul a (make Fq2.zero Fq2.one Fq2.zero)], the rotation of
      [(c0, c1, c2)] to [(xi * c2, c0, c1)]. The [Fq12] product uses it as its
      own non-residue scaling, so it is stated once here. *)

  val frobenius : int -> t -> t
  (** [frobenius k x] is [x] to the power [p^k]: the [Fq2] Frobenius map on each
      coefficient, then [c1] and [c2] scaled by entry [k] of the two [Fq6]
      Frobenius coefficient tables. The tables have six entries, and [k] is
      reduced into that range, so every [k] is accepted and a negative one is
      read as its positive residue. *)
end

module Fq12 : sig
  type t
  (** An element of [Fq12 = Fq6[w]/(w^2 - v)], written [c0 + c1 * w]. The
      non-residue is [v] itself ([ark-bn254] [fields/fq12.rs:13]). This is the
      field the pairing lands in. *)

  val make : Fq6.t -> Fq6.t -> t
  (** [make c0 c1] is [c0 + c1 * w]. *)

  val one : t
  (** The multiplicative identity, and the value a true pairing check compares
      against. *)

  val equal : t -> t -> bool
  (** [equal a b] is [true] when both coefficients agree. *)

  val is_one : t -> bool
  (** [is_one a] is [equal a one]. The [0x08] precompile reports exactly this
      bit. *)

  val mul : t -> t -> t
  (** [mul a b] is the extension product, which folds [w^2] to [v]. *)

  val square : t -> t
  (** [square a] is [mul a a]. *)

  val conjugate : t -> t
  (** [conjugate a] negates the [w] coefficient. It is [a] to the power [p^6],
      and on the cyclotomic subgroup the final exponentiation works in it is
      also the inverse of [a]. *)

  val inv : t -> t option
  (** [inv a] is the multiplicative inverse of [a], and [None] at [zero], the one
      element with no inverse. The final exponentiation inverts only values it
      has already produced from a non-zero Miller output, so that [None] arm is
      unreachable from the precompile. *)

  val frobenius : int -> t -> t
  (** [frobenius k x] is [x] to the power [p^k]: the [Fq6] Frobenius map on both
      coefficients, then [c1] scaled by entry [k] of the [Fq12] Frobenius
      coefficient table. The table has twelve entries, and [k] is reduced into
      that range as in {!Fq6.frobenius}. *)

  val mul_by_034 : c0:Fq2.t -> c3:Fq2.t -> c4:Fq2.t -> t -> t
  (** [mul_by_034 ~c0 ~c3 ~c4 a] multiplies [a] by the sparse element that holds
      [c0], [c3] and [c4] in slots 0, 3 and 4 of its six [Fq2] slots and zero in
      the other three. The pairing line evaluation produces exactly that shape.
      The result is the dense product: an optimised sparse routine agrees with it
      in value, and value equality is what byte-exactness needs. *)

  val pow : t -> Z.t -> t option
  (** [pow x e] is [x] to the power [e] by square and multiply, and [None] when
      [e] is negative, as {!Fq.pow}. *)

  val exp_x : t -> t
  (** [exp_x x] is [x] to the power [X], the BN parameter
      [4965661367192848881] ([ark-bn254] [curves/mod.rs:18]). The final
      exponentiation is a chain of these. [X] is positive, so no option arises. *)
end
