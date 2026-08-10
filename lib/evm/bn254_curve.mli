(** The BN254 (alt_bn128) curve groups, the geometry under the [0x06] ecAdd,
    [0x07] ecMul and [0x08] ecPairing precompiles.

    Ground truth is [ark-bn254] 0.5.0, the backend [revm-precompile] 32.1.0
    selects when its optional [bn] feature stays off. It builds both groups:
    [G1] on the curve [y^2 = x^3 + 3] over {!Bn254_field.Fq}, and [G2] on the
    sextic twist [y^2 = x^3 + 3/(u + 9)] over {!Bn254_field.Fq2}, together with
    the group order [r] that the [0x07] scalar is reduced by.

    This module owns the WIRE FORMAT of a point as well as its algebra.
    {!G1.decode} and {!G2.decode} are the whole accept and reject surface of the
    three precompile arms above them: a coordinate at or above the field
    modulus, a point off its curve, a [G2] point outside the [r]-order subgroup,
    and a word of the wrong width are all refused, and they are refused as ONE
    [None] because the precompile collapses every failure into a single
    rejection.

    Two properties hold of every function here. The group laws are TOTAL: the
    point at infinity is a value of the type, not an error, and each case guards
    the inversion it needs, so addition, doubling and encoding cannot fail.
    Scalar multiplication is the one exception, and its [None] arm carries a
    named meaning stated at the item. *)

val r : Z.t
(** The order of the group, and the order of the scalar field of the curve,
    [21888242871839275222246405745257275088548364400416034343698204186575808495617]
    ([ark-bn254] [fields/fr.rs:4]). The [0x07] scalar is a raw 256-bit word
    reduced modulo [r], never rejected, so the reduction needs this constant. *)

module G1 : sig
  type t
  (** A point of [G1]: either the point at infinity or an affine pair on
      [y^2 = x^3 + 3] over {!Bn254_field.Fq}. The two cases are concealed, so a
      value of this type is on the curve by construction. The cofactor is [1],
      so an on-curve point is also in the [r]-order subgroup and no further
      filter applies. *)

  val infinity : t
  (** The point at infinity, the identity of the group. *)

  val generator : t
  (** The standard generator [(1, 2)] ([ark-bn254] [curves/g1.rs:21-89]). *)

  val make : x:Bn254_field.Fq.t -> y:Bn254_field.Fq.t -> t option
  (** [make ~x ~y] is the affine point [(x, y)], and [None] when the pair does
      not satisfy the curve equation. This is the on-curve gate alone: it never
      builds infinity, because no affine pair denotes it. *)

  val xy : t -> (Bn254_field.Fq.t * Bn254_field.Fq.t) option
  (** [xy pt] is the affine pair of [pt], and [None] at infinity, the one point
      with no affine coordinates. *)

  val equal : t -> t -> bool
  (** [equal p q] is [true] when [p] and [q] are the same point. Coordinates are
      canonical, so this is coordinate equality. *)

  val is_infinity : t -> bool
  (** [is_infinity pt] is [equal pt infinity]. *)

  val neg : t -> t
  (** [neg pt] is the additive inverse of [pt], the reflection in the [x] axis.
      It fixes infinity. *)

  val add : t -> t -> t
  (** [add p q] is the group sum by the chord and tangent law. It is total: a
      point plus its negation is infinity, and infinity is the identity on both
      sides. *)

  val mul : Z.t -> t -> t option
  (** [mul k pt] is [k] copies of [pt] added together, by double and add, and
      [None] when [k] is negative. The scalar is NOT reduced here: the caller
      states the exact multiple it wants. A negative scalar is refused rather
      than read as a multiple of the negated point, so totality is carried by
      the type. The [0x07] arm passes a residue modulo {!r}, which is never
      negative. *)

  val decode : string -> t option
  (** [decode s] reads one wire point: exactly 64 bytes, the big-endian [x] word
      followed by the big-endian [y] word. It is [None] on every malformed
      input, and there are four of them: [s] is not exactly 64 bytes long, [x]
      is at or above the field modulus, [y] is at or above the field modulus, or
      the pair is off the curve. A coordinate is REJECTED at the modulus, never
      reduced, because the arkworks reader refuses a non-canonical word
      ([arkworks.rs:21-32]).

      64 zero bytes decode to {!infinity} and skip the curve equation, which is
      the arkworks special case for the zero point ([arkworks.rs:62-63]); the
      point [(0, 0)] is off the curve, so without that case the identity would
      be unreadable. *)

  val encode : t -> string
  (** [encode pt] is [pt] as exactly 64 bytes, the big-endian [x] word followed
      by the big-endian [y] word, and 64 zero bytes at infinity. It is the
      output format of the [0x06] and [0x07] precompiles. *)
end

module G2 : sig
  type t
  (** A point of [G2]: either the point at infinity or an affine pair on the
      sextic twist [y^2 = x^3 + 3/(u + 9)] over {!Bn254_field.Fq2}. The two cases
      are concealed, so a value of this type is on the twist by construction.
      Being on the twist is NOT the same as being in the [r]-order subgroup: the
      cofactor is large ([ark-bn254] [curves/g2.rs:20-25]), so {!in_subgroup} is
      a separate question with its own answer. *)

  val infinity : t
  (** The point at infinity, the identity of the group. *)

  val generator : t
  (** The standard generator ([ark-bn254] [curves/g2.rs:99-114]). *)

  val make : x:Bn254_field.Fq2.t -> y:Bn254_field.Fq2.t -> t option
  (** [make ~x ~y] is the affine point [(x, y)], and [None] when the pair does
      not satisfy the twist equation. This is the on-twist gate ALONE: it does
      not test the subgroup, and it never builds infinity, because no affine pair
      denotes it. *)

  val xy : t -> (Bn254_field.Fq2.t * Bn254_field.Fq2.t) option
  (** [xy pt] is the affine pair of [pt], and [None] at infinity, the one point
      with no affine coordinates. *)

  val equal : t -> t -> bool
  (** [equal p q] is [true] when [p] and [q] are the same point. Coordinates are
      canonical, so this is coordinate equality. *)

  val is_infinity : t -> bool
  (** [is_infinity pt] is [equal pt infinity]. *)

  val neg : t -> t
  (** [neg pt] is the additive inverse of [pt], the reflection in the [x] axis.
      It fixes infinity. *)

  val add : t -> t -> t
  (** [add p q] is the group sum by the chord and tangent law, as {!G1.add} and
      total in the same way. *)

  val mul : Z.t -> t -> t option
  (** [mul k pt] is [k] copies of [pt] added together, by double and add, and
      [None] when [k] is negative, as {!G1.mul}. The scalar is NOT reduced. *)

  val in_subgroup : t -> bool
  (** [in_subgroup pt] is [true] when [r] copies of [pt] sum to infinity, which
      is the definition of the [r]-order subgroup. arkworks answers the same
      question with an endomorphism identity ([p]P = [6X^2]P,
      [curves/g2.rs:56-63]) that eprint 2022/352 proves equivalent on the twist,
      so the accept and reject sets agree and the wire behaviour is the same. *)

  val decode : string -> t option
  (** [decode s] reads one wire point: exactly 128 bytes, the [x] coordinate in
      the first 64 and the [y] coordinate in the second 64. WITHIN each 64-byte
      half the [u] coefficient comes FIRST and the real coefficient second, so
      the four words are [x.c1], [x.c0], [y.c1], [y.c0]. That order is the
      arkworks reader's, which parses the second word of a pair before the first
      ([arkworks.rs:44-49, 158-162]), and it is what EIP-197 specifies.

      It is [None] on every malformed input: [s] is not exactly 128 bytes long,
      any of the four words is at or above the field modulus, the pair is off the
      twist, or the point is on the twist but outside the [r]-order subgroup.
      That last case is real here and has no [G1] counterpart, because the [G2]
      cofactor is not 1 ([arkworks.rs:86-99]).

      128 zero bytes decode to {!infinity} and skip both checks, which is the
      arkworks special case for the zero point ([arkworks.rs:87-88]).

      There is no encoder: [G2] is precompile INPUT only. The [0x08] precompile
      returns one word of [true] or [false], never a point. *)
end
