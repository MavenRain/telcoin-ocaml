(** The BN254 (alt_bn128) optimal ate pairing, the map the [0x08] ecPairing
    precompile decides with.

    Ground truth is the BN engine of [ark-ec] 0.5.0 ([models/bn/mod.rs],
    [models/bn/g2.rs]), reached through the backend [revm-precompile] 32.1.0
    selects when its optional [bn] feature stays off. The pairing is two halves.
    A Miller loop walks the signed-digit expansion of [6X + 2] with the [G2]
    argument in homogeneous projective coordinates over {!Bn254_field.Fq2},
    multiplying one sparse line value into an {!Bn254_field.Fq12} accumulator at
    every step. A final exponentiation then raises that accumulator to
    [(p^12 - 1) / r], which lands it in the [r]-order subgroup where the answer
    is a bit: one, or not one.

    ONE DELIBERATE RESHAPING of arkworks. arkworks folds N pairs into a single
    accumulator inside one Miller loop and exponentiates once; this module runs
    one Miller loop per pair, multiplies the results, and exponentiates that
    product once. The two agree in VALUE, because squaring distributes over a
    product in a commutative ring, which is the same identity arkworks leans on
    when it multiplies its per-chunk accumulators together. Value is all the
    wire observes. *)

val pair : Bn254_curve.G1.t -> Bn254_curve.G2.t -> Bn254_field.Fq12.t option
(** [pair p q] is the pairing of [p] and [q]: one Miller loop, then the final
    exponentiation.

    It is [None] in exactly one case, the final exponentiation inverting zero.
    No Miller output of a decoded pair is zero, so that arm is unreachable from
    the precompile; it exists because totality is carried by the type here, not
    by a comment. Either point at infinity gives [Some one], which is the value
    arkworks produces by dropping such a pair from its product.

    This is exposed to state the bilinearity the tests pin. The precompile
    itself needs {!pairing_check} alone. *)

val pairing_check : (Bn254_curve.G1.t * Bn254_curve.G2.t) list -> bool
(** [pairing_check pairs] is [true] when the product of the pairings of [pairs]
    is one. That bit is the whole output of the [0x08] precompile.

    A pair with either point at infinity is DROPPED before the product, exactly
    as arkworks drops it ([arkworks.rs:227-236]), and an empty list of
    survivors, which the empty input also produces, is [true]: the empty product
    is one. A [None] from the final exponentiation reads as [false]; it is the
    conservative answer and, as at {!pair}, unreachable on decoded points. *)
