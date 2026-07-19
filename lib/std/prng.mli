(** A pure, splittable pseudo-random generator (SplitMix64).

    The simulator's only source of nondeterminism is network latency jitter.
    Threading an explicit generator value rather than reaching for the global
    [Random] state keeps every run reproducible from its seed: the same seed
    replays the same schedule, which is what makes a divergence in the
    committed output a real bug rather than a flake.

    The algorithm is SplitMix64 (Steele, Lea, Flood 2014), chosen for being
    tiny, well-distributed, and portable across platforms with no C stubs. *)

type t

val of_seed : int64 -> t

val next_int64 : t -> int64 * t
(** Advances the generator, returning a uniformly distributed 64-bit value and
    the successor state. Purely functional: the input state is unchanged. *)

val int_in : t -> lo:int -> hi:int -> int * t
(** A uniform integer in the inclusive range [\[lo, hi\]]. When [hi <= lo] the
    range is a single point and [lo] is returned, so the function is total for
    every ordering of its bounds. *)

val split : t -> t * t
(** Two independent generators from one, for handing a private stream to a
    sub-computation without disturbing the caller's stream. *)
