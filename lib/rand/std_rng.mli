(** [rand 0.9.2]'s [StdRng] restricted to what [shuffle_new_committee]
    consumes ([tn-reth/src/evm/block.rs:21, 438-470]): u32/u64 draws over
    {!Chacha12} and [random_range(0..=bound)] via the exact [UniformInt]
    sampler the crate dispatches to for [usize]. *)

type t
(** The RNG state. Persistent; every draw returns the advanced state. *)

val of_randomness : Tn_hash32.Hash32.t -> t
(** [StdRng::from_seed]: the 32 randomness bytes verbatim
    ([block.rs:438-443]). Total because {!Tn_hash32.Hash32.t} is 32 bytes by
    construction. *)

val next_u32 : t -> int * t
(** One u32 draw: the next keystream word ([BlockRng::next_u32],
    [rand_core-0.9.5/src/block.rs:186-194]). *)

val next_u64 : t -> Stdlib.Int64.t * t
(** One u64 draw: two u32 draws, low word first ([BlockRng::next_u64],
    [rand_core-0.9.5/src/block.rs:197-219]; all three buffer-position cases
    of the crate collapse to the same two sequential words). Carried as
    [Int64.t] because a u64 does not fit OCaml's native 63-bit [int]. *)

type error =
  | Negative_bound of int
      (** The inclusive upper bound was negative, which has no Rust image
          ([usize] cannot be negative). Unreachable from the shuffle, whose
          bounds are [i >= 1]. *)

(** The one way a range draw can be refused. *)

val error_to_string : error -> string
(** Render an {!error} for diagnostics and test failure messages. *)

val random_range_inclusive : t -> bound:int -> (int * t, error) result
(** [rng.random_range(0..=bound)] for [usize] on a 64-bit target:
    [UniformUsize::sample_single_inclusive]
    ([rand-0.9.2/src/distr/uniform_int.rs:562-584]) dispatches on the bound.
    Bounds at or below [u32::MAX] take [UniformInt::<u32>]'s Canon's-method
    sampler (sample type u32: one u32 draw, a 32x32 to 64-bit widening
    multiply by the range, and a second u32 draw only in the rare biased
    case); larger bounds take [UniformInt::<u64>]'s, whose 64x64 to 128-bit
    widening multiply is hand-built from [Int64] halves because OCaml has no
    u128. The bias-correction draw consumes extra keystream, so a port that
    skips it diverges on exactly the streams where it fires. *)
