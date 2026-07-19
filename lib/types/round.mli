(** DAG round numbers.

    A round is the abstract analogue of the Rust [u32] [Round]. Keeping it
    abstract means an [Epoch] or a raw [int] can never be passed where a round
    is expected, and it lets round parity be a {e variant} rather than a naked
    [round mod 2 = 0] test scattered through the commit rule. *)

type t

val genesis : t
(** Round 0, the round of the genesis certificates. *)

val of_int : int -> t option
(** [Some] only within the [u32] domain [\[0, 2^32 - 1\]]; the bound is what a
    later byte-compatible encoding requires. *)

val to_int : t -> int

val succ : t -> t
(** The next round. Saturates at the [u32] maximum rather than overflowing;
    reaching it is not physically possible in any real run, so saturation is a
    safe total closure of the operation. *)

val pred : t -> t option
(** The previous round, or [None] at {!genesis}. *)

type parity = Even | Odd

val parity : t -> parity

val sub_saturating : t -> int -> t
(** [sub_saturating r n] moves [n] rounds earlier, clamped at {!genesis}. This
    is the garbage-collection horizon arithmetic ([round - gc_depth]). *)

val equal : t -> t -> bool
val compare : t -> t -> int
val to_string : t -> string

module Map : Map.S with type key = t
module Set : Set.S with type elt = t
