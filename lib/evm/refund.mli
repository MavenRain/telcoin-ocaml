(** The EIP-3529 refund accumulator: what the transaction gets back at the end.

    [SSTORE] credits a refund for freeing storage and claws it back when the
    slot is dirtied again in the same transaction, so the running total is
    {e signed} and genuinely goes negative part-way through: clear a slot for
    +4800 and write it again for -4800 and the total dips below where it
    started. revm's field is an [i64] for exactly this reason, and its own
    comment is about the {e final} value, not the running one
    ([revm-interpreter] [gas.rs:14]).

    That is why this is not a field of {!Gas.t}. An allowance is non-negative by
    construction and this counter is not; folding them into one type would force
    one of the two invariants to be a lie. There is no arithmetic between the
    two types at all, so a refund can never be added to or subtracted from an
    allowance by accident.

    It lives inside {!Effects.t} rather than beside the allowance because it is
    an effect: a reverted frame's refunds are discarded with its writes, and
    having one dropped value make both true is the point.

    Nothing here caps it. EIP-3529 caps the final refund at a fifth of the gas
    spent ([revm-interpreter] [gas.rs:113-120]), and [spent] is a property of a
    whole transaction, not of one frame — applying it per frame would be
    arithmetically wrong. The clamp belongs to the transaction chunk, which is
    where {!to_int} is consumed. *)

type t
(** A running total, of either sign. *)

val zero : t
(** Nothing refunded yet — the counter a transaction begins with. *)

val add : t -> int -> t
(** Accumulate one instruction's contribution, which may be negative. Overflow
    is unreachable: every term is one of 4800, 19900 or 2800, and the number of
    [SSTORE]s is bounded by an allowance that fits in a 63-bit [int]. *)

val to_int : t -> int
(** The running total, which may be negative. The caller applies the EIP-3529
    clamp. *)

val equal : t -> t -> bool
(** Equality of the totals. Two counters that reached the same number by
    different sequences of contributions are the same counter: nothing here
    records how it got there, because nothing downstream may price it that way. *)
