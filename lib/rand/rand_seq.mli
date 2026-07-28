(** [IteratorRandom::choose_multiple]
    ([rand-0.9.2/src/seq/iterator.rs:244-268]) as the pending-exit top-up
    uses it ([tn-reth/src/evm/block.rs:460-462]). Output order is the
    reservoir's order, NOT input order and NOT sorted; it feeds the
    Fisher-Yates input, so it is consensus-relevant. Transliterated from the
    crate source, not from an algorithm description. *)

val choose_multiple : Std_rng.t -> amount:int -> 'a list -> 'a list * Std_rng.t
(** Fill the reservoir with the first [amount] elements; then, for each later
    element (the [i]-th after the reservoir, from zero), draw rand's index
    [random_range(..i + 1 + amount)] and replace slot [k] exactly when
    [k < amount]. When the list is shorter than [amount] the result is the
    whole list in input order with no draws at all (the crate's
    exhausted-early return); when [amount] is zero the draws still happen,
    one per later element, exactly as in Rust. Total; a negative [amount],
    which has no Rust image, selects nothing and draws nothing. *)
