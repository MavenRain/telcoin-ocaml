(** The block's gas budget as a type with the bound built in.

    Telcoin computes [block_available_gas] as a raw [u64] subtraction whose
    non-underflow rests on an induction over a PUBLIC trait method a caller can
    invoke directly ([block.rs:868, 887-893]). Here the subtraction has no
    operands a caller can supply, so the argument is not needed: there is no
    value of this type whose [used] exceeds its [limit], and {!available} is
    therefore a total non-negative function rather than a lemma. *)

type t
(** A block's gas budget and what has been spent against it. Abstract, with
    [used <= limit] as a constructor invariant. *)

val start : Block_context.t -> t
(** The meter for a block, at zero used. TOTAL: {!Block_context.gas_limit} is
    already a non-negative [int], because the context narrowed it once. *)

val limit : t -> int
(** The block's gas limit, the number every charge is measured against. *)

val used : t -> int
(** The cumulative gas the block's transactions have consumed so far, which is
    the [cumulative_gas_used] the next receipt will carry once it is charged. *)

val available : t -> int
(** [limit - used], and never negative.

    This is the whole point of the type. Telcoin writes
    [self.evm.block().gas_limit() - self.gas_used] with no [checked_sub]
    ([block.rs:868]). It cannot underflow along the trait's own path, but
    [commit_transaction] is a PUBLIC trait method that adds to [gas_used] with
    no gas check of its own ([block.rs:887-893],
    [alloy-evm-0.27.3/src/block/mod.rs:336-351]), so calling it directly, or
    twice with the same output, pushes the total past the limit and the next
    subtraction wraps to a near-[u64::MAX] budget that silently disables the
    guard. There is no [t] here whose [used] exceeds its [limit]. *)

val charge_receipt : t -> Receipt.t -> t option
(** Advance the meter by this transaction's gas, [None] if that would pass the
    limit.

    It takes a {!Receipt.t} and NOT an [int], deliberately. There is exactly one
    number a block's cumulative gas may advance by, {!Receipt.gas_used}, net of
    refund, and it is the same number {!Block_roots.receipts_root} uses for its
    internal prefix sum ([block_roots.mli:48-52]). An [int] parameter would be a
    second chance to compute it; a {!Receipt.t} parameter is none, so the
    header's [gas_used] and the receipts root cannot disagree about what a
    transaction cost.

    Advance-then-report is telcoin's order ([block.rs:893] precedes the receipt
    build at [:896-902]), which is why a receipt's [cumulative_gas_used]
    INCLUDES its own transaction. This port gets that for free, because
    {!Block_roots.receipts_root} recomputes the prefix sum inclusively.

    The [None] is unreachable when the caller checked {!available} first, which
    {!Block_execution.run_transactions} does; it is present so the invariant is
    carried by the type rather than by that caller's discipline. *)

val equal : t -> t -> bool
(** Equality of both the limit and the amount used. Two meters that agree on
    what is left but not on where they started are not the same meter. *)
