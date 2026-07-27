(** The gas-limit inefficiency penalty of telcoin's [TNEvmHandler]
    ([tn-reth/src/evm/utils.rs:17-84]).

    Telcoin cannot know a transaction's true gas use until after consensus, so a
    transaction declaring far more gas than it spends dilutes batch capacity for
    free. [reimburse_caller] therefore withholds a penalty from the unused
    allowance before refunding the caller, and credits it to the chain's basefee
    address ([evm/handler.rs:96-131]); this module is the penalty formula alone,
    and {!Executor} is its consumer.

    The formula, in exact integer arithmetic (the Rust computes in [u128] on a
    [10^9] precision scale; this port computes in [Z], which contains it): a gas
    limit at or below [210_000] is exempt; otherwise, with
    [ratio = 10^9 * gas_spent / gas_limit], a ratio of at least [10^8] (ten
    percent usage) is exempt, and below that the penalty is
    [(10^8 - ratio)^2 * (gas_limit - gas_spent) / 10^16].

    [gas_spent] is the {e pre-refund} spend: [gas.spent()] as [reimburse_caller]
    reads it, after the EIP-7623 floor but before the EIP-3529 refund is
    subtracted ([handler.rs:62-76, 91]). Pricing the penalty on the post-refund
    figure would inflate it exactly when an SSTORE-clearing refund shrank the
    spend, which is why the Rust names the choice in its own doc comment. *)

val penalty : gas_limit:int -> gas_spent:int -> int
(** The penalty in gas units.

    For [0 <= gas_spent <= gas_limit] the result is bounded by
    [gas_limit - gas_spent]: on the penalty branch the inefficiency is at most
    [10^8], its square at most the [10^16] divisor, so the quotient never
    exceeds the unused gas. The bound is what makes the narrowing from [Z] back
    to [int] total, and it is why the Rust fallback ([utils.rs:83]'s
    [unwrap_or(unused_gas)]) is dead code this port leaves unported.

    Total over all of [int]: a negative [gas_spent] is clamped to zero (the
    explicit image of [u64]'s lower bound), and [gas_spent > gas_limit] lands
    the ratio past the ten-percent exemption and returns zero, exactly as the
    Rust arithmetic does. *)
