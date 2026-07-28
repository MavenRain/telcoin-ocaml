(** The single-transaction state-transition executor: telcoin's transaction
    STF.

    This is the piece {!Tn_state.Transfer} and the port's README defer to as "the
    gas and block-execution chunk that owns transaction inclusion". Given a world
    state, a block context and a {!Transaction.t}, {!execute} runs revm's
    transaction handler ([revm-handler] [handler.rs:97-236]) end to end: it
    validates the transaction against the environment and the caller's state,
    deducts the gas fee, warms the EIP-2929/2930/3651 access set, runs the first
    frame (a call or a creation) through {!Interpreter.run}, normalizes the gas per
    the outcome, applies the EIP-3529 refund cap and the EIP-7623 floor in that
    order, settles the fees, and returns a {!Receipt.t} beside the new world.

    {2 The telcoin fee split}

    Settlement is [TNEvmHandler]'s ([tn-reth/src/evm/handler.rs:46-172]), the
    two post-execution overrides telcoin substitutes for revm's mainnet
    accounting, and since step 31 this executor implements them rather than the
    mainnet split it started with:

    - [reimburse_caller] ([handler.rs:78-134]): the refund of the unused
      allowance is docked {!Gas_penalty}'s inefficiency penalty, priced on the
      {e pre-refund} spend; the caller receives
      [effective_price * (unused - penalty)] and the withheld
      [effective_price * penalty] is credited to the block's
      {!Env.Block.basefee_address}.
    - [reward_beneficiary] ([handler.rs:137-171]): the beneficiary receives the
      priority fee alone, [(effective_price - basefee) * gas_used], exactly as
      on mainnet, and the base fee portion [basefee * gas_used] is credited to
      the same [basefee_address] rather than burned.
    - Both are skipped wholesale when the sender is
      {!System_contracts.system_address} ([handler.rs:85-87, 145-147]), so a
      system call settles nothing; on the {!System_call} path every price is
      zero anyway, and the skip is what keeps the three accounts untouched
      rather than credited zero.

    The EIP-7702 authorization refund enters this split through the same
    refund accumulator as [SSTORE]'s: it enlarges the caller's refund while
    leaving the penalty untouched (the penalty is priced on the {e pre-refund}
    spend), and it shrinks BOTH the beneficiary priority fee and the
    basefee-address credit, which are priced on post-refund [gas_used]
    ([tn-reth/src/evm/handler.rs:89-113, 150-168]).

    The upfront charge is unchanged stock revm: the caller pays
    [gas_limit * effective_price] before execution and settlement returns what
    the split allows. Receipts are untouched by the penalty: [gas_used] stays
    the post-refund figure, so a penalized transaction's receipt (and every
    cumulative-gas figure over it) is byte-identical to mainnet's.

    {2 Included versus rejected}

    A transaction that is {e included} always produces [Ok (receipt, world')], and
    the receipt says how it ended: {!Receipt.Success}, {!Receipt.Reverted} or
    {!Receipt.Halted}. For every one of the three the caller's nonce advance and
    the fee payment persist in [world']; only a revert or a halt rolls back the
    value transfer, the storage writes and the logs. A transaction that is
    {e rejected} in validation produces [Error e] and leaves the world untouched,
    exactly as reth drops an invalid transaction before inclusion. Halting is not
    rejecting: a halt is a committed outcome that burns the whole gas limit, while
    a rejection changes nothing at all.

    {2 Scope and the deferred set}

    The scope is the shared path for Legacy, EIP-2930, EIP-1559 and, since
    chunk 33, EIP-7702 set-code transactions: the authorization loop runs in
    pre-execution ([handler.rs:179-185]) and the depth-0 frame resolves a
    delegation designator through {!Call_target}, exactly as the four call
    opcodes do. Only the EIP-4844 blob transaction type is still
    deferred: the blob term is absent, exactly as {!Transaction} carries no
    blob field.

    Five facts about the authorization loop are the ones a reader will
    otherwise get wrong. The loop NEVER invalidates the transaction: no
    validity error is constructed anywhere in [apply_auth_list]
    ([pre_execution.rs:214-266]), and the empty list, the one authorization
    rule that does invalidate, is {!Empty_authorization_list}, checked in
    validation before any loop exists. A self-authorizing sender must sign
    authorization nonce = tx.nonce + 1, because its fee deduction and nonce
    bump run first ([pre_execution.rs:171-177]), and such a sender ends the
    transaction at tx.nonce + 2. There is NO deduplication: the loop visits
    every listed entry ([pre_execution.rs:216]), so a repeated authority is
    re-checked against its already-bumped live nonce and, with consecutive
    nonces, applies, bumps and refunds TWICE. Every LISTED entry costs the
    full 25000 intrinsic even when the loop later skips it ({!Intrinsic}),
    and a skipped entry earns zero refund. And delegations, authority nonce
    bumps and authority warmth SURVIVE a REVERT and a HALT: they are
    journaled below the frame's checkpoint ([frame.rs:166-167],
    [journal/inner.rs:466-484]) and are undone only by whole-transaction
    rejection ([journal/inner.rs:145-147]).

    One error constructor is deliberately ABSENT. A [Set_code_not_supported]
    (revm's [Eip7702NotSupported]) exists upstream only behind the [SpecId]
    gate ([validation.rs:191-195]) that this port does not carry: it models
    the testnet fork level, where the gate always passes ({!Env} states the
    fork scope once, [env.mli:26-53]). A future spec chunk would put that
    rejection at the head of {!execute}'s type-4 validation arm, before
    {!Empty_authorization_list}, because the error order is observable
    upstream: pre-Prague plus an empty list is [Eip7702NotSupported], never
    [EmptyAuthorizationList] ([validation.rs:191-204]).

    EIP-161 touched-empty-account pruning is honored by construction: every credit
    and every transfer goes through {!Tn_state.World_state.set_account}, which
    prunes an {!Tn_state.Account.is_absent} account, so a zero-value call to a
    fresh address, a zero-reward beneficiary and a basefee address owed nothing
    (a zero-basefee block with no penalty) leave no empty account behind. The
    state root that would commit the pruned map is still downstream (reth), as
    everywhere in this port. *)

open Tn_types

type error =
  | Invalid_chain_id
      (** The transaction's chain id does not match the block's. *)
  | Missing_chain_id
      (** A typed (EIP-2930 or EIP-1559) transaction omitted its required chain
          id. A legacy transaction may omit it without error. *)
  | Gas_price_below_base_fee
      (** The gas price (or max fee) is below the block's base fee. *)
  | Priority_fee_above_max_fee
      (** An EIP-1559 or EIP-7702 transaction's priority fee exceeds its max
          fee. *)
  | Empty_authorization_list
      (** An EIP-7702 set-code transaction carries no authorizations
          ([EmptyAuthorizationList], [validation.rs:191-204]). The one
          authorization rule that invalidates a whole transaction — every other
          authorization defect is a per-entry skip — and its position is
          observable: it is checked after the two fee checks and before the
          gas guards, so a bad priority fee wins over an empty list and an
          empty list wins over an over-the-limit intrinsic. *)
  | Gas_limit_above_block  (** The gas limit exceeds the block's gas limit. *)
  | Init_code_size_limit
      (** A creation's init code exceeds {!Tn_state.Bytecode.max_initcode_size}
          (EIP-3860). *)
  | Intrinsic_gas_above_limit
      (** The intrinsic gas exceeds the gas limit
          ([CallGasCostMoreThanGasLimit]). *)
  | Gas_floor_above_limit
      (** The EIP-7623 floor exceeds the gas limit
          ([GasFloorMoreThanGasLimit]). *)
  | Sender_has_code
      (** EIP-3607: the sender holds code that is neither empty nor an EIP-7702
          delegation designator ([pre_execution.rs:92-102]). A delegated sender
          is EXEMPT — it must be, or a delegated EOA could never send another
          transaction, including the one that revokes the delegation. *)
  | Nonce_mismatch of { expected : Tn_state.Nonce.t; actual : Tn_state.Nonce.t }
      (** The transaction's nonce is not the sender's current nonce. [expected] is
          the account's nonce, [actual] the transaction's. *)
  | Insufficient_funds
      (** The sender's balance cannot cover [gas_limit * max_fee + value]. *)
  | Overflow_payment
      (** [gas_limit * max_fee + value] passes [2^256]
          ([OverflowPaymentInTransaction]). *)

val error_to_string : error -> string
(** Render a validation {!error} as a short human-readable string, for diagnostics
    and test failure messages. *)

val execute :
  Tn_state.World_state.t ->
  block:Env.Block.t ->
  Transaction.t ->
  (Receipt.t * Tn_state.World_state.t, error) result
(** Execute one transaction against a world state in a block context.

    [Ok (receipt, world')] for an included transaction, with [world'] carrying the
    committed nonce advance, fee payment and (on success) the value transfer,
    storage writes and code deployment. [Error e] for a transaction rejected in
    validation, leaving the world untouched. See the module header for the
    included-versus-rejected distinction and the EIP-7702 authorization-loop
    facts. *)
