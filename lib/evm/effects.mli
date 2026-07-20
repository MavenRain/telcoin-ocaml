(** Everything an execution frame can change outside itself, as one persistent
    value.

    A frame reads and writes the world, warms accounts and slots, accrues
    refunds, emits logs, and writes transient storage. revm tracks all five with
    a mutable state and an undo log it replays backwards on revert
    ([revm-context-interface] [journaled_state/entry.rs]). It has to: its state
    is a mutable map and there is no older version left to return to.

    This port has one. {!Tn_state.World_state.t}, {!Access.t}, the refund
    counter, {!Log_journal.t} and {!Transient.t} are all persistent, so the
    value that {e was} the state before a frame ran is still in the caller's
    hand after it. A checkpoint is a binding,
    a revert is using the old binding, and an exceptional halt is dropping the
    new one. Undoing is not an operation, it is the absence of one:
    {!Interpreter.Reverted} and {!Interpreter.Failed} simply carry no {!t}.

    That is also why there is no checkpoint stack here and why there will not
    need to be one when calls arrive. A sub-frame is handed its parent's {!t} and
    its success hands one back, so nesting is function composition and a reverted
    child is a value the parent drops. Every class of bug in which an undo entry
    is pushed for one change and forgotten for another is absent because there is
    no undo code. Each field added here inherits that for free: the logs a
    reverted frame emitted and the transient slots it wrote are discarded by the
    same act of dropping the value, and neither needed a line of code to say so.
    A sixth field on {!Interpreter}'s machine would not have got it, because
    [Reverted] is built from the remaining gas and the popped output alone.

    It reproduces revm exactly on the part that is easiest to get wrong: a revert
    {e un-warms}. One might reason that a cold read was genuinely paid for and
    should stay paid for, but reverting an [AccountWarmed] entry calls
    [mark_cold] on the account ([journaled_state/entry.rs:317-319]) and a
    [StorageWarmed] entry calls [mark_cold] on the slot ([:391-398]). Since the
    access set is a field of this value, dropping the value does that for free,
    while the transaction-level pre-warming — which happened before the frame —
    survives in the caller's copy. The warm set is revertible substate, not
    sticky state; with a single frame the distinction is unobservable, because
    discarding the whole value discards the warmings with it, and it becomes
    observable the day [CALL] lands.

    {!start} fixes the pre-transaction world once and offers no way to replace
    it, so {!Sstore_state.original} is transaction-scoped by construction. That
    is exact while a run is one frame, because the frame's start {e is} the
    transaction's start. It is the one assumption here that [CALL] will
    invalidate: once a nested frame can revert independently, the
    pre-transaction and pre-frame states diverge and [original] must move onto
    the slot, as revm has it. When that happens, this module gains a checkpoint
    and the pre-transaction world stops being a single value.

    Transient storage has a lifetime this value models only half of, and the
    half it models is the hard one. EIP-1153 requires a frame's revert to undo
    its transient writes, which is the drop above, and requires the whole map to
    be cleared at the end of the {e transaction}, which is the transaction layer
    letting go of this value. Neither needs a mechanism here. What would need
    one is the case that does not arise: transient storage surviving a frame it
    was written in while not surviving the transaction. *)

open Tn_types

type t

type 'a load
(** A completed lookup: the value read, the {!Access.warmth} it cost, and the
    effects with that access recorded. The three travel together so a price can
    never be attached to the wrong read. *)

val start : world:Tn_state.World_state.t -> access:Access.t -> t
(** The effects a transaction starts from: [world] is both the current state and
    the pre-transaction state every [SSTORE] nets against, [access] is whatever
    EIP-2929, EIP-2930 and EIP-3651 pre-warmed (build it with
    {!Access.of_transaction}), and the refund counter is zero.

    Nothing here pre-warms on the caller's behalf. A caller that passes
    {!Access.empty} is modelling a frame in which even the callee is cold, which
    no real transaction produces — see {!Interpreter.run}. *)

val world : t -> Tn_state.World_state.t
(** The working state: every write the frame has made so far. *)

val base : t -> Tn_state.World_state.t
(** The state as of {!start} — the source of EIP-2200's [original], and a named
    value so that the assumption above is visible rather than implicit. *)

val access : t -> Access.t
val refund : t -> Refund.t

val logs : t -> Log_journal.t
(** The logs emitted so far, in emission order. *)

val transient : t -> Transient.t
(** The EIP-1153 transient store as it currently stands. *)

val loaded : 'a load -> 'a
val warmth : 'a load -> Access.warmth

val warmed : 'a load -> t
(** The effects with the access recorded. For a read that is everything the
    lookup changed; for {!plan_store} the write is {e not} applied, see
    {!commit_store}. *)

val balance : t -> Units.Address.t -> Tn_state.U256.t load
(** [BALANCE]: read an account's balance and warm the account. Total — an
    account with no entry reads zero. *)

val ext_account : t -> Units.Address.t -> Tn_state.Account.t load
(** The external-code readers' lookup: read a whole account and warm it, exactly
    the account touch {!balance} performs. Total — an address with no entry reads
    {!Tn_state.Account.empty}, whose code is empty, whose {!Tn_state.Account.code_length}
    is zero and which is {!Tn_state.Account.is_empty}. It hands back the account
    rather than a projection of it because [EXTCODESIZE], [EXTCODEHASH] and
    [EXTCODECOPY] each read a different one, and splitting the single access into
    three would be three chances to warm on a different footing. The interpreter
    takes the length, the EIP-1052 hash or the code from what this returns. *)

val self_balance : t -> Units.Address.t -> Tn_state.U256.t * t
(** [SELFBALANCE]: read the executing account's balance for a flat 5
    ([revm-interpreter] [instructions.rs:191]) with no cold surcharge, ever
    ([instructions/host.rs:37-49] charges none).

    It returns no {!Access.warmth}, and that is the point: with no witness there
    is nothing to price, so the surcharge cannot be charged by accident.

    The account is nevertheless {e marked} warm, and this is not a liberty. revm
    reaches the balance through [Host::balance], whose default implementation is
    [load_account_info_skip_cold_load] ([revm-context-interface]
    [host.rs:140-144]) — the account goes through the journal like any other
    access and the instruction simply ignores the returned [is_cold]. It is
    unobservable on any real transaction, because EIP-2929 pre-warms the
    executing account before the frame starts; it is observable, and correct,
    from an {!Access.empty} start. *)

val storage :
  t -> Units.Address.t -> slot:Tn_state.U256.t -> Tn_state.U256.t load
(** [SLOAD]: read a slot and warm it. Total — an unwritten slot reads zero. *)

val log : t -> Mutability.permit -> Log.t -> t
(** [LOG0]-[LOG4]: append an entry to the journal.

    It returns a bare {!t} and no {!Access.warmth}. There is therefore nothing a
    caller could hand to {!Gas.account_access_cost}, which is correct: a log
    warms nothing and carries no cold surcharge. This is {!self_balance}'s "no
    witness escapes" argument used to forbid a price rather than to hide one.

    The {!Mutability.permit} is what makes EIP-214 unforgettable here. It is not
    read; the caller could not have produced one without consulting the frame's
    mutability, and that consultation is the guard. *)

val transient_load : t -> Units.Address.t -> slot:Tn_state.U256.t -> Tn_state.U256.t
(** [TLOAD]: read a transient slot. Total, returning zero for an unwritten slot,
    and it returns a bare word rather than a [load] because EIP-1153 places
    transient storage outside EIP-2929: there is no warmth to record and no
    surcharge to price. *)

val transient_store :
  t ->
  Mutability.permit ->
  Units.Address.t ->
  slot:Tn_state.U256.t ->
  value:Tn_state.U256.t ->
  t
(** [TSTORE]: write a transient slot. Unlike {!plan_store} there is no plan and
    commit split, because EIP-1153 gives [TSTORE] a flat price that depends on
    nothing it would have to look up first. *)

val plan_store :
  t ->
  Mutability.permit ->
  Units.Address.t ->
  slot:Tn_state.U256.t ->
  value:Tn_state.U256.t ->
  Sstore_state.t load
(** [SSTORE], priced but not yet applied. The triple it returns is the only one
    the interpreter ever sees, and {!Gas.sstore_dynamic_cost} and
    {!Gas.sstore_refund} are both functions of it, so the charge, the refund and
    the write are all derived from a single lookup.

    Splitting plan from commit is what makes revm's charging order expressible:
    the dynamic gas is charged first and only a successful charge reaches the
    refund ([revm-interpreter] [instructions/host.rs:272-287], where the [gas!]
    macro returns early). A frame that cannot pay never calls {!commit_store} —
    and it does not matter that {!warmed} has already recorded the access, since
    a frame that cannot pay halts exceptionally and its whole {!t} is discarded.

    (revm writes before charging, at [host.rs:251-279]. Planning first reaches
    the same observable state by a route that does not depend on the outcome type
    to stay sound.) *)

val commit_store : Sstore_state.t load -> t
(** Apply the planned write, record the access, and accrue
    {!Gas.sstore_refund} of the same triple. One function, so the three cannot
    drift apart and no caller can apply a write while forgetting its refund. *)

val transfer :
  t ->
  from:Units.Address.t ->
  to_:Units.Address.t ->
  value:Tn_state.U256.t ->
  t option
(** Move [value] from one account to another — the balance change a value-bearing
    [CALL] or [CALLCODE] applies to the sub-frame's effects.

    [None] on either of the two failures {!Tn_state.Account.debit} and
    {!Tn_state.Account.credit} report: a sender balance below [value] (revm's
    [InsufficientFunds]) or a recipient balance that [value] would overflow past
    [2^256] (revm's [OverflowPayment], unreachable at a real total supply). The
    option is the whole point of the signature: the caller routes a [None] through
    the same path as its own balance guard — push zero, hand back the forwarded
    gas, leave the effects as they were — so no failure is ever resolved into a
    forced state that would create or destroy ether. A total helper that dropped
    the [None] would break value conservation on exactly those two inputs.

    The label is [to_], not [to], because [to] is an OCaml keyword.

    It threads the world through the debit before reading the recipient, so a
    self-transfer — a [CALLCODE], whose sender and recipient are the executing
    account itself — reads the debited balance and credits it straight back,
    netting to no change and never spuriously overflowing. It moves value only:
    the access set, refund, logs and transient store pass through untouched,
    because the target account was already warmed when it was loaded, before this
    is reached. *)

val equal : t -> t -> bool
(** Exact content equality across the world, the access set, the refund, the log
    journal and the transient store — the property the tests need in order to
    state "the revert changed nothing".

    Note it is stricter than "same post-state": two runs reaching the same world
    by different access patterns compare unequal here. That is correct, because
    the warm set is gas-observable, but it makes this a sharper oracle than a
    state comparison and will produce confusing failures if used as one.

    The pre-transaction world of {!base} is compared too. Within one run it can
    never be the component that separates two values — {!start} is the only thing
    that sets it and nothing moves it afterwards — so this costs the tests
    nothing today; it is here so that the comparison stays exact on the day
    [CALL] makes that field mean something narrower. *)
