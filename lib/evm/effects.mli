(** Everything an execution frame can change outside itself, as one persistent
    value.

    A frame reads and writes the world, warms accounts and slots, and accrues
    refunds. revm tracks all three with a mutable state and an undo log it
    replays backwards on revert ([revm-context-interface]
    [journaled_state/entry.rs]). It has to: its state is a mutable map and there
    is no older version left to return to.

    This port has one. {!Tn_state.World_state.t}, {!Access.t} and the refund
    counter are all persistent, so the value that {e was} the state before a
    frame ran is still in the caller's hand after it. A checkpoint is a binding,
    a revert is using the old binding, and an exceptional halt is dropping the
    new one. Undoing is not an operation, it is the absence of one:
    {!Interpreter.Reverted} and {!Interpreter.Failed} simply carry no {!t}.

    That is also why there is no checkpoint stack here and why there will not
    need to be one when calls arrive. A sub-frame is handed its parent's {!t} and
    its success hands one back, so nesting is function composition and a reverted
    child is a value the parent drops. Every class of bug in which an undo entry
    is pushed for one change and forgotten for another is absent because there is
    no undo code.

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
    and the pre-transaction world stops being a single value. *)

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
val loaded : 'a load -> 'a
val warmth : 'a load -> Access.warmth

val warmed : 'a load -> t
(** The effects with the access recorded. For a read that is everything the
    lookup changed; for {!plan_store} the write is {e not} applied, see
    {!commit_store}. *)

val balance : t -> Units.Address.t -> Tn_state.U256.t load
(** [BALANCE]: read an account's balance and warm the account. Total — an
    account with no entry reads zero. *)

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

val plan_store :
  t ->
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

val equal : t -> t -> bool
(** Exact content equality across the world, the access set and the refund — the
    property the tests need in order to state "the revert changed nothing".

    Note it is stricter than "same post-state": two runs reaching the same world
    by different access patterns compare unequal here. That is correct, because
    the warm set is gas-observable, but it makes this a sharper oracle than a
    state comparison and will produce confusing failures if used as one.

    The pre-transaction world of {!base} is compared too. Within one run it can
    never be the component that separates two values — {!start} is the only thing
    that sets it and nothing moves it afterwards — so this costs the tests
    nothing today; it is here so that the comparison stays exact on the day
    [CALL] makes that field mean something narrower. *)
