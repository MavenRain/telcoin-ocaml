(** The EIP-7702 authorization loop — revm's [apply_auth_list]
    ([revm-handler] [pre_execution.rs:190-272]) as one fold over a
    {!Tn_state.World_state.t}, producing the four things pre-execution owes the
    rest of the transaction: the post-loop world, the warmed authorities, the
    refund pot, and a per-entry disposition list that makes the check ORDER
    directly assertable instead of inferred from state.

    {2 It cannot invalidate the transaction}

    Every defect is a per-entry SKIP ([pre_execution.rs:214-266]). The only
    authorization rule that rejects a transaction is the EMPTY list, and that
    lives in {!Executor}'s validation ([validation.rs:199-203]). That is why
    {!apply} is total and returns no [result].

    {2 Where it runs, and why that is load-bearing}

    AFTER the caller's fee deduction and nonce bump, BEFORE any frame exists
    ([handler.rs:150-153,179-185]). Three consequences the port must not lose:

    - a transaction may DELEGATE ITS OWN [to] TARGET and then execute the
      freshly installed delegate code IN THE SAME TRANSACTION — the canonical
      sponsored-setup shape, not a corner case;
    - a self-authorizing sender must sign nonce [tx.nonce + 1], and the loop
      bumps a SECOND time, so it ends at [tx.nonce + 2];
    - the journal entries sit BELOW every frame checkpoint ([frame.rs:166-167],
      [journal/inner.rs:466-484]), so delegations, authority nonce bumps and
      authority warmth ALL SURVIVE a top-level REVERT or an out-of-gas halt.
      The only undo is whole-transaction rejection. This module therefore works
      on a {!Tn_state.World_state.t} value — the one the executor's revert and
      halt arms also carry — and never on {!Effects.t} substate, which a
      reverting frame drops.

    {2 No deduplication}

    A repeated authority is re-checked against its ALREADY-BUMPED nonce and, if
    it matches, delegated again, bumped again, and may earn a SECOND refund
    ([pre_execution.rs:216]). Dedup loses both. *)

open Tn_types

type disposition =
  | Chain_id_mismatch
      (** Check 1 ([pre_execution.rs:217-221]): a nonzero [chain_id] unequal to
          the block's, compared over all 256 bits. Zero means any chain.
          NOTHING is warmed. *)
  | Nonce_saturated
      (** Check 2 ([pre_execution.rs:223-226]): the nonce is [2^64 - 1]. Tested
          BEFORE recovery, so this entry never recovers an authority and never
          warms. *)
  | Unrecoverable
      (** Check 3 ([pre_execution.rs:228-232]): bad parity, high [s], out-of-
          domain [r]/[s], or no curve point. Still nothing warmed. *)
  | Has_code
      (** Check 5 ([pre_execution.rs:239-245]): the authority holds code that is
          neither empty nor a designator. The authority is ALREADY WARM —
          check 4 ran first and unconditionally. *)
  | Nonce_mismatch
      (** Check 6 ([pre_execution.rs:247-250]): against the authority's LIVE
          nonce, i.e. after any bump earlier in this same loop. ALREADY WARM. *)
  | Applied of { refunded : bool }
      (** Checks 7 then 8+9: designator installed and nonce bumped, as one
          {!Tn_state.Account.delegate}. [refunded] is check 7's predicate
          ([pre_execution.rs:252-259]) and is INDEPENDENT of application — a
          fresh authority is delegated but earns nothing. *)

val disposition_to_string : disposition -> string
(** Render a {!disposition} as a short human-readable string, for diagnostics
    and test failure messages. *)

type t
(** One loop run. Abstract, {!apply} its only producer. *)

val apply :
  world:Tn_state.World_state.t ->
  chain_id:Tn_state.U256.t ->
  Authorization.signed list ->
  t
(** Fold over the list IN WIRE ORDER, threading the world. No sort, no dedup,
    no filter: the list's own order is the only ordering that exists. The empty
    list is the identity: its {!world} is the input world, its {!warmed} and
    {!dispositions} are empty and its {!refund} is zero, which is what lets the
    executor call this unconditionally for every transaction type — revm's own
    tx-type gate ([pre_execution.rs:196-200]) is subsumed because only a
    [Set_code] transaction carries a non-empty list.

    Checks 1 and 2 are re-stated here rather than read back out of
    {!Authorization.screen}, because revm's three [continue]s are
    indistinguishable in [screen]'s single [None] while a {!disposition} names
    the check that fired; [screen] still stands as the one gate between the
    pure checks and the warming, so the two can not drift in behaviour, only
    in attribution.

    {b Check 7's predicate, and the argument that licenses it.} revm's test is
    [!(is_empty && is_loaded_as_not_existing && !is_touched)]
    ([pre_execution.rs:252-259]). This port has no touched flag, and computes
    [not (Tn_state.Account.is_absent acct)] instead. That is exact for the
    first two conjuncts, because {!Tn_state.World_state.set_account} prunes
    every {!Tn_state.Account.is_absent} account, so an entry exists exactly
    when it carries information. The [!is_touched] conjunct is DROPPED on an
    argument, not on a type: within a type-4 transaction the only account
    touched before this loop is the CALLER, whose nonce was already bumped
    (type 4 is always a call, so [is_call()] holds), which defeats [is_empty]
    on its own; and any authority touched WITHIN the loop was delegated, which
    also bumps. {b The subsumption breaks the moment a later chunk introduces
    a pre-loop touch that leaves an account all-zero} — notably the end-of-tx
    EIP-161 clearing pass {!Tn_state.World_state} already flags as deferred.
    Re-derive this argument then; do not assume it. *)

val world : t -> Tn_state.World_state.t
(** The world after every applied delegation. THIS value, not the pre-loop one,
    is what {!Effects.start} must be built from and what the executor's revert
    and halt arms must return. *)

val warmed : t -> Units.Address.t list
(** The authorities check 4 loaded ([pre_execution.rs:234-237]) — every entry
    that passed checks 1-3, INCLUDING the ones checks 5 and 6 then skipped, in
    entry order and with a repeated authority listed once per entry. Warming is
    unconditional at step 4 and nothing later un-warms, so handing this list to
    {!Access.of_transaction} alongside the other pre-warmed addresses is
    exactly equivalent to warming inside the loop: a warm set records neither
    order nor multiplicity. It NEVER contains a delegation TARGET — the auth
    list warms authorities only ([journal.rs:170-173] is an address-set
    insert). *)

val refund : t -> int
(** [qualifying * (Intrinsic.per_empty_account_cost - per_auth_base_cost)] =
    12500 each ([pre_execution.rs:268-271]). This is the POT, not the discount:
    {!Executor} records it BEFORE the EIP-3529 [spent/5] cap, which usually
    binds, and the EIP-7623 floor can then zero it entirely. Exposed so a test
    can pin the pot without building a transaction big enough for the cap to
    clear. *)

val dispositions : t -> disposition list
(** One per input entry, in input order. This is how the check ORDER is
    ASSERTED rather than inferred: an entry that fails two checks at once
    reports the EARLIER one, and that is observable. *)

val per_auth_base_cost : int
(** [12500] ([revm-primitives] [eip7702.rs:5-9]). It is NEVER CHARGED. It
    appears only inside the refund difference above. The constant NAMED "base
    cost" is the one that is never a cost, and it lives in a DIFFERENT MODULE
    from {!Intrinsic.per_empty_account_cost} so no call site can reach for the
    wrong one. *)
