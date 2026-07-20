(** The EIP-2929 access set: which addresses and which storage slots this
    transaction has already touched, and therefore what a touch costs.

    Berlin priced the first touch of an address or a slot far above the rest —
    2600 against 100, 2100 against 100 — to charge for the trie read a node
    really performs. That makes "has this been touched before" a gas-observable
    fact, and this module answers it.

    The whole module exists to make the question impossible to skip. {!warmth}
    is abstract and has no constructor: the only way to obtain one is
    {!touch_account} or {!touch_slot}, which necessarily return the grown set
    alongside it. Since {!Gas.account_access_cost}, {!Gas.storage_access_cost}
    and {!Gas.sstore_dynamic_cost} accept nothing else, a cold surcharge can
    never be computed from a guess, a stale flag or a lookup that did not
    happen. The dangerous direction — pricing without consulting — is closed by
    the types. The other direction, consulting without charging, is closed only
    by tests, and §12 of the test plan says which ones.

    Nothing here is pre-warmed. EIP-2929 pre-warms the origin and the callee,
    EIP-3651 adds the block coinbase, and EIP-2930 adds the transaction's access
    list; all four are the transaction layer's business and arrive through
    {!of_transaction}. An {!empty} set means every first touch is cold, which is
    the honest reading of it rather than a hidden favour.

    Reverting is not this module's business. revm un-warms on revert by
    replaying [AccountWarmed] and [StorageWarmed] journal entries, both of which
    call [mark_cold] ([revm-context-interface] [journaled_state/entry.rs:317-319]
    and [:391-398]); here the set is persistent and lives inside {!Effects.t}, so
    a frame that reverts simply never hands its set back. A reverted [SLOAD]
    therefore leaves its slot cold, matching revm exactly, with no code. *)

open Tn_types

type t
(** The touched addresses and the touched (address, slot) pairs. Persistent: a
    touch returns a new set and leaves the old one intact, which is what lets a
    reverting frame drop its warmings by dropping the value. *)

type warmth
(** The result of one touch: whether it was the first. Abstract and
    constructorless, so a value of it can only ever describe a lookup that
    really happened. *)

val empty : t
(** Nothing warm. Not the state a real transaction begins in; see
    {!of_transaction}. *)

val of_transaction :
  addresses:Units.Address.t list ->
  slots:(Units.Address.t * Tn_state.U256.t) list ->
  t
(** The set a transaction begins with: the origin, the call target, the block
    coinbase and every entry of the EIP-2930 access list, assembled by the
    transaction layer. It takes them as arguments rather than deriving them
    because deriving them needs a transaction type this port does not have yet.

    The access-list share of both arguments is exactly what
    {!Env.Tx.declared_warm} returns, so a declared list reaches this function
    without being reshaped at the call site — the flattening of the grouped wire
    form lives there and only there. The EIP-2929 and EIP-3651 addresses are the
    caller's to prepend to [~addresses]. Both arguments become sets, so repeats
    and order are not observable in the result. *)

val touch_account : t -> Units.Address.t -> warmth * t
(** Record an account access and report whether it was the first. *)

val touch_slot : t -> Units.Address.t -> Tn_state.U256.t -> warmth * t
(** Record a storage-slot access and report whether it was the first. The slot
    is keyed by the pair: warming [(a, k)] says nothing about [(b, k)]. *)

val is_cold : warmth -> bool
(** Whether the touch that produced this witness was the first one. The only
    observation of a {!warmth} other than handing it to a price. *)

val mem_account : t -> Units.Address.t -> bool

val mem_slot : t -> Units.Address.t -> Tn_state.U256.t -> bool
(** Observe the set without recording a touch.

    These exist for tests and for nothing else, and they are safe to expose
    precisely because they return a [bool]: no pricing function in {!Gas} accepts
    a [bool], so a caller cannot route one of these into a surcharge. The
    query-and-then-warm pair that a naive interface offers — where the query
    returns the same type the price consumes — is the shape this module was
    written to forbid. *)

val equal : t -> t -> bool
(** Exact equality of both sets. Sound as content equality because a set holds
    membership and nothing else: nothing records {e when} or {e how often} an
    entry was touched, only that it was. *)
