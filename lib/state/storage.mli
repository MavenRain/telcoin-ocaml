(** An account's contract storage: the total map from 256-bit slot to 256-bit
    word.

    Storage is conceptually an infinite array of zero words of which a finite
    set has been written. That totality is not a convenience, it is the EVM's
    rule: [SLOAD] of a slot no transaction ever touched is zero, not an error,
    so {!get} cannot fail and this module has no error type at all.

    The representation is canonical in the same way {!Tn_evm.Memory}'s is: a
    write of zero {e removes} the key rather than storing it. Two storages that
    read alike therefore have identical representations, {!equal} is exact
    content equality, and {!is_empty} means "every slot reads zero" — which is
    the conjunct {!Account.is_absent} needs before the world state may prune an
    account away. Storing zero into a slot that already reads zero is the
    identity function, which is what makes an [SSTORE] no-op invisible in the
    state as well as free of refund.

    The storage root — the trie hash committing this map — needs the state trie,
    RLP and keccak this port defers with the rest of its crypto. Agreement is
    checked here by direct content equality, exactly as {!World_state} does. *)

type t

val empty : t
(** Every slot reads zero. *)

val is_empty : t -> bool
(** [true] when every slot reads zero. Because the representation is canonical
    this is a constant-time emptiness test on the map, not a scan over it. *)

val get : t -> U256.t -> U256.t
(** The word at a slot, zero for a slot never written. Total. *)

val set : t -> U256.t -> U256.t -> t
(** [set t slot value]. A zero [value] removes the slot, keeping the
    representation canonical — so a contract that clears every slot it wrote
    leaves a storage {!equal} to the one it started from, and two nodes that
    reached that state by different routes still agree by structural equality. *)

val bindings : t -> (U256.t * U256.t) list
(** Every nonzero slot, in ascending slot order. *)

val equal : t -> t -> bool
(** Exact content equality — sound because the representation is canonical. *)

val compare : t -> t -> int
