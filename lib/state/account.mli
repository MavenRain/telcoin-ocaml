(** An execution-layer account — the port of Rust's account state.

    An account is what the world state maps an address to: its {!nonce} (the
    number of transactions it has sent), its {!balance} (its native-token
    holdings) and its {!storage} (the contract slots written at that address).
    Rust's account also carries a [code_hash] and a [storage_root]; no account
    this chunk models has code, and the storage {e root} — the trie hash
    committing the slot map — needs the state trie, RLP and keccak this port
    defers with the rest of its crypto, so both are left to a later chunk. The
    slots themselves are present, because the interpreter's [SSTORE] needs
    somewhere to put them. Until code exists every account is empty of code, and
    {!is_empty} is the EIP-161 emptiness test over the fields present. *)

type t

val make : nonce:Nonce.t -> balance:U256.t -> t
(** An account with the given nonce and balance and empty storage. Storage is
    deliberately not a labelled argument: every caller that constructs an
    account constructs one that has never executed, and a required [~storage]
    would make each of them write [Storage.empty] to say so. Slots arrive
    through {!set_slot} and {!with_storage}, which is the only way execution
    produces them. *)

val empty : t
(** Zero nonce, zero balance and empty storage — an account that has never been
    touched, the value the world state reads back for an address it holds no
    entry for. *)

val nonce : t -> Nonce.t
val balance : t -> U256.t
val storage : t -> Storage.t

val with_storage : t -> Storage.t -> t
(** The account with its storage replaced. Nonce and balance are untouched:
    [SSTORE] moves no value and sends no transaction. *)

val slot : t -> U256.t -> U256.t
(** The word at a storage slot, zero if unwritten — {!Storage.get} lifted. *)

val set_slot : t -> U256.t -> U256.t -> t
(** The account after an [SSTORE]. Writing zero clears the slot. *)

val is_empty : t -> bool
(** The EIP-161 emptiness test: zero nonce, zero balance and — once code exists
    — no code. Storage is deliberately {e not} a conjunct, because EIP-161 does
    not make it one: the specification deletes a touched account on nonce,
    balance and code alone. This is the predicate state-clearing and the
    [CALL]-to-empty surcharge will use, and it must stay literal.

    It is {e not} the predicate the world state prunes on. See {!is_absent}. *)

val is_absent : t -> bool
(** [is_empty t && Storage.is_empty (storage t)] — the predicate
    {!World_state.set_account} prunes on, and the reason {!World_state.equal} is
    still exact content equality now that accounts carry storage.

    The two predicates exist separately because they answer different questions.
    {!is_empty} asks what the protocol considers an empty account; {!is_absent}
    asks whether an entry carries any information at all, which is what makes
    deleting it representation-preserving. On a real chain they agree on every
    account that can exist: reaching storage requires executing [SSTORE] at that
    address, which requires code, which makes {!is_empty} false. This port has
    no code in an account yet and no [CREATE], so the two differ on exactly one
    class of value — zero nonce, zero balance, nonempty storage — and pruning on
    the stronger predicate keeps that account rather than losing its writes.
    That is the conservative direction: this port loses no state where a real
    client would keep it.

    When [code_hash] arrives, {!is_empty} gains its third conjunct, {!is_absent}
    is unchanged, {!World_state.set_account} is unchanged, and the divergence
    closes. *)

val credit : t -> U256.t -> t option
(** Add to the balance, [None] on the (total-supply-unreachable) 256-bit
    overflow. *)

val debit : t -> U256.t -> t option
(** Subtract from the balance, [None] when the balance is below the amount. *)

val increment_nonce : t -> t
(** The account after sending one transaction: its nonce advanced by one. *)

val equal : t -> t -> bool
(** Exact content equality over every field, storage included — sound because
    {!Storage.t} is canonical on its own. *)

val compare : t -> t -> int
