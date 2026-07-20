(** The world state — the map from address to {!Account}.

    The execution state maps every 20-byte address to its {!Account}. An address
    with no entry reads back as {!Account.empty} (EVM semantics: an untouched
    account has zero nonce, zero balance and no storage), so the state is total
    on addresses, and total again at the slot level: {!storage} of a slot of an
    account that does not exist is zero. The representation is kept canonical —
    an entry that carries no information is never stored — so {!equal} is exact
    content equality, and two nodes that applied the same transactions from the
    same genesis hold identical states.

    An account's storage lives {e inside} its entry rather than in a second map
    keyed by address and slot. That placement is the reason orphan storage — a
    slot surviving the account it belongs to — is not representable here, and it
    is why {!remove_account} cannot forget half of its job.

    A state root (the trie hash that commits the whole map) needs the state trie,
    RLP and keccak this port defers with the rest of its crypto, so it arrives
    with that chunk; agreement is checked here by direct content equality. *)

open Tn_types

type t

val empty : t
(** No accounts — every address reads as {!Account.empty}. *)

val of_alloc : (Units.Address.t * U256.t) list -> t
(** The genesis state: fund each listed address with the given balance at nonce
    zero {e and empty storage} — the port of Rust's genesis [alloc] restricted to
    [GenesisAccount::with_balance]. A repeated address takes its last allocation;
    a zero allocation stores no entry.

    That restriction is a real gap, not a simplification. Reth's
    [GenesisAccount] carries a storage map and a nonce alongside the balance (and
    code, which no account in this port models yet), and a pair of address and
    balance can express none of it: an allocation with pre-populated storage
    would be funded here at {!Account.empty}'s storage and its slots silently
    lost. Nothing in this port passes storage at genesis, so nothing is lost
    today — but a chain whose genesis pre-populates storage, such as a
    pre-deployed system contract with a seeded configuration slot, needs this
    constructor widened to take an {!Account.t} (or the fields of a
    [GenesisAccount]) rather than a balance before its genesis is representable.
    Widening it, rather than writing the slots in afterwards with
    {!set_storage}, is what keeps genesis one total function of the alloc.

    This is the one constructor here that has fallen behind {!Account.t}; the
    account- and slot-level writers, {!set_account} and {!set_storage}, can
    express everything an account holds. *)

val account : t -> Units.Address.t -> Account.t
(** The account at an address, {!Account.empty} if the state holds no entry for
    it. Total. *)

val set_account : t -> Units.Address.t -> Account.t -> t
(** Replace the account at an address. An {!Account.is_absent} account removes
    the entry, keeping the representation canonical.

    Note the predicate. This used to prune on {!Account.is_empty}, which ignores
    storage — correctly, since EIP-161 ignores storage. With storage present
    that would erase an [SSTORE] into an account of zero nonce and zero balance,
    and {!equal} would stop being exact: two states differing in that slot would
    compare equal. {!Account.is_absent} is strictly stronger and covers every
    field {!Account.equal} compares, which is exactly the condition canonicity
    needs. *)

val balance : t -> Units.Address.t -> U256.t
val nonce : t -> Units.Address.t -> Nonce.t

val storage : t -> Units.Address.t -> U256.t -> U256.t
(** The word at a slot of an account, zero for an account with no entry or a
    slot never written. Total at both levels, in both arguments. *)

val set_storage : t -> Units.Address.t -> U256.t -> U256.t -> t
(** Write a word to one slot of one account, creating the entry if the write is
    nonzero and removing it again if the account is left {!Account.is_absent}.
    Clearing the only nonzero slot of an otherwise-empty account therefore
    restores a state {!equal} to the one before the first write. *)

val remove_account : t -> Units.Address.t -> t
(** Delete an account and, with it, all of its storage — the two halves live in
    one entry, so they cannot come apart.

    Its callers are deferred: [SELFDESTRUCT] and the end-of-transaction clearing
    of touched-empty accounts. It exists now so that the rule "deleting an
    account deletes its storage" has a named home before a later chunk
    rediscovers it, and so that a design that ever splits the two halves has an
    obvious thing to break. *)

val accounts : t -> (Units.Address.t * Account.t) list
(** Every stored (non-absent) account, in ascending address order. *)

val equal : t -> t -> bool
(** Exact content equality — still sound now that accounts carry storage,
    because {!Storage.t} is canonical on its own and {!Account.is_absent} covers
    every field {!Account.equal} compares. *)
