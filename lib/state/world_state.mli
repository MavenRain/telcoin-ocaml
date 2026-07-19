(** The world state — the map from address to {!Account}.

    The execution state maps every 20-byte address to its {!Account}. An address
    with no entry reads back as {!Account.empty} (EVM semantics: an untouched
    account has zero nonce and zero balance), so the state is total on addresses.
    The representation is kept canonical — an entry that would be empty is never
    stored (EIP-161) — so {!equal} is exact content equality, and two nodes that
    applied the same transactions from the same genesis hold identical states.

    A state root (the trie hash that commits the whole map) needs the state trie,
    RLP and keccak this port defers with the rest of its crypto, so it arrives
    with that chunk; agreement is checked here by direct content equality. *)

open Tn_types

type t

val empty : t
(** No accounts — every address reads as {!Account.empty}. *)

val of_alloc : (Units.Address.t * U256.t) list -> t
(** The genesis state: fund each listed address with the given balance at nonce
    zero — the port of Rust's genesis [alloc] ([GenesisAccount::with_balance]).
    A repeated address takes its last allocation; a zero allocation stores no
    entry. *)

val account : t -> Units.Address.t -> Account.t
(** The account at an address, {!Account.empty} if the state holds no entry for
    it. Total. *)

val set_account : t -> Units.Address.t -> Account.t -> t
(** Replace the account at an address. Setting it to an {!Account.is_empty}
    account removes the entry, keeping the representation canonical. *)

val balance : t -> Units.Address.t -> U256.t
val nonce : t -> Units.Address.t -> Nonce.t

val accounts : t -> (Units.Address.t * Account.t) list
(** Every stored (non-empty) account, in ascending address order. *)

val equal : t -> t -> bool
(** Exact content equality — sound because the representation is canonical. *)
