(** An execution-layer account — the port of Rust's account state.

    An account is what the world state maps an address to: its {!nonce} (the
    number of transactions it has sent) and its {!balance} (its native-token
    holdings). Rust's account also carries a [code_hash] and a [storage_root];
    every account this chunk models is externally owned — no contract code, no
    storage — so those two fields, which need the state trie, RLP and keccak this
    port defers with the rest of its crypto, are left to the contract-execution
    chunk. Until then every account is empty of code, and {!is_empty} is the
    EIP-161 emptiness test over the two fields present. *)

type t

val make : nonce:Nonce.t -> balance:U256.t -> t

val empty : t
(** Zero nonce and zero balance — an account that has never been touched, the
    value the world state reads back for an address it holds no entry for. *)

val nonce : t -> Nonce.t
val balance : t -> U256.t

val is_empty : t -> bool
(** [true] for an account with zero nonce and zero balance (and, once code
    exists, no code). EIP-161: an empty account is indistinguishable from an
    absent one, so the world state stores no entry for it. *)

val credit : t -> U256.t -> t option
(** Add to the balance, [None] on the (total-supply-unreachable) 256-bit
    overflow. *)

val debit : t -> U256.t -> t option
(** Subtract from the balance, [None] when the balance is below the amount. *)

val increment_nonce : t -> t
(** The account after sending one transaction: its nonce advanced by one. *)

val equal : t -> t -> bool
val compare : t -> t -> int
