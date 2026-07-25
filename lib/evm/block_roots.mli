(** The block-header commitments: state, storage, transactions and receipts
    roots, plus the state-root agreement oracle.

    These are functions over {!Tn_state.World_state.t} / {!Tn_state.Account.t}
    rather than methods on those types because the state library sits below the
    trie in the dependency graph and cannot call it: [tn_trie] already depends on
    [tn_state], so the roots must live one library up, here in [tn_evm]. *)

val storage_root : Tn_state.Account.t -> string
(** The account storage-trie root: {!Tn_trie.Trie.secure_root_of} over each
    nonzero slot, keyed by the 32-byte big-endian slot (keccak'd inside
    [secure_root_of]) with value the scalar RLP of the slot word. Empty storage
    gives {!Tn_trie.Trie.empty_root}. *)

val state_root : Tn_state.World_state.t -> string
(** The world-state trie root: {!Tn_trie.Trie.secure_root_of} over every account
    {!Tn_state.World_state.accounts} returns, keyed by the raw 20-byte address
    (keccak'd inside [secure_root_of]) with value
    [account_rlp(nonce, balance, storage_root account, code_hash)]. No accounts
    gives {!Tn_trie.Trie.empty_root}. *)

val transactions_root : string list -> string
(** The transactions root over caller-supplied VERBATIM EIP-2718 transaction
    envelopes. The port defers ECDSA, so {!Transaction.t} carries no signature and
    cannot be self-encoded to a signed envelope here; the caller passes
    already-encoded 2718 byte strings. Thin wrapper over
    {!Tn_trie.Trie.ordered_trie_root}. Empty gives {!Tn_trie.Trie.empty_root}. *)

val type_byte : Transaction.t -> int
(** The EIP-2718 type byte from {!Transaction.fee}: [Legacy -> 0],
    [Access_list -> 1], [Dynamic -> 2]. The port stores no type byte; it is
    recovered from the fee sum. *)

val receipts_root : (int * Receipt.t) list -> string
(** The receipts root. Each pair is [(type_byte, receipt)] in block order.
    [cumulative_gas_used] is the running prefix-sum of {!Receipt.gas_used} (net of
    refund); each leaf value is {!Receipt_envelope.encode_2718}. Empty gives
    {!Tn_trie.Trie.empty_root}. *)

val receipts_root_of_block : Transaction.t list -> Receipt.t list -> string option
(** Convenience: zip a block's transactions with its receipts, deriving each type
    byte via {!type_byte}, then {!receipts_root}. [None] on a length mismatch. *)

val agree : Tn_state.World_state.t -> Tn_state.World_state.t -> bool
(** The agreement oracle: [state_root a = state_root b]. This is what block import
    and consensus should use to check that a computed post-state matches a peer's
    or a header's [stateRoot]. {!Tn_state.World_state.equal} is kept and stays the
    exact structural equality used in tests and canonicity reasoning. *)
