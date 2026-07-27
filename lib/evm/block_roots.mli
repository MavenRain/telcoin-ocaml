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
(** The transactions root over VERBATIM EIP-2718 transaction envelopes, in block
    order. Thin wrapper over {!Tn_trie.Trie.ordered_trie_root}, whose leaf
    encoder wraps each value exactly once — so the bytes passed in must be the
    2718 form ({!Tx_envelope.encode_2718}) and never the network form and never
    an already-RLP-wrapped string. Empty gives {!Tn_trie.Trie.empty_root}. *)

val transactions_root_of : Tx_envelope.t list -> string
(** {!transactions_root} over {!Tx_envelope.encode_2718} of each envelope, in
    block order — the typed entry point, now that the port can encode a signed
    transaction of its own. Identical to calling the two by hand; it exists so
    the "must be 2718, not network, not re-wrapped" rule has one place it can be
    got wrong instead of every call site.

    Note that alloy roots the {e re-encoded} bytes of a decoded value
    ([alloy-consensus src/proofs.rs:19-24] over [Encodable2718]), so a root taken
    over the bytes as received and a root taken over {!Tx_envelope.t} values
    agree only for canonically framed input — which, since
    {!Tx_envelope.decode_2718} accepts nothing else, is the only input this port
    can produce a value from at all. *)

val withdrawals_root : Withdrawal.t list -> string
(** The withdrawals root: {!Tn_trie.Trie.ordered_trie_root} over
    {!Withdrawal.encode_rlp} of each withdrawal, in list order. Verbatim RLP
    bytes, not re-wrapped, which is the same rule {!transactions_root} states
    and for the same reason: the leaf encoder wraps each value exactly once.

    The empty list gives {!Tn_trie.Trie.empty_root}, which is alloy's
    [EMPTY_WITHDRAWALS]
    [0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421], the
    value telcoin writes on every non-closing block ([block.rs:976-978]);
    telcoin reaches it through
    [reth_primitives_traits::proofs::calculate_withdrawals_root]
    ([block.rs:34, 974]), a different helper from the alloy proofs used for
    transactions but the same ordered trie underneath.

    The ORDER is the caller's and is load-bearing: telcoin's list comes out of a
    [BTreeMap<Address, u32>] and is therefore sorted by execution address
    ascending ([crates/types/src/gas_accumulator.rs:123-158]). This function
    commits to whatever order it is given and does not sort. *)

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
