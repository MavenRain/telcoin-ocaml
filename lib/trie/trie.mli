(** Merkle-Patricia-Trie roots — the state, storage, transaction and receipt
    commitments.

    A trie root is [keccak256] of the RLP of the trie built from a complete set
    of key/value pairs. This module computes roots only (it never persists or
    proves against a node store), which is all the consensus-critical paths need:
    a block header commits to a [stateRoot], a [transactionsRoot] and a
    [receiptsRoot], and each is a root over a set known in full at the time.

    The builder is the recursive, group-by-nibble construction over the {b
    complete, sorted, de-duplicated} set (yellow paper Appendix D), not reth's
    streaming [HashBuilder]; both yield identical roots, and the recursive form
    is total and obviously terminating. Keys are raw byte strings, unpacked to
    nibbles internally; values are raw bytes the node encoder wraps exactly once.
    A shorter key that is a strict prefix of a longer one is supported: it lands
    in a branch's value slot, so the general Ethereum trie-test corpus is a valid
    oracle. The two prefix-free entry points, {!secure_root_of} (keys are 32-byte
    hashes) and {!ordered_trie_root} (keys are [RLP(index)]), never trigger that
    slot and so are byte-identical to reth.

    The root is {b always} [keccak256] of the root node's RLP, even when that RLP
    is under 32 bytes: the inline-versus-hash rule is for {e children}, never for
    the top. The empty set roots to {!empty_root}. *)

type error =
  | Duplicate_key of string
      (** Two entries share a key (shown in hex). The set fed to a root must be a
          map; rather than silently take a last-writer as reth's streaming
          builder would (it in fact panics), this is reported. *)

val error_to_string : error -> string
(** Render an {!error} as a short human-readable string. *)

val empty_root : string
(** The 32-byte root of the empty trie,
    [56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421]. It is
    [keccak256(rlp(""))], i.e. [keccak256(0x80)]; a codeless account's
    [storage_root] and an empty transaction/receipt trie both take this value.
    Distinct from [keccak256("")] (the empty {e code} hash), which is a different
    constant. *)

val root : (string * string) list -> (string, error) result
(** The 32-byte root committing to a complete key/value set. Keys are raw byte
    strings, values are raw bytes wrapped once by the node encoder. The order of
    the input does not matter (the builder sorts). [Ok empty_root] on the empty
    list; [Error (Duplicate_key _)] if two entries share a key. *)

val secure_root_of : (string * string) list -> (string, error) result
(** As {!root}, but each key is replaced by its [keccak256] before insertion —
    the "secure trie" used for the state trie (key = [keccak256(address)]) and
    the storage trie (key = [keccak256(slot)]). Values are passed through
    unchanged. *)

val ordered_trie_root : string list -> string
(** The transactions/receipts root over a list of {e already-encoded} items
    (verbatim EIP-2718 envelopes). Item [i] is stored under key
    [RLP(adjust_index_for_rlp i n)] so the [RLP(index)] keys are visited in
    nibble-sorted order. Keys are unique by construction, so this is total and
    returns a plain root; the empty list gives {!empty_root}. *)

val ordered_trie_root_rlp : string list -> string
(** As {!ordered_trie_root}, but each item is RLP-string-wrapped
    ({!Tn_rlp.Rlp.encode_bytes}) before insertion — the [Encodable]-of-bytes
    variant, as opposed to the verbatim-envelope variant {!ordered_trie_root}. *)

val adjust_index_for_rlp : int -> int -> int
(** [adjust_index_for_rlp i len] is the position item [i] of a [len]-item ordered
    trie is visited at, so the [RLP(index)] keys are fed in nibble-sorted order
    (alloy-trie [src/root.rs:8-16]): an index above [0x7f] is left in place; index
    [0x7f], and the index whose successor equals [len], map to [0]; every other
    index is bumped by one. Exposed so the permutation can be unit-tested at the
    [0x7e]/[0x7f]/[0x80] boundary independently of a full root. *)

val account_rlp :
  nonce:int -> balance:Tn_state.U256.t -> storage_root:string -> code_hash:string -> string
(** The RLP of a state-trie account: the four-element list
    [\[nonce; balance; storage_root; code_hash\]] in exactly that order
    (alloy-trie [src/account.rs:6-20]). [nonce] and [balance] use the scalar rule
    (trimmed big-endian, zero as [0x80]); [storage_root] and [code_hash] are
    32-byte hashes wrapped as byte-strings ([0xa0 || 32 bytes]). This is the
    value to insert (under [keccak256(address)]) when building a state root with
    {!secure_root_of}. *)
