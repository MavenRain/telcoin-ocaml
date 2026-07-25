(** Trie nodes: the three kinds, their RLP, and the inline-versus-hash child rule.

    A Merkle-Patricia trie has three node kinds plus an empty sentinel
    (alloy-trie 0.9.5 [src/nodes/mod.rs:30-39]):

    - {b Leaf} — a terminal [\[hex_prefix key; value\]] two-element list;
    - {b Extension} — a [\[hex_prefix shared_key; child\]] two-element list that
      collapses a shared prefix;
    - {b Branch} — a seventeen-element list: sixteen child slots (one per nibble)
      and a value slot at index 16 for a key that ends exactly here;
    - {b Empty} — the empty root, which encodes to the single byte [0x80].

    {2 The value invariant}

    A leaf or branch {e value} is an opaque byte string, wrapped {b exactly once}
    as an RLP byte-string during serialization ({!Tn_rlp.Rlp.encode_bytes}, {e
    not} the scalar encoding). The caller has already produced the value bytes
    ([RLP(account)], a verbatim transaction, a trimmed storage scalar); the node
    encoder never trims or double-wraps them. This is why the one-byte value
    [0x00] serializes to a bare [0x00] and not to [0x80].

    {2 The child rule}

    A child appears in its parent not as a nested node but as a {!child_ref}: if
    the child's own RLP is {b strictly under 32 bytes} it is spliced verbatim,
    otherwise it is replaced by [0xa0] followed by its 32-byte Keccak hash — a
    33-byte reference (alloy-trie [src/nodes/rlp.rs:98-123]). The type is
    [private string] so a reference can only be produced by {!to_ref}: a parent
    list can splice it but can never accidentally re-wrap or forge one. The
    collapse threshold applies to child {e nodes} only — a value is inlined
    whatever its length. *)

type child_ref = private string
(** A child as it sits in its parent's list: either an under-32-byte inline RLP
    node, or a 33-byte [0xa0 || keccak256(rlp)] hash reference. Abstract enough
    to forbid construction outside {!to_ref}, yet a [private] alias so a parent
    can read its bytes to splice them. *)

type t =
  | Empty  (** The empty trie; encodes to the single byte [0x80]. *)
  | Leaf of { path : Nibbles.t; value : string }
      (** A terminal node: the remaining key [path] and the raw [value] bytes. *)
  | Extension of { path : Nibbles.t; child : child_ref }
      (** A shared prefix [path] pointing at a single [child] reference. *)
  | Branch of { children : child_ref option array; value : string option }
      (** Sixteen slots ([None] = absent, encoded as [0x80]) and the index-16
          value slot ([None] = no key ends here, encoded as [0x80]). The array
          is length 16. *)

val encode : t -> string
(** The full RLP encoding of a node: [0x80] for {!Empty}; the two-element list
    for a {!Leaf} or {!Extension}; the seventeen-element list for a {!Branch},
    where a present child slot contributes its reference verbatim, an absent slot
    contributes [0x80], and the value slot is [encode_bytes v] or [0x80]. *)

val to_ref : t -> child_ref
(** The reference a parent stores for this node: the node's own RLP when that is
    strictly shorter than 32 bytes, otherwise [0xa0] followed by its 32-byte
    Keccak-256 hash. This is the only producer of a {!child_ref}. *)
