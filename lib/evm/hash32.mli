(** The 32-byte gate for every header field that is neither a keccak digest nor
    a protocol digest: the four trie roots, the close-epoch randomness, and the
    two pinned constants.

    It exists because {!Block_roots} and {!Tn_trie.Trie} return a plain [string]
    and [block_roots.ml:5-10] deliberately collapses an unreachable
    [Duplicate_key] into an error {e string} rather than a root. Without a gate
    that string would flow straight into a header field and hash to something no
    other node computes; with one it becomes a visible [None] at the boundary.

    Three header fields are deliberately {e not} this type. [parent_hash] is a
    {!Tn_keccak.t}, matching {!Block_hashes.of_recent}, which refuses raw bytes;
    [ommers_hash] and [parent_beacon_block_root] are {!Tn_types.Digests}
    newtypes. The close-epoch randomness cannot be a {!Tn_keccak.t} either:
    [tn_keccak.mli:26-42] gives that type exactly one producer ([digest]) and
    explicitly refuses to add an [of_bytes], so a randomness value decoded out of
    a 32-byte [extra_data] could never be built. This module is the answer to
    that. *)

type t
(** A 32-byte value that is not a {!Tn_keccak.t} and not a
    {!Tn_types.Digests} protocol digest: a trie root, the close-epoch
    randomness, a pinned constant. Abstract, so the only way to name one is
    through a constructor that has checked the length. *)

val length : int
(** [32]. *)

val of_bytes : string -> t option
(** [Some] exactly when the string is {!length} bytes. Deliberately fallible
    even for the roots {!Block_roots} returns: [block_roots.ml:5-10] collapses
    its unreachable [Duplicate_key] into an error {e string} rather than a root,
    so without this gate that path would produce a header that hashes to
    something no other node computes. *)

val of_keccak : Tn_keccak.t -> t
(** Total: a keccak digest is 32 bytes by construction. *)

val zero : t
(** Thirty-two zero bytes. *)

val to_bytes : t -> string
(** The {!length} bytes, most significant first, exactly as they go into an RLP
    byte string (leading zeros preserved, never the scalar rule). *)

val to_hex : t -> string
(** Sixty-four lowercase hex digits, no [0x] prefix, matching
    {!Tn_keccak.to_hex}. For diagnostics and test failure messages. *)

val equal : t -> t -> bool
(** Byte equality. *)

val compare : t -> t -> int
(** Lexicographic byte ordering, which for a fixed width is the big-endian
    numeric ordering. Present so a set or a map can be keyed on a root. *)
