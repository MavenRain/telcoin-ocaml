(** Nibble paths — the half-byte alphabet a Merkle-Patricia trie is keyed on.

    A trie key is not a byte string but a sequence of {e nibbles} (4-bit digits),
    because a branch node fans out sixteen ways, once per possible nibble. A byte
    unpacks {b high nibble first}: the byte [0xAB] becomes the two-nibble path
    [\[0x0A; 0x0B\]], so [unpack] of an [n]-byte string yields exactly [2n]
    nibbles and the empty string yields the empty path (nybbles 0.4.8
    [src/nibbles.rs:421-425]). Every nibble held by a value of this type is in
    [\[0, 15\]].

    The type is abstract so the "each element is a nibble" invariant cannot be
    broken from outside: the only producers, {!unpack} and {!of_int_list}, mask
    every element into range. Accessors that a caller might drive out of bounds
    are made {e total} rather than partial — {!nth_opt} returns an [option], and
    {!sub}/{!drop} clamp their arguments — so the builder never needs a bounds
    [assert] and can never raise. *)

type t
(** A nibble path: an abstract sequence of 4-bit digits, most-significant nibble
    first, each in [\[0, 15\]]. Two paths are equal exactly when {!compare}
    returns [0]. *)

val unpack : string -> t
(** Split a byte string into nibbles, high nibble first: [unpack "\xAB\xCD"] is
    the path [\[0xA; 0xB; 0xC; 0xD\]] and [unpack ""] is the empty path. The
    result always has an even length (twice the byte count); an odd-length path
    can only arise from {!drop} or {!of_int_list}. This is the map from a raw
    trie key (an address, a hashed slot, an [RLP(index)]) to its path. *)

val of_int_list : int list -> t
(** Build a path from a list of integers, each masked to its low four bits
    ([n land 0xf]). Total: any integer is accepted and reduced into range. This
    is the way to construct an {e odd-length} path (which {!unpack} cannot yield)
    and the inverse used by {!Hex_prefix.decode}. *)

val to_list : t -> int list
(** The nibbles as a plain [int list], each in [\[0, 15\]] — the inverse of
    {!of_int_list} and the shape tests compare against. *)

val length : t -> int
(** The number of nibbles in the path. *)

val nth_opt : t -> int -> int option
(** The nibble at index [i], or [None] when [i] is outside [\[0, length)]. Total
    by construction: this is the {e only} nibble accessor, and it is what lets
    the branch builder group by [nth_opt key depth] and treat an exhausted key
    (a key whose path ends exactly at the current depth) as the [None] case,
    matched exhaustively, instead of indexing past the end. *)

val sub : t -> pos:int -> len:int -> t
(** The sub-path of [len] nibbles starting at [pos]. Total: [pos] and [len] are
    clamped to the path's bounds, so an out-of-range request yields the largest
    in-range prefix of what was asked rather than raising. Used to cut the shared
    prefix out of an extension node's key. *)

val drop : t -> int -> t
(** The path with its first [i] nibbles removed ([sub t ~pos:i ~len:(length - i)]),
    clamped so a non-positive [i] returns the whole path and an [i] past the end
    returns the empty path. This is how a leaf's remaining key is taken once the
    builder has descended [i] nibbles. *)

val pack : t -> string
(** Recombine the nibbles two per byte, high nibble first. An {e odd} trailing
    nibble is placed in the high four bits of the last byte with a zero low
    nibble ([\[a; b; c\]] packs to [\[0xab; 0xc0\]]); the packed length is
    [(length + 1) / 2] (nybbles 0.4.8 [src/nibbles.rs:1324-1331]). This is the
    body of the hex-prefix encoding after the flag byte. *)

val common_prefix_len : t -> t -> from:int -> int
(** The number of nibbles two paths share, counting from index [from]: the
    largest [k] such that the two paths agree on indices [from .. from + k - 1].
    Clamped to the shorter path, so when one path is exhausted at [from] (its
    length is exactly [from]) the result is [0]. The recursive builder feeds it
    the first and last keys of a {e sorted} group, for which this equals the
    longest common prefix of the whole group — the length of the extension node
    to emit. *)

val compare : t -> t -> int
(** Lexicographic comparison of two paths, nibble by nibble, with a shorter path
    ordered before a longer one that extends it. This is exactly the byte-order
    of the original keys, so sorting the [(path, value)] pairs by it puts a key
    immediately before any key it is a prefix of, which is what makes duplicate
    detection an adjacent-equality check and makes the first/last of a group its
    lexicographic extremes. *)

val to_hex : t -> string
(** The path as lowercase hex, one digit per nibble (so an even-length path reads
    as the original key's hex). Used to name the offending key in a
    {!Trie.Duplicate_key} error. *)
