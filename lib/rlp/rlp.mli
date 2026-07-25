(** Recursive Length Prefix (RLP), Ethereum's canonical structural serialization.

    RLP is the encoding every Merkle-Patricia-Trie node, every account leaf and
    every transaction/receipt envelope commits to, so byte-for-byte agreement
    with the deployed rules is a consensus fact, not a convenience. This module
    is the port of the reth pin [alloy-rlp] 0.3.13, read directly rather than
    from memory of the yellow paper; every rule below is cited to that source in
    the implementation.

    RLP encodes exactly two shapes: a {e byte string} and a {e list} of items.
    There is no integer type on the wire: a scalar is a byte string whose
    big-endian minimal (leading-zero-stripped) representation is encoded, so the
    number zero and the empty string share the encoding {b 0x80}. This module
    keeps the two paths distinct in its names ({!encode_bytes} for raw bytes,
    {!encode_scalar}/{!encode_nat} for numbers) precisely because conflating
    them is the classic RLP bug: a one-byte string [0x00] encodes as [0x00],
    while the number zero encodes as [0x80].

    {2 Five encoding forms}

    - a single byte in [\[0x00, 0x7f\]] is itself, with no prefix;
    - a string of [0..55] bytes is [0x80 + len] then the bytes;
    - a longer string is [0xb7 + len_of_len], the length big-endian, then bytes;
    - a list whose payload is [0..55] bytes is [0xc0 + len] then the items;
    - a longer list is [0xf7 + len_of_len], the length, then the items.

    Encoding is total. Decoding returns a {!error} rather than raising, and is a
    round-trip/structural decoder over a generic [Str]/[List] tree: it enforces
    the {e structural} header-canonicity rules — a single byte written in long
    form ([Non_canonical_single_byte]), a long-form header whose payload would fit
    the short form ([Non_canonical_size]), a length with a leading zero byte
    ([Leading_zero]), a length wider than a native int ([Overflow]), and any
    truncation ([Input_too_short] / {!decode_exact}'s [Trailing_bytes]). It does
    {e not} perform integer or fixed-width canonicity (it never interprets a
    string as a trimmed scalar, nor rejects a leading-zero integer payload or an
    over-wide fixed-array), so it is not a consensus-scoped typed decoder — that
    typed layer belongs to the caller. *)

type item =
  | Str of string  (** a byte string; may be empty *)
  | List of item list  (** a list of nested items *)
      (** A decoded RLP item. The tree is exhaustive: an item is a byte string or
          a list, nothing else, so no consumer needs a wildcard arm. *)

type error =
  | Input_too_short
      (** The buffer ended inside a header, a declared length, or a payload. *)
  | Non_canonical_single_byte
      (** A one-byte string [0x81 b] with [b < 0x80]: it had to use the bare
          byte [b]. *)
  | Non_canonical_size
      (** A long-form header ([0xb8..] / [0xf8..]) whose decoded payload length
          is below [56]: it had to use the short form. *)
  | Leading_zero
      (** A long-form length whose most significant byte is [0x00]: the length
          was not minimally encoded. *)
  | Overflow
      (** A declared length exceeds what a native [int] can hold — unreachable
          for any real buffer, present so decode is total on adversarial input. *)
  | Trailing_bytes
      (** {!decode_exact} found bytes after the single decoded item. *)

val error_to_string : error -> string
(** Render an {!error} as a short human-readable string, for diagnostics and
    test failure messages. *)

(** {1 Encoding} *)

val encode_bytes : string -> string
(** Encode a raw byte string ([\[u8\]::encode]). A one-byte string whose byte is
    [< 0x80] is returned unchanged; every other string, including the empty one
    (which becomes [0x80]) and a one-byte string [>= 0x80] (which becomes
    [0x81 b]), gets a length header. Leading zero bytes are {e preserved} — this
    is the byte-string path, not the scalar path. *)

val encode_scalar : string -> string
(** Encode a big-endian scalar given as bytes: strip leading [0x00] bytes, then
    apply {!encode_bytes}. An all-zero (or empty) input is the number zero and
    encodes as [0x80]. This is the path for the account nonce and balance, a
    storage slot value and an [RLP(index)] key. *)

val encode_nat : int -> string
(** Encode a non-negative native integer as an RLP scalar. Total: a value [<= 0]
    encodes as [0x80] (the correct encoding of zero), so a caller can never drive
    it to a partial branch; every call site in this port passes a length, an
    index or a small count, all [>= 0]. *)

val encode_list : string list -> string
(** Wrap a sequence of {e already-encoded} item byte-chunks in a list header.
    The chunks are concatenated in order with no separators; the caller has
    already applied {!encode_bytes}/{!encode}/a node reference to each. This is
    how a trie leaf ([\[hp_key; value\]]), extension and 17-slot branch are
    assembled. *)

val encode : item -> string
(** Recursively encode an {!item} tree: a [Str] via {!encode_bytes}, a [List] by
    encoding each element and wrapping with {!encode_list}. *)

val length_of_length : int -> int
(** The number of bytes a header occupies for a payload of the given length: [1]
    when the length is [< 56] (a single prefix byte), otherwise [1] plus the
    minimal big-endian byte count of the length. Exposed so a node encoder can
    size a payload before allocating. *)

(** {1 Decoding} *)

val decode : string -> (item * string, error) result
(** Decode the first item at the start of the buffer, returning it beside the
    unconsumed tail. Enforces the canonicity rules of {!error}. The tail lets a
    caller decode a sequence of items by looping until it is empty. *)

val decode_exact : string -> (item, error) result
(** Decode a buffer that must contain exactly one item: as {!decode}, but any
    remaining bytes are [Error Trailing_bytes]. *)
