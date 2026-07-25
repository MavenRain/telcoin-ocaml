(** Hex-prefix (compact) path encoding — how a leaf or extension key is written.

    A nibble path is stored in a node as bytes, but a byte holds two nibbles, so
    an odd-length path would lose its last half-byte. Hex-prefix solves this with
    a one-byte header whose high nibble carries two flags — is this a leaf, and
    is the path an odd number of nibbles — and, when the path is odd, whose low
    nibble carries the first path nibble so that what remains packs evenly
    (alloy-trie 0.9.5 [src/nodes/mod.rs:224-244]).

    The flag high nibble is [2 * is_leaf + is_odd]:

    - extension, even length -> [0x00]
    - extension, odd length  -> [0x10] | first nibble
    - leaf, even length      -> [0x20]
    - leaf, odd length       -> [0x30] | first nibble

    There is {b no terminator nibble} in this pin: leaf-versus-extension is the
    explicit [is_leaf] flag, not a [0x10] appended to the path. The empty path
    encodes to the single flag byte ([0x20] for a leaf, [0x00] for an extension).
    {!decode} is the inverse, provided for round-trip testing; a root computation
    only ever encodes. *)

type error =
  | Empty_input
      (** {!decode} was given a zero-length buffer, which cannot even hold the
          flag byte. *)

val error_to_string : error -> string
(** Render an {!error} as a short human-readable string. *)

val encode : Nibbles.t -> is_leaf:bool -> string
(** Compact-encode a path. The result is the flag byte (see above) followed by
    the packed remainder of the path: for an odd path the first nibble is folded
    into the flag byte and the rest is packed; for an even path the whole path is
    packed after the flag. Total. *)

val decode : string -> (Nibbles.t * bool, error) result
(** Recover the [(path, is_leaf)] a {!encode} produced: read the flag byte for
    the leaf and parity bits, unpack the remaining bytes, and prepend the folded
    first nibble when the path was odd. [Error Empty_input] on an empty buffer.
    This is the inverse only up to the flag's meaning; it is used to prove the
    encoder round-trips, not to compute a root. *)
