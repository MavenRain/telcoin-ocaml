(** The Snappy stream framing format: a stream identifier chunk, then data,
    padding and skippable chunks, each data chunk carrying the masked CRC-32C
    of its uncompressed bytes.

    This is the layer telcoin-network's wire codec drives
    (crates/network-libp2p/src/codec.rs:91-94,140-143) through
    [snap::write::FrameEncoder] and [snap::read::FrameDecoder]. Every
    constant below is pinned to snap 1.1.1 and was verified against the crate
    source and a live experiment by the chunk-44 oracle harness before this
    module was written: 65536 uncompressed bytes per chunk
    (snap/src/lib.rs:97), a 76490-byte ceiling on any declared chunk length
    (snap/src/frame.rs:12, enforced at read.rs:129-135), the chunk type bytes
    of frame.rs:31-34 and the reserved ranges of read.rs:138-147. *)

type error =
  | Missing_stream_identifier
      (** The stream does not open with a [0xff] chunk (snap read.rs:123-128). *)
  | Bad_stream_identifier
      (** A [0xff] chunk whose declared length is not 6 or whose body is not
          ["sNaPpY"] (snap read.rs:160-171). *)
  | Truncated_chunk
      (** The input ends inside a chunk header, a checksum or a chunk body,
          which snap reports as a failure to fill its buffer. *)
  | Unskippable_reserved of int
      (** A chunk of a reserved type in [0x02 .. 0x7f], which a conforming
          decoder must reject (snap read.rs:138-142). *)
  | Crc_mismatch of { expected : int; actual : int }
      (** The masked CRC-32C in the chunk header is not the masked CRC-32C of
          the uncompressed bytes it covers. *)
  | Block_too_large of { len : int }
      (** One chunk carries more than 65536 uncompressed bytes: [len] is what
          it asked (snap read.rs:182-187 and 217-222). *)
  | Declared_length_too_large of { len : int }
      (** The 3-byte declared chunk length is above 76490. snap checks this
          BEFORE it dispatches on the chunk type (read.rs:129-135), so it is
          a size rejection distinct from {!Block_too_large}; the chunk-44
          fact note records it as a rule the design sketch did not carry. *)
  | Missing_checksum of { len : int }
      (** A [0x00] or [0x01] chunk whose declared length is below 4, so it
          cannot even hold the checksum (snap read.rs:174-179, 201-206). *)
  | Raw of Snappy_raw.error
      (** A [0x00] chunk whose payload is not a valid raw Snappy block. *)

val error_to_string : error -> string
(** [error_to_string e] is a one-line rendering of [e], meant to be read by a
    human in a log or a test report. *)

val compress : string -> string
(** [compress s] is a Snappy frame stream that decompresses back to [s]: the
    stream identifier chunk, then one uncompressed ([0x01]) chunk per slice
    of at most 65536 bytes, each with the masked CRC-32C of its slice.

    A compressed ([0x00]) chunk is never emitted. With a literal-only raw
    encoder a compressed chunk can never be smaller than the uncompressed
    form, so that branch would be dead code, and the bytes are not required
    to match Rust's anyway: compressed bytes are never canonicalized, hashed
    or signed in telcoin-network (GT:355-356), so decode compatibility is the
    whole bar. The emitted size is [n + 10 + 8 * ceil (n / 65536)], which
    stays inside the [32 + n + n/6] interop bound the wire codec checks
    (GT:294-298) at every size. *)

val decompress : max_len:int -> string -> (string, error) result
(** [decompress ~max_len stream] expands [stream] and stops once [max_len]
    bytes are produced, exactly as Rust's
    [FrameDecoder::new(r).take(max_len)] does.

    The truncation semantics are the decisive part, measured against snap
    before this module was written. A chunk that STRADDLES the cap is fully
    decoded and its CRC is checked, then its output is cut to the cap; chunks
    that lie WHOLLY past the cap are never read, so a bad checksum or a
    truncated body there stays invisible, and [max_len = 0] accepts anything,
    even a stream with no identifier. Success returns at most [max_len]
    bytes and can return fewer: an under-run is not an error at this layer,
    it is what the wire codec's own length check catches.

    [max_len] has no precondition. Rust counts the limit in [u64] and so
    cannot express a negative one; here a negative [max_len] behaves exactly
    like [max_len = 0], returning [Ok ""] for any input. This function is
    total: it returns a value of the result type for every [max_len] and
    every [stream], and raises nothing. *)
