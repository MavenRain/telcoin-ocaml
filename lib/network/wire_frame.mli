(** The telcoin-network wire envelope: a 4-byte little-endian uncompressed
    length, a 4-byte little-endian compressed length, then a Snappy frame
    stream whose content is the BCS message.

    This is the port of [crates/network-libp2p/src/codec.rs] at
    telcoin-network 31cc4e90: [encode_message] (112-154) and [decode_message]
    (32-105), in the same order of operations, with the async socket reads
    replaced by a whole buffer. Every request, response and gossip payload of
    the p2p layer crosses the wire inside this envelope.

    The header is eight bytes: the length of the BCS bytes BEFORE compression,
    then the length of the Snappy frame stream that follows, both unsigned
    32-bit little-endian (GT:265-271). The body is a Snappy stream-framing
    stream, never a raw Snappy block.

    What must match Rust and what may differ (GT:347-356): the eight header
    bytes, the meaning of both lengths and the [max_compress_len] bound MUST
    match, and this module pins them. The compressed bytes themselves MAY
    differ freely, because nothing in telcoin-network hashes, signs or
    canonicalizes them: only the decoded BCS payload matters. This port's
    {!Tn_snappy.Snappy_frame.compress} therefore emits uncompressed chunks and
    still interoperates, which the chunk-44 reverse gate proves by feeding its
    output back through the Rust [snap] decoder.

    Decoding is total: it never raises and reports every failure as {!error}.

    {2 The check order}

    [decode] runs Rust's checks in Rust's order, which is what makes the
    error taxonomy observable rather than incidental: the declared
    uncompressed length first, then the declared compressed length against
    the [max_compress_len] bound, then the presence of the body, then
    decompression under a [take] cap of the declared uncompressed length,
    and only then the produced length against that same declared value. A
    peer that lies about the uncompressed length in a downward direction is
    NOT caught here: [take] truncates the output to the lie and the length
    check compares the truncated length against the same lie, so both pass
    and the BCS parse is what finally rejects (GT:339). {!decode_msg} is
    where that failure surfaces, as {!Bcs_error}. *)

type header = private { uncompressed_len : int; compressed_len : int }
(** A parsed eight-byte header. Private: the only way to obtain one is
    {!parse_header}, so a header value always carries lengths that were read
    off the wire and checked against the caller's size limits. *)

type error =
  | Prefix_too_large of { declared : int; max : int }
      (** Check #1 (codec.rs:52-54): the declared uncompressed length is
          above the caller's [max_message_size]. Raised before any body byte
          is read, which is what stops a lying prefix from committing the
          reader to a large allocation. *)
  | Compressed_len_exceeds_bound of { declared : int; bound : int }
      (** Check #2 (codec.rs:63-67): the declared compressed length is above
          [max_compress_len declared_uncompressed_len], the largest a
          Snappy encoder could legitimately produce. *)
  | Truncated_body of { expected : int; got : int }
      (** Check #3 (codec.rs:78-83): the buffer holds fewer than
          [compressed_len] bytes after the header. [got] counts the bytes
          actually present after the header, matching the Rust reader's
          "delivered" count. *)
  | Snappy of Tn_snappy.Snappy_frame.error
      (** Check #5 (codec.rs:94): the body is not a valid Snappy frame
          stream, or a chunk inside the take window fails its checksum. *)
  | Length_mismatch of { declared : int; got : int }
      (** Check #6 (codec.rs:97-101): decompression produced a different
          number of bytes than the header declared. Only an under-run can
          reach this, since the take cap prevents an over-run. *)
  | Message_too_large of { len : int; max : int }
      (** Check #9 (codec.rs:134-136), the encode side: the BCS bytes are
          longer than [max_message_size]. Checked BEFORE compression, so a
          payload that would have compressed under the limit is still
          refused, exactly as Rust refuses it. *)
  | Header_truncated of { got : int }
      (** Fewer than eight bytes were offered, so there is no header to
          parse. Rust reads the two prefixes from a socket and reports the
          io error of a short read; this is the pure analog. *)

val error_to_string : error -> string
(** [error_to_string e] is a one-line rendering of [e], meant to be read by a
    human in a log or a test report. *)

val max_compress_len : int -> int
(** [max_compress_len n] is snap 1.1.1's [snap::raw::max_compress_len]
    (compress.rs:42-53): [32 + n + n / 6] with integer division, the ceiling
    check #2 applies to a declared compressed length. Pinned by the worked
    example of GT:294-297, [1_048_576 -> 1_223_370].

    Rust answers 0 for an [n] above [u32::MAX], because no such length can be
    declared in a 4-byte prefix; so does this, and so it does for a negative
    [n], which Rust cannot express at all. Rust also answers 0 when the
    computed sum [32 + n + n / 6] is itself above [u32::MAX], which starts at
    [n = 3_681_400_512]; the port applies the same clamp. A 0 bound rejects
    every non-zero compressed length, which is the intended refusal. *)

val parse_header : max_message_size:int -> string -> (header, error) result
(** [parse_header ~max_message_size wire] reads the eight-byte header at the
    front of [wire] and applies checks #1 and #2 to it, in that order. It
    looks at no other byte, so it answers for a buffer that holds the header
    alone: {!Header_truncated} when fewer than eight bytes are present,
    {!Prefix_too_large} when the declared uncompressed length is above
    [max_message_size], {!Compressed_len_exceeds_bound} when the declared
    compressed length is above {!max_compress_len} of it. *)

val encode : max_message_size:int -> string -> (string, error) result
(** [encode ~max_message_size bcs_bytes] is the full wire message carrying
    [bcs_bytes]: the size check first, then compression, then the header, in
    Rust's order (codec.rs:128-151). The size check runs BEFORE compression,
    so it measures the payload and not the compressed form.

    The only failure is {!Message_too_large}. The effective limit is
    [min max_message_size 0xffff_ffff], since a longer length cannot be
    expressed in the 4-byte prefix; every deployment limit is far below that
    ceiling (the node's is 1 MiB), where the limit is exactly
    [max_message_size]. *)

val decode : max_message_size:int -> string -> (string * int, error) result
(** [decode ~max_message_size wire] is the BCS payload carried by the message
    at the front of [wire], paired with the number of bytes that message
    occupied, [8 + compressed_len].

    Bytes beyond that message are ignored, not rejected, so a shim that
    reassembles a byte stream can decode one message and carry the remainder
    forward. The incremental 8192-byte read loop and its timeouts are runtime
    and are not ported here (GT:880).

    A declared uncompressed length SHORTER than the body's true content is
    accepted and truncates, matching Rust (GT:339); see the check order
    above. *)

type error_or_bcs =
  | Frame_error of error  (** The envelope itself was rejected. *)
  | Bcs_error of Tn_codec.Bcs.error
      (** The envelope was accepted and its payload is not a valid encoding
          of the requested type: taxonomy #7 (codec.rs:104), the one that
          catches a truncated or doctored prefix. *)

val error_or_bcs_to_string : error_or_bcs -> string
(** [error_or_bcs_to_string e] is a one-line rendering of [e]. *)

val encode_msg :
  max_message_size:int -> 'a Tn_codec.Bcs.t -> 'a -> (string, error_or_bcs) result
(** [encode_msg ~max_message_size codec v] encodes [v] with [codec] and wraps
    the result with {!encode}. The BCS encoder is total, so the only failure
    is a {!Frame_error}. *)

val decode_msg :
  max_message_size:int ->
  'a Tn_codec.Bcs.t ->
  string ->
  ('a * int, error_or_bcs) result
(** [decode_msg ~max_message_size codec wire] unwraps the envelope with
    {!decode} and then decodes its payload with [codec], requiring the whole
    payload to be consumed. The returned int is the wire length of the
    message, as in {!decode}. *)
