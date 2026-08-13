(** The raw Snappy block format: a varint preamble, then literal and copy
    tags. This is the payload of a [0x00] frame chunk; the stream framing
    lives in {!Snappy_frame}.

    The decoder is COMPLETE, because it must accept whatever the Rust
    compressor emits: the varint preamble of snap/src/bytes.rs:73-90, the
    literal tags and the copy tags with a 1-byte, 2-byte or 4-byte offset of
    snap/build.rs:40-67. The encoder is deliberately conservative and emits
    one literal run, which is valid Snappy that every compliant decoder
    accepts. That imbalance is sound because compressed bytes are never
    canonicalized, hashed or signed anywhere in telcoin-network (GT:355-356):
    decode compatibility is the only bar, and the size of the literal-only
    form stays far inside the interop bound [32 + n + n/6] that the wire
    codec applies (GT:294-298). *)

type error =
  | Truncated
      (** The input ends in the middle of the preamble, a tag, a literal or a
          copy offset. *)
  | Preamble_overflow
      (** The varint preamble does not fit in 32 bits, so no conforming
          compressor produced it (snap rejects the same inputs through
          [Error::Header] and [Error::TooBig]). *)
  | Copy_offset_out_of_range of { offset : int; produced : int }
      (** A copy tag points [offset] bytes back, which is 0 or more than the
          [produced] bytes decoded so far. *)
  | Length_mismatch of { declared : int; produced : int }
      (** The tags produce a different number of bytes than the preamble
          declared: [produced] is what the tags reach, [declared] what the
          preamble promised. *)
  | Exceeds_max of { declared : int; max : int }
      (** The preamble declares [declared] bytes, more than the [max] the
          caller allows. The frame layer sets that maximum to the 65536-byte
          chunk cap, so this is the block-level half of the size rule. *)

val error_to_string : error -> string
(** [error_to_string e] is a one-line rendering of [e], meant to be read by a
    human in a log or a test report. *)

val decode : max_len:int -> string -> (string, error) result
(** [decode ~max_len block] expands one raw Snappy block. The preamble must
    declare at most [max_len] bytes, and the tags must produce exactly the
    declared number of bytes; anything else is an {!error}, never an
    exception. *)

val encode : string -> string
(** [encode s] is a raw Snappy block that expands to [s]. It is total: the
    preamble plus one literal run always fits. The bytes are one valid
    encoding of [s], not the only one, and they agree with snap's own output
    on inputs snap also leaves uncompressed. *)
