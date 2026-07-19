(** Binary Canonical Serialization (BCS).

    A deterministic binary encoding in which every value has exactly one valid
    byte representation. Telcoin Network computes every digest and every
    signature over BCS-encoded structures, so byte-for-byte agreement with the
    Rust [bcs] crate is a prerequisite for wire compatibility with the Rust
    node.

    Encoding rules:
    - integers are little-endian and fixed width;
    - sequence lengths and enum variant indices are ULEB128, canonically
      encoded (a redundant continuation byte is rejected on decode);
    - struct fields are emitted in declaration order with no tags;
    - [option] is [0x00] for [None], [0x01] followed by the payload for [Some];
    - fixed-width byte arrays carry no length prefix.

    Decoding is total: it never raises, and reports failure as {!error}. *)

type error =
  | Unexpected_end_of_input of { offset : int; wanted : int }
  | Non_canonical_uleb128 of { offset : int }
  | Uleb128_overflow of { offset : int }
  | Invalid_bool of { offset : int; byte : int }
  | Invalid_option_tag of { offset : int; tag : int }
  | Unknown_variant of { offset : int; index : int }
  | Length_out_of_range of { offset : int; length : int }
  | Integer_out_of_range of { offset : int; width : int; value : int }
  | Trailing_bytes of { consumed : int; total : int }

val error_to_string : error -> string

(** {1 Low-level sinks and sources} *)

module Writer : sig
  type t

  val u8 : t -> int -> unit
  val u16 : t -> int -> unit
  val u32 : t -> int -> unit
  val u64 : t -> int64 -> unit
  val uleb128 : t -> int -> unit
  val raw : t -> string -> unit
end

module Reader : sig
  type t

  val u8 : t -> (int, error) result
  val u16 : t -> (int, error) result
  val u32 : t -> (int, error) result
  val u64 : t -> (int64, error) result
  val uleb128 : t -> (int, error) result
  val raw : t -> int -> (string, error) result
  val offset : t -> int
  val remaining : t -> int
end

(** {1 Codecs} *)

type 'a t
(** A paired encoder and decoder for values of type ['a]. *)

val make :
  write:(Writer.t -> 'a -> unit) ->
  read:(Reader.t -> ('a, error) result) ->
  'a t

val encode : 'a t -> 'a -> string

val decode : 'a t -> string -> ('a, error) result
(** Decodes a value and requires that the whole input be consumed; leftover
    bytes yield {!Trailing_bytes}, since a canonical encoding admits none. *)

val decode_prefix : 'a t -> string -> ('a * int, error) result
(** As {!decode}, but tolerates trailing bytes and reports how many were
    consumed. *)

(** {2 Primitives} *)

val unit : unit t
val bool : bool t
val u8 : int t
val u16 : int t
val u32 : int t
val u64 : int64 t
val uleb128 : int t

val bytes : string t
(** ULEB128 length prefix followed by the raw bytes. *)

val fixed_bytes : int -> string t
(** Exactly [n] raw bytes with no length prefix. Encoding a string of any
    other length is a programming error and is reported on decode as
    {!Length_out_of_range}; prefer wrapping this in a newtype that maintains
    the width as an invariant. *)

(** {2 Combinators} *)

val option : 'a t -> 'a option t
val list : 'a t -> 'a list t
val pair : 'a t -> 'b t -> ('a * 'b) t
val triple : 'a t -> 'b t -> 'c t -> ('a * 'b * 'c) t

val iso : inject:('a -> 'b) -> project:('b -> 'a) -> 'a t -> 'b t
(** Transports a codec across an isomorphism. [inject] and [project] must be
    mutually inverse for the result to stay canonical. *)

val refine :
  inject:('a -> ('b, string) result) ->
  project:('b -> 'a) ->
  'a t ->
  'b t
(** As {!iso}, but [inject] may reject a decoded value that fails a domain
    invariant. Rejection surfaces as {!Length_out_of_range} at the failing
    offset, carrying no payload beyond the message. *)

val sorted_map : 'k t -> 'v t -> compare:('k -> 'k -> int) -> ('k * 'v) list t
(** A BCS map: ULEB128 entry count followed by entries in ascending key order.
    Encoding sorts by [compare]; decoding checks that order was respected, so a
    non-canonical ordering is rejected rather than silently accepted. *)

(** {2 Sum types} *)

type 'a case

val case :
  index:int -> 'b t -> inject:('b -> 'a) -> project:('a -> 'b option) -> 'a case

val sum : 'a case list -> 'a t
(** Encodes the ULEB128 index of the first case whose [project] matches,
    followed by that case's payload; decoding dispatches on the index. An
    index with no matching case yields {!Unknown_variant}. *)
