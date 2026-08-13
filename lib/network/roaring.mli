(** The roaring-bitmap portable interchange format, as
    [Certificate.signed_authorities] and [EpochCertificate.signed_authorities]
    carry it (GT:146, GT:158).

    Nothing in the port had this codec before chunk 44. The layout is the one
    the stage-0 harness read out of [roaring] 0.10.12's
    [bitmap/serialization.rs] and pinned with golden rows
    (verified-facts.md section 4):

    - a [12346] u32 LE cookie, then a u32 LE container count; or a [12347] u16
      cookie whose high u16 holds [count - 1], followed by a run-container bit
      per container, [(count + 7) / 8] bytes;
    - one 4-byte description per container: key u16 LE, then
      [cardinality - 1] u16 LE;
    - offsets, one u32 LE per container, written under the no-run cookie and
      under the run cookie once there are at least four containers. The
      decoder discards them, exactly as Rust's does;
    - each container's payload: an ARRAY of u16 LE values at cardinality up to
      4096, a BITMAP of 1024 u64 LE (8192 bytes) above that, or a RUN of a u16
      count then [(start, len)] u16 pairs whose last value is [start + len].

    ENCODER ASYMMETRY, recorded because it is a deliberate divergence from the
    format's full generality: [roaring] 0.10.12 never emits run containers
    ([serialize_into] always writes the no-run cookie, serialization.rs:67), so
    neither does this encoder. The DECODER accepts them, because a peer running
    a different roaring version may send them. *)

type t
(** A set of 32-bit values. Abstract: the representation is kept strictly
    ascending and duplicate-free, which is what makes {!to_bytes} canonical. *)

type error =
  | Unknown_cookie of { cookie : int }
      (** The leading u32 is neither cookie. *)
  | Too_many_containers of { count : int }
      (** More containers than the 65536 a 32-bit key space can hold; a
          corrupt count is refused before any allocation. *)
  | Truncated of { offset : int }
      (** The bytes end inside the field that starts at [offset]. *)
  | Trailing_bytes of { consumed : int; total : int }
      (** Bytes remain after the last container. *)
  | Value_out_of_range of { value : int }
      (** A value handed to {!of_list} is negative or at least 2^32. *)
  | Run_out_of_range of { start : int; len : int }
      (** A run container's [start + len] leaves the container's 16-bit key
          space, which [s.checked_add(len)] refuses upstream
          (serialization.rs:229). *)

val error_to_string : error -> string

val empty : t
(** The empty bitmap, whose interchange form is the 8-byte
    [3a 30 00 00 00 00 00 00]. *)

val of_list : int list -> (t, error) result
(** Sorts and deduplicates. Every value must lie in [\[0, 2^32)]. *)

val to_list : t -> int list
(** Ascending, without duplicates. *)

val cardinality : t -> int
val mem : int -> t -> bool
val equal : t -> t -> bool

val to_bytes : t -> string
(** The portable interchange bytes, without the BCS length prefix. *)

val of_bytes : string -> (t, error) result
(** Parses the interchange bytes. Trailing bytes are refused: the BCS field
    length delimits the bitmap exactly. *)

val codec : t Tn_codec.Bcs.t
(** The [#\[serde_as(as = "RoaringBitmapSerde")\]] field: the adapter's binary
    path is [serialize_bytes], so BCS writes ULEB128(len) then {!to_bytes}
    (crates/types/src/serde.rs:19-28, verified-facts.md section 4). *)
