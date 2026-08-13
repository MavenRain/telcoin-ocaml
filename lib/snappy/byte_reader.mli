(** Total byte access over an immutable input buffer.

    Every accessor is bounds checked and answers with an [option], so the
    Snappy decoders hold no partial accessor and no index syntax at all. The
    precedent is Tn_codec.Bcs.Reader (bcs.mli:45-56), which wraps the same
    discipline around a moving cursor; this module leaves the cursor with the
    caller, because a Snappy decoder looks ahead, skips whole chunks and
    re-reads a region it has already passed. *)

type t
(** An immutable byte buffer, built once from a string. *)

val of_string : string -> t
(** [of_string s] is a reader over a private copy of [s]. *)

val length : t -> int
(** [length t] is the number of bytes in [t]. *)

val byte : t -> pos:int -> int option
(** [byte t ~pos] is the unsigned byte at [pos], or [None] when [pos] is
    outside [t]. *)

val le : t -> pos:int -> len:int -> int option
(** [le t ~pos ~len] is the little-endian unsigned integer held in the [len]
    bytes at [pos], or [None] when that window is outside [t]. [len] is meant
    to be at most 7: the result is an OCaml [int], which holds 63 bits. *)

val sub : t -> pos:int -> len:int -> string option
(** [sub t ~pos ~len] is the [len] bytes at [pos] as a fresh string, or
    [None] when that window is outside [t]. A [len] of 0 at a position inside
    [t] gives [Some ""]. *)
