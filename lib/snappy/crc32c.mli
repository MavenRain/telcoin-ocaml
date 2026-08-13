(** CRC-32C (Castagnoli), the checksum every Snappy frame chunk header holds.

    Pinned to snap 1.1.1, the version telcoin-network @ 31cc4e90 resolves
    (Cargo.lock:11163-11164): reflected polynomial [0x82f63b78]
    (snap/build.rs:6), register starting at [0xffffffff] and complemented at
    the end (snap/src/crc32.rs:85-111), and the frame masking of
    snap/src/crc32.rs:35-38. Results live in [0, 2^32) as an OCaml [int],
    which holds 63 bits, so no Int32 sign trap can appear.

    The chunk-44 oracle harness cross-checked this definition against the
    masked CRC snap itself wrote into every chunk header of five different
    inputs (facts-raw.txt:38-49): all MATCH. *)

type error =
  | Out_of_bounds of { pos : int; len : int; length : int }
      (** {!update} was asked to fold a window that is not inside the string:
          [pos] and [len] are the window asked, [length] the length of the
          string given. *)

val error_to_string : error -> string
(** [error_to_string e] is a one-line rendering of [e], meant to be read by a
    human in a log or a test report. *)

val digest : string -> int
(** [digest s] is the CRC-32C of all of [s], in [0, 2^32). [digest ""] is 0,
    the value snap reports (facts-raw.txt:47). *)

val update : int -> string -> pos:int -> len:int -> (int, error) result
(** [update prev s ~pos ~len] continues the CRC [prev] over the [len] bytes
    of [s] that start at [pos], and is [Error (Out_of_bounds _)] when that
    window is not inside [s]. [prev] is a finished CRC, not an internal
    register, so [update 0 s ~pos:0 ~len:(String.length s)] equals
    [digest s], and folding a string in two windows equals folding it in
    one. *)

val mask : int -> int
(** [mask crc] is the value the frame format stores instead of the bare CRC:
    [((crc lsr 15) lor (crc lsl 17)) + 0xa282ead8] modulo [2^32]
    (snap/src/crc32.rs:35-38). [mask 0] is [0xa282ead8]. *)
