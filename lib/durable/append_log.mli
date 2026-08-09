(** The physical writer layer: a 64-byte file header, then frames, then nothing.

    This module owns [<dir>/consensus.log] and the lock beside it. It knows
    about bytes, sequence numbers and durability, and about no port type at all,
    so the entire crash argument is settled before a consensus type is
    involved.

    The durability contract it implements:

    - {!append} returns only after the whole frame is written AND flushed, so a
      value that has been returned has never been non-durable.
    - Exactly one flush per {!append}. Two for an {!open_} that creates the log
      (the file, then the directory). Two for a heal (the file, then the
      directory). Zero for an {!open_} over a clean log.
    - The log is append-only. The one in-place mutation in the whole module is
      the open-time truncation of a torn tail, which is a pure function of the
      bytes on disk and therefore idempotent under repeated crashes.
    - Interior damage truncates NOTHING. See {!Frame.scan}. *)

type t
(** An open log, holding the lock on its root. ABSTRACT: the only way to change
    the file is {!append}, and the only way to give the root back is
    {!close}. *)

type heal =
  | No_heal  (** The log was already a whole number of frames. *)
  | Healed_tail of { last_good : int; dropped : int }
      (** A torn tail was cut back to [last_good], discarding [dropped] bytes
          that no reader had ever seen. Reported as a value rather than logged,
          so a caller can assert on it. *)

type error =
  | Io of Io.error  (** The operating system refused. *)
  | Lock of Store_lock.error  (** Another handle holds this root. *)
  | Corrupt of { at : int; why : Frame.bad; next_good : int }
      (** Damage with committed frames above it. The file is left exactly as it
          was found, for forensics and for a re-sync from peers. *)
  | Bad_magic of { found : string }
      (** The file does not start with this format's magic. A foreign root,
          caught before a single frame is parsed. *)
  | Bad_format of { found : int; supported : int }
      (** A container version this reader does not implement. *)
  | Bad_header_len of { found : int }
      (** The header length does not match this format. Also the arm for a file
          too short to hold a header at all, where [found] is the file's own
          length. *)
  | Header_mismatch of { field : string; stored : string; wanted : string }
      (** The stored header disagrees with the caller's about a named field.
          This is how a root belonging to another chain, epoch or anchor is
          refused rather than adopted. *)
  | Bad_payload_len of { len : int; cap : int }
      (** {!append} was handed a payload outside [1 .. Frame.max_payload]. The
          refusal happens before any byte is written, so the log cannot be given
          a frame that a later {!open_} would refuse to read. *)

val error_to_string : error -> string
(** A one-line rendering of an {!error}. *)

type opened = {
  log : t;  (** The open log, ready to append at its own end. *)
  payloads : (Frame.kind * string) list;
      (** Every durable payload, in append order. *)
  heal : heal;  (** What the open had to repair, if anything. *)
  frames : int;  (** How many frames are durable. *)
}
(** What an {!open_} found and what it did about it. *)

val open_ :
  ops:Io_ops.t -> dir:string -> file_header:string -> (opened, error) result
(** [open_ ~ops ~dir ~file_header] takes the root and returns its durable
    contents. Unconditional and non-destructive.

    It creates [dir] if needed, takes the lock, and then either creates the log
    with [file_header] as its first 64 bytes (file flush, THEN directory flush,
    in that order, so the bytes are durable before the name is) or validates the
    stored header against [file_header] field by field and scans the frames.

    A torn tail is truncated, flushed, and REPORTED in {!heal}. Interior damage
    is refused as {!Corrupt} with nothing truncated. Any refusal releases the
    lock before it returns, so a caller that retries after fixing the cause is
    not blocked by its own earlier attempt. *)

val append : t -> kind:Frame.kind -> payload:string -> (t, error) result
(** [append log ~kind ~payload] writes one frame at the log's own recorded end
    offset, never at [O_APPEND]'s idea of the end, and flushes it. DURABLE ON
    RETURN.

    Writing at a recorded offset is what makes a retry safe: an attempt that
    failed part way through is overwritten in place by the next one, instead of
    leaving a broken prefix underneath a good frame. *)

val end_offset : t -> int
(** Where the next frame will start, which is also the durable length of the
    file. *)

val next_seq : t -> int
(** The sequence number the next frame will carry, which is also the number of
    frames now durable. *)

val close : t -> (unit, error) result
(** [close log] closes the file and releases the lock. Both are attempted even
    if the first fails, so a failed close never strands the root. *)
