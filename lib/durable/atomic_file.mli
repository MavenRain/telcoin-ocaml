(** Small artefacts published by rename, so a reader never sees a half-written
    one.

    The container is a 32-byte header and a payload:

    {v
      offset  size  field        value
      0x00       8  magic        caller supplied, exactly 8 bytes
      0x08       4  format       u32be
      0x0C       8  generation   u64be, strictly increasing across publishes
      0x14       4  len          u32be, the payload length
      0x18       8  body_tag     BLAKE2B(payload)[0..8)
      0x20       L  payload      caller supplied
    v}

    All multi-byte integers are big-endian, which gives byte-ordered offsets in
    a hex dump. The tag is BLAKE2B rather than the port's own content hash
    because [Tn_crypto.Digest] is a virtual library whose bytes change with the
    linked implementation, so a file written by a stub-linked binary would fail
    every check under a blst-linked one.

    {!save} writes [<name>.tmp], flushes it, renames it over [<name>], and
    flushes the directory: four calls in that exact order, and each one is a
    named mutation site. {!load} never reads [<name>.tmp]; it removes it
    first, so a temp left by a crash is swept rather than adopted. *)

type error =
  | Io of Io.error  (** The operating system refused a call. *)
  | Bad_magic of { path : string }
      (** The stored magic is not the one asked for, or the caller's own magic
          is not exactly 8 bytes. *)
  | Bad_format of { path : string; found : int; supported : int }
      (** The stored format number is not the one asked for. On {!save} it
          means the caller's format number does not fit a u32, and [supported]
          is the largest that does. *)
  | Bad_body_tag of { path : string }
      (** The payload does not match the tag stored beside it. *)
  | Short of { path : string; have : int; need : int }
      (** The file is not the length its own header declares. *)
  | Bad_generation of { path : string }
      (** The stored generation does not fit an OCaml integer. Unreachable for
          a file this module wrote; it names a hand-edited or foreign one. *)

val error_to_string : error -> string
(** A one-line rendering of an {!error}. *)

val save :
  ops:Io_ops.t ->
  dir:string ->
  name:string ->
  magic:string ->
  format:int ->
  generation:int ->
  payload:string ->
  (unit, error) result
(** [save ~ops ~dir ~name ~magic ~format ~generation ~payload] publishes
    [payload] at [<dir>/<name>] atomically: sweep a stale temp, write
    [<dir>/<name>.tmp], flush it, rename it over the canonical name, flush the
    directory. Exactly two flushes, so the count is an assertable equality.
    On return the canonical name binds this payload, or it binds the previous
    one; there is no in-between state a reader can observe. *)

val load :
  ops:Io_ops.t ->
  dir:string ->
  name:string ->
  magic:string ->
  format:int ->
  ((int * string) option, error) result
(** [load ~ops ~dir ~name ~magic ~format] answers [None] when the canonical
    name has never existed, which means a fresh node and never a silent zero,
    and [Some (generation, payload)] otherwise. A stale [<name>.tmp] is swept
    BEFORE anything is read, so a partially written temp is never a
    candidate. *)

val sweep_temp : ops:Io_ops.t -> dir:string -> name:string -> (bool, error) result
(** [sweep_temp ~ops ~dir ~name] removes [<dir>/<name>.tmp] if it is there, and
    answers whether it was. *)
