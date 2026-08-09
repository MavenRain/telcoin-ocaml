(** The one exception boundary between this port and the operating system.

    Every value here is total: an operating-system failure comes back as an
    {!error}, never as an exception. The implementation holds exactly one
    handler, in a private guard, naming exactly [Unix.Unix_error] and
    [Sys_error], with no wildcard arm. Three families are ruled out rather than
    caught: the [Sys] module is never called from this library (renaming is
    [Unix.rename], never the [Sys] one, so the [Sys_error] arm is belt and
    braces rather than a live path), [End_of_file] cannot arise because nothing
    here uses the buffered
    channel API, and [Eio.Io] cannot arise because no [Eio] value is referenced
    and the dune stanza does not list it.

    {!fd} is abstract, so a caller cannot reach the [Unix.file_descr] and
    cannot bypass the boundary.

    Durability disclosure, load bearing and repeated in the store contract:
    {!fsync} is POSIX [fsync], not macOS [F_FULLFSYNC], which stock [Unix]
    cannot reach. On macOS this buys durability against process death and
    operating-system crash, and does NOT buy durability against power loss. *)

type op =
  | Open
  | Close
  | Write
  | Read
  | Fsync
  | Fsync_dir
  | Ftruncate
  | Lseek
  | Rename
  | Mkdir
  | Unlink
  | Lockf
  | Stat
  | Realpath
      (** The call family a failure came from. Closed, so every renderer over
          it is exhaustive. *)

val op_to_string : op -> string
(** A short lowercase name for an {!op}, for diagnostics. *)

type error =
  | Failed of { op : op; path : string; code : string }
      (** The call raised. [code] is the operating system's own message. *)
  | Short_write of { path : string; wanted : int; wrote : int }
      (** The device stopped accepting bytes before the payload was done. *)
  | Short_read of { path : string; at : int; wanted : int; got : int }
      (** The file ended before the requested span was filled. *)
  | Would_block of { op : op; path : string }
      (** Advisory-lock contention: [lockf F_TLOCK] met a holder. *)

val error_to_string : error -> string
(** A one-line rendering of an {!error}. *)

type fd
(** An open descriptor, ABSTRACT so no caller can reach the underlying
    [Unix.file_descr] and issue an unguarded call on it. *)

type mode =
  | Read_only  (** [O_RDONLY]. Also the mode that opens a directory. *)
  | Read_write_create  (** [O_RDWR; O_CREAT]. Never truncates. *)
  | Write_create_excl
      (** [O_WRONLY; O_CREAT; O_EXCL]. Fails if the name already exists, which
          is what keeps a temp file fresh rather than half stale. *)

val open_fd : ops:Io_ops.t -> path:string -> mode:mode -> (fd, error) result
(** [open_fd ~ops ~path ~mode] opens [path] and hands back the descriptor, which
    the caller must close with {!close_fd}.

    Prefer {!with_file}, which cannot leak one. This pair exists for the two
    descriptors that must outlive a single call and therefore cannot sit inside
    a scope: the advisory lock on a store root, which POSIX releases the moment
    ANY descriptor on that file closes, and the log a writer appends to for the
    lifetime of the store. *)

val close_fd : fd -> (unit, error) result
(** [close_fd fd] closes [fd]. Closing a file also drops every advisory lock
    this process holds on it. *)

val with_file :
  ops:Io_ops.t ->
  path:string ->
  mode:mode ->
  (fd -> ('a, error) result) ->
  ('a, error) result
(** [with_file ~ops ~path ~mode f] opens [path], runs [f], and closes on BOTH
    exits. A close failure is reported only when the body succeeded, so a real
    error is never masked by a cleanup error. *)

val write_all : fd -> string -> (unit, error) result
(** [write_all fd s] writes every byte of [s] at the current file position,
    looping over partial writes rather than assuming the first count is the
    whole payload. A device that accepts nothing on a further attempt is
    reported as {!Short_write}; it is never retried forever and never treated
    as success. *)

val pread_exact : fd -> at:int -> len:int -> (string, error) result
(** [pread_exact fd ~at ~len] seeks to [at] and reads exactly [len] bytes. A
    file that ends early is {!Short_read}, never a short string. The caller
    bounds [len]; this stage caps it at 1 GiB so no header can ask for an
    allocation the runtime would refuse. *)

val pread_all : fd -> at:int -> len:int -> (string, error) result
(** [pread_all fd ~at ~len] is {!pread_exact} without the untrusted-length
    ceiling, for a [len] the caller measured off the device itself with
    {!size}. The ceiling exists to bound an allocation asked for by a parsed
    header field; applied to a whole-file read it would make any file past
    1 GiB permanently unreadable, which for an append-only log means a node
    that can never restart. *)

val read_whole : ops:Io_ops.t -> path:string -> (string, error) result
(** [read_whole ~ops ~path] reads the whole of [path], however large it is. *)

val size : fd -> (int, error) result
(** [size fd] answers the file length, and leaves the file position AT THE END,
    which is also how a caller repositions for an append after a read. *)

val seek_to : fd -> at:int -> (unit, error) result
(** [seek_to fd ~at] puts the file position at [at], so the next {!write_all}
    lands there. An appender uses this rather than [O_APPEND]: a write at a
    RECORDED offset overwrites an interrupted attempt in place on retry, where
    an append would leave the broken prefix below a second copy. *)

val fsync : fd -> (unit, error) result
(** [fsync fd] flushes the file to the medium, and on success advances
    {!fsyncs}. *)

val ftruncate : fd -> at:int -> (unit, error) result
(** [ftruncate fd ~at] cuts the file to [at] bytes. The file position may then
    sit beyond the end, so a caller that goes on writing calls {!size}
    first. *)

val fsync_dir : ops:Io_ops.t -> path:string -> (unit, error) result
(** [fsync_dir ~ops ~path] opens the directory read-only, flushes it, and
    closes it: the call that makes a rename survive a crash. Probe-verified on
    this switch on 2026-08-08 and re-verified by this stage's suite on every
    build, so an absent failure is never the evidence. On success it advances
    {!fsyncs}. *)

val rename_over : ops:Io_ops.t -> src:string -> dst:string -> (unit, error) result
(** [rename_over ~ops ~src ~dst] renames [src] onto [dst], atomically replacing
    it. [Unix.rename], NEVER the [Sys] rename: that one raises [Sys_error], a
    second exception family this library refuses to acquire. *)

val mkdir_p : ops:Io_ops.t -> path:string -> (unit, error) result
(** [mkdir_p ~ops ~path] creates [path] and every missing parent. An existing
    directory is success, so the call is idempotent. *)

val unlink_if_present : ops:Io_ops.t -> path:string -> (unit, error) result
(** [unlink_if_present ~ops ~path] removes [path], and an already-absent [path]
    is success. Any other failure is reported. *)

val exists : ops:Io_ops.t -> path:string -> (bool, error) result
(** [exists ~ops ~path] answers whether [path] resolves. Absence is [Ok false];
    a permission or device fault is an {!error}, never a quiet [false]. *)

val realpath : ops:Io_ops.t -> path:string -> (string, error) result
(** [realpath ~ops ~path] resolves [path] to its canonical absolute form,
    every symlink and dot segment collapsed. [path] must exist: absence is an
    {!error} here, because the caller is asking which physical thing a name
    denotes, and an absent name denotes nothing. *)

val lock_exclusive : fd -> path:string -> (unit, error) result
(** [lock_exclusive fd ~path] takes [lockf F_TLOCK 0] on the whole file.
    Contention ([EAGAIN] or [EACCES]) is {!Would_block}, distinct from a fault.

    Note the POSIX ownership rule this inherits: an advisory lock belongs to
    the PROCESS, so a second handle inside the same process does not contend
    with the first. Cross-process exclusion is what this call buys; in-process
    exclusion is the caller's obligation. *)

val fsyncs : unit -> int
(** A monotone process-wide count of flush calls that RETURNED successfully,
    counting {!fsync} and {!fsync_dir} alike. The durability hook: "one
    accepted receive costs exactly one fsync" and "a refused receive costs
    zero" become assertable equalities, and deleting a flush becomes a mutation
    a suite can kill. It counts calls, not device behaviour: a device that
    ignores a flush still advances it. *)

val bytes_written : unit -> int
(** A monotone process-wide count of the bytes the write calls under
    {!write_all} reported as accepted. Pins "a refused receive writes zero
    bytes". *)
