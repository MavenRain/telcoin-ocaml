(** The syscall table {!Io} calls through.

    Transparent on purpose, by the same store-facing rule that keeps
    [Tn_engine.Engine.persisted] transparent: this record bears no invariant,
    it is a vtable, and a fault-injecting table has to be constructible outside
    this library without a functor threaded through every call site.

    Every field may signal failure the way the C call it wraps does, by raising
    [Unix.Unix_error]. {!Io} is the only caller in the port, and it calls every
    field from inside its single guard, so no exception reaches a user of this
    library. A test table is free to fail by returning a short count instead,
    which is what makes a partial write testable at all. *)

type t = {
  openfile : string -> Unix.open_flag list -> int -> Unix.file_descr;
      (** [openfile path flags perm] opens [path] and yields its descriptor. *)
  close : Unix.file_descr -> unit;  (** [close fd] releases [fd]. *)
  write : Unix.file_descr -> Bytes.t -> int -> int -> int;
      (** [write fd buf off len] writes at most [len] bytes and answers how
          many it accepted. A count below [len] is legal and is what
          {!Io.write_all} exists to handle. *)
  read : Unix.file_descr -> Bytes.t -> int -> int -> int;
      (** [read fd buf off len] reads at most [len] bytes and answers how many
          it delivered. Zero means end of file. *)
  fsync : Unix.file_descr -> unit;
      (** [fsync fd] flushes [fd] to the medium. POSIX [fsync], never macOS
          [F_FULLFSYNC], which stock [Unix] cannot reach. *)
  ftruncate : Unix.file_descr -> int -> unit;
      (** [ftruncate fd len] sets the file length to [len]. *)
  lseek : Unix.file_descr -> int -> Unix.seek_command -> int;
      (** [lseek fd off whence] moves the file position and answers the new
          absolute position. *)
  rename : string -> string -> unit;
      (** [rename src dst] renames atomically, replacing [dst]. *)
  mkdir : string -> int -> unit;
      (** [mkdir path perm] creates one directory. *)
  unlink : string -> unit;  (** [unlink path] removes one name. *)
  file_exists : string -> bool;
      (** [file_exists path] answers whether [path] resolves. The stock
          implementation reports absence by raising [ENOENT] rather than by
          answering [false], because no total existence call exists in [Unix];
          {!Io.exists} folds both shapes to a boolean. *)
  lockf : Unix.file_descr -> Unix.lock_command -> int -> unit;
      (** [lockf fd cmd len] takes or releases an advisory lock. *)
  realpath : string -> string;
      (** [realpath path] resolves [path] to its canonical absolute form, every
          symlink and dot segment collapsed. The path must exist. *)
}
(** The table of operating-system calls this library is allowed to make. *)

val real : t
(** The stock [Unix] table. The ONLY value production code passes. *)
