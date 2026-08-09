(* The syscall vtable. Nothing here interprets a failure: every field is the
   stock Unix call, and the single guard in [Io] is what turns a raised
   Unix_error into a value. *)

type t = {
  openfile : string -> Unix.open_flag list -> int -> Unix.file_descr;
  close : Unix.file_descr -> unit;
  write : Unix.file_descr -> Bytes.t -> int -> int -> int;
  read : Unix.file_descr -> Bytes.t -> int -> int -> int;
  fsync : Unix.file_descr -> unit;
  ftruncate : Unix.file_descr -> int -> unit;
  lseek : Unix.file_descr -> int -> Unix.seek_command -> int;
  rename : string -> string -> unit;
  mkdir : string -> int -> unit;
  unlink : string -> unit;
  file_exists : string -> bool;
  lockf : Unix.file_descr -> Unix.lock_command -> int -> unit;
  realpath : string -> string;
}

(* [Unix.stat] rather than the [Sys] existence test. Two reasons: the [Sys]
   module is banned inside this library, and its test answers [false] for a
   path it merely cannot reach, which would report a permission fault as an
   absence. Absence arrives here as an ENOENT failure and [Io.exists] names
   it. *)
let stat_exists path =
  let (_ : Unix.stats) = Unix.stat path in
  true

let real =
  {
    openfile = Unix.openfile;
    close = Unix.close;
    write = Unix.write;
    read = Unix.read;
    fsync = Unix.fsync;
    ftruncate = Unix.ftruncate;
    lseek = Unix.lseek;
    rename = Unix.rename;
    mkdir = Unix.mkdir;
    unlink = Unix.unlink;
    file_exists = stat_exists;
    lockf = Unix.lockf;
    realpath = Unix.realpath;
  }
