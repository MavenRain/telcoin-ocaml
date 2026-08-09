(* The one exception boundary. Read the guard below and you have read every
   place in this port where an operating-system exception can exist: there is
   exactly one handler in this file, it names exactly Unix_error and Sys_error,
   and it has no wildcard arm. Everything above it hands results around as
   values. *)

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

let op_to_string = function
  | Open -> "open"
  | Close -> "close"
  | Write -> "write"
  | Read -> "read"
  | Fsync -> "fsync"
  | Fsync_dir -> "fsync-dir"
  | Ftruncate -> "ftruncate"
  | Lseek -> "lseek"
  | Rename -> "rename"
  | Mkdir -> "mkdir"
  | Unlink -> "unlink"
  | Lockf -> "lockf"
  | Stat -> "stat"
  | Realpath -> "realpath"

type error =
  | Failed of { op : op; path : string; code : string }
  | Short_write of { path : string; wanted : int; wrote : int }
  | Short_read of { path : string; at : int; wanted : int; got : int }
  | Would_block of { op : op; path : string }

let error_to_string = function
  | Failed { op; path; code } ->
      Printf.sprintf "%s failed on %s: %s" (op_to_string op) path code
  | Short_write { path; wanted; wrote } ->
      Printf.sprintf "short write on %s: wanted %d bytes, the device took %d"
        path wanted wrote
  | Short_read { path; at; wanted; got } ->
      Printf.sprintf "short read on %s at %d: wanted %d bytes, got %d" path at
        wanted got
  | Would_block { op; path } ->
      Printf.sprintf "%s on %s would block: another holder has it"
        (op_to_string op) path

(* What the boundary caught, before it is named as an [error]. Private: the
   distinction between the two families never leaves this file. *)
type raised = Raised_unix of Unix.error | Raised_sys of string

(* THE boundary. The only handler in the library. *)
let catching : type a. (unit -> a) -> (a, raised) result =
 fun thunk ->
  try Ok (thunk ()) with
  | Unix.Unix_error (e, _, _) -> Error (Raised_unix e)
  | Sys_error message -> Error (Raised_sys message)

let code_of = function
  | Raised_unix e -> Unix.error_message e
  | Raised_sys message -> message

let is_unix target = function
  | Raised_unix e -> e = target
  | Raised_sys _ -> false

let guard ~op ~path thunk =
  Result.map_error
    (fun r -> Failed { op; path; code = code_of r })
    (catching thunk)

(* A call whose named failure is a legitimate outcome: an already-present
   directory, an already-absent name. *)
let guard_tolerating ~op ~path ~ok_when thunk =
  Result.fold ~ok:Result.ok
    ~error:(fun r ->
      match is_unix ok_when r with
      | true -> Ok ()
      | false -> Error (Failed { op; path; code = code_of r }))
    (catching thunk)

let fsync_count = ref 0
let byte_count = ref 0
let fsyncs () = !fsync_count
let bytes_written () = !byte_count
let count_fsync () = fsync_count := !fsync_count + 1
let count_bytes n = byte_count := !byte_count + n

type fd = { raw : Unix.file_descr; path : string; ops : Io_ops.t }
type mode = Read_only | Read_write_create | Write_create_excl

let flags_of_mode = function
  | Read_only -> [ Unix.O_RDONLY ]
  | Read_write_create -> [ Unix.O_RDWR; Unix.O_CREAT ]
  | Write_create_excl -> [ Unix.O_WRONLY; Unix.O_CREAT; Unix.O_EXCL ]

(* Data this port writes is private to the node that owns the root. *)
let file_perm = 0o600
let dir_perm = 0o700

(* An allocation ceiling, so a length read out of a damaged header can never
   ask the runtime for a block it would refuse. The framing layer narrows this
   much further to its own max_payload. *)
let max_read = 1 lsl 30

let open_fd ~ops ~path ~mode =
  Result.map
    (fun raw -> { raw; path; ops })
    (guard ~op:Open ~path (fun () ->
         ops.Io_ops.openfile path (flags_of_mode mode) file_perm))

let close_fd fd =
  guard ~op:Close ~path:fd.path (fun () -> fd.ops.Io_ops.close fd.raw)

let with_file ~ops ~path ~mode body =
  Result.bind (open_fd ~ops ~path ~mode) (fun fd ->
      let outcome = body fd in
      let closed = close_fd fd in
      Result.fold
        ~ok:(fun v -> Result.map (fun () -> v) closed)
        ~error:Result.error outcome)

let write_all fd payload =
  let buf = Bytes.of_string payload in
  let total = Bytes.length buf in
  let rec push ~off ~wrote =
    match total - off = 0 with
    | true -> Ok ()
    | false ->
        Result.bind
          (guard ~op:Write ~path:fd.path (fun () ->
               fd.ops.Io_ops.write fd.raw buf off (total - off)))
          (fun reported ->
            let took = min (max reported 0) (total - off) in
            let () = count_bytes took in
            match took = 0 with
            | true ->
                Error (Short_write { path = fd.path; wanted = total; wrote })
            | false -> push ~off:(off + took) ~wrote:(wrote + took))
  in
  push ~off:0 ~wrote:0

let seek fd ~at ~whence =
  guard ~op:Lseek ~path:fd.path (fun () -> fd.ops.Io_ops.lseek fd.raw at whence)

let size fd = seek fd ~at:0 ~whence:Unix.SEEK_END

let seek_to fd ~at =
  Result.map (fun (_ : int) -> ()) (seek fd ~at ~whence:Unix.SEEK_SET)

(* The read body both preads share. [len] has already been vetted by the
   caller: [pread_exact] holds it under the untrusted-length ceiling, and
   [pread_all] takes it from the caller's own measurement of the device. *)
let pread_vetted fd ~at ~len =
  let short got = Error (Short_read { path = fd.path; at; wanted = len; got }) in
  Result.bind (seek fd ~at ~whence:Unix.SEEK_SET) (fun (_ : int) ->
      let buf = Bytes.create len in
      let rec pull ~off =
        match len - off = 0 with
        | true -> Ok off
        | false ->
            Result.bind
              (guard ~op:Read ~path:fd.path (fun () ->
                   fd.ops.Io_ops.read fd.raw buf off (len - off)))
              (fun reported ->
                let got = min (max reported 0) (len - off) in
                match got = 0 with
                | true -> Ok off
                | false -> pull ~off:(off + got))
      in
      Result.bind (pull ~off:0) (fun got ->
          match got = len with
          | true -> Ok (Bytes.to_string buf)
          | false -> short got))

let pread_exact fd ~at ~len =
  match len >= 0 && len <= max_read && at >= 0 with
  | false -> Error (Short_read { path = fd.path; at; wanted = len; got = 0 })
  | true -> pread_vetted fd ~at ~len

(* Whole-file reads. The ceiling on [pread_exact] bounds an allocation driven
   by a length PARSED OUT OF A FILE; a length the caller measured off the
   device with [size] is bounded by what the device already holds, and running
   it through the ceiling would make any file past 1 GiB permanently
   unreadable, which for an append-only log is a node that can never
   restart. *)
let pread_all fd ~at ~len =
  match len >= 0 && at >= 0 with
  | false -> Error (Short_read { path = fd.path; at; wanted = len; got = 0 })
  | true -> pread_vetted fd ~at ~len

let read_whole ~ops ~path =
  with_file ~ops ~path ~mode:Read_only (fun fd ->
      Result.bind (size fd) (fun len -> pread_all fd ~at:0 ~len))

let fsync fd =
  Result.map
    (fun () -> count_fsync ())
    (guard ~op:Fsync ~path:fd.path (fun () -> fd.ops.Io_ops.fsync fd.raw))

let ftruncate fd ~at =
  guard ~op:Ftruncate ~path:fd.path (fun () ->
      fd.ops.Io_ops.ftruncate fd.raw at)

(* Written out rather than routed through [with_file] so a directory flush
   reports as [Fsync_dir] and is distinguishable from a file flush in a
   fault report. *)
let fsync_dir ~ops ~path =
  Result.bind
    (guard ~op:Fsync_dir ~path (fun () ->
         ops.Io_ops.openfile path [ Unix.O_RDONLY ] 0))
    (fun raw ->
      let flushed =
        Result.map
          (fun () -> count_fsync ())
          (guard ~op:Fsync_dir ~path (fun () -> ops.Io_ops.fsync raw))
      in
      let closed = guard ~op:Close ~path (fun () -> ops.Io_ops.close raw) in
      Result.fold ~ok:(fun () -> closed) ~error:Result.error flushed)

let rename_over ~ops ~src ~dst =
  guard ~op:Rename ~path:dst (fun () -> ops.Io_ops.rename src dst)

let mkdir_p ~ops ~path =
  let root = match String.starts_with ~prefix:"/" path with
    | true -> "/"
    | false -> ""
  in
  let step acc part =
    Result.bind acc (fun prefix ->
        match String.equal part "" with
        | true -> Ok prefix
        | false ->
            let next =
              match String.equal prefix "" with
              | true -> part
              | false -> Filename.concat prefix part
            in
            Result.map
              (fun () -> next)
              (guard_tolerating ~op:Mkdir ~path:next ~ok_when:Unix.EEXIST
                 (fun () -> ops.Io_ops.mkdir next dir_perm)))
  in
  Result.map
    (fun (_ : string) -> ())
    (List.fold_left step (Ok root) (String.split_on_char '/' path))

let unlink_if_present ~ops ~path =
  guard_tolerating ~op:Unlink ~path ~ok_when:Unix.ENOENT (fun () ->
      ops.Io_ops.unlink path)

let exists ~ops ~path =
  Result.fold ~ok:Result.ok
    ~error:(fun r ->
      match is_unix Unix.ENOENT r || is_unix Unix.ENOTDIR r with
      | true -> Ok false
      | false -> Error (Failed { op = Stat; path; code = code_of r }))
    (catching (fun () -> ops.Io_ops.file_exists path))

let realpath ~ops ~path =
  guard ~op:Realpath ~path (fun () -> ops.Io_ops.realpath path)

let lock_exclusive fd ~path =
  Result.fold ~ok:Result.ok
    ~error:(fun r ->
      match is_unix Unix.EAGAIN r || is_unix Unix.EACCES r with
      | true -> Error (Would_block { op = Lockf; path })
      | false -> Error (Failed { op = Lockf; path; code = code_of r }))
    (catching (fun () -> fd.ops.Io_ops.lockf fd.raw Unix.F_TLOCK 0))
