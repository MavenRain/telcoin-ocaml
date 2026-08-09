(* Fault-injecting syscall tables, test only.

   Note what this file does NOT contain: a raise. A synthetic exception would
   test the boundary against a fiction; every failure here is provoked by a
   real call that cannot succeed, so what the guard catches is exactly what the
   operating system produces. *)

module Io = Tn_durable.Io
module Io_ops = Tn_durable.Io_ops

let real = Io_ops.real

let bump counter =
  let n = !counter + 1 in
  let () = counter := n in
  n

let traced ~sink =
  {
    Io_ops.openfile =
      (fun path flags perm ->
        let () = sink ("openfile " ^ path) in
        real.openfile path flags perm);
    close =
      (fun fd ->
        let () = sink "close" in
        real.close fd);
    write =
      (fun fd buf off len ->
        let () = sink ("write " ^ string_of_int len) in
        real.write fd buf off len);
    read =
      (fun fd buf off len ->
        let () = sink ("read " ^ string_of_int len) in
        real.read fd buf off len);
    fsync =
      (fun fd ->
        let () = sink "fsync" in
        real.fsync fd);
    ftruncate =
      (fun fd len ->
        let () = sink ("ftruncate " ^ string_of_int len) in
        real.ftruncate fd len);
    lseek =
      (fun fd off whence ->
        let () = sink ("lseek " ^ string_of_int off) in
        real.lseek fd off whence);
    rename =
      (fun src dst ->
        let () = sink ("rename " ^ src ^ " -> " ^ dst) in
        real.rename src dst);
    mkdir =
      (fun path perm ->
        let () = sink ("mkdir " ^ path) in
        real.mkdir path perm);
    unlink =
      (fun path ->
        let () = sink ("unlink " ^ path) in
        real.unlink path);
    file_exists =
      (fun path ->
        let () = sink ("file_exists " ^ path) in
        real.file_exists path);
    lockf =
      (fun fd cmd len ->
        let () = sink "lockf" in
        real.lockf fd cmd len);
    realpath =
      (fun path ->
        let () = sink ("realpath " ^ path) in
        real.realpath path);
  }

type code = Absent | Contended

(* A path no filesystem can resolve: its first component is a name under the
   root that this port never creates. *)
let unresolvable = "/tn-durable-faults-no-such-root/no-such-file"

(* Provoke the real failure. Each branch performs a call that cannot succeed,
   so the Unix_error that reaches the guard came from the kernel. *)
let provoke = function
  | Absent ->
      let (_ : Unix.stats) = Unix.stat unresolvable in
      ()
  | Contended ->
      let readable, _writable = Unix.pipe () in
      let () = Unix.set_nonblock readable in
      let (_ : int) = Unix.read readable (Bytes.create 1) 0 1 in
      ()

let fail_at ~nth ~op ~code =
  let hits = ref 0 in
  let fire target =
    match target = op with
    | false -> ()
    | true -> (
        match bump hits = nth with true -> provoke code | false -> ())
  in
  {
    Io_ops.openfile =
      (fun path flags perm ->
        let () = fire Io.Open in
        real.openfile path flags perm);
    close =
      (fun fd ->
        let () = fire Io.Close in
        real.close fd);
    write =
      (fun fd buf off len ->
        let () = fire Io.Write in
        real.write fd buf off len);
    read =
      (fun fd buf off len ->
        let () = fire Io.Read in
        real.read fd buf off len);
    fsync =
      (fun fd ->
        let () = fire Io.Fsync in
        real.fsync fd);
    ftruncate =
      (fun fd len ->
        let () = fire Io.Ftruncate in
        real.ftruncate fd len);
    lseek =
      (fun fd off whence ->
        let () = fire Io.Lseek in
        real.lseek fd off whence);
    rename =
      (fun src dst ->
        let () = fire Io.Rename in
        real.rename src dst);
    mkdir =
      (fun path perm ->
        let () = fire Io.Mkdir in
        real.mkdir path perm);
    unlink =
      (fun path ->
        let () = fire Io.Unlink in
        real.unlink path);
    file_exists =
      (fun path ->
        let () = fire Io.Stat in
        real.file_exists path);
    lockf =
      (fun fd cmd len ->
        let () = fire Io.Lockf in
        real.lockf fd cmd len);
    realpath =
      (fun path ->
        let () = fire Io.Realpath in
        real.realpath path);
  }

let short_write_at ~nth ~bytes =
  let hits = ref 0 in
  {
    real with
    Io_ops.write =
      (fun fd buf off len ->
        let n = bump hits in
        match () with
        | () when n < nth -> real.write fd buf off len
        | () when n = nth -> real.write fd buf off (min bytes len)
        | () -> 0);
  }

let skip_fsync_at ~nth =
  let hits = ref 0 in
  {
    real with
    Io_ops.fsync =
      (fun fd -> match bump hits = nth with true -> () | false -> real.fsync fd);
  }
