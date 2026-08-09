(* Single-writer enforcement. Read the two halves of acquire together: the
   register catches a second handle in this process, lockf catches a second
   process. Neither half subsumes the other, because a POSIX advisory lock is
   owned by the process, so the kernel is blind to the case the register
   catches, and the register is blind to every other program on the machine. *)

type t = { fd : Io.fd; path : string }
type error = Io of Io.error | Held of { path : string }

let error_to_string = function
  | Io e -> Io.error_to_string e
  | Held { path } ->
      Printf.sprintf "%s: another handle already holds this root" path

let lock_name = "LOCK"

(* The roots this process holds. A list, because a node holds one root and a
   test holds a handful, so the cost of a scan is not worth a hashtable and a
   list makes the whole state of the register printable. *)
let register : string list ref = ref []
let holds path = List.exists (String.equal path) !register
let remember path = register := path :: !register
let forget path = register := List.filter (fun p -> not (String.equal p path)) !register

(* The register keys the CANONICAL root, not the spelling the caller used.
   Two names for one directory (relative and absolute, a symlink and its
   target) must contend here, because the kernel half is blind to the whole
   in-process case and a raw-string register would be blind to the alias. *)
let acquire ~ops ~dir =
  Result.bind
    (Result.map_error (fun e -> Io e) (Io.realpath ~ops ~path:dir))
    (fun canon ->
  let path = Filename.concat canon lock_name in
  match holds path with
  | true -> Error (Held { path })
  | false ->
      Result.bind
        (Result.map_error
           (fun e -> Io e)
           (Io.open_fd ~ops ~path ~mode:Io.Read_write_create))
        (fun fd ->
          Result.fold
            ~ok:(fun () ->
              let () = remember path in
              Ok { fd; path })
            ~error:(fun e ->
              (* The descriptor goes back before the refusal does: a leaked one
                 would hold a lock this call is reporting it does not have. *)
              let (_ : (unit, Io.error) result) = Io.close_fd fd in
              match e with
              | Io.Would_block _ -> Error (Held { path })
              | Io.Failed _ | Io.Short_write _ | Io.Short_read _ -> Error (Io e))
            (Io.lock_exclusive fd ~path)))

let release t =
  let () = forget t.path in
  Io.close_fd t.fd
