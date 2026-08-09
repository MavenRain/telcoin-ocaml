(* The physical writer layer.

   Two orderings in this file are the whole crash argument, and neither is an
   accident of code shape:

     create   write header to a TEMP name -> fsync file -> rename onto the
              log name -> fsync directory
     heal     ftruncate -> fsync file -> fsync directory

   In both, the bytes are made durable before the name that reaches them is:
   the log name only ever appears by a rename of a header already on the
   medium, so no crash can leave it binding a stub a later open would have to
   refuse. An append needs no directory flush at all, because it changes no
   directory entry, which is why the append path costs exactly one flush. *)

type t = { fd : Io.fd; lock : Store_lock.t; end_offset : int; next_seq : int }
type heal = No_heal | Healed_tail of { last_good : int; dropped : int }

type error =
  | Io of Io.error
  | Lock of Store_lock.error
  | Corrupt of { at : int; why : Frame.bad; next_good : int }
  | Bad_magic of { found : string }
  | Bad_format of { found : int; supported : int }
  | Bad_header_len of { found : int }
  | Header_mismatch of { field : string; stored : string; wanted : string }
  | Bad_payload_len of { len : int; cap : int }

type opened = {
  log : t;
  payloads : (Frame.kind * string) list;
  heal : heal;
  frames : int;
}

let log_name = "consensus.log"

(* The file header, byte for byte: magic 8, format 4, header length 4, then the
   three identity fields the caller owns. This module compares those three as
   opaque spans and only names them, so the meaning of an epoch or an anchor
   stays with the layer that has the types for it. *)
let file_header_size = 64
let magic_off = 0
let magic_size = 8
let format_off = 8
let header_len_off = 12
let word = 4

let identity_spans =
  [ ("epoch0", 16, 8); ("anchor0", 24, 8); ("parent0", 32, 32) ]

let error_to_string = function
  | Io e -> Io.error_to_string e
  | Lock e -> Store_lock.error_to_string e
  | Corrupt { at; why; next_good } ->
      Printf.sprintf
        "%s: committed frames continue at %d, so this is damage, not a torn \
         write; nothing was truncated"
        (Frame.bad_to_string why) next_good
      ^ Printf.sprintf " (damage at %d)" at
  | Bad_magic { found } ->
      Printf.sprintf "not a consensus log: it starts with %S" found
  | Bad_format { found; supported } ->
      Printf.sprintf "container format %d, this reader supports %d" found
        supported
  | Bad_header_len { found } ->
      Printf.sprintf "header length %d, this format uses %d" found
        file_header_size
  | Header_mismatch { field; stored; wanted } ->
      Printf.sprintf "this root is not the caller's: %s is %s on disk, the \
                      caller says %s"
        field stored wanted
  | Bad_payload_len { len; cap } ->
      Printf.sprintf "a payload of %d bytes is outside 1 .. %d" len cap

(* Total byte access, the same discipline Frame uses and for the same reason: a
   hand-edited header must be refusable, never a source of a raise. *)
let sub_at s ~off ~len =
  let bound = String.length s in
  let start = min (max 0 off) bound in
  let stop = min (max start (off + max 0 len)) bound in
  String.sub s start (stop - start) (* @total-accessor *)

let uint_at s ~off ~width =
  String.fold_left
    (fun acc c -> (acc lsl 8) lor Char.code c)
    0
    (sub_at s ~off ~len:width)

let hex s =
  String.fold_left (fun acc c -> acc ^ Printf.sprintf "%02x" (Char.code c)) "" s

let over_io r = Result.map_error (fun e -> Io e) r

(* A refusal gives the root back. A caller that fixes the cause and retries in
   the same process must not be blocked by its own earlier attempt. *)
let releasing lock r =
  Result.fold ~ok:Result.ok
    ~error:(fun e ->
      let (_ : (unit, Io.error) result) = Store_lock.release lock in
      Error e)
    r

let closing fd r =
  Result.fold ~ok:Result.ok
    ~error:(fun e ->
      let (_ : (unit, Io.error) result) = Io.close_fd fd in
      Error e)
    r

let mismatching ~stored ~wanted =
  List.find_map
    (fun (field, off, len) ->
      let found = sub_at stored ~off ~len in
      let asked = sub_at wanted ~off ~len in
      match String.equal found asked with
      | true -> None
      | false ->
          Some (Header_mismatch { field; stored = hex found; wanted = hex asked }))
    identity_spans

let validate_header ~stored ~wanted =
  let have = String.length stored in
  let found_magic = sub_at stored ~off:magic_off ~len:magic_size in
  let asked_magic = sub_at wanted ~off:magic_off ~len:magic_size in
  let found_format = uint_at stored ~off:format_off ~width:word in
  let asked_format = uint_at wanted ~off:format_off ~width:word in
  let found_header_len = uint_at stored ~off:header_len_off ~width:word in
  match () with
  | () when have < file_header_size -> Error (Bad_header_len { found = have })
  | () when not (String.equal found_magic asked_magic) ->
      Error (Bad_magic { found = found_magic })
  | () when found_format <> asked_format ->
      Error (Bad_format { found = found_format; supported = asked_format })
  | () when found_header_len <> file_header_size ->
      Error (Bad_header_len { found = found_header_len })
  | () -> Option.fold ~none:(Ok ()) ~some:Result.error (mismatching ~stored ~wanted)

let heal_tail ~ops ~dir ~fd ~at =
  over_io
    (Result.bind (Io.ftruncate fd ~at) (fun () ->
         Result.bind (Io.fsync fd) (fun () -> Io.fsync_dir ~ops ~path:dir)))

(* The log name must never bind an unflushed header: a crash between naming
   and flushing would leave a stub every later open routes to [adopt], which
   can only refuse it, so the root would be bricked by its own birth. Hence
   the same temp-then-rename discipline [Atomic_file] uses. A temp left by an
   earlier crashed create is swept first, so the exclusive create cannot trip
   over it; a crash before the rename leaves the log name absent and the next
   open simply creates again. *)
let create ~ops ~dir ~path ~file_header ~lock =
  let temp = path ^ ".tmp" in
  Result.bind
    (over_io
       (Result.bind (Io.unlink_if_present ~ops ~path:temp) (fun () ->
            Result.bind
              (Io.with_file ~ops ~path:temp ~mode:Io.Write_create_excl
                 (fun fd ->
                   Result.bind (Io.write_all fd file_header) (fun () ->
                       Io.fsync fd)))
              (fun () ->
                Result.bind (Io.rename_over ~ops ~src:temp ~dst:path)
                  (fun () -> Io.fsync_dir ~ops ~path:dir)))))
    (fun () ->
      Result.map
        (fun fd ->
          {
            log = { fd; lock; end_offset = file_header_size; next_seq = 0 };
            payloads = [];
            heal = No_heal;
            frames = 0;
          })
        (over_io (Io.open_fd ~ops ~path ~mode:Io.Read_write_create)))

let adopt ~ops ~dir ~path ~file_header ~lock =
  Result.bind (over_io (Io.open_fd ~ops ~path ~mode:Io.Read_write_create))
    (fun fd ->
      closing fd
        (Result.bind (over_io (Io.size fd)) (fun len ->
             Result.bind (over_io (Io.pread_all fd ~at:0 ~len)) (fun buf ->
                 Result.bind
                   (validate_header ~stored:buf ~wanted:file_header)
                   (fun () ->
                     let scanned = Frame.scan ~buf ~from:file_header_size in
                     let payloads =
                       List.map
                         (fun (head, payload) -> (head.Frame.kind, payload))
                         scanned.Frame.frames
                     in
                     let count = List.length scanned.Frame.frames in
                     let settle ~at ~heal =
                       {
                         log = { fd; lock; end_offset = at; next_seq = count };
                         payloads;
                         heal;
                         frames = count;
                       }
                     in
                     match scanned.Frame.stop with
                     | Frame.Clean { at } -> Ok (settle ~at ~heal:No_heal)
                     | Frame.Torn { at; why = _ } ->
                         Result.map
                           (fun () ->
                             settle ~at
                               ~heal:
                                 (Healed_tail
                                    { last_good = at; dropped = len - at }))
                           (heal_tail ~ops ~dir ~fd ~at)
                     | Frame.Corrupt { at; why; next_good } ->
                         Error (Corrupt { at; why; next_good }))))))

let open_ ~ops ~dir ~file_header =
  let path = Filename.concat dir log_name in
  match String.length file_header = file_header_size with
  | false -> Error (Bad_header_len { found = String.length file_header })
  | true ->
      Result.bind (over_io (Io.mkdir_p ~ops ~path:dir)) (fun () ->
          Result.bind
            (Result.map_error (fun e -> Lock e) (Store_lock.acquire ~ops ~dir))
            (fun lock ->
              releasing lock
                (Result.bind (over_io (Io.exists ~ops ~path)) (fun present ->
                     match present with
                     | false -> create ~ops ~dir ~path ~file_header ~lock
                     | true -> adopt ~ops ~dir ~path ~file_header ~lock))))

let append t ~kind ~payload =
  let len = String.length payload in
  match len < 1 || len > Frame.max_payload with
  | true -> Error (Bad_payload_len { len; cap = Frame.max_payload })
  | false ->
      let frame = Frame.encode ~kind ~seq:t.next_seq ~payload in
      over_io
        (Result.bind (Io.seek_to t.fd ~at:t.end_offset) (fun () ->
             Result.bind (Io.write_all t.fd frame) (fun () ->
                 Result.map
                   (fun () ->
                     {
                       t with
                       end_offset = t.end_offset + String.length frame;
                       next_seq = t.next_seq + 1;
                     })
                   (Io.fsync t.fd))))

let end_offset t = t.end_offset
let next_seq t = t.next_seq

let close t =
  let closed = Io.close_fd t.fd in
  let released = Store_lock.release t.lock in
  over_io (Result.bind closed (fun () -> released))
