(* Rename-published small artefacts. The whole crash argument for this module
   is one sentence: the canonical name is only ever moved onto by a rename of a
   file that has already been flushed, so it always binds a complete, tag-valid
   container of some earlier or current moment. *)

type error =
  | Io of Io.error
  | Bad_magic of { path : string }
  | Bad_format of { path : string; found : int; supported : int }
  | Bad_body_tag of { path : string }
  | Short of { path : string; have : int; need : int }
  | Bad_generation of { path : string }

let error_to_string = function
  | Io e -> Io.error_to_string e
  | Bad_magic { path } -> Printf.sprintf "%s: not the expected magic" path
  | Bad_format { path; found; supported } ->
      Printf.sprintf "%s: format %d, this reader supports %d" path found
        supported
  | Bad_body_tag { path } ->
      Printf.sprintf "%s: the payload does not match its own tag" path
  | Short { path; have; need } ->
      Printf.sprintf "%s: %d bytes on disk, the header declares %d" path have
        need
  | Bad_generation { path } ->
      Printf.sprintf "%s: the stored generation is out of range" path

let magic_size = 8
let format_off = 8
let generation_off = 12
let len_off = 20
let tag_off = 24
let header_size = 32
let tag_size = 8
let max_u32 = 0xFFFFFFFF
let max_generation = (1 lsl 62) - 1
let temp_of name = name ^ ".tmp"

(* Total byte access: no index accessor, so no offset in this module can raise
   on a hand-edited file. *)
let char_at s i =
  Option.fold ~none:'\x00' ~some:fst (Seq.uncons (Seq.drop i (String.to_seq s)))

let byte_at s i = Char.code (char_at s i)

(* ONE traversal, not one per character. [char_at] costs O(i), so spelling this
   as [String.init len (fun i -> char_at s (off + i))] is quadratic in the
   payload, which is invisible on a header field and costs seconds on a
   real checkpoint. The rule is unchanged: a read past the end yields NUL, so a
   damaged header still drives a bounded, deterministic decode, and an offset
   before the start is clamped rather than reaching a negative index. *)
let sub_at s ~off ~len =
  let want = max 0 len in
  let start = min (max 0 off) (String.length s) in
  let buf = Buffer.create want in
  let () =
    Seq.iter (Buffer.add_char buf)
      (Seq.take want (Seq.drop start (String.to_seq s)))
  in
  let () =
    Buffer.add_string buf (String.make (max 0 (want - Buffer.length buf)) '\x00')
  in
  Buffer.contents buf

let uint_at s ~off ~width =
  List.fold_left
    (fun acc i -> (acc lsl 8) lor byte_at s (off + i))
    0
    (List.init width Fun.id)

let be ~width v =
  let out = Buffer.create width in
  let () =
    List.iter
      (fun i -> Buffer.add_uint8 out ((v lsr ((width - 1 - i) * 8)) land 0xff))
      (List.init width Fun.id)
  in
  Buffer.contents out

(* BLAKE2B rather than the port's own content hash: [Tn_crypto.Digest] is a
   virtual library whose bytes change with the linked implementation. *)
let tag8 payload =
  let raw = Digestif.BLAKE2B.(to_raw_string (digest_string payload)) in
  match String.length raw >= tag_size with
  | true -> String.sub raw 0 tag_size (* @total-accessor *)
  | false -> raw

let encode ~magic ~format ~generation ~payload =
  String.concat ""
    [
      magic;
      be ~width:4 format;
      be ~width:8 generation;
      be ~width:4 (String.length payload);
      tag8 payload;
      payload;
    ]

let decode ~path ~magic ~format buf =
  let have = String.length buf in
  let stored_magic = sub_at buf ~off:0 ~len:magic_size in
  let stored_format = uint_at buf ~off:format_off ~width:4 in
  let gen_hi = uint_at buf ~off:generation_off ~width:4 in
  let gen_lo = uint_at buf ~off:(generation_off + 4) ~width:4 in
  let len = uint_at buf ~off:len_off ~width:4 in
  let stored_tag = sub_at buf ~off:tag_off ~len:tag_size in
  match () with
  | () when have < header_size -> Error (Short { path; have; need = header_size })
  | () when not (String.equal stored_magic magic) -> Error (Bad_magic { path })
  | () when stored_format <> format ->
      Error (Bad_format { path; found = stored_format; supported = format })
  | () when gen_hi > max_generation lsr 32 -> Error (Bad_generation { path })
  | () when have <> header_size + len ->
      Error (Short { path; have; need = header_size + len })
  | () ->
      (* The payload is materialised only now, once the file is known to be
         exactly as long as its header claims, so a damaged length can never
         drive the allocation. *)
      let payload = sub_at buf ~off:header_size ~len in
      let generation = (gen_hi lsl 32) lor gen_lo in
      Result.map
        (fun () -> (generation, payload))
        (match String.equal stored_tag (tag8 payload) with
        | true -> Ok ()
        | false -> Error (Bad_body_tag { path }))

let over_io r = Result.map_error (fun e -> Io e) r

let sweep_temp ~ops ~dir ~name =
  let path = Filename.concat dir (temp_of name) in
  over_io
    (Result.bind (Io.exists ~ops ~path) (fun present ->
         match present with
         | false -> Ok false
         | true ->
             Result.map
               (fun () -> true)
               (Io.unlink_if_present ~ops ~path)))

let save ~ops ~dir ~name ~magic ~format ~generation ~payload =
  let path = Filename.concat dir name in
  let temp = Filename.concat dir (temp_of name) in
  match () with
  | () when String.length magic <> magic_size -> Error (Bad_magic { path })
  | () when format < 0 || format > max_u32 ->
      Error (Bad_format { path; found = format; supported = max_u32 })
  | () when generation < 0 || generation > max_generation ->
      Error (Bad_generation { path })
  | () ->
      let bytes = encode ~magic ~format ~generation ~payload in
      over_io
        (Result.bind (Io.unlink_if_present ~ops ~path:temp) (fun () ->
             Result.bind
               (Io.with_file ~ops ~path:temp ~mode:Io.Write_create_excl
                  (fun fd ->
                    Result.bind (Io.write_all fd bytes) (fun () -> Io.fsync fd)))
               (fun () ->
                 Result.bind (Io.rename_over ~ops ~src:temp ~dst:path)
                   (fun () -> Io.fsync_dir ~ops ~path:dir))))

let load ~ops ~dir ~name ~magic ~format =
  let path = Filename.concat dir name in
  Result.bind (sweep_temp ~ops ~dir ~name) (fun (_ : bool) ->
      Result.bind (over_io (Io.exists ~ops ~path)) (fun present ->
          match present with
          | false -> Ok None
          | true ->
              Result.bind
                (over_io (Io.read_whole ~ops ~path))
                (fun buf ->
                  Result.map Option.some (decode ~path ~magic ~format buf))))
