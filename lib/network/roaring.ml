module Bcs = Tn_codec.Bcs
module Reader = Tn_snappy.Byte_reader

type t = int list

type error =
  | Unknown_cookie of { cookie : int }
  | Too_many_containers of { count : int }
  | Truncated of { offset : int }
  | Trailing_bytes of { consumed : int; total : int }
  | Value_out_of_range of { value : int }
  | Run_out_of_range of { start : int; len : int }

let error_to_string = function
  | Unknown_cookie { cookie } -> Printf.sprintf "unknown roaring cookie %d" cookie
  | Too_many_containers { count } ->
      Printf.sprintf "roaring container count %d above 65536" count
  | Truncated { offset } -> Printf.sprintf "roaring bytes end at offset %d" offset
  | Trailing_bytes { consumed; total } ->
      Printf.sprintf "roaring left %d of %d bytes unread" (total - consumed) total
  | Value_out_of_range { value } ->
      Printf.sprintf "roaring value %d outside [0, 2^32)" value
  | Run_out_of_range { start; len } ->
      Printf.sprintf "roaring run %d + %d leaves the container" start len

let ( let* ) = Result.bind

(* serialization.rs:11-12 *)
let cookie_no_run = 12346
let cookie_run = 12347

(* One container holds the 65536 values sharing a 16-bit key; above 4096 of
   them the payload switches from an array to a bitmap
   (serialization.rs:90-99). The key/value split is a shift and a mask, never
   a division, so no divisor can be zero. *)
let key_of_value v = v lsr 16
let low_of_value v = v land 0xffff
let base_of_key k = k lsl 16
let array_max_cardinality = 4096
let bitmap_bytes_len = 8192
let max_value = 0x1_0000_0000
let max_containers = 65536

(* The largest low half a container can hold: run ends are u16 upstream. *)
let container_max_low = 0xffff

let empty = []
let to_list t = t
let cardinality t = List.length t
let mem v t = List.exists (fun x -> Int.equal x v) t
let equal a b = List.equal Int.equal a b

let of_list vs =
  let sorted = List.sort_uniq Int.compare vs in
  Option.fold ~none:(Ok sorted)
    ~some:(fun value -> Error (Value_out_of_range { value }))
    (List.find_opt (fun v -> v < 0 || v >= max_value) sorted)

(* ------------------------------------------------------------------ encode *)

(* Ascending values to ascending [(key, ascending low halves)] groups. *)
let containers values =
  let step acc v =
    let key = key_of_value v and low = low_of_value v in
    match acc with
    | [] -> [ (key, [ low ]) ]
    | (k, lows) :: rest ->
        if Int.equal k key then (k, low :: lows) :: rest
        else (key, [ low ]) :: (k, lows) :: rest
  in
  List.rev_map
    (fun (k, lows) -> (k, List.rev lows))
    (List.fold_left step [] values)

let container_cardinality (_, lows) = List.length lows

let container_size c =
  if container_cardinality c > array_max_cardinality then bitmap_bytes_len
  else 2 * container_cardinality c

(* Little-endian emitters over a buffer local to {!to_bytes}. Bcs.Writer is
   not reachable from here (bcs.mli:34-43 exposes no constructor), and the
   interchange bytes are not a BCS structure anyway: they are the opaque
   payload of one BCS [bytes] field. *)
let put_u8 buf v = Buffer.add_uint8 buf (v land 0xff)

let put_u16 buf v =
  put_u8 buf v;
  put_u8 buf (v lsr 8)

let put_u32 buf v =
  put_u16 buf (v land 0xffff);
  put_u16 buf (v lsr 16)

(* The bitmap payload is 1024 u64 LE, which byte for byte is 8192 bytes whose
   bit [v land 7] of byte [v lsr 3] marks the value [v]. Written a byte at a
   time, walking the ascending lows once; the recursion is tail. *)
let write_bitmap buf lows =
  let rec fill remaining byte ~base =
    match remaining with
    | [] -> ([], byte)
    | v :: rest ->
        if v < base + 8 then fill rest (byte lor (1 lsl (v - base))) ~base
        else (remaining, byte)
  in
  let rec go i remaining =
    if i >= bitmap_bytes_len then ()
    else
      let remaining, byte = fill remaining 0 ~base:(i * 8) in
      put_u8 buf byte;
      go (i + 1) remaining
  in
  go 0 lows

let to_bytes t =
  let cs = containers t in
  let count = List.length cs in
  let buf = Buffer.create (16 + (8 * count)) in
  put_u32 buf cookie_no_run;
  put_u32 buf count;
  List.iter
    (fun c ->
      put_u16 buf (fst c);
      put_u16 buf (container_cardinality c - 1))
    cs;
  (* First payload offset: the 8-byte header plus 4 description and 4 offset
     bytes per container (serialization.rs:75-86). *)
  ignore
    (List.fold_left
       (fun offset c ->
         put_u32 buf offset;
         offset + container_size c)
       (8 + (8 * count))
       cs);
  List.iter
    (fun (_, lows) ->
      if List.length lows > array_max_cardinality then write_bitmap buf lows
      else List.iter (fun low -> put_u16 buf low) lows)
    cs;
  Buffer.contents buf

(* ------------------------------------------------------------------ decode *)

let le r ~pos ~len =
  Option.to_result ~none:(Truncated { offset = pos }) (Reader.le r ~pos ~len)

(* The run-container flag for container [i]: bit [i land 7] of the byte at
   [i lsr 3] of the run bitmap, the shift form of the format's [i / 8]. *)
let run_flag r ~run_bitmap_pos ~index =
  Option.fold ~none:false
    ~some:(fun byte -> Int.equal ((byte lsr (index land 7)) land 1) 1)
    (Reader.byte r ~pos:(run_bitmap_pos + (index lsr 3)))

let read_descriptions r ~pos ~size ~run_bitmap_pos ~has_runs =
  let rec go i pos acc =
    if i >= size then Ok (pos, List.rev acc)
    else
      let* key = le r ~pos ~len:2 in
      let* card_less_one = le r ~pos:(pos + 2) ~len:2 in
      let is_run = has_runs && run_flag r ~run_bitmap_pos ~index:i in
      go (i + 1) (pos + 4) ((key, card_less_one + 1, is_run) :: acc)
  in
  go 0 pos []

let read_array r ~pos ~base ~card =
  let rec go i pos acc =
    if i >= card then Ok (pos, List.rev acc)
    else
      let* low = le r ~pos ~len:2 in
      go (i + 1) (pos + 2) ((base + low) :: acc)
  in
  go 0 pos []

let read_bitmap r ~pos ~base =
  let bits byte ~at =
    List.filter_map
      (fun j ->
        if Int.equal ((byte lsr j) land 1) 1 then Some (base + at + j) else None)
      [ 0; 1; 2; 3; 4; 5; 6; 7 ]
  in
  let rec go i pos acc =
    if i >= bitmap_bytes_len then Ok (pos, List.rev acc)
    else
      let* byte = le r ~pos ~len:1 in
      go (i + 1) (pos + 1) (List.rev_append (bits byte ~at:(i * 8)) acc)
  in
  go 0 pos []

let read_runs r ~pos ~base =
  let* runs = le r ~pos ~len:2 in
  let rec go i pos acc =
    if i >= runs then Ok (pos, List.concat (List.rev acc))
    else
      let* start = le r ~pos ~len:2 in
      let* len = le r ~pos:(pos + 2) ~len:2 in
      (* serialization.rs:229 ends the run at [s.checked_add(len)] and aborts
         the WHOLE decode when that leaves the u16 key space, so a run like
         (0xfff0, 0xffff) is refused here rather than spilling its tail into
         the next container's values. *)
      if start + len > container_max_low then
        Error (Run_out_of_range { start; len })
      else
        go (i + 1) (pos + 4)
          (List.init (len + 1) (fun j -> base + start + j) :: acc)
  in
  go 0 (pos + 2) []

let read_containers r ~pos ~specs =
  let rec go pos specs acc =
    match specs with
    | [] -> Ok (pos, List.concat (List.rev acc))
    | (key, card, is_run) :: rest ->
        let base = base_of_key key in
        let* pos, values =
          if is_run then read_runs r ~pos ~base
          else if card > array_max_cardinality then read_bitmap r ~pos ~base
          else read_array r ~pos ~base ~card
        in
        go pos rest (values :: acc)
  in
  go pos specs []

let read_header r =
  let* cookie = le r ~pos:0 ~len:4 in
  if Int.equal cookie cookie_no_run then
    Result.map (fun count -> (count, false, 8)) (le r ~pos:4 ~len:4)
  else if Int.equal (cookie land 0xffff) cookie_run then
    Ok ((cookie lsr 16) + 1, true, 4)
  else Error (Unknown_cookie { cookie })

let of_bytes s =
  let r = Reader.of_string s in
  let* size, has_runs, pos = read_header r in
  if size > max_containers then Error (Too_many_containers { count = size })
  else
    let run_bitmap_pos = pos in
    (* The run bitmap is [(size + 7) / 8] bytes, written here as a shift
       (serialization.rs:183-189). *)
    let pos = if has_runs then pos + ((size + 7) lsr 3) else pos in
    let* pos, specs = read_descriptions r ~pos ~size ~run_bitmap_pos ~has_runs in
    (* Offsets are written under the no-run cookie always, and under the run
       cookie only from four containers up (serialization.rs:75-86,200-204).
       They are read past, exactly as Rust discards them. *)
    let pos = if (not has_runs) || size >= 4 then pos + (4 * size) else pos in
    let* pos, values = read_containers r ~pos ~specs in
    let total = Reader.length r in
    if pos <> total then Error (Trailing_bytes { consumed = pos; total })
    else of_list values

let codec : t Bcs.t =
  Bcs.refine
    ~inject:(fun raw -> Result.map_error error_to_string (of_bytes raw))
    ~project:to_bytes Bcs.bytes
