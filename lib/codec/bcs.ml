type error =
  | Unexpected_end_of_input of { offset : int; wanted : int }
  | Non_canonical_uleb128 of { offset : int }
  | Uleb128_overflow of { offset : int }
  | Invalid_bool of { offset : int; byte : int }
  | Invalid_option_tag of { offset : int; tag : int }
  | Unknown_variant of { offset : int; index : int }
  | Length_out_of_range of { offset : int; length : int }
  | Integer_out_of_range of { offset : int; width : int; value : int }
  | Trailing_bytes of { consumed : int; total : int }

let error_to_string = function
  | Unexpected_end_of_input { offset; wanted } ->
      Printf.sprintf "unexpected end of input at offset %d (wanted %d bytes)"
        offset wanted
  | Non_canonical_uleb128 { offset } ->
      Printf.sprintf "non-canonical ULEB128 at offset %d" offset
  | Uleb128_overflow { offset } ->
      Printf.sprintf "ULEB128 value exceeds 32 bits at offset %d" offset
  | Invalid_bool { offset; byte } ->
      Printf.sprintf "invalid bool byte 0x%02x at offset %d" byte offset
  | Invalid_option_tag { offset; tag } ->
      Printf.sprintf "invalid option tag 0x%02x at offset %d" tag offset
  | Unknown_variant { offset; index } ->
      Printf.sprintf "unknown enum variant %d at offset %d" index offset
  | Length_out_of_range { offset; length } ->
      Printf.sprintf "length %d out of range at offset %d" length offset
  | Integer_out_of_range { offset; width; value } ->
      Printf.sprintf "value %d does not fit in %d bytes at offset %d" value
        width offset
  | Trailing_bytes { consumed; total } ->
      Printf.sprintf "trailing bytes: consumed %d of %d" consumed total

(* The result monad, kept local so the decoder reads as a straight-line
   pipeline without a for/while loop or a raised exception in sight. *)
let ( let* ) = Result.bind
let ok = Result.ok

module Writer = struct
  type t = Buffer.t

  let raw t s = Buffer.add_string t s
  let u8 t n = Buffer.add_char t (Char.chr (n land 0xff))

  let u16 t n =
    u8 t n;
    u8 t (n asr 8)

  let u32 t n =
    u16 t n;
    u16 t (n asr 16)

  let u64 t n =
    let byte i = Int64.to_int (Int64.logand (Int64.shift_right_logical n i) 0xffL) in
    List.iter (fun i -> u8 t (byte i)) [ 0; 8; 16; 24; 32; 40; 48; 56 ]

  (* ULEB128 over a non-negative host int. Emitted low group first, high bit
     set on every group but the last. Recursion stands in for the loop. *)
  let rec uleb128 t n =
    let low = n land 0x7f and rest = n lsr 7 in
    if rest = 0 then u8 t low
    else begin
      u8 t (low lor 0x80);
      uleb128 t rest
    end
end

module Reader = struct
  type t = { src : string; mutable pos : int }

  let offset t = t.pos
  let remaining t = String.length t.src - t.pos

  let take t n =
    if remaining t < n then
      Error (Unexpected_end_of_input { offset = t.pos; wanted = n })
    else begin
      let s = String.sub t.src t.pos n in
      t.pos <- t.pos + n;
      Ok s
    end

  let raw = take

  let byte t =
    let* s = take t 1 in
    ok (Char.code s.[0])

  let u8 = byte

  let u16 t =
    let* lo = byte t in
    let* hi = byte t in
    ok (lo lor (hi lsl 8))

  let u32 t =
    let* lo = u16 t in
    let* hi = u16 t in
    ok (lo lor (hi lsl 16))

  let u64 t =
    let* s = take t 8 in
    let acc =
      List.fold_left
        (fun acc i ->
          let b = Int64.of_int (Char.code s.[i]) in
          Int64.logor acc (Int64.shift_left b (8 * i)))
        0L
        [ 0; 1; 2; 3; 4; 5; 6; 7 ]
    in
    ok acc

  (* Canonical ULEB128 into a host int, rejecting the two non-canonical
     shapes the Rust decoder also rejects: overlong encodings (a final 0x00
     continuation that adds no value) and payloads past 32 bits. *)
  let uleb128 t =
    let start = t.pos in
    let rec go shift acc =
      let* b = byte t in
      let acc = acc lor ((b land 0x7f) lsl shift) in
      if b land 0x80 <> 0 then
        if shift + 7 >= 35 then Error (Uleb128_overflow { offset = start })
        else go (shift + 7) acc
      else if b = 0 && shift <> 0 then
        Error (Non_canonical_uleb128 { offset = start })
      else if acc < 0 || acc > 0xffff_ffff then
        Error (Uleb128_overflow { offset = start })
      else ok acc
    in
    go 0 0
end

type 'a t = {
  write : Writer.t -> 'a -> unit;
  read : Reader.t -> ('a, error) result;
}

let make ~write ~read = { write; read }

let encode c v =
  let b = Buffer.create 64 in
  c.write b v;
  Buffer.contents b

let decode_prefix c s =
  let r = { Reader.src = s; pos = 0 } in
  let* v = c.read r in
  ok (v, r.pos)

let decode c s =
  let* v, consumed = decode_prefix c s in
  let total = String.length s in
  if consumed = total then ok v else Error (Trailing_bytes { consumed; total })

let unit = make ~write:(fun _ () -> ()) ~read:(fun _ -> ok ())

let bool =
  make
    ~write:(fun w b -> Writer.u8 w (if b then 1 else 0))
    ~read:(fun r ->
      let off = Reader.offset r in
      let* b = Reader.u8 r in
      match b with
      | 0 -> ok false
      | 1 -> ok true
      | byte -> Error (Invalid_bool { offset = off; byte }))

let u8 = make ~write:Writer.u8 ~read:Reader.u8
let u16 = make ~write:Writer.u16 ~read:Reader.u16
let u32 = make ~write:Writer.u32 ~read:Reader.u32
let u64 = make ~write:Writer.u64 ~read:Reader.u64
let uleb128 = make ~write:Writer.uleb128 ~read:Reader.uleb128

let bytes =
  make
    ~write:(fun w s ->
      Writer.uleb128 w (String.length s);
      Writer.raw w s)
    ~read:(fun r ->
      let* n = Reader.uleb128 r in
      Reader.raw r n)

let fixed_bytes n =
  make
    ~write:(fun w s -> Writer.raw w s)
    ~read:(fun r -> Reader.raw r n)

let option c =
  make
    ~write:(fun w -> function
      | None -> Writer.u8 w 0
      | Some v ->
          Writer.u8 w 1;
          c.write w v)
    ~read:(fun r ->
      let off = Reader.offset r in
      let* tag = Reader.u8 r in
      match tag with
      | 0 -> ok None
      | 1 ->
          let* v = c.read r in
          ok (Some v)
      | tag -> Error (Invalid_option_tag { offset = off; tag }))

let list c =
  make
    ~write:(fun w xs ->
      Writer.uleb128 w (List.length xs);
      List.iter (c.write w) xs)
    ~read:(fun r ->
      let* n = Reader.uleb128 r in
      (* Fold the count into a growing accumulator; reversed once at the end so
         no element is ever re-appended in place. *)
      let rec go i acc =
        if i = 0 then ok (List.rev acc)
        else
          let* v = c.read r in
          go (i - 1) (v :: acc)
      in
      go n [])

let pair a b =
  make
    ~write:(fun w (x, y) ->
      a.write w x;
      b.write w y)
    ~read:(fun r ->
      let* x = a.read r in
      let* y = b.read r in
      ok (x, y))

let triple a b c =
  make
    ~write:(fun w (x, y, z) ->
      a.write w x;
      b.write w y;
      c.write w z)
    ~read:(fun r ->
      let* x = a.read r in
      let* y = b.read r in
      let* z = c.read r in
      ok (x, y, z))

let iso ~inject ~project c =
  make
    ~write:(fun w v -> c.write w (project v))
    ~read:(fun r ->
      let* v = c.read r in
      ok (inject v))

let refine ~inject ~project c =
  make
    ~write:(fun w v -> c.write w (project v))
    ~read:(fun r ->
      let off = Reader.offset r in
      let* v = c.read r in
      match inject v with
      | Ok v' -> ok v'
      | Error _ -> Error (Length_out_of_range { offset = off; length = 0 }))

let sorted_map k v ~compare =
  let entry = pair k v in
  make
    ~write:(fun w pairs ->
      let sorted =
        List.sort (fun (k1, _) (k2, _) -> compare k1 k2) pairs
      in
      Writer.uleb128 w (List.length sorted);
      List.iter (entry.write w) sorted)
    ~read:(fun r ->
      let* n = Reader.uleb128 r in
      let rec go i prev acc =
        if i = 0 then ok (List.rev acc)
        else
          let off = Reader.offset r in
          let* (key, _) as e = entry.read r in
          match prev with
          | Some p when compare p key >= 0 ->
              Error (Length_out_of_range { offset = off; length = i })
          | _ -> go (i - 1) (Some key) (e :: acc)
      in
      go n None [])

type 'a case = {
  index : int;
  encode_case : (Writer.t -> 'a -> bool);
  decode_case : (int -> (Reader.t -> ('a, error) result) option);
}

let case ~index c ~inject ~project =
  {
    index;
    encode_case =
      (fun w v ->
        match project v with
        | None -> false
        | Some payload ->
            Writer.uleb128 w index;
            c.write w payload;
            true);
    decode_case =
      (fun i ->
        if i = index then
          Some
            (fun r ->
              let* payload = c.read r in
              ok (inject payload))
        else None);
  }

let sum cases =
  make
    ~write:(fun w v ->
      (* Emit the first case whose projection matches. A value that matches no
         case is a construction bug, not a decode error; encode nothing so the
         defect surfaces immediately as a malformed (empty) buffer rather than
         a silently wrong tag. *)
      let _ : bool =
        List.fold_left
          (fun done_ c -> done_ || c.encode_case w v)
          false cases
      in
      ())
    ~read:(fun r ->
      let off = Reader.offset r in
      let* index = Reader.uleb128 r in
      let chosen =
        List.find_map (fun c -> c.decode_case index) cases
      in
      match chosen with
      | Some read -> read r
      | None -> Error (Unknown_variant { offset = off; index }))
