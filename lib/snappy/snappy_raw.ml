(* The raw Snappy block format.  Every byte read goes through Byte_reader,
   which is total, and every byte written goes into a Buffer local to the
   call, so nothing mutable escapes and no index appears.

   The decode rules are transcribed from snap 1.1.1, the pinned version:
   - preamble: snap/src/bytes.rs:73-90 read_varu64, plus the 2^32 ceiling of
     snap/src/decompress.rs:362-374.  snap accepts a NON-MINIMAL varint
     there, so this decoder does too: rejecting it would make the port
     refuse a block the Rust node accepts.
   - tags: snap/build.rs:40-67, the generated tag table.
   - copy bounds: snap/src/decompress.rs:245-250.
   - exact production: snap/src/decompress.rs:141-146.
   One deliberate relaxation: snap demands 4 readable bytes after any
   literal tag whose length field is 60 to 63 (decompress.rs:189-198), an
   artifact of its 32-bit load; this decoder demands only the 1 to 4 bytes
   the field actually spans.  Every block snap emits is accepted either way,
   and the extra byte window is only reachable on truncated input, which
   both sides then reject through the length rule. *)

type error =
  | Truncated
  | Preamble_overflow
  | Copy_offset_out_of_range of { offset : int; produced : int }
  | Length_mismatch of { declared : int; produced : int }
  | Exceeds_max of { declared : int; max : int }

let error_to_string = function
  | Truncated -> "snappy raw: input ends inside a tag"
  | Preamble_overflow -> "snappy raw: preamble does not fit in 32 bits"
  | Copy_offset_out_of_range { offset; produced } ->
      Printf.sprintf "snappy raw: copy offset %d with %d bytes produced" offset
        produced
  | Length_mismatch { declared; produced } ->
      Printf.sprintf "snappy raw: declared %d bytes, tags produce %d" declared
        produced
  | Exceeds_max { declared; max } ->
      Printf.sprintf "snappy raw: declared %d bytes, at most %d allowed"
        declared max

let ( let* ) = Result.bind
let need o e = Option.to_result ~none:e o

(* snap/src/lib.rs MAX_INPUT_SIZE: a block may declare at most 2^32 - 1. *)
let max_input_size = 0xffff_ffff

(* The four tag classes.  [tag land 3] has exactly these four values, so the
   last arm of [classify] is the 3 case and nothing is left out. *)
type copy_width = Copy_1 | Copy_2 | Copy_4
type tag_kind = Literal | Copy of copy_width

let classify tag =
  match tag land 3 with
  | 0 -> Literal
  | 1 -> Copy Copy_1
  | 2 -> Copy Copy_2
  | _ -> Copy Copy_4

(* snap accumulates the preamble in a u64 and shifts with [checked_shl]
   (bytes.rs:73-90), which fails on the SHIFT reaching 64 and never on lost
   value bits: a payload bit pushed past bit 63 is dropped in silence.  Shifts
   climb by 7, so bits are dropped at shift 63 alone, where bit 0 of the
   payload is the only survivor.  Everything the shift keeps is what snap's
   own accumulator holds. *)
let surviving_payload ~shift payload =
  if shift >= 64 then 0
  else if shift + 7 <= 64 then payload
  else payload land ((1 lsl (64 - shift)) - 1)

(* The varint preamble.  [shift] climbs by 7 per byte; past 35 no surviving
   payload bit can land inside 32 bits any more, so a non-zero payload there
   would put snap's own accumulator past MAX_INPUT_SIZE and is the overflow it
   reports, while a payload that survives as zero is the padding snap accepts
   (a tenth byte with an EVEN payload among them). *)
let preamble r =
  let rec go pos shift acc =
    let* b = need (Byte_reader.byte r ~pos) Truncated in
    let payload = surviving_payload ~shift (b land 0x7f) in
    match () with
    | () when shift >= 70 -> Error Preamble_overflow
    | () when shift >= 35 && payload <> 0 -> Error Preamble_overflow
    | () ->
        let acc = if shift >= 35 then acc else acc lor (payload lsl shift) in
        if b land 0x80 <> 0 then go (pos + 1) (shift + 7) acc
        else if acc > max_input_size then Error Preamble_overflow
        else Ok (acc, pos + 1)
  in
  go 0 0 0

(* snap/build.rs:43-51: a literal tag holds its length minus one in the top 6
   bits when that fits in 59; the values 60 to 63 mean the length minus one
   follows in 1 to 4 little-endian bytes. *)
let literal_len r ~pos ~tag =
  let field = tag lsr 2 in
  if field < 60 then Ok (field + 1, pos)
  else
    let width = field - 59 in
    let* v = need (Byte_reader.le r ~pos ~len:width) Truncated in
    Ok (v + 1, pos + width)

(* snap/build.rs:52-64: copy tags.  Width 1 holds three offset bits in the
   tag byte and eight more in the byte that follows; widths 2 and 4 hold the
   whole offset in the bytes that follow. *)
let copy_op r ~pos ~tag ~width =
  match width with
  | Copy_1 ->
      let* lo = need (Byte_reader.byte r ~pos) Truncated in
      let len = 4 + ((tag lsr 2) land 0x07) in
      Ok (len, (((tag lsr 5) land 0x07) lsl 8) lor lo, pos + 1)
  | Copy_2 ->
      let* off = need (Byte_reader.le r ~pos ~len:2) Truncated in
      Ok ((tag lsr 2) + 1, off, pos + 2)
  | Copy_4 ->
      let* off = need (Byte_reader.le r ~pos ~len:4) Truncated in
      Ok ((tag lsr 2) + 1, off, pos + 4)

(* A Snappy copy may overlap the bytes it produces (an [offset] below [len]
   is the run-length case), so the copy advances in slices of at most
   [offset] bytes: each slice reads only bytes already in the buffer, which
   is what makes the read window provably inside it. *)
let copy_bytes out ~offset ~len =
  let rec go left =
    if left <= 0 then ()
    else
      let start = Buffer.length out - offset in
      let step = min offset left in
      Buffer.add_string out (Buffer.sub out start step);
      go (left - step)
  in
  go len

(* [produced > declared - len] is [produced + len > declared] written so no
   sum of two 32-bit quantities is computed. *)
let literal out r ~pos ~len ~declared =
  let produced = Buffer.length out in
  if produced > declared - len then
    Error (Length_mismatch { declared; produced = produced + len })
  else
    let* run_bytes = need (Byte_reader.sub r ~pos ~len) Truncated in
    Ok (Buffer.add_string out run_bytes)

let copy out ~offset ~len ~declared =
  let produced = Buffer.length out in
  match () with
  | () when offset < 1 || offset > produced ->
      Error (Copy_offset_out_of_range { offset; produced })
  | () when produced > declared - len ->
      Error (Length_mismatch { declared; produced = produced + len })
  | () -> Ok (copy_bytes out ~offset ~len)

let finish out ~declared =
  let produced = Buffer.length out in
  if produced = declared then Ok (Buffer.contents out)
  else Error (Length_mismatch { declared; produced })

let rec run r out ~declared ~pos =
  if Byte_reader.length r <= pos then finish out ~declared
  else
    let* tag = need (Byte_reader.byte r ~pos) Truncated in
    match classify tag with
    | Literal ->
        let* len, next = literal_len r ~pos:(pos + 1) ~tag in
        let* () = literal out r ~pos:next ~len ~declared in
        run r out ~declared ~pos:(next + len)
    | Copy width ->
        let* len, offset, next = copy_op r ~pos:(pos + 1) ~tag ~width in
        let* () = copy out ~offset ~len ~declared in
        run r out ~declared ~pos:next

(* The initial buffer is capped at one Snappy block so a hostile preamble
   cannot make the port reserve gigabytes before a single tag is read. *)
let initial_size declared = max 16 (min declared 65536)

let decode ~max_len src =
  let r = Byte_reader.of_string src in
  let* declared, pos = preamble r in
  if declared > max_len then Error (Exceeds_max { declared; max = max_len })
  else run r (Buffer.create (initial_size declared)) ~declared ~pos

let put_varint buf n =
  let rec go v =
    if v < 0x80 then Buffer.add_uint8 buf v
    else begin
      Buffer.add_uint8 buf ((v land 0x7f) lor 0x80);
      go (v lsr 7)
    end
  in
  go n

let put_le buf ~width v =
  List.iter
    (fun i -> Buffer.add_uint8 buf ((v lsr (8 * i)) land 0xff))
    (List.init width Fun.id)

(* The literal tag of a run of [n] bytes, [n] at least 1, in the smallest of
   the five shapes snap's decoder reads back. *)
let put_literal_tag buf n =
  match () with
  | () when n <= 60 -> Buffer.add_uint8 buf ((n - 1) lsl 2)
  | () when n <= 0x100 ->
      Buffer.add_uint8 buf (60 lsl 2);
      put_le buf ~width:1 (n - 1)
  | () when n <= 0x1_0000 ->
      Buffer.add_uint8 buf (61 lsl 2);
      put_le buf ~width:2 (n - 1)
  | () when n <= 0x100_0000 ->
      Buffer.add_uint8 buf (62 lsl 2);
      put_le buf ~width:3 (n - 1)
  | () ->
      Buffer.add_uint8 buf (63 lsl 2);
      put_le buf ~width:4 (n - 1)

let encode src =
  let n = String.length src in
  let buf = Buffer.create (n + 16) in
  put_varint buf n;
  if n > 0 then begin
    put_literal_tag buf n;
    Buffer.add_string buf src
  end;
  Buffer.contents buf
