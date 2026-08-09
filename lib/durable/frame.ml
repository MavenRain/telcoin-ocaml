(* The on-disk envelope. A pure function over strings: no syscall, no port
   type, no mutable state. That is what lets the whole torn-write and
   interior-damage argument be tested without a filesystem. *)

type kind = Record | Epoch_open

let max_payload = 16777216
let header_size = 24
let trailer_size = 16
let frame_size ~payload_len = payload_len + header_size + trailer_size

(* Field offsets inside a frame, relative to its own start. *)
let len_off = 0
let kind_off = 4
let seq_off = 8
let head_tag_off = 16
let tag_size = 8
let len_field = 4
let end_magic = "TNCE"
let end_magic_size = 4

type head = { kind : kind; seq : int; payload_len : int }

type bad =
  | Short of { at : int; have : int; need : int }
  | Bad_head_tag of { at : int }
  | Bad_body_tag of { at : int }
  | Length_disagrees of { at : int; head : int; echo : int }
  | Missing_end_magic of { at : int }
  | Bad_kind of { at : int; byte : int }
  | Oversize of { at : int; len : int; cap : int }
  | Seq_out_of_order of { at : int; expected : int; got : int }

let bad_to_string = function
  | Short { at; have; need } ->
      Printf.sprintf "offset %d: %d bytes left, a frame needs %d" at have need
  | Bad_head_tag { at } ->
      Printf.sprintf "offset %d: the header does not match its own tag" at
  | Bad_body_tag { at } ->
      Printf.sprintf "offset %d: the payload does not match its own tag" at
  | Length_disagrees { at; head; echo } ->
      Printf.sprintf "offset %d: the header says %d bytes, the trailer says %d"
        at head echo
  | Missing_end_magic { at } ->
      Printf.sprintf "offset %d: the frame does not end in %s" at end_magic
  | Bad_kind { at; byte } ->
      Printf.sprintf "offset %d: kind byte 0x%02x is not a frame kind" at byte
  | Oversize { at; len; cap } ->
      Printf.sprintf "offset %d: the declared length %d is outside 1 .. %d" at
        len cap
  | Seq_out_of_order { at; expected; got } ->
      Printf.sprintf "offset %d: expected sequence %d, the frame carries %d" at
        expected got

let bad_offset = function
  | Short { at; _ }
  | Bad_head_tag { at }
  | Bad_body_tag { at }
  | Length_disagrees { at; _ }
  | Missing_end_magic { at }
  | Bad_kind { at; _ }
  | Oversize { at; _ }
  | Seq_out_of_order { at; _ } ->
      at

(* Total byte access, with no index accessor anywhere in the module, so no
   offset here can raise on a hand-edited file. A span that runs off either end
   is CLAMPED rather than zero-filled, and every caller establishes that the
   span is present before it reads a field, so the clamped case is never the
   one a decision rests on. *)
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

let be ~width v =
  let out = Buffer.create width in
  let () =
    List.iter
      (fun i -> Buffer.add_uint8 out ((v lsr ((width - 1 - i) * 8)) land 0xff))
      (List.init width Fun.id)
  in
  Buffer.contents out

(* BLAKE2B rather than the port's own content hash: Tn_crypto.Digest is a
   virtual library whose bytes change with the linked implementation, and these
   bytes are on disk forever. Eight bytes gives a 2^-64 false accept, against
   2^-32 for a CRC32. *)
let tag8 payload =
  let raw = Digestif.BLAKE2B.(to_raw_string (digest_string payload)) in
  match String.length raw >= tag_size with
  | true -> String.sub raw 0 tag_size (* @total-accessor *)
  | false -> raw

let byte_of_kind = function Record -> 1 | Epoch_open -> 2

let kind_of_byte = function
  | 1 -> Some Record
  | 2 -> Some Epoch_open
  | _ -> None

let head_bytes ~kind ~seq ~payload_len =
  String.concat ""
    [
      be ~width:len_field payload_len;
      be ~width:1 (byte_of_kind kind);
      String.make 3 '\x00';
      be ~width:8 seq;
    ]

let encode ~kind ~seq ~payload =
  let payload_len = String.length payload in
  let prefix = head_bytes ~kind ~seq ~payload_len in
  String.concat ""
    [
      prefix;
      tag8 prefix;
      payload;
      tag8 payload;
      be ~width:len_field payload_len;
      end_magic;
    ]

(* The header, and nothing that depends on the payload. The length bound is
   checked before the kind and before the tag, so an injected oversize length
   is reported AS an oversize length and never drives an allocation. *)
let read_head ~buf ~at =
  let have = String.length buf - at in
  let len = uint_at buf ~off:(at + len_off) ~width:len_field in
  let kind_byte = uint_at buf ~off:(at + kind_off) ~width:1 in
  let seq = uint_at buf ~off:(at + seq_off) ~width:8 in
  match () with
  | () when have < header_size ->
      Error (Short { at; have = max 0 have; need = header_size })
  | () when len < 1 || len > max_payload ->
      Error (Oversize { at; len; cap = max_payload })
  | () ->
      Result.bind
        (Option.fold
           ~none:(Error (Bad_kind { at; byte = kind_byte }))
           ~some:Result.ok (kind_of_byte kind_byte))
        (fun kind ->
          let stored = sub_at buf ~off:(at + head_tag_off) ~len:tag_size in
          let computed = tag8 (sub_at buf ~off:at ~len:head_tag_off) in
          match String.equal stored computed with
          | true -> Ok { kind; seq; payload_len = len }
          | false -> Error (Bad_head_tag { at }))

(* The payload and the trailer, once the header is known good. The payload is
   materialised only after the whole frame is known to be present, so a length
   that survived the bound check still cannot ask for bytes that are not
   there. *)
let read_body ~buf ~at ~head =
  let total = frame_size ~payload_len:head.payload_len in
  let have = String.length buf - at in
  match have < total with
  | true -> Error (Short { at; have = max 0 have; need = total })
  | false ->
      let payload_at = at + header_size in
      let trailer_at = payload_at + head.payload_len in
      let payload = sub_at buf ~off:payload_at ~len:head.payload_len in
      let stored = sub_at buf ~off:trailer_at ~len:tag_size in
      let echo = uint_at buf ~off:(trailer_at + tag_size) ~width:len_field in
      let magic =
        sub_at buf
          ~off:(trailer_at + tag_size + len_field)
          ~len:end_magic_size
      in
      (match () with
      | () when not (String.equal stored (tag8 payload)) ->
          Error (Bad_body_tag { at })
      | () when echo <> head.payload_len ->
          Error (Length_disagrees { at; head = head.payload_len; echo })
      | () when not (String.equal magic end_magic) ->
          Error (Missing_end_magic { at })
      | () -> Ok (payload, at + total))

(* Every check a frame must pass EXCEPT its position in the log. This is the
   predicate a resync probe needs: position is exactly the thing that is in
   question when the walk has lost its place. *)
let whole_frame_at ~buf ~at =
  Result.bind (read_head ~buf ~at) (fun head ->
      Result.map
        (fun (payload, next) -> (head, payload, next))
        (read_body ~buf ~at ~head))

let decode_at ~buf ~at ~expect_seq =
  Result.bind (whole_frame_at ~buf ~at) (fun (head, payload, next) ->
      match head.seq = expect_seq with
      | true -> Ok (head, payload, next)
      | false ->
          Error (Seq_out_of_order { at; expected = expect_seq; got = head.seq }))

type stop =
  | Clean of { at : int }
  | Torn of { at : int; why : bad }
  | Corrupt of { at : int; why : bad; next_good : int }

type scan = { frames : (head * string) list; stop : stop }

(* A candidate resync point: a structurally perfect frame that does not rewind
   the log. A frame carrying a LOWER sequence than the one already expected is
   old bytes, not a continuation, so it is not a resync point. *)
let resyncs_at ~buf ~at ~min_seq =
  Result.fold
    ~error:(fun (_ : bad) -> false)
    ~ok:(fun (head, (_ : string), (_ : int)) -> head.seq >= min_seq)
    (whole_frame_at ~buf ~at)

let rec next_good_from ~buf ~at ~min_seq =
  match at >= String.length buf with
  | true -> None
  | false -> (
      match resyncs_at ~buf ~at ~min_seq with
      | true -> Some at
      | false -> next_good_from ~buf ~at:(at + 1) ~min_seq)

let scan ~buf ~from =
  let rec walk ~at ~expect_seq ~acc =
    match at >= String.length buf with
    | true -> { frames = List.rev acc; stop = Clean { at } }
    | false ->
        Result.fold
          ~ok:(fun (head, payload, next) ->
            walk ~at:next ~expect_seq:(expect_seq + 1)
              ~acc:((head, payload) :: acc))
          ~error:(fun why ->
            {
              frames = List.rev acc;
              stop =
                Option.fold
                  ~none:(Torn { at; why })
                  ~some:(fun p -> Corrupt { at; why; next_good = p })
                  (next_good_from ~buf ~at ~min_seq:expect_seq);
            })
          (decode_at ~buf ~at ~expect_seq)
  in
  walk ~at:(max 0 from) ~expect_seq:0 ~acc:[]
