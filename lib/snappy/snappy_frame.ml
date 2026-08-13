(* The Snappy stream framing format, transcribed from snap 1.1.1's
   FrameDecoder (src/read.rs:111-238) and FrameEncoder (src/frame.rs), with
   every constant taken from the chunk-44 verified fact note rather than from
   the design sketch it corrected.

   Order of operations inside a chunk is part of the wire contract, so the
   decoder keeps snap's: type byte, 3-byte declared length, the 76490
   ceiling, the type dispatch, the 4-byte masked checksum, the 65536 cap on
   uncompressed bytes, the body, and only then the checksum comparison. *)

type error =
  | Missing_stream_identifier
  | Bad_stream_identifier
  | Truncated_chunk
  | Unskippable_reserved of int
  | Crc_mismatch of { expected : int; actual : int }
  | Block_too_large of { len : int }
  | Declared_length_too_large of { len : int }
  | Missing_checksum of { len : int }
  | Raw of Snappy_raw.error

let error_to_string = function
  | Missing_stream_identifier -> "snappy frame: no stream identifier chunk"
  | Bad_stream_identifier -> "snappy frame: malformed stream identifier chunk"
  | Truncated_chunk -> "snappy frame: input ends inside a chunk"
  | Unskippable_reserved ty ->
      Printf.sprintf "snappy frame: reserved chunk type 0x%02x must be rejected"
        ty
  | Crc_mismatch { expected; actual } ->
      Printf.sprintf "snappy frame: checksum 0x%08x, computed 0x%08x" expected
        actual
  | Block_too_large { len } ->
      Printf.sprintf "snappy frame: chunk holds %d uncompressed bytes, cap 65536"
        len
  | Declared_length_too_large { len } ->
      Printf.sprintf "snappy frame: declared chunk length %d, cap 76490" len
  | Missing_checksum { len } ->
      Printf.sprintf "snappy frame: data chunk length %d cannot hold a checksum"
        len
  | Raw e -> "snappy frame: " ^ Snappy_raw.error_to_string e

let ( let* ) = Result.bind
let need o e = Option.to_result ~none:e o

(* snap/src/lib.rs:97 MAX_BLOCK_SIZE. *)
let max_block_size = 65536

(* snap/src/frame.rs:12 MAX_COMPRESS_BLOCK_SIZE, the ceiling read.rs:129-135
   applies to the declared length of ANY chunk. *)
let max_declared_chunk_len = 76490

(* snap/src/frame.rs:18,21 STREAM_IDENTIFIER and its body. *)
let stream_body = "sNaPpY"
let stream_chunk = "\xff\x06\x00\x00sNaPpY"
let chunk_header_len = 4
let checksum_len = 4

type chunk_kind =
  | Stream_identifier
  | Compressed
  | Uncompressed
  | Padding
  | Reserved_unskippable
  | Reserved_skippable

(* snap/src/frame.rs:31-34 and read.rs:138-147.  The two reserved arms come
   last, so they cover exactly 0x02-0x7f and 0x80-0xfd. *)
let classify ty =
  match () with
  | () when ty = 0xff -> Stream_identifier
  | () when ty = 0x00 -> Compressed
  | () when ty = 0x01 -> Uncompressed
  | () when ty = 0xfe -> Padding
  | () when ty <= 0x7f -> Reserved_unskippable
  | () -> Reserved_skippable

let put_le buf ~width v =
  List.iter
    (fun i -> Buffer.add_uint8 buf ((v lsr (8 * i)) land 0xff))
    (List.init width Fun.id)

let put_uncompressed_chunk buf slice =
  Buffer.add_uint8 buf 0x01;
  put_le buf ~width:3 (String.length slice + checksum_len);
  put_le buf ~width:4 (Crc32c.mask (Crc32c.digest slice));
  Buffer.add_string buf slice

let compress src =
  let r = Byte_reader.of_string src in
  let total = String.length src in
  let buf = Buffer.create (total + 32) in
  Buffer.add_string buf stream_chunk;
  let rec go pos =
    if pos >= total then ()
    else
      let len = min max_block_size (total - pos) in
      (* [pos] is inside the input and [len] stops at its end, so this window
         is always present; [Option.iter] keeps the accessor total, and a
         missing slice could only shorten the output, which the round-trip
         rows in test/test_snappy.ml would catch at once. *)
      Option.iter (put_uncompressed_chunk buf) (Byte_reader.sub r ~pos ~len);
      go (pos + len)
  in
  go 0;
  Buffer.contents buf

(* [Buffer.sub] is partial below 0, and [max_len] is a caller-supplied int
   that the type says nothing about, so the cut length is clamped into
   [0, Buffer.length out] before it is used. Rust's [take] counts in u64 and
   cannot express a negative limit, so a negative cap is the empty one: the
   same answer [max_len = 0] gives. *)
let truncate_out out ~max_len =
  Buffer.sub out 0 (max 0 (min (Buffer.length out) max_len))
(* @total-accessor: the length is clamped to [0, Buffer.length out] above *)

let check_crc ~expected data =
  let actual = Crc32c.mask (Crc32c.digest data) in
  if actual = expected then Ok () else Error (Crc_mismatch { expected; actual })

(* snap reports a raw block whose preamble declares more than one block as a
   chunk-length error (read.rs:217-222), not as a corrupt block. *)
let raw_error = function
  | Snappy_raw.Exceeds_max { declared; max = _ } ->
      Block_too_large { len = declared }
  | ( Snappy_raw.Truncated | Snappy_raw.Preamble_overflow
    | Snappy_raw.Copy_offset_out_of_range _ | Snappy_raw.Length_mismatch _ ) as
    e ->
      Raw e

let rec chunks r out ~max_len ~pos ~seen_id =
  match () with
  (* Rust's Take stops calling the inner reader once its limit reaches 0, so
     a chunk wholly past the cap is never read, let alone validated. *)
  | () when Buffer.length out >= max_len -> Ok (truncate_out out ~max_len)
  | () when Byte_reader.length r <= pos -> Ok (truncate_out out ~max_len)
  | () ->
      let* ty = need (Byte_reader.byte r ~pos) Truncated_chunk in
      let* declared =
        need (Byte_reader.le r ~pos:(pos + 1) ~len:3) Truncated_chunk
      in
      let body = pos + chunk_header_len in
      let next = body + declared in
      let data = body + checksum_len in
      let payload = declared - checksum_len in
      (match () with
      | () when (not seen_id) && ty <> 0xff -> Error Missing_stream_identifier
      | () when declared > max_declared_chunk_len ->
          Error (Declared_length_too_large { len = declared })
      | () -> (
          match classify ty with
          | Stream_identifier ->
              if declared <> String.length stream_body then
                Error Bad_stream_identifier
              else
                let* got =
                  need
                    (Byte_reader.sub r ~pos:body ~len:declared)
                    Truncated_chunk
                in
                if String.equal got stream_body then
                  chunks r out ~max_len ~pos:next ~seen_id:true
                else Error Bad_stream_identifier
          | Padding | Reserved_skippable ->
              (* snap reads the body and discards it, so a truncated one is
                 still an error (read.rs:143-147,155-158). *)
              let* (_ : string) =
                need (Byte_reader.sub r ~pos:body ~len:declared) Truncated_chunk
              in
              chunks r out ~max_len ~pos:next ~seen_id
          | Reserved_unskippable -> Error (Unskippable_reserved ty)
          | Uncompressed ->
              if declared < checksum_len then
                Error (Missing_checksum { len = declared })
              else
                let* expected =
                  need (Byte_reader.le r ~pos:body ~len:4) Truncated_chunk
                in
                if payload > max_block_size then
                  Error (Block_too_large { len = payload })
                else
                  let* got =
                    need
                      (Byte_reader.sub r ~pos:data ~len:payload)
                      Truncated_chunk
                  in
                  let* () = check_crc ~expected got in
                  Buffer.add_string out got;
                  chunks r out ~max_len ~pos:next ~seen_id
          | Compressed ->
              if declared < checksum_len then
                Error (Missing_checksum { len = declared })
              else
                let* expected =
                  need (Byte_reader.le r ~pos:body ~len:4) Truncated_chunk
                in
                let* block =
                  need
                    (Byte_reader.sub r ~pos:data ~len:payload)
                    Truncated_chunk
                in
                let* got =
                  Result.map_error raw_error
                    (Snappy_raw.decode ~max_len:max_block_size block)
                in
                let* () = check_crc ~expected got in
                Buffer.add_string out got;
                chunks r out ~max_len ~pos:next ~seen_id))

let decompress ~max_len frame =
  chunks
    (Byte_reader.of_string frame)
    (Buffer.create (max 16 (min max_len max_block_size)))
    ~max_len ~pos:0 ~seen_id:false
