(* The wire envelope of crates/network-libp2p/src/codec.rs at
   telcoin-network 31cc4e90. The interface file carries the layout, the check
   order and the taxonomy; this file carries only the mechanics.

   No byte of this module is reached by an index. The eight-byte header is
   read through the BCS reader, which is bounds checked and reports a short
   buffer as an error (bcs.mli:45-56), and the body is cut out through
   Tn_snappy.Byte_reader.sub, which answers None for a window outside the
   buffer. So there is no String.get, no String.sub and no partial accessor
   anywhere below, and no exception can escape.

   Division audit for the house rule: this file contains exactly one '/', in
   [sixth], and its denominator is the literal 6. *)

module Bcs = Tn_codec.Bcs
module Frame = Tn_snappy.Snappy_frame
module Byte_reader = Tn_snappy.Byte_reader

type header = { uncompressed_len : int; compressed_len : int }

type error =
  | Prefix_too_large of { declared : int; max : int }
  | Compressed_len_exceeds_bound of { declared : int; bound : int }
  | Truncated_body of { expected : int; got : int }
  | Snappy of Frame.error
  | Length_mismatch of { declared : int; got : int }
  | Message_too_large of { len : int; max : int }
  | Header_truncated of { got : int }

let error_to_string = function
  | Prefix_too_large { declared; max } ->
      Printf.sprintf
        "prefix indicates message size is too large: %d declared, %d allowed"
        declared max
  | Compressed_len_exceeds_bound { declared; bound } ->
      Printf.sprintf
        "compressed size exceeds max for reported uncompressed size: %d \
         declared, %d allowed"
        declared bound
  | Truncated_body { expected; got } ->
      Printf.sprintf
        "compressed body shorter than reported compressed size: %d expected, \
         %d present"
        expected got
  | Snappy e -> "snappy frame: " ^ Frame.error_to_string e
  | Length_mismatch { declared; got } ->
      Printf.sprintf
        "decompressed size does not match reported uncompressed size: %d \
         declared, %d produced"
        declared got
  | Message_too_large { len; max } ->
      Printf.sprintf "encode data > max_message_size: %d bytes, %d allowed" len
        max
  | Header_truncated { got } ->
      Printf.sprintf "wire header truncated: %d of 8 bytes" got

let ( let* ) = Result.bind

(* The header is exactly what BCS calls a pair of u32s: four little-endian
   bytes each, in the order [uncompressed_len] then [compressed_len]
   (codec.rs:146-150). Reusing the codec keeps the read bounds checked and
   the write free of any hand-rolled shifting. *)
let header_codec = Bcs.pair Bcs.u32 Bcs.u32

(* The largest length a 4-byte prefix can carry. Rust holds these lengths in
   a u32 and casts with [as u32]; the OCaml int is 63-bit, so the ceiling is
   stated here instead of being implied by the type. *)
let prefix_ceiling = 0xffff_ffff

(* Integer division by a non-zero literal: total for every input, including
   0 and negative numbers, and the only '/' in this file. *)
let sixth n = n / 6

let max_compress_len n =
  (* snap clamps TWICE (compress.rs:42-53): once on the input length, and
     once on the computed sum [32 + n + n / 6] when that sum itself passes
     MAX_INPUT_SIZE. The second clamp starts at n = 3_681_400_512, well below
     the prefix ceiling, so it is reachable from a 4-byte prefix. *)
  if n < 0 || n > prefix_ceiling then 0
  else
    let m = 32 + n + sixth n in
    if m > prefix_ceiling then 0 else m

(* The whole header, before any size check. The only way [header_codec] can
   fail on a string is running out of input, so every BCS error at this point
   means the same thing: fewer than eight bytes were offered. *)
let read_header wire =
  Result.fold
    ~ok:(fun ((uncompressed_len, compressed_len), (_ : int)) ->
      Ok { uncompressed_len; compressed_len })
    ~error:(fun (_ : Bcs.error) ->
      Error (Header_truncated { got = String.length wire }))
    (Bcs.decode_prefix header_codec wire)

(* Checks #1 and #2, in Rust's order (codec.rs:52-67). *)
let check_header ~max_message_size h =
  let bound = max_compress_len h.uncompressed_len in
  if h.uncompressed_len > max_message_size then
    Error
      (Prefix_too_large { declared = h.uncompressed_len; max = max_message_size })
  else if h.compressed_len > bound then
    Error (Compressed_len_exceeds_bound { declared = h.compressed_len; bound })
  else Ok h

let parse_header ~max_message_size wire =
  let* h = read_header wire in
  check_header ~max_message_size h

(* Check #3 (codec.rs:78-83): the body must be present in full. [got] counts
   what is there after the header, which is the Rust reader's "delivered"
   count, and is clamped at 0 for a buffer that is all header. *)
let body_of ~compressed_len wire =
  let present = String.length wire - 8 in
  Option.fold
    ~none:
      (Error
         (Truncated_body
            { expected = compressed_len; got = (if present < 0 then 0 else present) }))
    ~some:Result.ok
    (Byte_reader.sub (Byte_reader.of_string wire) ~pos:8 ~len:compressed_len)

let encode ~max_message_size bcs_bytes =
  let len = String.length bcs_bytes in
  let max =
    if max_message_size < prefix_ceiling then max_message_size
    else prefix_ceiling
  in
  if len > max then Error (Message_too_large { len; max })
  else
    let frame = Frame.compress bcs_bytes in
    Ok (Bcs.encode header_codec (len, String.length frame) ^ frame)

let decode ~max_message_size wire =
  let* h = parse_header ~max_message_size wire in
  let* body = body_of ~compressed_len:h.compressed_len wire in
  (* Check #5 and the take cap (codec.rs:88-94): decompression stops at the
     declared uncompressed length instead of rejecting an over-run. *)
  let* produced =
    Result.map_error
      (fun e -> Snappy e)
      (Frame.decompress ~max_len:h.uncompressed_len body)
  in
  let got = String.length produced in
  (* Check #6 (codec.rs:97-101), on the RETURNED length. *)
  if got <> h.uncompressed_len then
    Error (Length_mismatch { declared = h.uncompressed_len; got })
  else Ok (produced, 8 + h.compressed_len)

type error_or_bcs = Frame_error of error | Bcs_error of Bcs.error

let error_or_bcs_to_string = function
  | Frame_error e -> error_to_string e
  | Bcs_error e -> "bcs payload: " ^ Bcs.error_to_string e

let encode_msg ~max_message_size codec v =
  Result.map_error
    (fun e -> Frame_error e)
    (encode ~max_message_size (Bcs.encode codec v))

let decode_msg ~max_message_size codec wire =
  let* payload, consumed =
    Result.map_error (fun e -> Frame_error e) (decode ~max_message_size wire)
  in
  Result.fold
    ~ok:(fun v -> Ok (v, consumed))
    ~error:(fun e -> Error (Bcs_error e))
    (Bcs.decode codec payload)
