(* RLP, ported byte-for-byte from the reth pin alloy-rlp 0.3.13. Source citations
   below are to that crate's src/. All arithmetic is on native int: an RLP length
   never approaches 2^62, and decode guards the one adversarial case (a declared
   length wider than int) with the Overflow error. *)

type item =
  | Str of string
  | List of item list

type error =
  | Input_too_short
  | Non_canonical_single_byte
  | Non_canonical_size
  | Leading_zero
  | Overflow
  | Trailing_bytes

let error_to_string = function
  | Input_too_short -> "input too short"
  | Non_canonical_single_byte -> "non-canonical single byte"
  | Non_canonical_size -> "non-canonical size"
  | Leading_zero -> "leading zero in length"
  | Overflow -> "length overflows a native int"
  | Trailing_bytes -> "trailing bytes after item"

(* ---- shared constants (alloy-rlp src/lib.rs:40,43; header.rs:156) ---- *)

let empty_string_code = 0x80
let empty_list_code = 0xc0
let long_string_base = 0xb7
let long_list_base = 0xf7

(* The short/long boundary is 56: a payload of 55 bytes is still short
   (alloy-rlp src/header.rs:150). *)
let short_limit = 56

(* Minimal big-endian bytes of a non-negative int, no leading zeros; 0 -> "".
   A right fold builds the byte list most-significant-first without a loop. *)
let big_endian n =
  let rec digits n acc =
    if n <= 0 then acc else digits (n lsr 8) (Char.chr (n land 0xff) :: acc)
  in
  String.of_seq (List.to_seq (digits n []))

(* alloy-rlp src/encode.rs:364-371: 1 for a short payload, else 1 + the minimal
   big-endian byte count of the length. *)
let length_of_length n =
  if n < short_limit then 1 else 1 + String.length (big_endian n)

(* A header for [short_base] (0x80 string / 0xc0 list) and its matching long base
   (0xb7 / 0xf7): short form is a single [short_base + len] byte; long form is
   [long_base + len_of_len] followed by the minimal big-endian length
   (alloy-rlp src/header.rs:149-159). *)
let header ~short_base ~long_base payload_length =
  if payload_length < short_limit then
    String.make 1 (Char.chr (short_base + payload_length))
  else
    let len_be = big_endian payload_length in
    String.make 1 (Char.chr (long_base + String.length len_be)) ^ len_be

let string_header = header ~short_base:empty_string_code ~long_base:long_string_base
let list_header = header ~short_base:empty_list_code ~long_base:long_list_base

(* alloy-rlp src/encode.rs:86-92: a one-byte string whose byte is < 0x80 is its
   own encoding; every other string gets a header. Leading zeros are preserved. *)
let encode_bytes s =
  if String.length s = 1 && Char.code (String.get s 0) < empty_string_code then s
  else string_header (String.length s) ^ s

let strip_leading_zeros s =
  let n = String.length s in
  let rec first_nonzero i =
    if i >= n then n else if String.get s i = '\000' then first_nonzero (i + 1) else i
  in
  let i = first_nonzero 0 in
  String.sub s i (n - i)

(* alloy-rlp src/encode.rs:172-185: a scalar is its minimal big-endian bytes run
   through the byte-string rule, so 0 (and any all-zero input) becomes 0x80. *)
let encode_scalar s = encode_bytes (strip_leading_zeros s)

let encode_nat n = encode_scalar (big_endian n)

(* alloy-rlp src/encode.rs:330-384: concatenate the already-encoded items and
   prepend a list header sized to their total length. *)
let encode_list items =
  let payload = String.concat "" items in
  list_header (String.length payload) ^ payload

let rec encode = function
  | Str s -> encode_bytes s
  | List items -> encode_list (List.map encode items)

(* ---- decode (alloy-rlp src/header.rs:24-69, decode.rs:102-113) ---- *)

let byte_at s i = Char.code (String.get s i)

(* Decode a big-endian length from [len] bytes at [pos]; reject a leading zero
   byte (non-minimal) and a value wider than a native int. *)
let decode_length s pos len =
  if pos + len > String.length s then Error Input_too_short
  else if len > 0 && byte_at s pos = 0 then Error Leading_zero
  else
    let rec go i acc =
      if i >= len then Ok acc
      else
        let b = byte_at s (pos + i) in
        (* guard the multiply-then-add before it can overflow into a negative. *)
        if acc > (max_int - b) / 256 then Error Overflow
        else go (i + 1) ((acc * 256) + b)
    in
    go 0 0

(* Decode one item starting at [pos]; return it with the next position. *)
let rec decode_at s pos =
  let slen = String.length s in
  if pos >= slen then Error Input_too_short
  else
    let b = byte_at s pos in
    if b < empty_string_code then Ok (Str (String.sub s pos 1), pos + 1)
    else if b < long_string_base + 1 then
      decode_short_string s (pos + 1) (b - empty_string_code)
    else if b < empty_list_code then
      decode_long s (pos + 1) (b - long_string_base) ~is_list:false
    else if b < long_list_base + 1 then decode_short_list s (pos + 1) (b - empty_list_code)
    else decode_long s (pos + 1) (b - long_list_base) ~is_list:true

and decode_short_string s start len =
  if start + len > String.length s then Error Input_too_short
  else
    let payload = String.sub s start len in
    if len = 1 && Char.code (String.get payload 0) < empty_string_code then
      Error Non_canonical_single_byte
    else Ok (Str payload, start + len)

and decode_short_list s start len =
  if start + len > String.length s then Error Input_too_short
  else
    Result.map (fun items -> (List items, start + len)) (decode_items s start (start + len) [])

(* A long-form header ([0xb8..0xbf] string, [0xf8..0xff] list): read the
   [len_of_len] length bytes, reject a payload that should have been short, then
   read the payload. *)
and decode_long s len_start len_of_len ~is_list =
  match decode_length s len_start len_of_len with
  | Error _ as e -> e
  | Ok payload_length ->
      if payload_length < short_limit then Error Non_canonical_size
      else
        let start = len_start + len_of_len in
        (* Compare by SUBTRACTION, never by forming [start + payload_length]: a
           declared length may be as large as [max_int] (that is exactly what
           [decode_length]'s guard admits), and the sum would wrap to a negative
           int, pass this test, and reach [String.sub] with a 2^62 length —
           raising [Invalid_argument] out of a total decoder. [decode_length] has
           already rejected [len_start + len_of_len > String.length s], so
           [start <= String.length s] and the subtraction cannot underflow. *)
        if payload_length > String.length s - start then Error Input_too_short
        else if is_list then
          Result.map
            (fun items -> (List items, start + payload_length))
            (decode_items s start (start + payload_length) [])
        else Ok (Str (String.sub s start payload_length), start + payload_length)

(* Decode items until exactly [stop]; an item that would cross [stop] is a
   malformed length. *)
and decode_items s pos stop acc =
  if pos = stop then Ok (List.rev acc)
  else if pos > stop then Error Input_too_short
  else
    match decode_at s pos with
    | Error _ as e -> e
    | Ok (item, next) ->
        if next > stop then Error Input_too_short else decode_items s next stop (item :: acc)

let decode s =
  decode_at s 0 |> Result.map (fun (item, pos) -> (item, String.sub s pos (String.length s - pos)))

let decode_exact s =
  match decode_at s 0 with
  | Error _ as e -> e
  | Ok (item, pos) -> if pos = String.length s then Ok item else Error Trailing_bytes
