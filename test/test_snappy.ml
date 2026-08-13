(* Chunk-44 stage 1: [Tn_snappy] against the chunk-44 Rust oracle harness.

   The golden rows in snappy_vectors.ml are the byte output of snap 1.1.1,
   the version telcoin-network @ 31cc4e90 pins, so a green run here is wire
   evidence and not round-trip self-consistency. The suite covers both
   directions of the interop claim: this file decodes Rust-produced bytes,
   and `dune exec test/test_snappy.exe -- --emit-reverse` prints the port's
   own output as `kind cap hex expected` rows that the harness's `decode-file`
   subcommand replays through snap itself.

   The take-boundary rows (T1-T6) are the discriminating ones. Rust decodes
   with `FrameDecoder::new(r).take(uncompressed_len)`, which TRUNCATES rather
   than rejecting: a chunk straddling the cap is fully decoded and checksum
   checked, a chunk wholly past the cap is never read at all, and a cap of 0
   accepts anything. Each of those was measured against snap by the harness
   (facts-raw.txt:64-79) and each hand-built stream was replayed through it
   (reverse-gate-handbuilt.txt) before it was trusted here. *)

module V = Snappy_vectors
module Crc = Tn_snappy.Crc32c
module Raw = Tn_snappy.Snappy_raw
module Frame = Tn_snappy.Snappy_frame

(* ------------------------------------------------------------------ helpers *)

let hex s =
  let buf = Buffer.create ((String.length s * 2) + 2) in
  String.iter
    (fun c -> Buffer.add_string buf (Printf.sprintf "%02x" (Char.code c)))
    s;
  Buffer.contents buf

let prefix n s =
  Tn_snappy.Byte_reader.sub
    (Tn_snappy.Byte_reader.of_string s)
    ~pos:0
    ~len:(min (max n 0) (String.length s))
  |> Option.value ~default:""

let shape expected got =
  Printf.sprintf " (expected %d bytes, got %d)" (String.length expected)
    (String.length got)

(* Error tags, one exhaustive match per error type, so a negative row can name
   the exact rejection without a catch-all arm and without pinning payload
   fields the row does not care about. *)
let raw_tag = function
  | Raw.Truncated -> "truncated"
  | Raw.Preamble_overflow -> "preamble_overflow"
  | Raw.Copy_offset_out_of_range _ -> "copy_offset_out_of_range"
  | Raw.Length_mismatch _ -> "length_mismatch"
  | Raw.Exceeds_max _ -> "exceeds_max"

let frame_tag = function
  | Frame.Missing_stream_identifier -> "missing_stream_identifier"
  | Frame.Bad_stream_identifier -> "bad_stream_identifier"
  | Frame.Truncated_chunk -> "truncated_chunk"
  | Frame.Unskippable_reserved _ -> "unskippable_reserved"
  | Frame.Crc_mismatch _ -> "crc_mismatch"
  | Frame.Block_too_large _ -> "block_too_large"
  | Frame.Declared_length_too_large _ -> "declared_length_too_large"
  | Frame.Missing_checksum _ -> "missing_checksum"
  | Frame.Raw _ -> "raw"

let expect_bytes name ~expected got =
  Alcotest.(check bool)
    (name ^ shape expected got)
    true
    (String.equal expected got)

let raw_ok name ~expected got =
  Result.fold
    ~ok:(fun s -> expect_bytes name ~expected s)
    ~error:(fun e -> Alcotest.fail (name ^ ": " ^ Raw.error_to_string e))
    got

let frame_ok name ~expected got =
  Result.fold
    ~ok:(fun s -> expect_bytes name ~expected s)
    ~error:(fun e -> Alcotest.fail (name ^ ": " ^ Frame.error_to_string e))
    got

let raw_rejects name ~tag got =
  Result.fold
    ~ok:(fun s ->
      Alcotest.fail
        (Printf.sprintf "%s: accepted %d bytes" name (String.length s)))
    ~error:(fun e -> Alcotest.(check string) name tag (raw_tag e))
    got

let frame_rejects name ~tag got =
  Result.fold
    ~ok:(fun s ->
      Alcotest.fail
        (Printf.sprintf "%s: accepted %d bytes" name (String.length s)))
    ~error:(fun e -> Alcotest.(check string) name tag (frame_tag e))
    got

let put_le buf ~width v =
  List.iter
    (fun i -> Buffer.add_uint8 buf ((v lsr (8 * i)) land 0xff))
    (List.init width Fun.id)

(* A 0x01 chunk built straight to the format, so the size-cap rows can ask
   for a chunk this port's own compressor would never emit. *)
let uncompressed_chunk data =
  let buf = Buffer.create (String.length data + 8) in
  Buffer.add_uint8 buf 0x01;
  put_le buf ~width:3 (String.length data + 4);
  put_le buf ~width:4 (Crc.mask (Crc.digest data));
  Buffer.add_string buf data;
  Buffer.contents buf

let stream_id = V.stream_hex "ok_stream_id_only"

(* The interop bound the wire codec applies to a compressed body,
   snap::raw::max_compress_len = 32 + n + n / 6 (GT:294-298). Division by a
   non-zero literal, so it is total. *)
let max_compress_len n = 32 + n + (n / 6)

(* The size the port's frame compressor emits: a 10-byte stream identifier
   plus 8 bytes of header per chunk of at most 65536 bytes. *)
let compressed_size n = 10 + n + (8 * ((n + 65535) / 65536))

let generator_inputs =
  List.map (fun (r : V.row) -> (r.name, V.input_of r.gen)) V.golden_rows

(* --------------------------------------------------------------- the floor *)

let vector_count =
  List.length V.golden_rows + List.length V.crc_kat + List.length V.streams

let case_total = ref 0

let t_floor () =
  Alcotest.(check bool)
    (Printf.sprintf "vector rows %d >= 25" vector_count)
    true
    (vector_count >= 25);
  Alcotest.(check bool)
    (Printf.sprintf "test cases %d >= 25" !case_total)
    true
    (!case_total >= 25);
  Alcotest.(check bool)
    "the oracle golden rows are present"
    true
    (List.length V.golden_rows >= 19)

(* ---------------------------------------------------------------- CRC-32C *)

let t_crc_kat () =
  List.iter
    (fun (input, crc, masked) ->
      Alcotest.(check int)
        (Printf.sprintf "crc32c %S" input)
        crc (Crc.digest input);
      Alcotest.(check int)
        (Printf.sprintf "masked %S" input)
        masked
        (Crc.mask (Crc.digest input)))
    V.crc_kat

let t_crc_oracle_rows () =
  let checked =
    List.fold_left
      (fun n (r : V.row) ->
        let input = V.input_of r.gen in
        Alcotest.(check int)
          (r.name ^ " input length")
          r.input_len (String.length input);
        Alcotest.(check int) (r.name ^ " crc32c") r.crc32c (Crc.digest input);
        Alcotest.(check int)
          (r.name ^ " masked")
          r.crc32c_masked
          (Crc.mask (Crc.digest input));
        n + 1)
      0 V.golden_rows
  in
  Alcotest.(check int) "rows checked" (List.length V.golden_rows) checked

let t_crc_update () =
  let s = "the quick brown fox jumps over a lazy dog" in
  let n = String.length s in
  Result.fold
    ~ok:(fun c ->
      Alcotest.(check int) "update over all of it = digest" (Crc.digest s) c)
    ~error:(fun e -> Alcotest.fail (Crc.error_to_string e))
    (Crc.update 0 s ~pos:0 ~len:n);
  Result.fold
    ~ok:(fun c -> Alcotest.(check int) "two windows compose" (Crc.digest s) c)
    ~error:(fun e -> Alcotest.fail (Crc.error_to_string e))
    (Result.bind (Crc.update 0 s ~pos:0 ~len:7) (fun c ->
         Crc.update c s ~pos:7 ~len:(n - 7)));
  Result.fold
    ~ok:(fun (_ : int) -> Alcotest.fail "accepted a window past the end")
    ~error:(fun e ->
      Alcotest.(check string)
        "past the end"
        (Printf.sprintf
           "crc32c: window pos=%d len=1 is not inside a string of %d bytes" n n)
        (Crc.error_to_string e))
    (Crc.update 0 s ~pos:n ~len:1);
  Result.fold
    ~ok:(fun (_ : int) -> Alcotest.fail "accepted a negative start")
    ~error:(fun (_ : Crc.error) -> ())
    (Crc.update 0 s ~pos:(-1) ~len:2)

let t_crc_mask () =
  Alcotest.(check int) "mask 0" 0xa282ead8 (Crc.mask 0);
  Alcotest.(check int) "mask 0xffffffff" 0xa282ead7 (Crc.mask 0xffffffff);
  Alcotest.(check int)
    "mask of the check value" 0xc78ab0e5 (Crc.mask 0xe3069283);
  List.iter
    (fun v ->
      let m = Crc.mask v in
      Alcotest.(check bool)
        (Printf.sprintf "mask 0x%08x stays inside 32 bits" v)
        true
        (m >= 0 && m <= 0xffffffff))
    [ 0; 1; 0x8000; 0x1_0000; 0x7fff_ffff; 0x8000_0000; 0xffff_ffff ]

(* ------------------------------------------------------------- raw blocks *)

let t_raw_golden () =
  let checked =
    List.fold_left
      (fun n (r : V.row) ->
        Option.fold ~none:n
          ~some:(fun h ->
            let input = V.input_of r.gen in
            let block = V.unhex h in
            Alcotest.(check int)
              (r.name ^ " raw length")
              r.raw_len (String.length block);
            raw_ok (r.name ^ " raw decode") ~expected:input
              (Raw.decode ~max_len:(String.length input) block);
            n + 1)
          r.raw_hex)
      0 V.golden_rows
  in
  (* Positive control: the rows really were exercised, so a vector file that
     lost its hex column cannot pass this vacuously. *)
  Alcotest.(check bool)
    (Printf.sprintf "%d raw rows decoded" checked)
    true (checked >= 15)

let t_raw_encode_matches_snap () =
  let literal_only =
    [
      "s_empty"; "s_one_byte"; "s_kat_123456789"; "s_hello"; "s_lcg_64";
      "s_lcg_1024";
    ]
  in
  let checked =
    List.fold_left
      (fun n (r : V.row) ->
        if List.mem r.name literal_only then
          Option.fold ~none:n
            ~some:(fun h ->
              expect_bytes
                (r.name ^ " encode = snap")
                ~expected:(V.unhex h)
                (Raw.encode (V.input_of r.gen));
              n + 1)
            r.raw_hex
        else n)
      0 V.golden_rows
  in
  Alcotest.(check int)
    "literal-only rows compared" (List.length literal_only) checked

let t_raw_roundtrip () =
  List.iter
    (fun (name, input) ->
      raw_ok (name ^ " raw round trip") ~expected:input
        (Raw.decode ~max_len:(String.length input) (Raw.encode input)))
    generator_inputs

let t_raw_bound () =
  List.iter
    (fun n ->
      let size = String.length (Raw.encode (String.make n 'q')) in
      Alcotest.(check bool)
        (Printf.sprintf "raw encode %d -> %d <= %d" n size (max_compress_len n))
        true
        (size <= max_compress_len n))
    [ 0; 1; 59; 60; 61; 255; 256; 257; 65535; 65536; 65537; 1_048_576 ]

let t_raw_truncated () =
  (* "hello world" as one literal, cut three bytes short. *)
  raw_rejects "truncated literal" ~tag:"truncated"
    (Raw.decode ~max_len:64 (prefix 10 (V.unhex "0b2868656c6c6f20776f726c64")));
  raw_rejects "empty block" ~tag:"truncated" (Raw.decode ~max_len:64 "")

let t_raw_copy_offset () =
  (* Declares 10 bytes, then a 2-byte-offset copy 8 bytes back with nothing
     produced yet. *)
  raw_rejects "copy before the start" ~tag:"copy_offset_out_of_range"
    (Raw.decode ~max_len:64 (V.unhex "0a0e0800"));
  (* One literal byte, then a copy of offset 0. *)
  raw_rejects "copy offset zero" ~tag:"copy_offset_out_of_range"
    (Raw.decode ~max_len:64 (V.unhex "0a00410e0000"))

let t_raw_length_mismatch () =
  (* Declares 12 bytes, the single literal produces 11. *)
  raw_rejects "short production" ~tag:"length_mismatch"
    (Raw.decode ~max_len:64 (V.unhex "0c2868656c6c6f20776f726c64"));
  (* Declares 4 bytes, the literal produces 11. *)
  raw_rejects "long production" ~tag:"length_mismatch"
    (Raw.decode ~max_len:64 (V.unhex "042868656c6c6f20776f726c64"))

let t_raw_exceeds_max () =
  raw_rejects "declared above the cap" ~tag:"exceeds_max"
    (Raw.decode ~max_len:10 (V.unhex "0b2868656c6c6f20776f726c64"));
  raw_ok "declared at the cap" ~expected:"hello world"
    (Raw.decode ~max_len:11 (V.unhex "0b2868656c6c6f20776f726c64"))

let t_raw_preamble () =
  (* snap's read_varu64 (bytes.rs:73-90) has no minimality rule, so a padded
     preamble must be ACCEPTED, exactly as the Rust node accepts it. *)
  raw_ok "non-minimal preamble" ~expected:"A"
    (Raw.decode ~max_len:64 (V.unhex "81000041"));
  (* snap keeps the accumulator in a u64 and [checked_shl] fails only when the
     SHIFT reaches 64, so payload bits pushed past bit 63 are DROPPED rather
     than reported. A tenth byte sits at shift 63, where an EVEN payload
     survives as nothing and the block decodes: the oracle probe against snap
     1.1.1 answers ok "abc" for these very bytes. An ODD payload keeps bit 63,
     which puts the length past MAX_INPUT_SIZE, and snap reports TooBig. *)
  raw_ok "a ten-byte preamble, even terminal payload" ~expected:"abc"
    (Raw.decode ~max_len:64 (V.unhex "8380808080808080800208616263"));
  raw_rejects "a ten-byte preamble, odd terminal payload"
    ~tag:"preamble_overflow"
    (Raw.decode ~max_len:64 (V.unhex "8380808080808080800108616263"));
  (* Payload bits past 2^32. *)
  raw_rejects "preamble past 32 bits" ~tag:"preamble_overflow"
    (Raw.decode ~max_len:0xffffffff (V.unhex "ffffffffff7f"));
  raw_rejects "preamble with no terminator" ~tag:"truncated"
    (Raw.decode ~max_len:64 (V.unhex "8080"))

(* ----------------------------------------------------------- frame streams *)

let t_frame_golden () =
  let checked =
    List.fold_left
      (fun n (r : V.row) ->
        Option.fold ~none:n
          ~some:(fun h ->
            let input = V.input_of r.gen in
            let frame = V.unhex h in
            Alcotest.(check int)
              (r.name ^ " frame length")
              r.frame_len (String.length frame);
            frame_ok (r.name ^ " frame decompress") ~expected:input
              (Frame.decompress ~max_len:(String.length input) frame);
            n + 1)
          r.frame_hex)
      0 V.golden_rows
  in
  Alcotest.(check bool)
    (Printf.sprintf "%d oracle frames decoded" checked)
    true (checked >= 14)

let t_frame_boundary () =
  let boundary =
    [
      "s_mod251_65535"; "s_mod251_65536"; "s_mod251_65537"; "s_zeros_65536";
      "s_zeros_65537";
    ]
  in
  let checked =
    List.fold_left
      (fun n (r : V.row) ->
        if List.mem r.name boundary then
          Option.fold ~none:n
            ~some:(fun h ->
              let input = V.input_of r.gen in
              frame_ok (r.name ^ " boundary") ~expected:input
                (Frame.decompress ~max_len:(String.length input) (V.unhex h));
              n + 1)
            r.frame_hex
        else n)
      0 V.golden_rows
  in
  Alcotest.(check int) "boundary rows" (List.length boundary) checked

let t_frame_roundtrip () =
  List.iter
    (fun (name, input) ->
      frame_ok (name ^ " frame round trip") ~expected:input
        (Frame.decompress ~max_len:(String.length input) (Frame.compress input)))
    generator_inputs

let t_frame_structure () =
  List.iter
    (fun n ->
      let out = Frame.compress (String.make n 'w') in
      Alcotest.(check int)
        (Printf.sprintf "compress %d size" n)
        (compressed_size n) (String.length out);
      expect_bytes
        (Printf.sprintf "compress %d opens with the stream identifier" n)
        ~expected:stream_id (prefix 10 out))
    [ 0; 1; 65535; 65536; 65537; 131_072; 131_073 ]

let t_frame_bound () =
  List.iter
    (fun n ->
      let size = String.length (Frame.compress (String.make n 'w')) in
      Alcotest.(check bool)
        (Printf.sprintf "frame %d -> %d <= %d" n size (max_compress_len n))
        true
        (size <= max_compress_len n))
    [ 0; 1; 65536; 65537; 1_048_576 ]

(* ------------------------------------------------- the take-boundary rules *)

let a10 = String.make 10 'A'
let b10 = String.make 10 'B'

let t_take_mid_chunk () =
  let s = V.stream_hex "take_two_good" in
  frame_ok "cap 5 lands mid-chunk" ~expected:(prefix 5 a10)
    (Frame.decompress ~max_len:5 s);
  frame_ok "cap 10 ends a chunk" ~expected:a10 (Frame.decompress ~max_len:10 s);
  frame_ok "cap 15 lands mid-chunk"
    ~expected:(a10 ^ prefix 5 b10)
    (Frame.decompress ~max_len:15 s);
  frame_ok "cap 20 takes both"
    ~expected:(a10 ^ b10)
    (Frame.decompress ~max_len:20 s);
  frame_ok "cap 40 under-runs"
    ~expected:(a10 ^ b10)
    (Frame.decompress ~max_len:40 s)

let t_take_corrupt_past_cap () =
  let s = V.stream_hex "take_second_corrupt" in
  frame_ok "corrupt chunk past the cap is never read" ~expected:a10
    (Frame.decompress ~max_len:10 s);
  frame_ok "cap 5 stops before it too" ~expected:(prefix 5 a10)
    (Frame.decompress ~max_len:5 s)

let t_take_corrupt_one_byte_in () =
  frame_rejects "one byte into the corrupt chunk" ~tag:"crc_mismatch"
    (Frame.decompress ~max_len:11 (V.stream_hex "take_second_corrupt"));
  frame_rejects "well past it" ~tag:"crc_mismatch"
    (Frame.decompress ~max_len:20 (V.stream_hex "take_second_corrupt"))

let t_take_corrupt_straddling () =
  (* The straddling chunk IS decoded and checksum checked, so a bad checksum
     inside the consumed region is fatal even when the cap cuts it short. *)
  frame_rejects "straddling chunk is checksum checked" ~tag:"crc_mismatch"
    (Frame.decompress ~max_len:5 (V.stream_hex "take_first_corrupt"));
  frame_rejects "and at a larger cap" ~tag:"crc_mismatch"
    (Frame.decompress ~max_len:20 (V.stream_hex "take_first_corrupt"))

let t_take_truncated_tail () =
  let s = V.stream_hex "take_truncated_last" in
  frame_ok "truncated tail past the cap is invisible" ~expected:a10
    (Frame.decompress ~max_len:10 s);
  frame_rejects "truncated tail inside the cap" ~tag:"truncated_chunk"
    (Frame.decompress ~max_len:20 s)

let t_take_zero_cap () =
  List.iter
    (fun name ->
      frame_ok ("cap 0 accepts " ^ name) ~expected:""
        (Frame.decompress ~max_len:0 (V.stream_hex name)))
    [
      "take_two_good"; "take_first_corrupt"; "neg_missing_stream_id";
      "neg_reserved_02";
    ];
  frame_ok "cap 0 accepts arbitrary bytes" ~expected:""
    (Frame.decompress ~max_len:0 (V.unhex "deadbeefdeadbeef"))

(* A negative cap cannot come from the wire codec, whose length is always a
   decoded u32, but [decompress] is typed to take any int and the house rule
   is that a result-typed function is total for every value of its argument
   types. Rust counts the [take] limit in u64 and cannot express a negative
   one, so the empty answer of [max_len = 0] is the only faithful reading. *)
let t_take_negative_cap () =
  List.iter
    (fun name ->
      frame_ok ("cap -1 accepts " ^ name) ~expected:""
        (Frame.decompress ~max_len:(-1) (V.stream_hex name)))
    [
      "take_two_good"; "take_first_corrupt"; "neg_missing_stream_id";
      "neg_reserved_02";
    ];
  frame_ok "cap -1 accepts a bare stream identifier" ~expected:""
    (Frame.decompress ~max_len:(-1) stream_id);
  frame_ok "min_int cap accepts arbitrary bytes" ~expected:""
    (Frame.decompress ~max_len:min_int (V.unhex "deadbeefdeadbeef"));
  frame_ok "negative cap on this port's own output" ~expected:""
    (Frame.decompress ~max_len:(-4096) (Frame.compress a10))

(* --------------------------------------------------------- frame negatives *)

let t_neg_missing_stream_id () =
  frame_rejects "no stream identifier" ~tag:"missing_stream_identifier"
    (Frame.decompress ~max_len:100 (V.stream_hex "neg_missing_stream_id"))

let t_neg_bad_stream_id () =
  frame_rejects "sNaPpX body" ~tag:"bad_stream_identifier"
    (Frame.decompress ~max_len:100 (V.stream_hex "neg_bad_stream_body"));
  frame_rejects "stream identifier of length 7" ~tag:"bad_stream_identifier"
    (Frame.decompress ~max_len:100 (V.stream_hex "neg_stream_len_7"))

let t_neg_crc () =
  frame_rejects "corrupt checksum inside the consumed region" ~tag:"crc_mismatch"
    (Frame.decompress ~max_len:100 (V.stream_hex "neg_crc_corrupt"))

let t_neg_truncated () =
  frame_rejects "chunk header cut short" ~tag:"truncated_chunk"
    (Frame.decompress ~max_len:100 (V.stream_hex "neg_truncated_header"));
  frame_rejects "chunk body cut short" ~tag:"truncated_chunk"
    (Frame.decompress ~max_len:100 (prefix 22 (V.stream_hex "take_two_good")))

let t_neg_reserved () =
  frame_rejects "reserved 0x02" ~tag:"unskippable_reserved"
    (Frame.decompress ~max_len:100 (V.stream_hex "neg_reserved_02"));
  frame_rejects "reserved 0x7f" ~tag:"unskippable_reserved"
    (Frame.decompress ~max_len:100 (V.stream_hex "neg_reserved_7f"))

let t_neg_block_cap () =
  let at_cap = String.make 65536 'z' in
  let over_cap = String.make 65537 'z' in
  frame_ok "a chunk of exactly 65536 bytes is accepted" ~expected:at_cap
    (Frame.decompress ~max_len:65536 (stream_id ^ uncompressed_chunk at_cap));
  frame_rejects "a chunk of 65537 bytes is rejected" ~tag:"block_too_large"
    (Frame.decompress ~max_len:65537 (stream_id ^ uncompressed_chunk over_cap))

let t_neg_declared_cap () =
  frame_rejects "declared length 76491" ~tag:"declared_length_too_large"
    (Frame.decompress ~max_len:100 (V.stream_hex "neg_declared_76491"))

let t_neg_short_data_chunk () =
  frame_rejects "data chunk with no room to hold a checksum"
    ~tag:"missing_checksum"
    (Frame.decompress ~max_len:100 (V.stream_hex "neg_short_data_chunk"))

let t_neg_compressed_block_cap () =
  frame_rejects "compressed block declaring 65537 bytes" ~tag:"block_too_large"
    (Frame.decompress ~max_len:100 (V.stream_hex "neg_compressed_over_cap"))

let t_skippable_and_padding () =
  let payload = "0123456789" in
  List.iter
    (fun name ->
      frame_ok (name ^ " is skipped") ~expected:payload
        (Frame.decompress ~max_len:100 (V.stream_hex name)))
    [ "ok_padding_fe"; "ok_skippable_80"; "ok_skippable_fd" ];
  (* A second stream identifier mid-stream is ACCEPTED by snap
     (facts-raw.txt:59), a rule the design sketch did not carry. *)
  frame_ok "a second stream identifier is accepted"
    ~expected:(payload ^ payload)
    (Frame.decompress ~max_len:100 (V.stream_hex "ok_second_stream_id"));
  frame_ok "a stream identifier alone decodes to nothing" ~expected:""
    (Frame.decompress ~max_len:100 stream_id)

(* ---------------------------------------------------------------- qcheck *)

(* Bytes go in through [Buffer.add_uint8], which truncates instead of
   failing, so the generator covers the whole 0-255 range with no partial
   [Char.chr]. *)
let bytes_of_ints l =
  let buf = Buffer.create (List.length l + 1) in
  List.iter (Buffer.add_uint8 buf) l;
  Buffer.contents buf

let gen_bytes =
  QCheck.Gen.(map bytes_of_ints (list_size (int_bound 4000) (int_bound 255)))

let arb_bytes =
  QCheck.make
    ~print:(fun s -> Printf.sprintf "%d bytes" (String.length s))
    gen_bytes

(* The cap range starts below 0 on purpose: [decompress] accepts any int, so
   the property has to explore the negative caps that the T7 rows pin down by
   hand. [prefix] already clamps a negative length to the empty string, so
   the expected value needs no special case. *)
let arb_bytes_and_cap =
  QCheck.make
    ~print:(fun (s, k) -> Printf.sprintf "%d bytes, cap %d" (String.length s) k)
    QCheck.Gen.(pair gen_bytes (int_range (-16) 4000))

let prop_frame_roundtrip s =
  Frame.decompress ~max_len:(String.length s) (Frame.compress s) = Ok s

let prop_frame_truncates (s, k) =
  Frame.decompress ~max_len:k (Frame.compress s) = Ok (prefix k s)

let prop_raw_roundtrip s =
  Raw.decode ~max_len:(String.length s) (Raw.encode s) = Ok s

let mk_prop ~salt ~count name arb fn =
  Alcotest.test_case name `Slow (fun () ->
      QCheck.Test.check_exn
        ~rand:(Random.State.make [| 0x5eed_44; salt |])
        (QCheck.Test.make ~count ~name arb fn))

(* ------------------------------------------------------- the reverse gate *)

(* Rows the Rust harness replays: `kind cap hex expected`, the shape
   `chunk44-oracle decode-file` reads. Printed before Alcotest starts, so the
   framework never captures them. *)
let reverse_rows () =
  let row kind cap payload bytes =
    Printf.sprintf "%s %d %s %s" kind cap (hex bytes) (hex payload)
  in
  let frame_row (_, input) =
    row "frame" (String.length input) input (Frame.compress input)
  in
  let raw_row (_, input) = row "raw" (String.length input) input (Raw.encode input) in
  let capped (_, input) =
    let cap = String.length input / 2 in
    row "frame" cap (prefix cap input) (Frame.compress input)
  in
  let small =
    List.filter (fun (_, i) -> String.length i <= 70_000) generator_inputs
  in
  let at_cap = String.make 65536 'z' in
  let over_cap = String.make 65537 'z' in
  List.concat
    [
      List.map frame_row generator_inputs;
      List.map raw_row small;
      List.map capped small;
      [ row "frame" 65536 at_cap (stream_id ^ uncompressed_chunk at_cap) ];
      (* A comment line, which decode-file skips: the reverse gate replays it
         on its own, because snap must REJECT it. *)
      [
        Printf.sprintf "# overcap frame 65537 %s"
          (hex (stream_id ^ uncompressed_chunk over_cap));
      ];
    ]

let () =
  if Array.exists (fun a -> String.equal a "--emit-reverse") Sys.argv then begin
    List.iter print_endline (reverse_rows ());
    exit 0
  end

(* ------------------------------------------------------------------ suites *)

let suites =
  [
    ("floor", [ Alcotest.test_case "F1 vector and case floor" `Quick t_floor ]);
    ( "crc32c",
      [
        Alcotest.test_case "C1 known answers" `Quick t_crc_kat;
        Alcotest.test_case "C2 oracle input rows" `Quick t_crc_oracle_rows;
        Alcotest.test_case "C3 update composes and is bounds checked" `Quick
          t_crc_update;
        Alcotest.test_case "C4 masking" `Quick t_crc_mask;
      ] );
    ( "raw blocks",
      [
        Alcotest.test_case "R1 oracle blocks decode" `Quick t_raw_golden;
        Alcotest.test_case "R2 encode = snap on literal-only rows" `Quick
          t_raw_encode_matches_snap;
        Alcotest.test_case "R3 encode then decode" `Quick t_raw_roundtrip;
        Alcotest.test_case "R4 inside the interop bound" `Quick t_raw_bound;
        Alcotest.test_case "R5 truncated" `Quick t_raw_truncated;
        Alcotest.test_case "R6 copy offset out of range" `Quick t_raw_copy_offset;
        Alcotest.test_case "R7 length mismatch" `Quick t_raw_length_mismatch;
        Alcotest.test_case "R8 declared above the cap" `Quick t_raw_exceeds_max;
        Alcotest.test_case "R9 preamble rules" `Quick t_raw_preamble;
      ] );
    ( "frame streams",
      [
        Alcotest.test_case "G1 oracle frames decompress" `Quick t_frame_golden;
        Alcotest.test_case "G2 chunk boundary rows" `Quick t_frame_boundary;
        Alcotest.test_case "G3 compress then decompress" `Quick t_frame_roundtrip;
        Alcotest.test_case "G4 emitted structure and size" `Quick
          t_frame_structure;
        Alcotest.test_case "G5 inside the interop bound" `Quick t_frame_bound;
      ] );
    ( "take boundary",
      [
        Alcotest.test_case "T1 cap mid-chunk truncates" `Quick t_take_mid_chunk;
        Alcotest.test_case "T2 corrupt chunk past the cap is accepted" `Quick
          t_take_corrupt_past_cap;
        Alcotest.test_case "T3 one byte into the corrupt chunk rejects" `Quick
          t_take_corrupt_one_byte_in;
        Alcotest.test_case "T4 straddling chunk is checksum checked" `Quick
          t_take_corrupt_straddling;
        Alcotest.test_case "T5 truncated tail" `Quick t_take_truncated_tail;
        Alcotest.test_case "T6 cap 0 accepts anything" `Quick t_take_zero_cap;
        Alcotest.test_case "T7 a negative cap behaves like cap 0" `Quick
          t_take_negative_cap;
      ] );
    ( "frame negatives",
      [
        Alcotest.test_case "N1 missing stream identifier" `Quick
          t_neg_missing_stream_id;
        Alcotest.test_case "N2 bad stream identifier" `Quick t_neg_bad_stream_id;
        Alcotest.test_case "N3 corrupt checksum" `Quick t_neg_crc;
        Alcotest.test_case "N4 truncated chunk" `Quick t_neg_truncated;
        Alcotest.test_case "N5 unskippable reserved types" `Quick t_neg_reserved;
        Alcotest.test_case "N6 uncompressed chunk cap" `Quick t_neg_block_cap;
        Alcotest.test_case "N7 declared length cap" `Quick t_neg_declared_cap;
        Alcotest.test_case "N8 data chunk without a checksum" `Quick
          t_neg_short_data_chunk;
        Alcotest.test_case "N9 compressed block cap" `Quick
          t_neg_compressed_block_cap;
        Alcotest.test_case "N10 padding, skippable, second identifier" `Quick
          t_skippable_and_padding;
      ] );
    ( "properties",
      [
        mk_prop ~salt:1 ~count:200 "Q1 frame round trip" arb_bytes
          prop_frame_roundtrip;
        mk_prop ~salt:2 ~count:200 "Q2 frame truncation" arb_bytes_and_cap
          prop_frame_truncates;
        mk_prop ~salt:3 ~count:200 "Q3 raw round trip" arb_bytes
          prop_raw_roundtrip;
      ] );
  ]

let () =
  case_total := List.fold_left (fun acc (_, cs) -> acc + List.length cs) 0 suites;
  Alcotest.run "tn_snappy" suites
