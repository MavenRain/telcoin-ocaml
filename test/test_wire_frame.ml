(* Chunk-44 stage 2: [Tn_network.Wire_frame] against the chunk-44 Rust oracle
   harness.

   The golden rows in network_vectors.ml are the byte output of the harness's
   verbatim port of crates/network-libp2p/src/codec.rs at telcoin-network
   31cc4e90, driving snap 1.1.1 and bcs 0.1.6, the versions that tree's
   Cargo.lock pins. So a green run here is wire evidence and not round-trip
   self-consistency, and it covers both directions of the interop claim: this
   file decodes Rust-produced wire bytes, and
   `dune exec test/test_wire_frame.exe -- --emit-reverse` prints the port's
   own output as `kind max hex expected` rows that the harness's `decode-file`
   subcommand replays through the Rust decoder.

   The discriminating rows are the doctored prefixes (T1, T2). A peer that
   shrinks the uncompressed_len prefix is NOT caught by the frame layer: the
   take cap truncates the output to the lie, and the length check compares
   the truncated length against the same lie, so both pass. Rust accepts
   those bytes (GT:339, wire-rows.txt WIRE_DOCTORED), and so must this port;
   the rejection belongs to BCS, one layer up. Asserting the intuitive
   rejection instead would have been a silent interop divergence. *)

module NV = Network_vectors
module SV = Snappy_vectors
module W = Tn_network.Wire_frame
module Bcs = Tn_codec.Bcs

(* ------------------------------------------------------------------ helpers *)

let hex s =
  let buf = Buffer.create ((String.length s * 2) + 2) in
  String.iter
    (fun c -> Buffer.add_string buf (Printf.sprintf "%02x" (Char.code c)))
    s;
  Buffer.contents buf

let unhex = SV.unhex

(* The harness constant these rows were produced under (wire-rows.txt line 1). *)
let max_size = NV.wire_max_message_size

(* One exhaustive rendering per error, so a negative row names the exact
   rejection AND the payload the Rust row pins, without a catch-all arm. The
   shapes mirror the Debug output quoted beside each use. *)
let error_detail = function
  | W.Prefix_too_large { declared; max } ->
      Printf.sprintf "prefix_too_large declared=%d max=%d" declared max
  | W.Compressed_len_exceeds_bound { declared; bound } ->
      Printf.sprintf "compressed_len_exceeds_bound declared=%d bound=%d"
        declared bound
  | W.Truncated_body { expected; got } ->
      Printf.sprintf "truncated_body expected=%d got=%d" expected got
  | W.Snappy _ -> "snappy"
  | W.Length_mismatch { declared; got } ->
      Printf.sprintf "length_mismatch declared=%d got=%d" declared got
  | W.Message_too_large { len; max } ->
      Printf.sprintf "message_too_large len=%d max=%d" len max
  | W.Header_truncated { got } -> Printf.sprintf "header_truncated got=%d" got

let msg_error_detail = function
  | W.Frame_error e -> "frame:" ^ error_detail e
  | W.Bcs_error _ -> "bcs"

let decoded name ~max wire k =
  Result.fold
    ~ok:k
    ~error:(fun e ->
      Alcotest.fail (Printf.sprintf "%s: %s" name (error_detail e)))
    (W.decode ~max_message_size:max wire)

let decode_rejects name ~detail ~max wire =
  Result.fold
    ~ok:(fun ((payload : string), (_ : int)) ->
      Alcotest.fail
        (Printf.sprintf "%s: accepted, %d payload bytes" name
           (String.length payload)))
    ~error:(fun e -> Alcotest.(check string) name detail (error_detail e))
    (W.decode ~max_message_size:max wire)

let encoded name ~max payload k =
  Result.fold
    ~ok:k
    ~error:(fun e ->
      Alcotest.fail (Printf.sprintf "%s: %s" name (error_detail e)))
    (W.encode ~max_message_size:max payload)

let bytes_equal name ~expected got =
  Alcotest.(check bool)
    (Printf.sprintf "%s (expected %d bytes, got %d)" name
       (String.length expected) (String.length got))
    true
    (String.equal expected got)

(* An 8-byte header built straight to the layout, so the header negatives can
   ask for prefixes this port's own encoder would never emit. Written through
   the BCS pair the module itself uses, so the test states the layout once. *)
let header_bytes ~uncompressed ~compressed =
  Bcs.encode (Bcs.pair Bcs.u32 Bcs.u32) (uncompressed, compressed)

(* The payload shape of the worker_gossip_batch row: WorkerGossip::Batch of a
   u32 epoch and a B256 block hash, whose BCS form is a ULEB128 variant tag,
   4 little-endian bytes and a ULEB128(32)-prefixed 32-byte digest
   (GT:87). Enough of a codec to prove taxonomy #7 fires. *)
let batch_gossip_codec = Bcs.triple Bcs.u8 Bcs.u32 (Bcs.sized_bytes 32)

let named_wire_row name =
  List.find_opt (fun (r : NV.wire_row) -> String.equal r.name name) NV.wire_rows

(* A sentinel for the keyed row lookup below. Its hex fields are empty, so a
   lookup that missed turns every row that uses it red instead of quietly
   testing nothing; the floor case asserts the lookup hits by name. *)
let missing_row : NV.wire_row =
  { name = "MISSING"; bcs_hex = ""; frame_hex = ""; wire_hex = "" }

let worker_gossip_row () =
  Option.value ~default:missing_row (named_wire_row "worker_gossip_batch")

(* --------------------------------------------------------------- the floor *)

let vector_count =
  List.length NV.wire_rows + List.length NV.sweep_rows
  + List.length NV.doctored_rows
  + List.length NV.max_compress_len_rows

let case_total = ref 0

let t_floor () =
  Alcotest.(check bool)
    (Printf.sprintf "vector rows %d >= 18" vector_count)
    true
    (vector_count >= 18);
  Alcotest.(check bool)
    (Printf.sprintf "test cases %d >= 18" !case_total)
    true
    (!case_total >= 18);
  Alcotest.(check bool)
    "the oracle wire rows are present" true
    (List.length NV.wire_rows >= 7 && List.length NV.doctored_rows >= 3);
  (* Positive control for the keyed row lookup the negative cases build on,
     with its miss beside it, so a renamed row cannot leave those cases
     testing a sentinel. *)
  Alcotest.(check string)
    "the keyed row lookup hits" "worker_gossip_batch" (worker_gossip_row ()).name;
  Alcotest.(check bool)
    "the keyed row lookup misses an absent name" true
    (Option.is_none (named_wire_row "no_such_row"))

(* -------------------------------------------------------- max_compress_len *)

let t_max_compress_len () =
  List.iter
    (fun (n, expected) ->
      Alcotest.(check int)
        (Printf.sprintf "max_compress_len %d" n)
        expected (W.max_compress_len n))
    NV.max_compress_len_rows;
  (* The worked example of GT:294-297, stated on its own so the row cannot
     silently leave the table: 1 MiB -> 1_048_576 + 174_762 + 32. *)
  Alcotest.(check int)
    "max_compress_len (1 MiB) = 1_223_370" 1_223_370
    (W.max_compress_len 1_048_576)

let t_max_compress_len_guards () =
  (* snap answers 0 above u32::MAX (compress.rs:42-53); a 0 bound refuses
     every non-zero compressed length. A negative length is unrepresentable
     in Rust and gets the same refusal here. *)
  Alcotest.(check int) "above u32::MAX" 0 (W.max_compress_len 0x1_0000_0000);
  (* At u32::MAX the computed sum [32 + n + n / 6] passes MAX_INPUT_SIZE, so
     snap's second clamp answers 0 (compress.rs:42-53). Oracle rows against
     snap 1.1.1 pin the clamp boundary: 3_681_400_511 is the last input with
     a non-zero answer. *)
  Alcotest.(check int) "at u32::MAX" 0 (W.max_compress_len 0xffff_ffff);
  Alcotest.(check int)
    "last input under the sum clamp" 4_294_967_294
    (W.max_compress_len 3_681_400_511);
  Alcotest.(check int)
    "first input the sum clamp zeroes" 0
    (W.max_compress_len 3_681_400_512);
  Alcotest.(check int) "negative" 0 (W.max_compress_len (-1));
  Alcotest.(check int) "zero" 32 (W.max_compress_len 0)

(* ------------------------------------------------ golden rows, Rust -> port *)

let t_golden_decode () =
  List.iter
    (fun (r : NV.wire_row) ->
      let wire = unhex r.wire_hex and payload = unhex r.bcs_hex in
      decoded r.name ~max:max_size wire (fun (got, consumed) ->
          bytes_equal (r.name ^ " payload") ~expected:payload got;
          Alcotest.(check int)
            (r.name ^ " consumed")
            (String.length wire) consumed))
    NV.wire_rows

let t_golden_header () =
  List.iter
    (fun (r : NV.wire_row) ->
      let wire = unhex r.wire_hex in
      Result.fold
        ~ok:(fun (h : W.header) ->
          Alcotest.(check int)
            (r.name ^ " uncompressed_len")
            (String.length (unhex r.bcs_hex))
            h.W.uncompressed_len;
          Alcotest.(check int)
            (r.name ^ " compressed_len")
            (String.length (unhex r.frame_hex))
            h.W.compressed_len;
          Alcotest.(check int)
            (r.name ^ " total wire length")
            (String.length wire)
            (8 + h.W.compressed_len))
        ~error:(fun e -> Alcotest.fail (r.name ^ ": " ^ error_detail e))
        (W.parse_header ~max_message_size:max_size wire))
    NV.wire_rows

let t_sweep_decode () =
  List.iter
    (fun (r : NV.sweep_row) ->
      Option.fold ~none:()
        ~some:(fun h ->
          let wire = unhex h in
          decoded
            (Printf.sprintf "sweep %d" r.size)
            ~max:max_size wire
            (fun (got, consumed) ->
              bytes_equal
                (Printf.sprintf "sweep %d payload" r.size)
                ~expected:(SV.mod251 r.size) got;
              Alcotest.(check int)
                (Printf.sprintf "sweep %d consumed" r.size)
                r.wire_len consumed))
        r.sweep_hex)
    NV.sweep_rows

(* ------------------------------------------------ this port's own envelopes *)

let roundtrip name ~max payload =
  encoded name ~max payload (fun wire ->
      decoded name ~max wire (fun (got, consumed) ->
          bytes_equal (name ^ " payload") ~expected:payload got;
          Alcotest.(check int) (name ^ " consumed") (String.length wire) consumed))

let t_roundtrip_sizes () =
  (* Every size the sweep covers, including the 65536-byte snappy chunk
     boundary either side and 1 MiB minus one. *)
  List.iter
    (fun (r : NV.sweep_row) ->
      roundtrip (Printf.sprintf "roundtrip %d" r.size) ~max:max_size
        (SV.mod251 r.size))
    NV.sweep_rows

let t_roundtrip_golden () =
  List.iter
    (fun (r : NV.wire_row) ->
      roundtrip ("roundtrip " ^ r.name) ~max:max_size (unhex r.bcs_hex))
    NV.wire_rows

let t_encode_structure () =
  List.iter
    (fun n ->
      let payload = SV.mod251 n in
      encoded
        (Printf.sprintf "structure %d" n)
        ~max:max_size payload
        (fun wire ->
          Result.fold
            ~ok:(fun (h : W.header) ->
              Alcotest.(check int)
                (Printf.sprintf "structure %d uncompressed_len" n)
                n h.W.uncompressed_len;
              Alcotest.(check int)
                (Printf.sprintf "structure %d compressed_len" n)
                (String.length wire - 8)
                h.W.compressed_len;
              (* The interop bound decode check #2 applies: a Rust peer
                 rejects a body above it, so this port must stay under it at
                 every size. *)
              Alcotest.(check bool)
                (Printf.sprintf "structure %d body %d <= bound %d" n
                   h.W.compressed_len (W.max_compress_len n))
                true
                (h.W.compressed_len <= W.max_compress_len n))
            ~error:(fun e ->
              Alcotest.fail (Printf.sprintf "structure %d: %s" n (error_detail e)))
            (W.parse_header ~max_message_size:max_size wire)))
    [ 0; 1; 100; 65535; 65536; 65537 ]

let t_encode_size_limit () =
  (* Both polarities at the limit, matching the harness rows
     `WIRE_NEG encode_at_max Ok(42)` and
     `WIRE_NEG encode_over_max Err(MessageTooLarge { len: 17, max: 16 })`. *)
  let at_max = String.make 16 '\007' and over_max = String.make 17 '\007' in
  encoded "encode at max" ~max:16 at_max (fun wire ->
      Alcotest.(check bool)
        "a message of exactly max_message_size is accepted" true
        (String.length wire > 8));
  Result.fold
    ~ok:(fun (_ : string) ->
      Alcotest.fail "encode accepted a message above max_message_size")
    ~error:(fun e ->
      Alcotest.(check string)
        "encode over max" "message_too_large len=17 max=16" (error_detail e))
    (W.encode ~max_message_size:16 over_max);
  Result.fold
    ~ok:(fun (_ : string) -> Alcotest.fail "encode accepted a byte at max 0")
    ~error:(fun e ->
      Alcotest.(check string)
        "encode over a zero limit" "message_too_large len=1 max=0"
        (error_detail e))
    (W.encode ~max_message_size:0 "x");
  encoded "encode empty at max 0" ~max:0 "" (fun wire ->
      decoded "encode empty at max 0" ~max:0 wire (fun (got, (_ : int)) ->
          bytes_equal "empty payload" ~expected:"" got))

(* ------------------------------------------------------ header-parse rejects *)

let t_prefix_too_large () =
  (* Harness row: Err(PrefixTooLarge { declared: 17, max: 16 }). *)
  let wire = header_bytes ~uncompressed:17 ~compressed:1 ^ "\x00" in
  decode_rejects "prefix too large" ~detail:"prefix_too_large declared=17 max=16"
    ~max:16 wire;
  Result.fold
    ~ok:(fun (_ : W.header) -> Alcotest.fail "parse_header accepted it")
    ~error:(fun e ->
      Alcotest.(check string)
        "parse_header refuses the same prefix"
        "prefix_too_large declared=17 max=16" (error_detail e))
    (W.parse_header ~max_message_size:16 wire)

let t_compressed_len_bound () =
  (* Harness row: Err(CompressedLenExceedsBound { declared: 40, bound: 33 }),
     the bound being max_compress_len 1 = 33. *)
  let wire = header_bytes ~uncompressed:1 ~compressed:40 ^ String.make 40 '\000' in
  decode_rejects "compressed len over bound"
    ~detail:"compressed_len_exceeds_bound declared=40 bound=33" ~max:1024 wire

let t_short_body () =
  (* Harness row: Err(TruncatedBody { expected: 20, got: 3 }). *)
  let wire = header_bytes ~uncompressed:1 ~compressed:20 ^ String.make 3 '\000' in
  decode_rejects "short body" ~detail:"truncated_body expected=20 got=3" ~max:1024
    wire;
  (* A header with no body at all: the 8-byte malicious_header of
     codec_tests.rs:276-281, which commits no buffer. *)
  decode_rejects "header only"
    ~detail:"truncated_body expected=1200000 got=0" ~max:1_048_576
    (header_bytes ~uncompressed:1_048_576 ~compressed:1_200_000)

let t_header_truncated () =
  (* Harness row: Err(HeaderTruncated { got: 7 }). *)
  decode_rejects "seven bytes" ~detail:"header_truncated got=7" ~max:1024
    (String.make 7 '\000');
  decode_rejects "no bytes" ~detail:"header_truncated got=0" ~max:1024 "";
  Result.fold
    ~ok:(fun (_ : W.header) -> Alcotest.fail "parse_header accepted 7 bytes")
    ~error:(fun e ->
      Alcotest.(check string)
        "parse_header refuses a short header" "header_truncated got=7"
        (error_detail e))
    (W.parse_header ~max_message_size:1024 (String.make 7 '\000'))

(* --------------------------------------------------------- body-level rejects *)

let t_body_not_a_frame () =
  (* Check #5: the body passes both prefix checks and is not a Snappy frame
     stream at all. max_compress_len 5 = 37, so 4 body bytes are inside the
     bound and the failure has to come from the decompressor. *)
  let wire = header_bytes ~uncompressed:5 ~compressed:4 ^ unhex "deadbeef" in
  decode_rejects "body is not a frame stream" ~detail:"snappy" ~max:1024 wire

let t_length_mismatch () =
  (* A genuine under-run: an honest body, but a declared uncompressed length
     ABOVE what it holds. The take cap cannot pad, so check #6 fires. This is
     the mirror image of the doctored rows below, where the declared length is
     BELOW the true one and Rust accepts. *)
  let row = worker_gossip_row () in
  let frame = unhex row.frame_hex in
  let wire =
    header_bytes ~uncompressed:40 ~compressed:(String.length frame) ^ frame
  in
  decode_rejects "under-run" ~detail:"length_mismatch declared=40 got=38"
    ~max:max_size wire

(* ------------------------------------------------------- the doctored prefix *)

let doctored_wire (r : NV.doctored_row) =
  let frame = unhex (worker_gossip_row ()).frame_hex in
  header_bytes ~uncompressed:r.declared ~compressed:(String.length frame) ^ frame

let t_doctored_accepted () =
  List.iter
    (fun (r : NV.doctored_row) ->
      let name = Printf.sprintf "doctored declared=%d" r.declared in
      decoded name ~max:max_size (doctored_wire r) (fun (got, consumed) ->
          bytes_equal (name ^ " payload") ~expected:(unhex r.produced_hex) got;
          Alcotest.(check int) (name ^ " length") r.produced (String.length got);
          Alcotest.(check int) (name ^ " consumed") r.consumed consumed))
    NV.doctored_rows

let t_doctored_fails_at_bcs () =
  let row = worker_gossip_row () in
  (* The honest message decodes all the way to a value. *)
  Result.fold
    ~ok:(fun (((tag, epoch, digest) : int * int * string), consumed) ->
      Alcotest.(check int) "gossip variant tag" 0 tag;
      Alcotest.(check int) "gossip epoch" 7 epoch;
      bytes_equal "gossip block hash" ~expected:(String.make 32 '\xaa') digest;
      Alcotest.(check int)
        "gossip consumed"
        (String.length (unhex row.wire_hex))
        consumed)
    ~error:(fun e -> Alcotest.fail ("honest message: " ^ msg_error_detail e))
    (W.decode_msg ~max_message_size:max_size batch_gossip_codec
       (unhex row.wire_hex));
  (* Every doctored one is a strict prefix, so it clears the frame layer and
     dies in BCS: taxonomy #7, exactly the mechanism GT:339 traces. *)
  List.iter
    (fun (r : NV.doctored_row) ->
      Result.fold
        ~ok:(fun (((_ : int), (_ : int), (_ : string)), (_ : int)) ->
          Alcotest.fail
            (Printf.sprintf "doctored declared=%d decoded to a message"
               r.declared))
        ~error:(fun e ->
          Alcotest.(check string)
            (Printf.sprintf "doctored declared=%d fails at bcs" r.declared)
            "bcs" (msg_error_detail e))
        (W.decode_msg ~max_message_size:max_size batch_gossip_codec
           (doctored_wire r)))
    NV.doctored_rows

(* --------------------------------------------------------------- msg codecs *)

let t_msg_roundtrip () =
  let value = (0, 7, String.make 32 '\xaa') in
  Result.fold
    ~ok:(fun wire ->
      bytes_equal "encode_msg equals encode of the bcs bytes"
        ~expected:(unhex (worker_gossip_row ()).bcs_hex)
        (Bcs.encode batch_gossip_codec value);
      Result.fold
        ~ok:(fun (got, consumed) ->
          Alcotest.(check bool)
            "encode_msg then decode_msg" true
            (got = value);
          Alcotest.(check int)
            "encode_msg consumed" (String.length wire) consumed)
        ~error:(fun e -> Alcotest.fail ("decode_msg: " ^ msg_error_detail e))
        (W.decode_msg ~max_message_size:max_size batch_gossip_codec wire))
    ~error:(fun e -> Alcotest.fail ("encode_msg: " ^ msg_error_detail e))
    (W.encode_msg ~max_message_size:max_size batch_gossip_codec value);
  (* The frame layer's own refusal still reaches the caller. *)
  Result.fold
    ~ok:(fun (_ : string) -> Alcotest.fail "encode_msg ignored max_message_size")
    ~error:(fun e ->
      Alcotest.(check string)
        "encode_msg over the limit" "frame:message_too_large len=38 max=16"
        (msg_error_detail e))
    (W.encode_msg ~max_message_size:16 batch_gossip_codec value)

let t_trailing_bytes_are_a_stream () =
  (* decode reports what it consumed so a reassembly shim can carry the rest
     of a byte stream forward; a second message glued on must not disturb the
     first. *)
  let row = worker_gossip_row () in
  let one = unhex row.wire_hex in
  let stream = one ^ one ^ "junk" in
  decoded "stream head" ~max:max_size stream (fun (got, consumed) ->
      bytes_equal "stream head payload" ~expected:(unhex row.bcs_hex) got;
      Alcotest.(check int) "stream head consumed" (String.length one) consumed)

let t_empty_payload () =
  (* Rust's empty message is 8 bytes: snap's frame encoder writes nothing at
     all for an empty input (sweep row size=0, wire_len=8). This port's
     compressor writes the 10-byte stream identifier instead, so the two
     encoders disagree byte for byte and BOTH decode, which is the whole
     content of the "compressed bytes MAY differ" rule (GT:355-356). *)
  let rust_empty = unhex "0000000000000000" in
  decoded "rust empty" ~max:max_size rust_empty (fun (got, consumed) ->
      bytes_equal "rust empty payload" ~expected:"" got;
      Alcotest.(check int) "rust empty consumed" 8 consumed);
  encoded "port empty" ~max:max_size "" (fun wire ->
      Alcotest.(check int) "port empty wire length" 18 (String.length wire);
      Alcotest.(check bool)
        "the two encoders differ on the empty message" true
        (not (String.equal wire rust_empty));
      decoded "port empty" ~max:max_size wire (fun (got, (_ : int)) ->
          bytes_equal "port empty payload" ~expected:"" got))

(* ------------------------------------------------------------ reverse gate *)

(* Rows for the harness's `decode-file`: `kind max hex expected`. The empty
   payload has an empty expected field, which would leave the line three
   fields wide, so it is emitted as a comment for the gate script to replay
   through `decode` with an explicit "" argument. *)
let reverse_rows () =
  let row payload =
    Result.fold
      ~ok:(fun wire ->
        Printf.sprintf "wire %d %s %s" max_size (hex wire) (hex payload))
      ~error:(fun e -> "# ERROR " ^ error_detail e)
      (W.encode ~max_message_size:max_size payload)
  in
  let sizes = [ 1; 100; 65535; 65536; 65537; 1_048_575 ] in
  let empty =
    Result.fold
      ~ok:(fun wire -> Printf.sprintf "# empty wire %d %s" max_size (hex wire))
      ~error:(fun e -> "# ERROR " ^ error_detail e)
      (W.encode ~max_message_size:max_size "")
  in
  List.concat
    [
      List.map (fun n -> row (SV.mod251 n)) sizes;
      List.map (fun (r : NV.wire_row) -> row (unhex r.bcs_hex)) NV.wire_rows;
      [ empty ];
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
    ( "bounds",
      [
        Alcotest.test_case "B1 max_compress_len oracle rows" `Quick
          t_max_compress_len;
        Alcotest.test_case "B2 max_compress_len guards" `Quick
          t_max_compress_len_guards;
      ] );
    ( "oracle rows",
      [
        Alcotest.test_case "D1 golden messages decode" `Quick t_golden_decode;
        Alcotest.test_case "D2 golden headers parse" `Quick t_golden_header;
        Alcotest.test_case "D3 payload-size sweep decodes" `Quick t_sweep_decode;
      ] );
    ( "this port's envelopes",
      [
        Alcotest.test_case "E1 round trip at every sweep size" `Quick
          t_roundtrip_sizes;
        Alcotest.test_case "E2 round trip of every golden payload" `Quick
          t_roundtrip_golden;
        Alcotest.test_case "E3 emitted structure and interop bound" `Quick
          t_encode_structure;
        Alcotest.test_case "E4 max_message_size, both polarities" `Quick
          t_encode_size_limit;
      ] );
    ( "header negatives",
      [
        Alcotest.test_case "N1 declared uncompressed above the limit" `Quick
          t_prefix_too_large;
        Alcotest.test_case "N2 declared compressed above the bound" `Quick
          t_compressed_len_bound;
        Alcotest.test_case "N3 body shorter than declared" `Quick t_short_body;
        Alcotest.test_case "N4 header truncated" `Quick t_header_truncated;
      ] );
    ( "body negatives",
      [
        Alcotest.test_case "N5 body is not a frame stream" `Quick
          t_body_not_a_frame;
        Alcotest.test_case "N6 under-run is a length mismatch" `Quick
          t_length_mismatch;
      ] );
    ( "doctored prefix",
      [
        Alcotest.test_case "T1 the frame layer accepts it" `Quick
          t_doctored_accepted;
        Alcotest.test_case "T2 the bcs layer rejects it" `Quick
          t_doctored_fails_at_bcs;
      ] );
    ( "message codecs",
      [
        Alcotest.test_case "M1 encode_msg and decode_msg" `Quick t_msg_roundtrip;
        Alcotest.test_case "M2 consumed length over a stream" `Quick
          t_trailing_bytes_are_a_stream;
        Alcotest.test_case "M3 the empty message, both encoders" `Quick
          t_empty_payload;
      ] );
  ]

let () =
  case_total := List.fold_left (fun acc (_, cs) -> acc + List.length cs) 0 suites;
  Alcotest.run "tn_network wire_frame" suites
