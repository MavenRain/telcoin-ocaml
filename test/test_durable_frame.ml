(* Chunk 40, stage S2: the on-disk envelope.

   Everything here is a pure function over strings, which is the point: the
   torn-write argument, the interior-damage argument and the resync rule are all
   decided before a filesystem is involved.

   Two disciplines run through the file. Every one of the eight refusal arms is
   fired by a TARGETED single-field change to a known-good frame, so a check
   that stopped working could not hide behind a neighbouring check. And every
   damage case asserts what SURVIVES as well as what is refused, because a
   reader that heals by throwing everything away also passes an assertion that
   only names the failure. *)

module Frame = Tn_durable.Frame

(* Byte handling for the test side, total by the same rule the library uses: a
   span that runs off either end is clamped, and a byte is built through a
   Buffer rather than through a partial character constructor. *)
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

(* Overwrite [bytes] at [at], leaving the length of the string unchanged. This
   is the only mutation shape the eight-arm group uses, so "one field changed"
   is a property of the helper and not of each case. *)
let splice s ~at ~bytes =
  let width = String.length bytes in
  String.concat ""
    [
      sub_at s ~off:0 ~len:at;
      bytes;
      sub_at s ~off:(at + width) ~len:(String.length s - at - width);
    ]

let flip s ~at =
  splice s ~at ~bytes:(be ~width:1 (uint_at s ~off:at ~width:1 lxor 0x01))

let keep s n = sub_at s ~off:0 ~len:n
let letters = "abcdefghijklmnopqrstuvwxyz"

(* Doubling rather than a repeat count, so there is no division anywhere in the
   fixture builder. *)
let rec grow block ~upto =
  match String.length block >= upto with
  | true -> block
  | false -> grow (block ^ block) ~upto

let payload_of n = keep (grow letters ~upto:(max 1 n)) n

let kind_to_string = function
  | Frame.Record -> "record"
  | Frame.Epoch_open -> "epoch-open"

let stop_to_string = function
  | Frame.Clean { at } -> Printf.sprintf "clean at %d" at
  | Frame.Torn { at; why } ->
      Printf.sprintf "torn at %d (%s)" at (Frame.bad_to_string why)
  | Frame.Corrupt { at; why; next_good } ->
      Printf.sprintf "corrupt at %d, next good %d (%s)" at next_good
        (Frame.bad_to_string why)

(* A refusal is checked by a predicate over the arm, so a case that fires the
   wrong arm reports which one it got rather than a bare false. *)
let expect_bad ~what holds r =
  Result.fold
    ~ok:(fun (_ : Frame.head * string * int) ->
      Alcotest.failf "%s: expected a refusal, the frame decoded" what)
    ~error:(fun bad ->
      match holds bad with
      | true -> ()
      | false ->
          Alcotest.failf "%s: the wrong refusal: %s" what
            (Frame.bad_to_string bad))
    r

let expect_frame ~what r =
  Result.fold ~ok:Fun.id
    ~error:(fun bad -> Alcotest.failf "%s: %s" what (Frame.bad_to_string bad))
    r

let is_short ~have ~need = function
  | Frame.Short s -> s.have = have && s.need = need
  | Frame.Bad_head_tag _ | Frame.Bad_body_tag _ | Frame.Length_disagrees _
  | Frame.Missing_end_magic _ | Frame.Bad_kind _ | Frame.Oversize _
  | Frame.Seq_out_of_order _ ->
      false

let is_bad_head_tag = function
  | Frame.Bad_head_tag _ -> true
  | Frame.Short _ | Frame.Bad_body_tag _ | Frame.Length_disagrees _
  | Frame.Missing_end_magic _ | Frame.Bad_kind _ | Frame.Oversize _
  | Frame.Seq_out_of_order _ ->
      false

let is_bad_body_tag = function
  | Frame.Bad_body_tag _ -> true
  | Frame.Short _ | Frame.Bad_head_tag _ | Frame.Length_disagrees _
  | Frame.Missing_end_magic _ | Frame.Bad_kind _ | Frame.Oversize _
  | Frame.Seq_out_of_order _ ->
      false

let is_length_disagrees ~head ~echo = function
  | Frame.Length_disagrees d -> d.head = head && d.echo = echo
  | Frame.Short _ | Frame.Bad_head_tag _ | Frame.Bad_body_tag _
  | Frame.Missing_end_magic _ | Frame.Bad_kind _ | Frame.Oversize _
  | Frame.Seq_out_of_order _ ->
      false

let is_missing_end_magic = function
  | Frame.Missing_end_magic _ -> true
  | Frame.Short _ | Frame.Bad_head_tag _ | Frame.Bad_body_tag _
  | Frame.Length_disagrees _ | Frame.Bad_kind _ | Frame.Oversize _
  | Frame.Seq_out_of_order _ ->
      false

let is_bad_kind ~byte = function
  | Frame.Bad_kind k -> k.byte = byte
  | Frame.Short _ | Frame.Bad_head_tag _ | Frame.Bad_body_tag _
  | Frame.Length_disagrees _ | Frame.Missing_end_magic _ | Frame.Oversize _
  | Frame.Seq_out_of_order _ ->
      false

let is_oversize ~len = function
  | Frame.Oversize o -> o.len = len && o.cap = Frame.max_payload
  | Frame.Short _ | Frame.Bad_head_tag _ | Frame.Bad_body_tag _
  | Frame.Length_disagrees _ | Frame.Missing_end_magic _ | Frame.Bad_kind _
  | Frame.Seq_out_of_order _ ->
      false

let is_seq_out_of_order ~expected ~got = function
  | Frame.Seq_out_of_order s -> s.expected = expected && s.got = got
  | Frame.Short _ | Frame.Bad_head_tag _ | Frame.Bad_body_tag _
  | Frame.Length_disagrees _ | Frame.Missing_end_magic _ | Frame.Bad_kind _
  | Frame.Oversize _ ->
      false

(* Round trip. *)

let round_trip ~kind ~seq ~payload =
  let head, got, next =
    expect_frame
      ~what:
        (Printf.sprintf "decode a %s frame of %d bytes" (kind_to_string kind)
           (String.length payload))
      (Frame.decode_at
         ~buf:(Frame.encode ~kind ~seq ~payload)
         ~at:0 ~expect_seq:seq)
  in
  let whole = Frame.frame_size ~payload_len:(String.length payload) in
  let () = Alcotest.(check int) "one past the frame" whole next in
  let () = Alcotest.(check int) "the sequence" seq head.Frame.seq in
  let () =
    Alcotest.(check int) "the length" (String.length payload)
      head.Frame.payload_len
  in
  let () =
    Alcotest.(check string) "the kind" (kind_to_string kind)
      (kind_to_string head.Frame.kind)
  in
  Alcotest.(check string) "the payload" payload got

let test_one_byte_payload () =
  round_trip ~kind:Frame.Record ~seq:0 ~payload:(payload_of 1)

let test_max_payload () =
  round_trip ~kind:Frame.Record ~seq:41 ~payload:(payload_of Frame.max_payload)

let test_epoch_open_round_trips () =
  round_trip ~kind:Frame.Epoch_open ~seq:7 ~payload:(payload_of 96)

let test_the_format_sizes () =
  let () = Alcotest.(check int) "header" 24 Frame.header_size in
  let () = Alcotest.(check int) "trailer" 16 Frame.trailer_size in
  let () = Alcotest.(check int) "cap" 16777216 Frame.max_payload in
  Alcotest.(check int) "envelope" 40 (Frame.frame_size ~payload_len:0)

let test_a_frame_decodes_at_an_offset () =
  let payload = payload_of 33 in
  let frame = Frame.encode ~kind:Frame.Record ~seq:5 ~payload in
  let buf = String.make 64 '\xee' ^ frame in
  let (_ : Frame.head), got, next =
    expect_frame ~what:"decode at offset 64"
      (Frame.decode_at ~buf ~at:64 ~expect_seq:5)
  in
  let () = Alcotest.(check string) "the payload" payload got in
  Alcotest.(check int) "one past the frame" (String.length buf) next

let arb_frame =
  QCheck.make
    ~print:(fun (record, seq, n) ->
      Printf.sprintf "record=%b seq=%d len=%d" record seq n)
    QCheck.Gen.(triple bool (int_range 0 100000) (int_range 1 300))

let prop_round_trip =
  QCheck.Test.make ~count:200 ~name:"encode then decode_at is the identity"
    arb_frame (fun (record, seq, n) ->
      let kind =
        match record with true -> Frame.Record | false -> Frame.Epoch_open
      in
      let payload = payload_of n in
      let frame = Frame.encode ~kind ~seq ~payload in
      String.length frame = Frame.frame_size ~payload_len:n
      && Result.fold
           ~error:(fun (_ : Frame.bad) -> false)
           ~ok:(fun (head, got, next) ->
             head.Frame.kind = kind && head.Frame.seq = seq
             && head.Frame.payload_len = n
             && String.equal got payload
             && next = String.length frame)
           (Frame.decode_at ~buf:frame ~at:0 ~expect_seq:seq))

let check ~salt t () =
  QCheck.Test.check_exn ~rand:(Random.State.make [| 0x5eed; salt |]) t

(* The eight refusal arms, one targeted change each. *)

let good_payload = payload_of 19
let good = Frame.encode ~kind:Frame.Record ~seq:0 ~payload:good_payload
let good_len = String.length good_payload
let echo_off = Frame.header_size + good_len + 8
let decode_good buf = Frame.decode_at ~buf ~at:0 ~expect_seq:0

let test_short_header () =
  expect_bad ~what:"a buffer that stops inside the header"
    (is_short ~have:10 ~need:Frame.header_size)
    (decode_good (keep good 10))

let test_oversize_is_refused_before_any_allocation () =
  (* The length is injected into the HEADER ONLY: the buffer is still the small
     frame it was. An implementation that sized a read from the header before
     bounding it would report the buffer as short, or ask the runtime for 16 MiB
     that is not there. Reporting the bound is the evidence the bound came
     first. *)
  let injected =
    splice good ~at:0 ~bytes:(be ~width:4 (Frame.max_payload + 1))
  in
  expect_bad ~what:"a header declaring more than the cap"
    (is_oversize ~len:(Frame.max_payload + 1))
    (decode_good injected)

let test_a_frame_cut_one_byte_short_is_short () =
  (* The positive control for the case above. Here the header is untouched and
     therefore self-consistent, and the only thing wrong is that the last byte
     is missing: the answer is the availability check. The oversize case is
     decided EARLIER than this one, before the head tag and before any span of
     the payload is taken, which is what makes it an allocation-free refusal. *)
  let cut = keep good (String.length good - 1) in
  expect_bad ~what:"a frame cut one byte short"
    (is_short ~have:(String.length cut)
       ~need:(Frame.frame_size ~payload_len:good_len))
    (decode_good cut)

let test_bad_kind () =
  expect_bad ~what:"an unknown kind byte" (is_bad_kind ~byte:7)
    (decode_good (splice good ~at:4 ~bytes:(be ~width:1 7)))

let test_bad_head_tag () =
  expect_bad ~what:"a header tag that does not match the header" is_bad_head_tag
    (decode_good (flip good ~at:16))

let test_bad_body_tag () =
  expect_bad ~what:"a payload byte flipped under a valid header" is_bad_body_tag
    (decode_good (flip good ~at:Frame.header_size))

let test_length_disagrees () =
  expect_bad ~what:"a trailing length that contradicts the header"
    (is_length_disagrees ~head:good_len ~echo:(good_len + 1))
    (decode_good (splice good ~at:echo_off ~bytes:(be ~width:4 (good_len + 1))))

let test_missing_end_magic () =
  expect_bad ~what:"a frame that does not end in TNCE" is_missing_end_magic
    (decode_good (splice good ~at:(echo_off + 4) ~bytes:"ZZZZ"))

let test_seq_out_of_order () =
  (* The one arm a raw byte change cannot reach on its own, because the sequence
     lives under the head tag: a frame whose sequence field alone is edited is
     refused as a bad head tag, one check earlier. So the change is made where
     the format makes it, as a whole self-consistent frame carrying the wrong
     position. That is exactly the shape a spliced log has. *)
  let elsewhere = Frame.encode ~kind:Frame.Record ~seq:5 ~payload:good_payload in
  expect_bad ~what:"a perfect frame at the wrong position"
    (is_seq_out_of_order ~expected:0 ~got:5)
    (Frame.decode_at ~buf:elsewhere ~at:0 ~expect_seq:0)

let test_an_edited_sequence_field_is_caught_by_the_head_tag () =
  expect_bad ~what:"a sequence field edited in place" is_bad_head_tag
    (decode_good (flip good ~at:8))

let test_bad_offset_and_rendering () =
  let bad =
    Result.fold
      ~ok:(fun (_ : Frame.head * string * int) ->
        Alcotest.fail "the truncated frame decoded")
      ~error:Fun.id
      (Frame.decode_at ~buf:(keep good 10) ~at:0 ~expect_seq:0)
  in
  let () =
    Alcotest.(check int) "the offset it was found at" 0 (Frame.bad_offset bad)
  in
  Alcotest.(check bool) "it renders something" true
    (String.length (Frame.bad_to_string bad) > 0)

(* Scanning: what survives, and how damage is classified. *)

let prefix_size = 64
let prefix = String.make prefix_size '\xee'
let p0 = payload_of 19
let p1 = payload_of 48
let p2 = payload_of 7
let f0 = Frame.encode ~kind:Frame.Record ~seq:0 ~payload:p0
let f1 = Frame.encode ~kind:Frame.Epoch_open ~seq:1 ~payload:p1
let f2 = Frame.encode ~kind:Frame.Record ~seq:2 ~payload:p2
let off0 = prefix_size
let off1 = off0 + String.length f0
let off2 = off1 + String.length f1
let whole = String.concat "" [ prefix; f0; f1; f2 ]

let payloads_of (scanned : Frame.scan) =
  List.map (fun ((_ : Frame.head), payload) -> payload) scanned.Frame.frames

let check_payloads ~what expected scanned =
  Alcotest.(check (list string)) what expected (payloads_of scanned)

let check_torn ~what ~at scanned =
  match scanned.Frame.stop with
  | Frame.Torn t -> Alcotest.(check int) what at t.at
  | Frame.Clean _ | Frame.Corrupt _ ->
      Alcotest.failf "%s: expected a tail tear, got %s" what
        (stop_to_string scanned.Frame.stop)

let check_corrupt ~what ~at ~next_good scanned =
  match scanned.Frame.stop with
  | Frame.Corrupt c ->
      let () = Alcotest.(check int) (what ^ ": damage offset") at c.at in
      Alcotest.(check int) (what ^ ": next good frame") next_good c.next_good
  | Frame.Clean _ | Frame.Torn _ ->
      Alcotest.failf "%s: expected interior damage, got %s" what
        (stop_to_string scanned.Frame.stop)

let check_clean ~what ~at scanned =
  match scanned.Frame.stop with
  | Frame.Clean c -> Alcotest.(check int) what at c.at
  | Frame.Torn _ | Frame.Corrupt _ ->
      Alcotest.failf "%s: expected a clean stop, got %s" what
        (stop_to_string scanned.Frame.stop)

let test_a_clean_run_of_frames () =
  let scanned = Frame.scan ~buf:whole ~from:prefix_size in
  let () =
    check_clean ~what:"the end of the last frame" ~at:(String.length whole)
      scanned
  in
  check_payloads ~what:"every payload, in order" [ p0; p1; p2 ] scanned

let test_an_empty_region_is_clean () =
  let scanned = Frame.scan ~buf:prefix ~from:prefix_size in
  let () = check_clean ~what:"nothing to read" ~at:prefix_size scanned in
  check_payloads ~what:"no payloads" [] scanned

(* The five boundary classes a torn write can stop in. Each one heals to the
   SAME last good offset, and each one keeps every earlier frame. *)
let torn_at_cut ~what ~keep_bytes =
  let buf = String.concat "" [ prefix; f0; f1; keep f2 keep_bytes ] in
  let scanned = Frame.scan ~buf ~from:prefix_size in
  let () = check_torn ~what ~at:off2 scanned in
  check_payloads ~what:(what ^ ": the earlier frames survive") [ p0; p1 ] scanned

let last = String.length f2
let test_torn_in_the_length () = torn_at_cut ~what:"cut inside len" ~keep_bytes:2

let test_torn_in_the_head_tag () =
  torn_at_cut ~what:"cut inside head_tag" ~keep_bytes:18

let test_torn_in_the_payload () =
  torn_at_cut ~what:"cut inside the payload" ~keep_bytes:28

let test_torn_in_the_length_echo () =
  torn_at_cut ~what:"cut inside len_echo" ~keep_bytes:(last - 6)

let test_torn_in_the_end_magic () =
  torn_at_cut ~what:"cut inside end_magic" ~keep_bytes:(last - 2)

let test_a_garbage_tail_heals () =
  (* The analogue of upstream's own torn-write test, which appends 64 raw
     garbage bytes to a closed pack and expects a reopen to heal. *)
  let garbage =
    String.concat ""
      (List.init 64 (fun i -> be ~width:1 (((i * 37) + 11) land 0xff)))
  in
  let buf = String.concat "" [ prefix; f0; f1; garbage ] in
  let scanned = Frame.scan ~buf ~from:prefix_size in
  let () = check_torn ~what:"64 bytes of garbage" ~at:off2 scanned in
  check_payloads ~what:"the earlier frames survive" [ p0; p1 ] scanned

let test_a_zero_filled_tail_heals () =
  (* A filesystem that extends a file with a hole leaves NUL, not garbage. A run
     of NUL declares a length of zero, which no frame can have, so it is refused
     by the bound before anything else looks at it. *)
  let buf = String.concat "" [ prefix; f0; f1; String.make 96 '\x00' ] in
  let scanned = Frame.scan ~buf ~from:prefix_size in
  let () = check_torn ~what:"a zero fill" ~at:off2 scanned in
  check_payloads ~what:"the earlier frames survive" [ p0; p1 ] scanned

let test_an_interior_bit_flip_is_corrupt_not_torn () =
  (* One bit inside the payload of the MIDDLE frame. Frame 2 above it is
     untouched and correctly sequenced, so this cannot be a torn write: a crash
     appends, it does not reach back into a frame that is already down. The
     verdict must name the damage and the resync point, and a caller must not
     truncate. *)
  let buf = flip whole ~at:(off1 + Frame.header_size + 3) in
  let scanned = Frame.scan ~buf ~from:prefix_size in
  let () =
    check_corrupt ~what:"a flipped bit in the middle frame" ~at:off1
      ~next_good:off2 scanned
  in
  check_payloads ~what:"only the frame below the damage" [ p0 ] scanned

let test_a_spliced_log_is_corrupt () =
  (* Two individually perfect frames whose sequences skip one: a root assembled
     from two runs, or a hand-edited log. Nothing here is torn, so healing would
     silently drop a committed frame. The verdict is interior damage, and the
     resync point is the misplaced frame itself. *)
  let skipped = Frame.encode ~kind:Frame.Record ~seq:2 ~payload:p1 in
  let buf = String.concat "" [ prefix; f0; skipped ] in
  let scanned = Frame.scan ~buf ~from:prefix_size in
  let () =
    check_corrupt ~what:"a sequence that skips one" ~at:off1 ~next_good:off1
      scanned
  in
  check_payloads ~what:"only the frame below the splice" [ p0 ] scanned

let test_damage_in_the_last_frame_with_nothing_above_is_torn () =
  (* The same bit flip, in the LAST frame instead of an interior one. Now there
     is no correctly sequenced frame above it, so the same damage is a tail tear
     and is healable. This pair is the whole discriminator, stated twice. *)
  let buf = flip whole ~at:(off2 + Frame.header_size + 3) in
  let scanned = Frame.scan ~buf ~from:prefix_size in
  let () = check_torn ~what:"a flipped bit in the last frame" ~at:off2 scanned in
  check_payloads ~what:"the earlier frames survive" [ p0; p1 ] scanned

let () =
  Alcotest.run "durable frame"
    [
      ( "a frame is its own inverse",
        [
          Alcotest.test_case "a payload of one byte" `Quick test_one_byte_payload;
          Alcotest.test_case "a payload of exactly max_payload" `Quick
            test_max_payload;
          Alcotest.test_case "an epoch-open frame" `Quick
            test_epoch_open_round_trips;
          Alcotest.test_case "random payloads" `Quick
            (check ~salt:1 prop_round_trip);
          Alcotest.test_case "at a non-zero offset" `Quick
            test_a_frame_decodes_at_an_offset;
          Alcotest.test_case "the format's own sizes" `Quick
            test_the_format_sizes;
        ] );
      ( "every refusal arm is fired by one targeted change",
        [
          Alcotest.test_case "Short" `Quick test_short_header;
          Alcotest.test_case "Oversize, before any allocation" `Quick
            test_oversize_is_refused_before_any_allocation;
          Alcotest.test_case "and its positive control, a frame cut short"
            `Quick test_a_frame_cut_one_byte_short_is_short;
          Alcotest.test_case "Bad_kind" `Quick test_bad_kind;
          Alcotest.test_case "Bad_head_tag" `Quick test_bad_head_tag;
          Alcotest.test_case "Bad_body_tag" `Quick test_bad_body_tag;
          Alcotest.test_case "Length_disagrees" `Quick test_length_disagrees;
          Alcotest.test_case "Missing_end_magic" `Quick test_missing_end_magic;
          Alcotest.test_case "Seq_out_of_order" `Quick test_seq_out_of_order;
          Alcotest.test_case "an edited sequence field never gets that far"
            `Quick test_an_edited_sequence_field_is_caught_by_the_head_tag;
          Alcotest.test_case "a refusal carries its offset and renders" `Quick
            test_bad_offset_and_rendering;
        ] );
      ( "scanning classifies damage",
        [
          Alcotest.test_case "a clean run of frames" `Quick
            test_a_clean_run_of_frames;
          Alcotest.test_case "an empty region" `Quick
            test_an_empty_region_is_clean;
          Alcotest.test_case "torn inside len" `Quick test_torn_in_the_length;
          Alcotest.test_case "torn inside head_tag" `Quick
            test_torn_in_the_head_tag;
          Alcotest.test_case "torn inside the payload" `Quick
            test_torn_in_the_payload;
          Alcotest.test_case "torn inside len_echo" `Quick
            test_torn_in_the_length_echo;
          Alcotest.test_case "torn inside end_magic" `Quick
            test_torn_in_the_end_magic;
          Alcotest.test_case "a 64-byte garbage tail" `Quick
            test_a_garbage_tail_heals;
          Alcotest.test_case "a zero-filled tail" `Quick
            test_a_zero_filled_tail_heals;
          Alcotest.test_case "an interior bit flip is corrupt" `Quick
            test_an_interior_bit_flip_is_corrupt_not_torn;
          Alcotest.test_case "the same flip in the last frame is torn" `Quick
            test_damage_in_the_last_frame_with_nothing_above_is_torn;
          Alcotest.test_case "a spliced log is corrupt" `Quick
            test_a_spliced_log_is_corrupt;
        ] );
    ]
