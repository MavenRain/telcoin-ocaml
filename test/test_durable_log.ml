(* Chunk 40, stage S2: the log on a real filesystem, and the lock beside it.

   The frame suite settles what the bytes mean. This one settles what the
   filesystem does with them: what an open creates, what it repairs, what it
   refuses, and what each of those costs in flushes. Every durability claim in
   this file is an EQUALITY on the flush counter rather than a description, so
   deleting a flush is a change a case can kill.

   Damage is injected with the log CLOSED, which is the only honest way to model
   a crash: the process that wrote the bytes is gone, and the next process finds
   whatever the device kept. *)

module Io = Tn_durable.Io
module Io_ops = Tn_durable.Io_ops
module Frame = Tn_durable.Frame
module Append_log = Tn_durable.Append_log
module Store_lock = Tn_durable.Store_lock

let ops = Io_ops.real

(* Byte handling, total by the same rule the library uses. *)
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

let keep s n = sub_at s ~off:0 ~len:n

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

let letters = "abcdefghijklmnopqrstuvwxyz"

let rec grow block ~upto =
  match String.length block >= upto with
  | true -> block
  | false -> grow (block ^ block) ~upto

let payload_of n = keep (grow letters ~upto:(max 1 n)) n

(* The 64-byte file header of S2's format. The three identity fields are what
   makes a root belong to one chain rather than another. *)
let magic = "TNCSLOG\x00"

let header ?(epoch = 7) ?(anchor = 4242) ?(parent = String.make 32 '\x11') () =
  String.concat ""
    [
      magic;
      be ~width:4 1;
      be ~width:4 64;
      be ~width:8 epoch;
      be ~width:8 anchor;
      parent;
    ]

let file_header = header ()
let log_of dir = Filename.concat dir "consensus.log"

let root =
  Filename.concat (Filename.get_temp_dir_name ())
    (Printf.sprintf "tn-durable-log-%d" (Unix.getpid ()))

let expect_io ~what r =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "%s: %s" what (Io.error_to_string e))
    r

let expect_log ~what r =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "%s: %s" what (Append_log.error_to_string e))
    r

let expect_log_refusal ~what holds r =
  Result.fold
    ~ok:(fun (_ : Append_log.opened) ->
      Alcotest.failf "%s: expected a refusal, the log opened" what)
    ~error:(fun e ->
      match holds e with
      | true -> ()
      | false ->
          Alcotest.failf "%s: the wrong refusal: %s" what
            (Append_log.error_to_string e))
    r

let dir_for case =
  let path = Filename.concat root case in
  let () =
    expect_io ~what:"prepare the case directory" (Io.mkdir_p ~ops ~path)
  in
  path

let read_file path = expect_io ~what:"read back" (Io.read_whole ~ops ~path)

let put ~path ~content =
  expect_io ~what:"rewrite the file"
    (Io.with_file ~ops ~path ~mode:Io.Read_write_create (fun fd ->
         Result.bind (Io.write_all fd content) (fun () ->
             Io.ftruncate fd ~at:(String.length content))))

let flushes f =
  let before = Io.fsyncs () in
  let value = f () in
  (value, Io.fsyncs () - before)

(* Refusal predicates, exhaustive over the eight arms so a renamed arm is a
   build failure rather than a silently weakened case. *)
let is_corrupt ~at ~next_good = function
  | Append_log.Corrupt c -> c.at = at && c.next_good = next_good
  | Append_log.Io _ | Append_log.Lock _ | Append_log.Bad_magic _
  | Append_log.Bad_format _ | Append_log.Bad_header_len _
  | Append_log.Header_mismatch _ | Append_log.Bad_payload_len _ ->
      false

let is_bad_magic = function
  | Append_log.Bad_magic _ -> true
  | Append_log.Io _ | Append_log.Lock _ | Append_log.Corrupt _
  | Append_log.Bad_format _ | Append_log.Bad_header_len _
  | Append_log.Header_mismatch _ | Append_log.Bad_payload_len _ ->
      false

let is_bad_format ~found = function
  | Append_log.Bad_format f -> f.found = found && f.supported = 1
  | Append_log.Io _ | Append_log.Lock _ | Append_log.Corrupt _
  | Append_log.Bad_magic _ | Append_log.Bad_header_len _
  | Append_log.Header_mismatch _ | Append_log.Bad_payload_len _ ->
      false

let is_bad_header_len ~found = function
  | Append_log.Bad_header_len h -> h.found = found
  | Append_log.Io _ | Append_log.Lock _ | Append_log.Corrupt _
  | Append_log.Bad_magic _ | Append_log.Bad_format _
  | Append_log.Header_mismatch _ | Append_log.Bad_payload_len _ ->
      false

let is_header_mismatch ~field = function
  | Append_log.Header_mismatch m -> String.equal m.field field
  | Append_log.Io _ | Append_log.Lock _ | Append_log.Corrupt _
  | Append_log.Bad_magic _ | Append_log.Bad_format _
  | Append_log.Bad_header_len _ | Append_log.Bad_payload_len _ ->
      false

let is_lock_held = function
  | Append_log.Lock (Store_lock.Held _) -> true
  | Append_log.Lock (Store_lock.Io _)
  | Append_log.Io _ | Append_log.Corrupt _ | Append_log.Bad_magic _
  | Append_log.Bad_format _ | Append_log.Bad_header_len _
  | Append_log.Header_mismatch _ | Append_log.Bad_payload_len _ ->
      false

let is_io_failure = function
  | Append_log.Io (Io.Failed _) -> true
  | Append_log.Io (Io.Short_write _ | Io.Short_read _ | Io.Would_block _)
  | Append_log.Lock _ | Append_log.Corrupt _ | Append_log.Bad_magic _
  | Append_log.Bad_format _ | Append_log.Bad_header_len _
  | Append_log.Header_mismatch _ | Append_log.Bad_payload_len _ ->
      false

let is_bad_payload_len ~len = function
  | Append_log.Bad_payload_len b -> b.len = len && b.cap = Frame.max_payload
  | Append_log.Io _ | Append_log.Lock _ | Append_log.Corrupt _
  | Append_log.Bad_magic _ | Append_log.Bad_format _
  | Append_log.Bad_header_len _ | Append_log.Header_mismatch _ ->
      false

let heal_to_string = function
  | Append_log.No_heal -> "no heal"
  | Append_log.Healed_tail { last_good; dropped } ->
      Printf.sprintf "healed to %d, dropped %d" last_good dropped

let check_no_heal ~what (opened : Append_log.opened) =
  match opened.Append_log.heal with
  | Append_log.No_heal -> ()
  | Append_log.Healed_tail _ ->
      Alcotest.failf "%s: expected an untouched log, got %s" what
        (heal_to_string opened.Append_log.heal)

let check_healed ~what ~last_good ~dropped (opened : Append_log.opened) =
  match opened.Append_log.heal with
  | Append_log.Healed_tail h ->
      let () =
        Alcotest.(check int) (what ^ ": last good offset") last_good h.last_good
      in
      Alcotest.(check int) (what ^ ": bytes dropped") dropped h.dropped
  | Append_log.No_heal ->
      Alcotest.failf "%s: expected a heal, the log was taken as clean" what

let payloads (opened : Append_log.opened) =
  List.map
    (fun ((_ : Frame.kind), payload) -> payload)
    opened.Append_log.payloads

let kinds (opened : Append_log.opened) =
  List.map
    (fun (kind, (_ : string)) ->
      match kind with Frame.Record -> "record" | Frame.Epoch_open -> "epoch-open")
    opened.Append_log.payloads

let close_log ~what log =
  expect_log ~what:(what ^ ": close") (Append_log.close log)

(* Open, do something, close. The close runs on the success path only, because
   a failed open holds nothing to close: the module releases the root itself
   before it reports a refusal, which is a claim this suite also tests
   directly. *)
let with_open ~what ?(dir_header = file_header) dir f =
  let opened =
    expect_log ~what (Append_log.open_ ~ops ~dir ~file_header:dir_header)
  in
  let value = f opened in
  let () = close_log ~what opened.Append_log.log in
  value

let append_all ~what log entries =
  List.fold_left
    (fun acc (kind, payload) ->
      expect_log ~what:(what ^ ": append") (Append_log.append acc ~kind ~payload))
    log entries

(* A fresh root. *)

let test_a_fresh_root_creates_the_log () =
  let dir = dir_for "fresh" in
  let opened =
    expect_log ~what:"open a fresh root"
      (Append_log.open_ ~ops ~dir ~file_header)
  in
  let () = check_no_heal ~what:"a fresh log" opened in
  let () = Alcotest.(check int) "no frames" 0 opened.Append_log.frames in
  let () = Alcotest.(check (list string)) "no payloads" [] (payloads opened) in
  let () =
    Alcotest.(check int) "the next frame goes after the header" 64
      (Append_log.end_offset opened.Append_log.log)
  in
  let () =
    Alcotest.(check int) "the first sequence is zero" 0
      (Append_log.next_seq opened.Append_log.log)
  in
  let () = close_log ~what:"a fresh log" opened.Append_log.log in
  Alcotest.(check string)
    "the header on disk is the header that was asked for" file_header
    (read_file (log_of dir))

let test_creating_a_log_costs_exactly_two_flushes () =
  let dir = dir_for "fresh-flushes" in
  let opened, count =
    flushes (fun () ->
        expect_log ~what:"open a fresh root"
          (Append_log.open_ ~ops ~dir ~file_header))
  in
  let () = close_log ~what:"fresh flushes" opened.Append_log.log in
  Alcotest.(check int) "the file, then the directory" 2 count

let test_reopening_a_clean_log_costs_nothing () =
  let dir = dir_for "reopen-clean" in
  let () = with_open ~what:"create" dir (fun (_ : Append_log.opened) -> ()) in
  let opened, count =
    flushes (fun () ->
        expect_log ~what:"reopen" (Append_log.open_ ~ops ~dir ~file_header))
  in
  let () = check_no_heal ~what:"a clean reopen" opened in
  let () = close_log ~what:"reopen clean" opened.Append_log.log in
  Alcotest.(check int) "a clean open changes nothing and flushes nothing" 0
    count

(* Appending. *)

let entries =
  [
    (Frame.Record, payload_of 19);
    (Frame.Epoch_open, payload_of 48);
    (Frame.Record, payload_of 7);
  ]

let test_appended_payloads_come_back_in_order () =
  let dir = dir_for "append-order" in
  let () =
    with_open ~what:"create" dir (fun opened ->
        let log = append_all ~what:"three frames" opened.Append_log.log entries in
        Alcotest.(check int) "three sequences used" 3 (Append_log.next_seq log))
  in
  let reopened =
    expect_log ~what:"reopen" (Append_log.open_ ~ops ~dir ~file_header)
  in
  let () = Alcotest.(check int) "three frames" 3 reopened.Append_log.frames in
  let () =
    Alcotest.(check (list string))
      "the payloads, in append order"
      (List.map (fun ((_ : Frame.kind), payload) -> payload) entries)
      (payloads reopened)
  in
  let () =
    Alcotest.(check (list string))
      "and their kinds"
      [ "record"; "epoch-open"; "record" ]
      (kinds reopened)
  in
  close_log ~what:"the reader" reopened.Append_log.log

let test_an_append_costs_exactly_one_flush () =
  let dir = dir_for "append-flush" in
  with_open ~what:"create" dir (fun opened ->
      let log, count =
        flushes (fun () ->
            expect_log ~what:"append"
              (Append_log.append opened.Append_log.log ~kind:Frame.Record
                 ~payload:(payload_of 40)))
      in
      let () =
        Alcotest.(check int) "the file, and no directory entry changed" 1 count
      in
      Alcotest.(check int) "the end offset moved by the whole frame"
        (64 + Frame.frame_size ~payload_len:40)
        (Append_log.end_offset log))

let test_an_append_outside_the_size_bound_writes_nothing () =
  let dir = dir_for "append-bound" in
  with_open ~what:"create" dir (fun opened ->
      let log = opened.Append_log.log in
      let before_bytes = Io.bytes_written () in
      let before_flushes = Io.fsyncs () in
      let refuse ~what ~len payload =
        Result.fold
          ~ok:(fun (_ : Append_log.t) ->
            Alcotest.failf "%s: the append was accepted" what)
          ~error:(fun e ->
            match is_bad_payload_len ~len e with
            | true -> ()
            | false ->
                Alcotest.failf "%s: the wrong refusal: %s" what
                  (Append_log.error_to_string e))
          (Append_log.append log ~kind:Frame.Record ~payload)
      in
      let () = refuse ~what:"an empty payload" ~len:0 "" in
      let () =
        refuse ~what:"a payload over the cap" ~len:(Frame.max_payload + 1)
          (String.make (Frame.max_payload + 1) 'x')
      in
      let () =
        Alcotest.(check int) "no bytes were written" before_bytes
          (Io.bytes_written ())
      in
      Alcotest.(check int) "no flushes were spent" before_flushes
        (Io.fsyncs ()))

(* A foreign root is refused before a frame is parsed. *)

let corrupt_header ~dir ~bytes ~at =
  let path = log_of dir in
  put ~path ~content:(splice (read_file path) ~at ~bytes)

let refuse_open ~what ~dir holds =
  expect_log_refusal ~what holds (Append_log.open_ ~ops ~dir ~file_header)

let test_a_foreign_magic_is_refused () =
  let dir = dir_for "foreign-magic" in
  let () = with_open ~what:"create" dir (fun (_ : Append_log.opened) -> ()) in
  let () = corrupt_header ~dir ~at:0 ~bytes:"TNXXLOG\x00" in
  refuse_open ~what:"a file that is not a consensus log" ~dir is_bad_magic

let test_a_foreign_format_is_refused () =
  let dir = dir_for "foreign-format" in
  let () = with_open ~what:"create" dir (fun (_ : Append_log.opened) -> ()) in
  let () = corrupt_header ~dir ~at:8 ~bytes:(be ~width:4 9) in
  refuse_open ~what:"a container version this reader does not implement" ~dir
    (is_bad_format ~found:9)

let test_a_foreign_header_length_is_refused () =
  let dir = dir_for "foreign-header-len" in
  let () = with_open ~what:"create" dir (fun (_ : Append_log.opened) -> ()) in
  let () = corrupt_header ~dir ~at:12 ~bytes:(be ~width:4 96) in
  refuse_open ~what:"a header length this format does not use" ~dir
    (is_bad_header_len ~found:96)

let test_a_file_too_short_for_a_header_is_refused () =
  let dir = dir_for "short-header" in
  let () = with_open ~what:"create" dir (fun (_ : Append_log.opened) -> ()) in
  let () = put ~path:(log_of dir) ~content:(keep file_header 40) in
  refuse_open ~what:"a header that was never finished" ~dir
    (is_bad_header_len ~found:40)

let test_another_chain_is_refused_by_its_epoch () =
  let dir = dir_for "other-epoch" in
  let () =
    with_open ~what:"create" ~dir_header:(header ~epoch:9 ()) dir
      (fun (_ : Append_log.opened) -> ())
  in
  refuse_open ~what:"a root opened at another epoch" ~dir
    (is_header_mismatch ~field:"epoch0")

let test_another_chain_is_refused_by_its_parent () =
  let dir = dir_for "other-parent" in
  let () =
    with_open ~what:"create"
      ~dir_header:(header ~parent:(String.make 32 '\x22') ())
      dir
      (fun (_ : Append_log.opened) -> ())
  in
  refuse_open ~what:"a root whose first parent is another digest" ~dir
    (is_header_mismatch ~field:"parent0")

let test_a_caller_header_of_the_wrong_width_is_refused () =
  let dir = dir_for "wrong-width-header" in
  let () =
    expect_log_refusal ~what:"a caller header that is not 64 bytes"
      (is_bad_header_len ~found:40)
      (Append_log.open_ ~ops ~dir ~file_header:(keep file_header 40))
  in
  (* The refusal happened before anything was taken, so the root is still
     openable. *)
  with_open ~what:"the root is untouched" dir (fun opened ->
      Alcotest.(check int) "nothing was created before the refusal" 0
        opened.Append_log.frames)

(* Recovery: a torn tail heals, interior damage does not. *)

let sizes = List.map (fun (_, payload) -> Frame.frame_size ~payload_len:(String.length payload)) entries

let offset_of n =
  List.fold_left ( + ) 64
    (List.filteri (fun i (_ : int) -> i < n) sizes)

let seeded dir =
  with_open ~what:"seed three frames" dir (fun opened ->
      let (_ : Append_log.t) =
        append_all ~what:"seed" opened.Append_log.log entries
      in
      ())

let expected_payloads n =
  List.filteri
    (fun i (_ : string) -> i < n)
    (List.map (fun ((_ : Frame.kind), payload) -> payload) entries)

let tear_after ~dir ~keep_bytes =
  let path = log_of dir in
  let whole = read_file path in
  put ~path ~content:(keep whole (offset_of 2 + keep_bytes))

let torn_class ~case ~keep_bytes =
  let dir = dir_for case in
  let () = seeded dir in
  let () = tear_after ~dir ~keep_bytes in
  let opened =
    expect_log ~what:case (Append_log.open_ ~ops ~dir ~file_header)
  in
  let () =
    check_healed ~what:case ~last_good:(offset_of 2) ~dropped:keep_bytes opened
  in
  let () =
    Alcotest.(check (list string))
      (case ^ ": every earlier frame still reads back")
      (expected_payloads 2) (payloads opened)
  in
  let () =
    Alcotest.(check int)
      (case ^ ": the next append goes at the healed end")
      (offset_of 2)
      (Append_log.end_offset opened.Append_log.log)
  in
  let () = close_log ~what:case opened.Append_log.log in
  (* The heal is on disk, not only in the value. *)
  let () =
    Alcotest.(check int)
      (case ^ ": the file is the healed length")
      (offset_of 2)
      (String.length (read_file (log_of dir)))
  in
  with_open ~what:(case ^ ": reopen") dir (fun again ->
      let () = check_no_heal ~what:(case ^ ": reopen") again in
      Alcotest.(check (list string))
        (case ^ ": and the payloads are unchanged")
        (expected_payloads 2) (payloads again))

let test_torn_in_the_length () = torn_class ~case:"torn-len" ~keep_bytes:2

let test_torn_in_the_head_tag () =
  torn_class ~case:"torn-head-tag" ~keep_bytes:18

let test_torn_in_the_payload () =
  torn_class ~case:"torn-payload" ~keep_bytes:28

let last_frame = Frame.frame_size ~payload_len:7

let test_torn_in_the_length_echo () =
  torn_class ~case:"torn-len-echo" ~keep_bytes:(last_frame - 6)

let test_torn_in_the_end_magic () =
  torn_class ~case:"torn-end-magic" ~keep_bytes:(last_frame - 2)

let test_a_garbage_tail_heals () =
  let dir = dir_for "garbage-tail" in
  let () = seeded dir in
  let path = log_of dir in
  let garbage =
    String.concat ""
      (List.init 64 (fun i -> be ~width:1 (((i * 37) + 11) land 0xff)))
  in
  let () = put ~path ~content:(read_file path ^ garbage) in
  with_open ~what:"a 64-byte garbage tail" dir (fun opened ->
      let () =
        check_healed ~what:"a 64-byte garbage tail" ~last_good:(offset_of 3)
          ~dropped:64 opened
      in
      Alcotest.(check (list string))
        "every committed frame survives" (expected_payloads 3)
        (payloads opened))

let test_a_zero_filled_tail_heals () =
  let dir = dir_for "zero-tail" in
  let () = seeded dir in
  let path = log_of dir in
  let () = put ~path ~content:(read_file path ^ String.make 96 '\x00') in
  with_open ~what:"a zero-filled tail" dir (fun opened ->
      let () =
        check_healed ~what:"a zero-filled tail" ~last_good:(offset_of 3)
          ~dropped:96 opened
      in
      Alcotest.(check (list string))
        "every committed frame survives" (expected_payloads 3)
        (payloads opened))

let test_a_heal_costs_exactly_two_flushes () =
  let dir = dir_for "heal-flushes" in
  let () = seeded dir in
  let () = tear_after ~dir ~keep_bytes:18 in
  let opened, count =
    flushes (fun () ->
        expect_log ~what:"heal" (Append_log.open_ ~ops ~dir ~file_header))
  in
  let () =
    check_healed ~what:"heal" ~last_good:(offset_of 2) ~dropped:18 opened
  in
  let () = close_log ~what:"heal flushes" opened.Append_log.log in
  Alcotest.(check int) "the file, then the directory" 2 count

let test_three_opens_over_one_tear_are_healed_then_clean_twice () =
  (* W10. A crash DURING a heal leaves the file at the healed length, at the old
     length, or somewhere between, and all three reclassify to the same last
     good offset, because the heal is a pure function of the bytes. Three
     consecutive opens are the cheapest way to state that. *)
  let dir = dir_for "w10" in
  let () = seeded dir in
  let () = tear_after ~dir ~keep_bytes:28 in
  let first = expect_log ~what:"open 1" (Append_log.open_ ~ops ~dir ~file_header) in
  let () =
    check_healed ~what:"open 1" ~last_good:(offset_of 2) ~dropped:28 first
  in
  let () = close_log ~what:"open 1" first.Append_log.log in
  let second = expect_log ~what:"open 2" (Append_log.open_ ~ops ~dir ~file_header) in
  let () = check_no_heal ~what:"open 2" second in
  let () = close_log ~what:"open 2" second.Append_log.log in
  let third = expect_log ~what:"open 3" (Append_log.open_ ~ops ~dir ~file_header) in
  let () = check_no_heal ~what:"open 3" third in
  let () =
    Alcotest.(check (list string))
      "and the same payloads all three times" (expected_payloads 2)
      (payloads third)
  in
  close_log ~what:"open 3" third.Append_log.log

let test_interior_damage_refuses_and_changes_nothing () =
  (* A1. One bit inside the payload of the middle frame, with a correctly
     sequenced frame above it. Healing here would discard committed history, so
     the open refuses, names the offset, and leaves every byte where it was. The
     comparison against the pre-open image is the assertion that nothing was
     truncated. *)
  let dir = dir_for "interior" in
  let () = seeded dir in
  let path = log_of dir in
  let () =
    put ~path
      ~content:(flip (read_file path) ~at:(offset_of 1 + Frame.header_size + 3))
  in
  let before = read_file path in
  let () =
    refuse_open ~what:"a flipped bit under a committed frame" ~dir
      (is_corrupt ~at:(offset_of 1) ~next_good:(offset_of 2))
  in
  let () =
    Alcotest.(check string) "the file is byte-identical after the refusal"
      before (read_file path)
  in
  (* And the refusal gave the root back, so the same refusal is reachable
     again rather than being masked by a lock this process still holds. *)
  refuse_open ~what:"the same refusal, a second time" ~dir
    (is_corrupt ~at:(offset_of 1) ~next_good:(offset_of 2))

(* The lock. *)

(* The header goes to a TEMP name, is flushed, and only then renamed onto the
   log name. Fail that first flush - the crash point the discipline defends -
   and the log name must not exist, so the next open takes the create path
   afresh rather than adopting a header the device never took. Write the
   header at the final name directly and this case is the one that goes
   red. *)
let test_a_crashed_create_leaves_no_log () =
  let dir = dir_for "create-crash" in
  let table =
    Durable_faults.fail_at ~nth:1 ~op:Io.Fsync ~code:Durable_faults.Absent
  in
  let () =
    expect_log_refusal ~what:"a create whose temp flush fails" is_io_failure
      (Append_log.open_ ~ops:table ~dir ~file_header)
  in
  let () =
    Alcotest.(check bool) "the log name does not exist" false
      (expect_io ~what:"probe the log name"
         (Io.exists ~ops ~path:(log_of dir)))
  in
  let () =
    with_open ~what:"and a healthy retry creates it"
      dir (fun (_ : Append_log.opened) -> ())
  in
  Alcotest.(check bool) "now the log name exists" true
    (expect_io ~what:"probe the log name again"
       (Io.exists ~ops ~path:(log_of dir)))

let test_a_second_acquire_on_one_root_is_held () =
  (* A4, in this process. A POSIX advisory lock belongs to the process, so the
     kernel would let this through: the register is what refuses it. *)
  let dir = dir_for "lock-twice" in
  let held =
    Result.fold ~ok:Fun.id
      ~error:(fun e ->
        Alcotest.failf "the first acquire: %s" (Store_lock.error_to_string e))
      (Store_lock.acquire ~ops ~dir)
  in
  let () =
    Result.fold
      ~ok:(fun (_ : Store_lock.t) ->
        Alcotest.fail "the second acquire was granted")
      ~error:(fun e ->
        match e with
        | Store_lock.Held _ -> ()
        | Store_lock.Io _ ->
            Alcotest.failf "the wrong refusal: %s" (Store_lock.error_to_string e))
      (Store_lock.acquire ~ops ~dir)
  in
  let () =
    expect_io ~what:"release" (Store_lock.release held)
  in
  (* Released means released: the root is acquirable again. *)
  let again =
    Result.fold ~ok:Fun.id
      ~error:(fun e ->
        Alcotest.failf "acquire after release: %s"
          (Store_lock.error_to_string e))
      (Store_lock.acquire ~ops ~dir)
  in
  expect_io ~what:"release again" (Store_lock.release again)

let test_lock_contention_from_outside_is_held () =
  (* A4, across processes, which is the half the register cannot see. The
     contention is a REAL EAGAIN from the operating system, injected at the
     vtable, because a second process cannot be spawned from this suite. Remove
     the lock call from acquire and this case is the one that goes red. *)
  let dir = dir_for "lock-contended" in
  let table =
    Durable_faults.fail_at ~nth:1 ~op:Io.Lockf ~code:Durable_faults.Contended
  in
  Result.fold
    ~ok:(fun (_ : Store_lock.t) ->
      Alcotest.fail "a contended lock was granted")
    ~error:(fun e ->
      match e with
      | Store_lock.Held _ -> ()
      | Store_lock.Io _ ->
          Alcotest.failf "the wrong refusal: %s" (Store_lock.error_to_string e))
    (Store_lock.acquire ~ops:table ~dir)

let test_two_spellings_of_one_root_contend () =
  (* The register keys the CANONICAL path. Without [realpath] in acquire the
     dotted spelling below would slip past the register, and the kernel would
     grant it too - a POSIX advisory lock belongs to the process, so a process
     never contends with itself - leaving two writers on one root. *)
  let dir = dir_for "lock-alias" in
  let alias =
    Filename.concat
      (Filename.concat dir Filename.parent_dir_name)
      (Filename.basename dir)
  in
  let held =
    Result.fold ~ok:Fun.id
      ~error:(fun e ->
        Alcotest.failf "the canonical acquire: %s"
          (Store_lock.error_to_string e))
      (Store_lock.acquire ~ops ~dir)
  in
  let () =
    Result.fold
      ~ok:(fun (_ : Store_lock.t) ->
        Alcotest.fail "an aliased spelling was granted")
      ~error:(fun e ->
        match e with
        | Store_lock.Held _ -> ()
        | Store_lock.Io _ ->
            Alcotest.failf "the wrong refusal: %s"
              (Store_lock.error_to_string e))
      (Store_lock.acquire ~ops ~dir:alias)
  in
  let () = expect_io ~what:"release" (Store_lock.release held) in
  (* Released means released, under either spelling. *)
  let again =
    Result.fold ~ok:Fun.id
      ~error:(fun e ->
        Alcotest.failf "acquire by alias after release: %s"
          (Store_lock.error_to_string e))
      (Store_lock.acquire ~ops ~dir:alias)
  in
  expect_io ~what:"release the alias" (Store_lock.release again)

let test_an_open_on_a_held_root_is_refused () =
  let dir = dir_for "open-held" in
  let held =
    Result.fold ~ok:Fun.id
      ~error:(fun e ->
        Alcotest.failf "take the root first: %s" (Store_lock.error_to_string e))
      (Store_lock.acquire ~ops ~dir)
  in
  let () = refuse_open ~what:"a root another handle holds" ~dir is_lock_held in
  let () = expect_io ~what:"release" (Store_lock.release held) in
  with_open ~what:"and the root opens once it is free" dir
    (fun (_ : Append_log.opened) -> ())

let () =
  Alcotest.run "durable log"
    [
      ( "a fresh root",
        [
          Alcotest.test_case "an open creates the log and its header" `Quick
            test_a_fresh_root_creates_the_log;
          Alcotest.test_case "creating costs exactly two flushes" `Quick
            test_creating_a_log_costs_exactly_two_flushes;
          Alcotest.test_case "reopening a clean log costs none" `Quick
            test_reopening_a_clean_log_costs_nothing;
          Alcotest.test_case "a crashed create leaves no log" `Quick
            test_a_crashed_create_leaves_no_log;
        ] );
      ( "appending",
        [
          Alcotest.test_case "payloads come back in append order" `Quick
            test_appended_payloads_come_back_in_order;
          Alcotest.test_case "an append costs exactly one flush" `Quick
            test_an_append_costs_exactly_one_flush;
          Alcotest.test_case "a payload outside the bound writes nothing" `Quick
            test_an_append_outside_the_size_bound_writes_nothing;
        ] );
      ( "a foreign root is refused before a frame is parsed",
        [
          Alcotest.test_case "a foreign magic" `Quick
            test_a_foreign_magic_is_refused;
          Alcotest.test_case "a foreign format" `Quick
            test_a_foreign_format_is_refused;
          Alcotest.test_case "a foreign header length" `Quick
            test_a_foreign_header_length_is_refused;
          Alcotest.test_case "a header that was never finished" `Quick
            test_a_file_too_short_for_a_header_is_refused;
          Alcotest.test_case "another epoch" `Quick
            test_another_chain_is_refused_by_its_epoch;
          Alcotest.test_case "another first parent" `Quick
            test_another_chain_is_refused_by_its_parent;
          Alcotest.test_case "and a caller header of the wrong width" `Quick
            test_a_caller_header_of_the_wrong_width_is_refused;
        ] );
      ( "recovery",
        [
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
          Alcotest.test_case "a heal costs exactly two flushes" `Quick
            test_a_heal_costs_exactly_two_flushes;
          Alcotest.test_case "three opens over one tear: healed, clean, clean"
            `Quick test_three_opens_over_one_tear_are_healed_then_clean_twice;
          Alcotest.test_case "interior damage refuses and truncates nothing"
            `Quick test_interior_damage_refuses_and_changes_nothing;
        ] );
      ( "one writer per root",
        [
          Alcotest.test_case "a second acquire in this process is held" `Quick
            test_a_second_acquire_on_one_root_is_held;
          Alcotest.test_case "two spellings of one root contend" `Quick
            test_two_spellings_of_one_root_contend;
          Alcotest.test_case "contention from outside is held" `Quick
            test_lock_contention_from_outside_is_held;
          Alcotest.test_case "an open on a held root is refused" `Quick
            test_an_open_on_a_held_root_is_refused;
        ] );
    ]
