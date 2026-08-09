(* Chunk 40, stage S1: the IO boundary.

   Negative controls come first, on purpose. A suite that only ever asks
   whether the happy path works cannot tell a boundary that names its failures
   from one that lets them escape, so every fault case here is stated before
   the case that uses the same call successfully.

   The middle group promotes the 2026-08-08 harness probe into a permanent
   in-suite test: file flush, DIRECTORY flush, and rename-over-existing are
   verified on the machine running the suite, on every build. Absence of a
   failure is then never the evidence. *)

module Io = Tn_durable.Io
module Io_ops = Tn_durable.Io_ops
module Atomic_file = Tn_durable.Atomic_file

let ops = Io_ops.real

(* The container header this module writes is 32 bytes: magic 8, format 4,
   generation 8, length 4, tag 8. Named here so the byte-level cases below say
   what they mean. *)
let header_size = 32
let magic = "TNPROBE\x00"

(* One root per process, so two runs in parallel never share a name. *)
let root =
  Filename.concat (Filename.get_temp_dir_name ())
    (Printf.sprintf "tn-durable-io-%d" (Unix.getpid ()))

let expect_ok ~what render r =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "%s: %s" what (render e))
    r

let expect_io ~what r = expect_ok ~what Io.error_to_string r
let expect_af ~what r = expect_ok ~what Atomic_file.error_to_string r

let expect_refusal ~what render holds r =
  Result.fold
    ~ok:(fun _ -> Alcotest.failf "%s: expected a refusal, got success" what)
    ~error:(fun e ->
      match holds e with
      | true -> ()
      | false -> Alcotest.failf "%s: the wrong refusal: %s" what (render e))
    r

let expect_io_refusal ~what holds r =
  expect_refusal ~what Io.error_to_string holds r

let expect_af_refusal ~what holds r =
  expect_refusal ~what Atomic_file.error_to_string holds r

let failed_on wanted = function
  | Io.Failed { op; _ } -> op = wanted
  | Io.Short_write _ | Io.Short_read _ | Io.Would_block _ -> false

let would_block = function
  | Io.Would_block _ -> true
  | Io.Failed _ | Io.Short_write _ | Io.Short_read _ -> false

let short_write ~wanted ~wrote = function
  | Io.Short_write s -> s.wanted = wanted && s.wrote = wrote
  | Io.Failed _ | Io.Short_read _ | Io.Would_block _ -> false

let is_bad_magic = function
  | Atomic_file.Bad_magic _ -> true
  | Atomic_file.Io _ | Atomic_file.Bad_format _ | Atomic_file.Bad_body_tag _
  | Atomic_file.Short _ | Atomic_file.Bad_generation _ ->
      false

let is_bad_format ~found ~supported = function
  | Atomic_file.Bad_format f -> f.found = found && f.supported = supported
  | Atomic_file.Io _ | Atomic_file.Bad_magic _ | Atomic_file.Bad_body_tag _
  | Atomic_file.Short _ | Atomic_file.Bad_generation _ ->
      false

let is_bad_body_tag = function
  | Atomic_file.Bad_body_tag _ -> true
  | Atomic_file.Io _ | Atomic_file.Bad_magic _ | Atomic_file.Bad_format _
  | Atomic_file.Short _ | Atomic_file.Bad_generation _ ->
      false

let is_short ~have = function
  | Atomic_file.Short s -> s.have = have
  | Atomic_file.Io _ | Atomic_file.Bad_magic _ | Atomic_file.Bad_format _
  | Atomic_file.Bad_body_tag _ | Atomic_file.Bad_generation _ ->
      false

let dir_for case =
  let path = Filename.concat root case in
  let () = expect_io ~what:"prepare the case directory" (Io.mkdir_p ~ops ~path) in
  path

let touch ?(table = ops) path =
  Io.with_file ~ops:table ~path ~mode:Io.Read_write_create (fun _fd -> Ok ())

let put ~path ~content =
  Io.with_file ~ops ~path ~mode:Io.Read_write_create (fun fd ->
      Result.bind (Io.write_all fd content) (fun () ->
          Io.ftruncate fd ~at:(String.length content)))

let first_word line =
  Option.fold ~none:line
    ~some:(fun i -> String.sub line 0 i (* @total-accessor *))
    (String.index_opt line ' ')

(* Negative controls. *)

let test_open_in_an_unwritable_directory () =
  let dir = dir_for "unwritable" in
  let () = Unix.chmod dir 0o500 in
  let outcome = touch (Filename.concat dir "child.dat") in
  let () = Unix.chmod dir 0o700 in
  expect_io_refusal ~what:"open in an unwritable directory" (failed_on Io.Open)
    outcome

let test_open_under_a_non_directory () =
  let dir = dir_for "not-a-directory" in
  let blocker = Filename.concat dir "blocker" in
  let () = expect_io ~what:"create the blocker" (touch blocker) in
  expect_io_refusal ~what:"open under a regular file" (failed_on Io.Open)
    (touch (Filename.concat blocker "child.dat"))

let test_rename_onto_a_directory () =
  let dir = dir_for "rename-onto-a-directory" in
  let src = Filename.concat dir "src.dat" in
  let dst = Filename.concat dir "occupied" in
  let () = expect_io ~what:"create the source" (touch src) in
  let () = expect_io ~what:"create the target directory" (Io.mkdir_p ~ops ~path:dst) in
  expect_io_refusal ~what:"rename over a directory" (failed_on Io.Rename)
    (Io.rename_over ~ops ~src ~dst)

let test_lock_contention_is_would_block () =
  let dir = dir_for "lock-contention" in
  let path = Filename.concat dir "LOCK" in
  let held =
    Durable_faults.fail_at ~nth:1 ~op:Io.Lockf ~code:Durable_faults.Contended
  in
  expect_io_refusal ~what:"lock a file another holder owns" would_block
    (Io.with_file ~ops:held ~path ~mode:Io.Read_write_create (fun fd ->
         Io.lock_exclusive fd ~path))

let test_a_short_write_is_reported () =
  let dir = dir_for "short-write" in
  let path = Filename.concat dir "s.dat" in
  let stalling = Durable_faults.short_write_at ~nth:1 ~bytes:3 in
  expect_io_refusal ~what:"a device that takes a prefix and stops"
    (short_write ~wanted:10 ~wrote:3)
    (Io.with_file ~ops:stalling ~path ~mode:Io.Write_create_excl (fun fd ->
         Io.write_all fd "0123456789"))

let test_a_read_past_the_end_is_reported () =
  let dir = dir_for "short-read" in
  let path = Filename.concat dir "r.dat" in
  let () = expect_io ~what:"seed the file" (put ~path ~content:"0123") in
  expect_io_refusal ~what:"read more than the file holds"
    (function
      | Io.Short_read { wanted; got; _ } -> wanted = 16 && got = 4
      | Io.Failed _ | Io.Short_write _ | Io.Would_block _ -> false)
    (Io.with_file ~ops ~path ~mode:Io.Read_only (fun fd ->
         Io.pread_exact fd ~at:0 ~len:16))

(* Probe parity, promoted from the harness into the suite. *)

let test_probe_parity () =
  let dir = dir_for "probe-parity" in
  let source = Filename.concat dir "a.tmp" in
  let target = Filename.concat dir "b.dat" in
  let payload = "probe-payload" in
  let () =
    expect_io ~what:"write and flush a file"
      (Io.with_file ~ops ~path:source ~mode:Io.Write_create_excl (fun fd ->
           Result.bind (Io.write_all fd payload) (fun () -> Io.fsync fd)))
  in
  let () = expect_io ~what:"seed the rename target" (touch target) in
  let () =
    expect_io ~what:"rename over an existing file"
      (Io.rename_over ~ops ~src:source ~dst:target)
  in
  let () = expect_io ~what:"flush the directory" (Io.fsync_dir ~ops ~path:dir) in
  let back = expect_io ~what:"reread the renamed file" (Io.read_whole ~ops ~path:target) in
  let () = Alcotest.(check int) "the renamed file rereads at its own length" 13 (String.length back) in
  let () = Alcotest.(check string) "and byte for byte" payload back in
  Alcotest.(check bool) "the source name is gone" false
    (expect_io ~what:"ask after the source" (Io.exists ~ops ~path:source))

let test_a_directory_flush_is_reachable_and_counted () =
  let dir = dir_for "directory-flush" in
  let before = Io.fsyncs () in
  let () = expect_io ~what:"flush the directory" (Io.fsync_dir ~ops ~path:dir) in
  Alcotest.(check int) "one directory flush, counted once" 1 (Io.fsyncs () - before)

let test_mkdir_p_is_idempotent () =
  let path = Filename.concat (dir_for "nested") "a/b/c" in
  let () = expect_io ~what:"create a nested path" (Io.mkdir_p ~ops ~path) in
  let () = expect_io ~what:"create it again" (Io.mkdir_p ~ops ~path) in
  Alcotest.(check bool) "the leaf is there" true
    (expect_io ~what:"ask after the leaf" (Io.exists ~ops ~path))

let test_unlink_if_present_tolerates_absence () =
  let dir = dir_for "unlink-absent" in
  let path = Filename.concat dir "never-written" in
  let () = expect_io ~what:"remove a name that was never there" (Io.unlink_if_present ~ops ~path) in
  Alcotest.(check bool) "and it is still not there" false
    (expect_io ~what:"ask after it" (Io.exists ~ops ~path))

(* A measured platform fact, not a wish: an advisory lock is owned by the
   PROCESS, so a second handle inside this process does not contend with the
   first. Stage S2's single-writer enforcement therefore needs an in-process
   register beside the lock file; the lock file alone only excludes other
   processes. *)
let test_same_process_locks_do_not_contend () =
  let dir = dir_for "lock-ownership" in
  let path = Filename.concat dir "LOCK" in
  let outcome =
    Io.with_file ~ops ~path ~mode:Io.Read_write_create (fun outer ->
        Result.bind (Io.lock_exclusive outer ~path) (fun () ->
            Io.with_file ~ops ~path ~mode:Io.Read_write_create (fun inner ->
                Io.lock_exclusive inner ~path)))
  in
  Alcotest.(check bool)
    "a second handle in the SAME process takes the lock without contending"
    true (Result.is_ok outcome)

(* The atomic file. *)

let test_save_then_load_round_trips () =
  let dir = dir_for "round-trip" in
  let payload = "a payload of no particular shape" in
  let () =
    expect_af ~what:"save"
      (Atomic_file.save ~ops ~dir ~name:"slot" ~magic ~format:1 ~generation:7
         ~payload)
  in
  let loaded = expect_af ~what:"load" (Atomic_file.load ~ops ~dir ~name:"slot" ~magic ~format:1) in
  Alcotest.(check (option (pair int string)))
    "the payload and its generation come back unchanged"
    (Some (7, payload)) loaded

let test_load_of_a_never_written_name_is_none () =
  let dir = dir_for "never-written" in
  let loaded =
    expect_af ~what:"load" (Atomic_file.load ~ops ~dir ~name:"slot" ~magic ~format:1)
  in
  Alcotest.(check (option (pair int string)))
    "a fresh node reads None, never a silent zero" None loaded

let test_a_stale_temp_is_never_a_load_candidate () =
  let dir = dir_for "stale-temp" in
  let () =
    expect_af ~what:"publish the canonical file"
      (Atomic_file.save ~ops ~dir ~name:"slot" ~magic ~format:1 ~generation:1
         ~payload:"the published payload")
  in
  (* A complete, tag-valid container at the temp name: exactly what a crash
     between the temp flush and the rename leaves behind. *)
  let () =
    expect_af ~what:"build a plausible temp"
      (Atomic_file.save ~ops ~dir ~name:"other" ~magic ~format:1 ~generation:99
         ~payload:"the payload that must not win")
  in
  let () =
    expect_io ~what:"put it at the temp name"
      (Io.rename_over ~ops
         ~src:(Filename.concat dir "other")
         ~dst:(Filename.concat dir "slot.tmp"))
  in
  let loaded = expect_af ~what:"load" (Atomic_file.load ~ops ~dir ~name:"slot" ~magic ~format:1) in
  let () =
    Alcotest.(check (option (pair int string)))
      "the canonical name wins, at its own generation"
      (Some (1, "the published payload"))
      loaded
  in
  Alcotest.(check bool) "and the temp was swept before anything was read" false
    (expect_io ~what:"ask after the temp"
       (Io.exists ~ops ~path:(Filename.concat dir "slot.tmp")))

let test_sweep_temp_answers_whether_it_swept () =
  let dir = dir_for "sweep" in
  let () =
    expect_af ~what:"publish something to move"
      (Atomic_file.save ~ops ~dir ~name:"other" ~magic ~format:1 ~generation:1
         ~payload:"x")
  in
  let () =
    expect_io ~what:"put it at the temp name"
      (Io.rename_over ~ops
         ~src:(Filename.concat dir "other")
         ~dst:(Filename.concat dir "slot.tmp"))
  in
  let swept = expect_af ~what:"sweep" (Atomic_file.sweep_temp ~ops ~dir ~name:"slot") in
  let () = Alcotest.(check bool) "the first sweep removes it" true swept in
  let again = expect_af ~what:"sweep again" (Atomic_file.sweep_temp ~ops ~dir ~name:"slot") in
  Alcotest.(check bool) "the second has nothing to do" false again

let test_save_costs_exactly_two_flushes () =
  let dir = dir_for "flush-count" in
  let before = Io.fsyncs () in
  let () =
    expect_af ~what:"save"
      (Atomic_file.save ~ops ~dir ~name:"slot" ~magic ~format:1 ~generation:1
         ~payload:"counted")
  in
  Alcotest.(check int) "the temp, then the directory: exactly two" 2
    (Io.fsyncs () - before)

let test_save_writes_exactly_its_container () =
  let dir = dir_for "byte-count" in
  let payload = "counted bytes" in
  let before = Io.bytes_written () in
  let () =
    expect_af ~what:"save"
      (Atomic_file.save ~ops ~dir ~name:"slot" ~magic ~format:1 ~generation:1
         ~payload)
  in
  Alcotest.(check int) "header plus payload, and nothing else"
    (header_size + String.length payload)
    (Io.bytes_written () - before)

let test_save_makes_its_calls_in_the_durable_order () =
  let dir = dir_for "call-order" in
  let seen = ref [] in
  let recorded = Durable_faults.traced ~sink:(fun line -> seen := line :: !seen) in
  let () =
    expect_af ~what:"save"
      (Atomic_file.save ~ops:recorded ~dir ~name:"slot" ~magic ~format:1
         ~generation:1 ~payload:"ordered")
  in
  let lines = List.rev !seen in
  let () =
    Alcotest.(check (list string))
      "sweep, write, flush the file, rename, flush the directory"
      [
        "unlink"; "openfile"; "write"; "fsync"; "close"; "rename"; "openfile";
        "fsync"; "close";
      ]
      (List.map first_word lines)
  in
  Alcotest.(check (list string))
    "and the second flush is on the DIRECTORY, not on the file again"
    [ "openfile " ^ Filename.concat dir "slot.tmp"; "openfile " ^ dir ]
    (List.filter (fun line -> String.starts_with ~prefix:"openfile " line) lines)

let test_the_flush_counter_counts_calls_not_devices () =
  let dir = dir_for "lying-device" in
  let lying = Durable_faults.skip_fsync_at ~nth:1 in
  let before = Io.fsyncs () in
  let () =
    expect_af ~what:"save against a device that ignores a flush"
      (Atomic_file.save ~ops:lying ~dir ~name:"slot" ~magic ~format:1
         ~generation:1 ~payload:"lied about")
  in
  Alcotest.(check int)
    "the counter counts calls that returned, so a lying device still advances it"
    2 (Io.fsyncs () - before)

(* Container negatives. *)

let seeded ~case ~payload =
  let dir = dir_for case in
  let () =
    expect_af ~what:"seed the container"
      (Atomic_file.save ~ops ~dir ~name:"slot" ~magic ~format:1 ~generation:3
         ~payload)
  in
  dir

let test_load_refuses_a_foreign_magic () =
  let dir = seeded ~case:"foreign-magic" ~payload:"body" in
  expect_af_refusal ~what:"load with another magic" is_bad_magic
    (Atomic_file.load ~ops ~dir ~name:"slot" ~magic:"OTHERMAG" ~format:1)

let test_load_refuses_a_foreign_format () =
  let dir = seeded ~case:"foreign-format" ~payload:"body" in
  expect_af_refusal ~what:"load at another format"
    (is_bad_format ~found:1 ~supported:2)
    (Atomic_file.load ~ops ~dir ~name:"slot" ~magic ~format:2)

let test_load_refuses_a_damaged_payload () =
  let dir = seeded ~case:"damaged-payload" ~payload:"body" in
  let path = Filename.concat dir "slot" in
  let raw = expect_io ~what:"read the container back" (Io.read_whole ~ops ~path) in
  let damaged =
    String.mapi (fun i c -> match i = header_size with true -> 'X' | false -> c) raw
  in
  let () = expect_io ~what:"write the damaged container" (put ~path ~content:damaged) in
  expect_af_refusal ~what:"load a payload that does not match its tag"
    is_bad_body_tag
    (Atomic_file.load ~ops ~dir ~name:"slot" ~magic ~format:1)

let test_load_refuses_a_truncated_container () =
  let dir = seeded ~case:"truncated" ~payload:"body" in
  let path = Filename.concat dir "slot" in
  let () =
    expect_io ~what:"cut the container short"
      (Io.with_file ~ops ~path ~mode:Io.Read_write_create (fun fd ->
           Io.ftruncate fd ~at:20))
  in
  expect_af_refusal ~what:"load a container shorter than its own header"
    (is_short ~have:20)
    (Atomic_file.load ~ops ~dir ~name:"slot" ~magic ~format:1)

let test_save_refuses_a_magic_of_the_wrong_width () =
  let dir = dir_for "wrong-width-magic" in
  expect_af_refusal ~what:"save with a seven-byte magic" is_bad_magic
    (Atomic_file.save ~ops ~dir ~name:"slot" ~magic:"SEVEN77" ~format:1
       ~generation:1 ~payload:"body")

(* The 1 GiB ceiling binds a length a PARSED HEADER CLAIMS; a length the
   caller measured off the device itself is trusted. A sparse file one word
   past the ceiling tells the two reads apart: the capped read refuses it
   outright, the whole-file read returns every byte. Re-cap [pread_all] and
   the second check goes red; cap nothing and the first one does. *)
let test_the_ceiling_binds_claimed_lengths_only () =
  let dir = dir_for "ceiling" in
  let path = Filename.concat dir "sparse" in
  let over = (1 lsl 30) + 8 in
  let () =
    expect_io ~what:"grow a sparse file past the ceiling"
      (Io.with_file ~ops ~path ~mode:Io.Read_write_create (fun fd ->
           Io.ftruncate fd ~at:over))
  in
  let () =
    expect_io ~what:"read on both sides of the ceiling"
      (Io.with_file ~ops ~path ~mode:Io.Read_only (fun fd ->
           let () =
             expect_io_refusal ~what:"the capped read refuses the length"
               (fun e ->
                 match e with
                 | Io.Short_read { wanted; got; _ } -> wanted = over && got = 0
                 | Io.Failed _ | Io.Short_write _ | Io.Would_block _ -> false)
               (Io.pread_exact fd ~at:0 ~len:over)
           in
           Result.map
             (fun whole ->
               Alcotest.(check int) "the whole-file read returns every byte"
                 over (String.length whole))
             (Io.pread_all fd ~at:0 ~len:over)))
  in
  expect_io ~what:"drop the sparse file" (Io.unlink_if_present ~ops ~path)

let () =
  Alcotest.run "durable io"
    [
      ( "the boundary names its failures",
        [
          Alcotest.test_case "an open in an unwritable directory is a value"
            `Quick test_open_in_an_unwritable_directory;
          Alcotest.test_case "and so is an open under a regular file" `Quick
            test_open_under_a_non_directory;
          Alcotest.test_case "a rename onto a directory is a value" `Quick
            test_rename_onto_a_directory;
          Alcotest.test_case "contention is Would_block, not a fault" `Quick
            test_lock_contention_is_would_block;
          Alcotest.test_case "a short write is never assumed complete" `Quick
            test_a_short_write_is_reported;
          Alcotest.test_case "a read past the end is never a short string"
            `Quick test_a_read_past_the_end_is_reported;
          Alcotest.test_case "the ceiling binds claimed lengths only" `Quick
            test_the_ceiling_binds_claimed_lengths_only;
        ] );
      ( "probe parity on this machine",
        [
          Alcotest.test_case "file flush, directory flush, rename over existing"
            `Quick test_probe_parity;
          Alcotest.test_case "a directory flush is reachable and counted" `Quick
            test_a_directory_flush_is_reachable_and_counted;
          Alcotest.test_case "mkdir_p is idempotent" `Quick
            test_mkdir_p_is_idempotent;
          Alcotest.test_case "unlink tolerates an absent name" `Quick
            test_unlink_if_present_tolerates_absence;
          Alcotest.test_case "an advisory lock belongs to the process" `Quick
            test_same_process_locks_do_not_contend;
        ] );
      ( "the atomic file",
        [
          Alcotest.test_case "save then load round-trips" `Quick
            test_save_then_load_round_trips;
          Alcotest.test_case "a never-written name loads as None" `Quick
            test_load_of_a_never_written_name_is_none;
          Alcotest.test_case "a stale temp is swept and never wins" `Quick
            test_a_stale_temp_is_never_a_load_candidate;
          Alcotest.test_case "sweeping answers whether it swept" `Quick
            test_sweep_temp_answers_whether_it_swept;
          Alcotest.test_case "save costs exactly two flushes" `Quick
            test_save_costs_exactly_two_flushes;
          Alcotest.test_case "save writes exactly its container" `Quick
            test_save_writes_exactly_its_container;
          Alcotest.test_case "save makes its calls in the durable order" `Quick
            test_save_makes_its_calls_in_the_durable_order;
          Alcotest.test_case "the flush counter counts calls, not devices"
            `Quick test_the_flush_counter_counts_calls_not_devices;
        ] );
      ( "the container refuses what it cannot vouch for",
        [
          Alcotest.test_case "a foreign magic" `Quick
            test_load_refuses_a_foreign_magic;
          Alcotest.test_case "a foreign format" `Quick
            test_load_refuses_a_foreign_format;
          Alcotest.test_case "a payload that does not match its tag" `Quick
            test_load_refuses_a_damaged_payload;
          Alcotest.test_case "a container cut short" `Quick
            test_load_refuses_a_truncated_container;
          Alcotest.test_case "and a magic of the wrong width, on save" `Quick
            test_save_refuses_a_magic_of_the_wrong_width;
        ] );
    ]
