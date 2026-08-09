(* Chunk 40, stage S4: the durable store on a real filesystem.

   The codec suite settles what a payload means and the log suite settles what
   the filesystem does with bytes. This one settles the join: that the value a
   reader sees is exactly the value the device holds, and that it costs what the
   contract says it costs.

   Three disciplines run through the file.

   Every durability claim is an EQUALITY on the flush and byte counters rather
   than a description, so deleting a flush, or writing where the contract says
   nothing is written, is a change a case can kill.

   Every claim about what a reopened store holds is made through the SAME six
   observations the seam's own conformance profile uses - cardinal,
   expected_next, earliest, latest_received, record_at and gap - rendered to
   strings, and the renderings are checked to be pairwise distinct across
   prefixes before any agreement between two of them is trusted. Agreement
   between two renderings that cannot tell anything apart is not evidence.

   Damage is injected with the store CLOSED and re-framed through the real
   framer, which is the only honest way to model a hand-edited or spliced root:
   every frame is individually perfect, so what the store refuses is the chain,
   not the bytes. *)

open Tn_types
open Tn_vertex
open Tn_consensus
module Cb = Tn_execution.Consensus_block
module Chain = Tn_execution.Consensus_chain
module Store = Tn_execution.Consensus_store
module Record = Tn_execution.Consensus_store.Record
module Replay = Tn_execution.Replay
module Disk = Tn_durable_store.Consensus_store_disk
module Rc = Tn_durable_store.Record_codec
module Io = Tn_durable.Io
module Io_ops = Tn_durable.Io_ops
module Frame = Tn_durable.Frame
module Append_log = Tn_durable.Append_log
module Nonempty = Tn_std.Nonempty

(* Totalise an option under a named expectation; [Result.fold] keeps both arms
   lazy, where [Option.fold]'s [~none] is eager. *)
let get what o =
  Result.fold ~ok:Fun.id ~error:(fun msg -> Alcotest.fail msg)
    (Option.to_result ~none:what o)

let nth what l n = get what (List.nth_opt l n)

(* Byte handling, total by the same rule the library uses: a span running off
   either end is clamped rather than raising. *)
let sub_at s ~off ~len =
  let bound = String.length s in
  let start = min (max 0 off) bound in
  let stop = min (max start (off + max 0 len)) bound in
  String.sub s start (stop - start) (* @total-accessor *)

let first_word line = Option.value ~default:line (List.nth_opt (String.split_on_char ' ' line) 0)

(* {1 Fixtures} *)

(* Four validators, exactly the shape the seam's own suite uses. *)
let committee, sk_of =
  let sks = List.init 4 (fun i -> Tn_crypto.Secret_key.derive (Int64.of_int i)) in
  let authorities =
    List.map
      (fun sk ->
        Authority.make
          ~protocol_key:(Tn_crypto.Secret_key.public_key sk)
          ~execution_address:Units.Address.zero)
      sks
  in
  let committee =
    Result.fold ~ok:Fun.id
      ~error:(fun e ->
        Alcotest.failf "committee: %s" (Committee.error_to_string e))
      (Committee.create ~epoch:Units.Epoch.zero authorities)
  in
  let sk_of id =
    get "secret key"
      (List.find_opt
         (fun sk ->
           Authority_id.equal
             (Authority_id.of_public_key (Tn_crypto.Secret_key.public_key sk))
             id)
         sks)
  in
  (committee, sk_of)

let ids = List.map Authority.id (Committee.authorities committee)
let epoch0 = Units.Epoch.zero
let epoch1 = Units.Epoch.succ epoch0
let epoch2 = Units.Epoch.succ epoch1

let synthetic_sub_dag ?(epoch = epoch0) ?(payload = []) ~author ~r () =
  let certify header =
    let votes = List.map (fun id -> Vote.sign (sk_of id) ~voter:id header) ids in
    Result.fold ~ok:Fun.id
      ~error:(fun e ->
        Alcotest.failf "certify: %s" (Certificate.error_to_string e))
      (Certificate.assemble committee header votes)
  in
  let header =
    Header.make ~latest_execution_block:Tn_types.Block_num_hash.zero ~author
      ~round:(get "round" (Round.of_int r))
      ~epoch
      ~created_at:(get "timestamp" (Units.Timestamp.of_sec (Int64.of_int (50 + r))))
      ~payload
      ~parents:(List.map Certificate.digest (Certificate.genesis committee))
  in
  Sub_dag.create
    ~sequence:(Nonempty.singleton (certify header))
    ~scores:(Reputation_scores.fresh committee)
    ~previous:None

let batch tag =
  Batch.make ~transactions:[ tag ] ~epoch:epoch0 ~beneficiary:Units.Address.zero
    ~base_fee_per_gas:(Units.Base_fee.of_int64 7L)
    ~worker_id:Units.Worker_id.zero

let ba = batch "\x0a"
let bb = batch "\x0b"
let bc = batch "\x0c"
let bodies_pool = [ ba; bb; bc ]
let da = Batch.digest ba
let db = Batch.digest bb
let dc = Batch.digest bc
let worker n = get "worker id" (Units.Worker_id.of_int n)

let lookup d =
  List.find_opt (fun body -> Digests.Batch_digest.equal (Batch.digest body) d)
    bodies_pool

(* Five heights. The fifth commits in epoch 1, so one fixture chain carries the
   whole of an epoch roll: four records, the roll, and a record above it. *)
let payload_at = function
  | 0 -> [ (da, worker 0) ]
  | 1 -> [ (da, worker 0); (db, worker 1) ]
  | 2 -> []
  | 3 -> [ (da, worker 0); (dc, worker 2) ]
  | _ -> [ (db, worker 1) ]

let sub_dags =
  List.mapi
    (fun i r ->
      synthetic_sub_dag
        ~epoch:(match i = 4 with true -> epoch1 | false -> epoch0)
        ~payload:(payload_at i)
        ~author:(nth "author" ids (i mod 4))
        ~r ())
    [ 1; 2; 3; 4; 5 ]

(* Minted by the driver's own fold, so the links are real rather than asserted
   into existence. *)
let blocks =
  let _, rev =
    List.fold_left
      (fun (c, acc) sd ->
        let c', b = Chain.append c sd in
        (c', b :: acc))
      (Chain.genesis, []) sub_dags
  in
  List.rev rev

let b1 = nth "b1" blocks 0
let b2 = nth "b2" blocks 1
let b3 = nth "b3" blocks 2
let b4 = nth "b4" blocks 3
let b5 = nth "b5" blocks 4

let record_of what block =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "%s: %s" what (Record.error_to_string e))
    (Record.create ~consensus:block ~lookup)

let r1 = record_of "r1" b1
let r2 = record_of "r2" b2
let r3 = record_of "r3" b3
let r4 = record_of "r4" b4
let r5 = record_of "r5" b5
let number n = get "height" (Cb.Number.of_int n)

(* A block at the next expected height whose parent is not the tip. *)
let unlinked_block =
  Cb.create ~parent_hash:Cb.genesis_parent
    ~sub_dag:(synthetic_sub_dag ~author:(nth "author" ids 0) ~r:21 ())
    ~number:(number 2)

let unlinked = record_of "unlinked" unlinked_block

(* A different block at a height the store already holds. *)
let rival_block =
  Cb.create ~parent_hash:Cb.genesis_parent
    ~sub_dag:(synthetic_sub_dag ~author:(nth "author" ids 1) ~r:22 ())
    ~number:(number 1)

let rival = record_of "rival" rival_block

(* {1 The six observations} *)

let dhex d = Digests.Output_digest.to_hex d
let block_hex b = dhex (Cb.digest b)
let body_hex body = Digests.Batch_digest.to_hex (Batch.digest body)

let render_record r =
  Printf.sprintf "record %s at %s" (dhex (Record.digest r))
    (Cb.Number.to_string (Record.number r))

let render_run run =
  String.concat "|"
    [
      String.concat "," (List.map block_hex (Replay.blocks run));
      String.concat "," (List.map body_hex (Replay.bodies run));
      Cb.Number.to_string (Replay.upto run);
    ]

let asks = List.map number [ 0; 1; 2; 3; 4; 5; 6; 7 ]
let afters = None :: List.map Option.some [ b1; b2; b3; b4; b5 ]

(* The same six members the seam's conformance profile renders, in the same
   shape, so a disk store and a value store are comparable at all. *)
let profile store =
  [
    Printf.sprintf "cardinal %d" (Store.cardinal store);
    Printf.sprintf "expected_next %s"
      (Cb.Number.to_string (Store.expected_next store));
    Printf.sprintf "earliest %s"
      (Option.fold ~none:"none" ~some:Cb.Number.to_string (Store.earliest store));
    Printf.sprintf "latest %s"
      (Option.fold ~none:"none" ~some:render_record (Store.latest_received store));
  ]
  @ List.map
      (fun n ->
        Result.fold ~ok:render_record ~error:Store.miss_to_string
          (Store.record_at store n))
      asks
  @ List.map
      (fun after ->
        Result.fold ~ok:render_run ~error:Store.miss_to_string
          (Store.gap store ~after))
      afters

let epoch_facts store =
  [
    Units.Epoch.to_string (Store.epoch store);
    Cb.Number.to_string (Store.epoch_start store);
    dhex (Store.epoch_parent store);
  ]

(* {1 Roots, and the fold that fills one} *)

let root =
  Filename.concat (Filename.get_temp_dir_name ())
    (Printf.sprintf "tn-store-disk-%d" (Unix.getpid ()))

let expect_io ~what r =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "%s: %s" what (Io.error_to_string e))
    r

let dir_for case =
  let path = Filename.concat root case in
  let () =
    expect_io ~what:"prepare the case directory"
      (Io.mkdir_p ~ops:Io_ops.real ~path)
  in
  path

let log_of dir = Filename.concat dir "consensus.log"

let read_file path =
  expect_io ~what:"read the log back" (Io.read_whole ~ops:Io_ops.real ~path)

let put ~path ~content =
  expect_io ~what:"rewrite the log"
    (Io.with_file ~ops:Io_ops.real ~path ~mode:Io.Read_write_create (fun fd ->
         Result.bind (Io.write_all fd content) (fun () ->
             Io.ftruncate fd ~at:(String.length content))))

let opened what r =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "%s: %s" what (Disk.fault_to_string e))
    r

let open_fault what r =
  Result.fold
    ~ok:(fun ((_ : Disk.t), (_ : Disk.report)) ->
      Alcotest.failf "%s: expected a fault, the store opened" what)
    ~error:Fun.id r

let wrote what r =
  Result.fold ~ok:Fun.id
    ~error:(fun e ->
      Alcotest.failf "%s: %s" what (Disk.write_error_to_string e))
    r

let write_fault what r =
  Result.fold
    ~ok:(fun (_ : Disk.t) ->
      Alcotest.failf "%s: expected a refusal, the write succeeded" what)
    ~error:Fun.id r

let closed what r =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "%s: %s" what (Disk.fault_to_string e))
    r

let open_at ?ops ?(epoch = epoch0) ?(anchor = Cb.Number.genesis)
    ?(parent = Cb.genesis_parent) dir =
  Disk.open_ ?ops ~dir ~epoch ~anchor ~parent ()

(* {1 Arm names, exhaustive so a renamed arm is a build failure} *)

let refusal what = function
  | Disk.Refused cause -> cause
  | Disk.Fault f ->
      Alcotest.failf "%s: expected a refusal, got a fault: %s" what
        (Disk.fault_to_string f)

let fault_of what = function
  | Disk.Fault f -> f
  | Disk.Refused cause ->
      Alcotest.failf "%s: expected a fault, got a refusal: %s" what
        (Store.error_to_string cause)

let arm_of = function
  | Store.Not_next _ -> "not_next"
  | Store.Broken_chain _ -> "broken_chain"
  | Store.Conflicting_record _ -> "conflicting_record"
  | Store.Wrong_epoch _ -> "wrong_epoch"
  | Store.Epoch_not_advanced _ -> "epoch_not_advanced"

let fault_arm = function
  | Disk.Io _ -> "io"
  | Disk.Log _ -> "log"
  | Disk.Lock _ -> "lock"
  | Disk.Decode _ -> "decode"
  | Disk.Meta_disagrees _ -> "meta_disagrees"
  | Disk.Replayed_refusal _ -> "replayed_refusal"

let replayed_parts what = function
  | Disk.Replayed_refusal { at; seq; cause } -> (at, seq, cause)
  | ( Disk.Io _ | Disk.Log _ | Disk.Lock _ | Disk.Decode _
    | Disk.Meta_disagrees _ ) as f ->
      Alcotest.failf "%s: expected a replayed refusal, got %s" what
        (Disk.fault_to_string f)

let decode_parts what = function
  | Disk.Decode { at; seq; error } -> (at, seq, error)
  | ( Disk.Io _ | Disk.Log _ | Disk.Lock _ | Disk.Meta_disagrees _
    | Disk.Replayed_refusal _ ) as f ->
      Alcotest.failf "%s: expected a decode fault, got %s" what
        (Disk.fault_to_string f)

let disagreeing_field what = function
  | Disk.Meta_disagrees { field; _ } -> field
  | ( Disk.Io _ | Disk.Log _ | Disk.Lock _ | Disk.Decode _
    | Disk.Replayed_refusal _ ) as f ->
      Alcotest.failf "%s: expected a meta disagreement, got %s" what
        (Disk.fault_to_string f)

let log_error what = function
  | Disk.Log e -> e
  | ( Disk.Io _ | Disk.Lock _ | Disk.Decode _ | Disk.Meta_disagrees _
    | Disk.Replayed_refusal _ ) as f ->
      Alcotest.failf "%s: expected a log error, got %s" what
        (Disk.fault_to_string f)

let mismatched_field what = function
  | Append_log.Header_mismatch { field; _ } -> field
  | ( Append_log.Io _ | Append_log.Lock _ | Append_log.Corrupt _
    | Append_log.Bad_magic _ | Append_log.Bad_format _
    | Append_log.Bad_header_len _ | Append_log.Bad_payload_len _ ) as e ->
      Alcotest.failf "%s: expected a header mismatch, got %s" what
        (Append_log.error_to_string e)

let heal_to_string = function
  | Append_log.No_heal -> "no heal"
  | Append_log.Healed_tail { last_good; dropped } ->
      Printf.sprintf "healed to %d, dropped %d" last_good dropped

let durability_of (report : Disk.report) =
  match report.Disk.durability with `Fsync_no_fullsync -> "fsync, no fullsync"

(* {1 Filling a root} *)

let receive_all what store records =
  List.fold_left
    (fun s record -> wrote what (Disk.receive s record))
    store records

(* Four records, the roll, and one record above it: the shape every reopen case
   is checked against. *)
let fill store =
  let four = receive_all "fill the store" store [ r1; r2; r3; r4 ] in
  let rolled = wrote "roll to epoch 1" (Disk.open_epoch four ~epoch:epoch1) in
  wrote "the first record of epoch 1" (Disk.receive rolled r5)

let costs_nothing what store f =
  let bytes = Disk.bytes_appended store in
  let flushes = Disk.fsyncs store in
  let value = f () in
  let () =
    Alcotest.(check int)
      (what ^ ": it appended no bytes")
      bytes (Disk.bytes_appended store)
  in
  let () =
    Alcotest.(check int)
      (what ^ ": it spent no flushes")
      flushes (Disk.fsyncs store)
  in
  value

(* Re-frame a chosen payload list over the root's own 64-byte header. Every
   frame is produced by the real framer, so tags, echoes and sequence numbers
   are all correct and the only thing under test is the chain. *)
let respell dir payloads =
  let path = log_of dir in
  let header = sub_at (read_file path) ~off:0 ~len:64 in
  let framed =
    List.mapi
      (fun i (kind, payload) -> Frame.encode ~kind ~seq:i ~payload)
      payloads
  in
  put ~path ~content:(String.concat "" (header :: framed))

let record_frame r = (Frame.Record, Rc.encode_record r)
let frame_width payload = Frame.frame_size ~payload_len:(String.length payload)
let record_width r = frame_width (Rc.encode_record r)

(* The epoch facts the roll after [r4] really derives, so a case can state one
   fact wrongly and leave the rest right. *)
let true_meta =
  { Rc.Meta.epoch = epoch1; epoch_start = number 5; epoch_parent = Cb.digest b4 }

let rolled_log meta =
  List.map record_frame [ r1; r2; r3; r4 ]
  @ [ (Frame.Epoch_open, Rc.Meta.encode meta) ]
  @ [ record_frame r5 ]

(* {1 Open, create, adopt} *)

let test_open_creates_then_adopts () =
  let dir = dir_for "create" in
  let store, report = opened "create the root" (open_at dir) in
  let () =
    Alcotest.(check bool) "the first open created the log" true
      report.Disk.created
  in
  let () = Alcotest.(check int) "with no frames" 0 report.Disk.frames in
  let () =
    Alcotest.(check string) "and nothing to heal" "no heal"
      (heal_to_string report.Disk.heal)
  in
  let () =
    Alcotest.(check string) "the durability limit is a value, not a footnote"
      "fsync, no fullsync" (durability_of report)
  in
  let () =
    Alcotest.(check int) "a fresh handle has appended nothing" 0
      (Disk.bytes_appended store)
  in
  let () =
    Alcotest.(check int) "and spent no flushes of its own" 0 (Disk.fsyncs store)
  in
  let () =
    Alcotest.(check bool) "an empty store has no durable tip" true
      (Option.is_none (Disk.durable_tip store))
  in
  let () = closed "close the fresh root" (Disk.close store) in
  let again, report = opened "reopen the root" (open_at dir) in
  let () =
    Alcotest.(check bool) "the second open adopted rather than created" false
      report.Disk.created
  in
  let () = Alcotest.(check int) "and still found no frames" 0 report.Disk.frames in
  closed "close the adopted root" (Disk.close again)

let test_a_second_handle_is_refused () =
  let dir = dir_for "lock" in
  let store, _ = opened "take the root" (open_at dir) in
  let held = open_fault "a second handle" (open_at dir) in
  let () =
    Alcotest.(check string) "the second handle meets the lock" "lock"
      (fault_arm held)
  in
  closed "close the root" (Disk.close store)

(* {1 The reopen rung: what the disk holds is what the reader sees} *)

let test_reopen_renders_identically () =
  let dir = dir_for "reopen" in
  let store, _ = opened "open the root" (open_at dir) in
  let store = fill store in
  let before = profile (Disk.mirror store) in
  let facts_before = epoch_facts (Disk.mirror store) in
  let tip_before = Disk.durable_tip store in
  let () = closed "close after filling" (Disk.close store) in
  let again, report = opened "reopen after the roll" (open_at dir) in
  let () =
    Alcotest.(check int) "every frame written is durable" 6 report.Disk.frames
  in
  let () =
    Alcotest.(check string) "and none of them needed healing" "no heal"
      (heal_to_string report.Disk.heal)
  in
  let () =
    Alcotest.(check (list string))
      "the rebuilt mirror renders identically through all six observations"
      before
      (profile (Disk.mirror again))
  in
  let () =
    Alcotest.(check (list string))
      "and states the same epoch facts" facts_before
      (epoch_facts (Disk.mirror again))
  in
  let () =
    Alcotest.(check (option int))
      "the durable tip survives the restart"
      (Option.map Cb.Number.to_int tip_before)
      (Option.map Cb.Number.to_int (Disk.durable_tip again))
  in
  closed "close the reopened root" (Disk.close again)

(* The vacuity guard the agreement above rests on: six prefixes, six DIFFERENT
   renderings. Two stores agreeing through observations that cannot tell any two
   states apart is not evidence of anything. *)
let test_the_profile_tells_the_prefixes_apart () =
  let dir = dir_for "prefixes" in
  let store, _ = opened "open the root" (open_at dir) in
  let seen, store =
    List.fold_left
      (fun (acc, s) record ->
        let s = wrote "fill one step" (Disk.receive s record) in
        (profile (Disk.mirror s) :: acc, s))
      ([ profile (Disk.mirror store) ], store)
      [ r1; r2; r3; r4 ]
  in
  let rolled = wrote "roll to epoch 1" (Disk.open_epoch store ~epoch:epoch1) in
  let last = wrote "the record above the roll" (Disk.receive rolled r5) in
  let all = List.rev (profile (Disk.mirror last) :: seen) in
  let () =
    Alcotest.(check int) "six prefixes were rendered" 6 (List.length all)
  in
  let () =
    Alcotest.(check int) "and no two of them render alike" 6
      (List.length (List.sort_uniq compare all))
  in
  closed "close the root" (Disk.close last)

(* {1 D3: every refusal is free} *)

let filled_root case =
  let dir = dir_for case in
  let store, _ = opened "open the root" (open_at dir) in
  (dir, receive_all "fill the store" store [ r1 ])

let refusal_costs_nothing ~case ~what ~arm f =
  let _dir, store = filled_root case in
  let e =
    costs_nothing what store (fun () -> write_fault what (f store))
  in
  let () =
    Alcotest.(check string) (what ^ ": the arm it names") arm
      (arm_of (refusal what e))
  in
  closed "close the root" (Disk.close store)

let test_not_next_is_free () =
  refusal_costs_nothing ~case:"refuse-not-next"
    ~what:"a record past the next slot" ~arm:"not_next" (fun store ->
      Disk.receive store r3)

let test_broken_chain_is_free () =
  refusal_costs_nothing ~case:"refuse-broken-chain"
    ~what:"a record that does not link to the tip" ~arm:"broken_chain"
    (fun store -> Disk.receive store unlinked)

let test_conflicting_record_is_free () =
  refusal_costs_nothing ~case:"refuse-conflict"
    ~what:"a different block at a height already held" ~arm:"conflicting_record"
    (fun store -> Disk.receive store rival)

(* The record that is BOTH of the wrong epoch and past the next slot. The epoch
   guard runs first, so this is [wrong_epoch]; a store that checked the number
   first would call it [not_next] and hide the epoch violation behind a
   sequencing one. *)
let test_wrong_epoch_wins_over_not_next () =
  refusal_costs_nothing ~case:"refuse-wrong-epoch"
    ~what:"a record of the wrong epoch, also past the next slot"
    ~arm:"wrong_epoch" (fun store -> Disk.receive store r5)

let test_epoch_not_advanced_is_free () =
  refusal_costs_nothing ~case:"refuse-stale-roll"
    ~what:"a roll to the epoch already open" ~arm:"epoch_not_advanced"
    (fun store -> Disk.open_epoch store ~epoch:epoch0)

(* {1 D4: an idempotent re-file is free} *)

let test_a_re_file_costs_nothing () =
  let dir = dir_for "refile" in
  let store, _ = opened "open the root" (open_at dir) in
  let store = receive_all "fill the store" store [ r1; r2; r3 ] in
  let before = profile (Disk.mirror store) in
  let length_before = String.length (read_file (log_of dir)) in
  let again =
    costs_nothing "re-filing a record already durable" store (fun () ->
        wrote "re-file r2" (Disk.receive store r2))
  in
  let () =
    Alcotest.(check (list string))
      "the store is unchanged by a re-file" before
      (profile (Disk.mirror again))
  in
  let () =
    Alcotest.(check int) "and the file did not grow" length_before
      (String.length (read_file (log_of dir)))
  in
  let () = closed "close the root" (Disk.close again) in
  let reopened, report = opened "reopen after the re-file" (open_at dir) in
  let () =
    Alcotest.(check int) "the log still holds exactly three frames" 3
      report.Disk.frames
  in
  closed "close the reopened root" (Disk.close reopened)

(* {1 D5: exactly one flush per accepted write} *)

let test_each_acceptance_costs_one_flush () =
  let dir = dir_for "one-flush" in
  let store, _ = opened "open the root" (open_at dir) in
  let step what store expected_bytes f =
    let flushes = Disk.fsyncs store in
    let bytes = Disk.bytes_appended store in
    let next = wrote what (f store) in
    let () =
      Alcotest.(check int)
        (what ^ ": exactly one flush")
        (flushes + 1) (Disk.fsyncs next)
    in
    let () =
      Alcotest.(check int)
        (what ^ ": exactly one frame of bytes")
        (bytes + expected_bytes)
        (Disk.bytes_appended next)
    in
    next
  in
  let store =
    step "file r1" store (record_width r1) (fun s -> Disk.receive s r1)
  in
  let store =
    step "file r2" store (record_width r2) (fun s -> Disk.receive s r2)
  in
  let store =
    step "file r3" store (record_width r3) (fun s -> Disk.receive s r3)
  in
  let store =
    step "file r4" store (record_width r4) (fun s -> Disk.receive s r4)
  in
  let store =
    step "roll to epoch 1" store
      (frame_width (Rc.Meta.encode true_meta))
      (fun s -> Disk.open_epoch s ~epoch:epoch1)
  in
  let store =
    step "file r5" store (record_width r5) (fun s -> Disk.receive s r5)
  in
  let () =
    Alcotest.(check int) "six accepted writes, six flushes" 6 (Disk.fsyncs store)
  in
  closed "close the root" (Disk.close store)

(* {1 D2: the order of the calls, and what a failed flush leaves behind} *)

let test_one_receive_is_write_then_flush () =
  let dir = dir_for "ordering" in
  let seen = ref [] in
  let table = Durable_faults.traced ~sink:(fun line -> seen := line :: !seen) in
  let store, _ = opened "open the root through a traced table" (open_at ~ops:table dir) in
  let () = seen := [] in
  let store = wrote "file r1" (Disk.receive store r1) in
  let calls = List.map first_word (List.rev !seen) in
  let () =
    Alcotest.(check (list string))
      "one accepted receive is one positioned write and one flush"
      [ "lseek"; "write"; "fsync" ]
      calls
  in
  let () =
    Alcotest.(check (list string))
      "and the flush comes after the write, not before"
      [ "write"; "fsync" ]
      (List.filter
         (fun c -> String.equal c "write" || String.equal c "fsync")
         calls)
  in
  closed "close the root" (Disk.close store)

(* A device that REFUSES the flush. The bytes reached it, the flush did not
   return, and therefore nothing about the record is observable: the caller
   still holds the pre-call store. This is the case a mirror advanced before the
   flush returns would fail. The FILE is the witness that the write happened;
   the handle's own [bytes_appended] counts acknowledged appends only, so it
   stays at zero here - which is itself pinned. *)
let test_an_unflushed_record_is_not_observable () =
  let dir = dir_for "unflushed" in
  let store, _ = opened "create the root" (open_at dir) in
  let () = closed "close the fresh root" (Disk.close store) in
  let table =
    Durable_faults.fail_at ~nth:1 ~op:Io.Fsync ~code:Durable_faults.Absent
  in
  let store, _ =
    opened "reopen with a device that refuses the flush" (open_at ~ops:table dir)
  in
  let before = profile (Disk.mirror store) in
  let length_before = String.length (read_file (log_of dir)) in
  let e = write_fault "the flush is refused" (Disk.receive store r1) in
  let () =
    Alcotest.(check string) "the failure is a fault, not a chain refusal" "log"
      (fault_arm (fault_of "a refused flush" e))
  in
  let () =
    Alcotest.(check bool) "the bytes did reach the device" true
      (String.length (read_file (log_of dir)) > length_before)
  in
  let () =
    Alcotest.(check int) "and this handle acknowledges none of them" 0
      (Disk.bytes_appended store)
  in
  let () =
    Alcotest.(check (list string))
      "and yet nothing about the record is observable" before
      (profile (Disk.mirror store))
  in
  let () =
    Alcotest.(check bool) "the durable tip did not move" true
      (Option.is_none (Disk.durable_tip store))
  in
  closed "close the root" (Disk.close store)

(* The companion control, and the reason the case above is the ordering oracle
   rather than this one: a device that LIES about a flush returns success, so no
   counter and no value above the vtable can see it. What the suite can pin is
   the sequence of calls and the refusal path. *)
let test_a_lying_flush_is_invisible_above_the_vtable () =
  let dir = dir_for "lying-flush" in
  let store, _ = opened "create the root" (open_at dir) in
  let () = closed "close the fresh root" (Disk.close store) in
  let store, _ =
    opened "reopen over a device that lies"
      (open_at ~ops:(Durable_faults.skip_fsync_at ~nth:1) dir)
  in
  let store = wrote "file r1" (Disk.receive store r1) in
  let () =
    Alcotest.(check int) "the counter counts calls, not device behaviour" 1
      (Disk.fsyncs store)
  in
  let () =
    Alcotest.(check (option int)) "so the record is filed as far as this port can tell"
      (Some 1)
      (Option.map Cb.Number.to_int (Disk.durable_tip store))
  in
  closed "close the root" (Disk.close store)

(* {1 A2: a log that frames perfectly and still violates the chain} *)

let test_a_spliced_log_is_refused_with_the_stores_own_error () =
  let dir = dir_for "spliced-gap" in
  let store, _ = opened "create the root" (open_at dir) in
  let () = closed "close the fresh root" (Disk.close store) in
  let () = respell dir [ record_frame r1; record_frame r3 ] in
  let f = open_fault "a log with a height missing" (open_at dir) in
  let at, seq, cause = replayed_parts "the spliced log" f in
  let () =
    Alcotest.(check string) "the replay refuses with the store's own arm"
      "not_next" (arm_of cause)
  in
  let () = Alcotest.(check int) "at the second frame" 1 seq in
  let () =
    Alcotest.(check int) "and names its offset" (64 + record_width r1) at
  in
  Alcotest.(check bool) "the refusal renders" true
    (String.length (Disk.fault_to_string f) > 0)

let test_a_spliced_epoch_is_refused_with_the_stores_own_error () =
  let dir = dir_for "spliced-epoch" in
  let store, _ = opened "create the root" (open_at dir) in
  let () = closed "close the fresh root" (Disk.close store) in
  (* The epoch-1 record with no epoch-open frame in front of it. *)
  let () = respell dir [ record_frame r1; record_frame r5 ] in
  let f = open_fault "a log that rolled without saying so" (open_at dir) in
  let _at, seq, cause = replayed_parts "the spliced log" f in
  let () =
    Alcotest.(check string) "recovery applies the live epoch guard" "wrong_epoch"
      (arm_of cause)
  in
  Alcotest.(check int) "at the second frame" 1 seq

let test_an_undecodable_payload_is_named () =
  let dir = dir_for "bad-payload" in
  let store, _ = opened "create the root" (open_at dir) in
  let () = closed "close the fresh root" (Disk.close store) in
  let () = respell dir [ (Frame.Record, "not a record at all") ] in
  let f = open_fault "a frame carrying rubbish" (open_at dir) in
  let at, seq, error = decode_parts "the rubbish frame" f in
  let () = Alcotest.(check int) "the first frame" 0 seq in
  let () = Alcotest.(check int) "at the head of the file" 64 at in
  Alcotest.(check bool) "and the codec's own diagnosis is carried out" true
    (String.length (Rc.error_to_string error) > 0)

(* {1 A foreign root, one case per header field} *)

let foreign_root ~case ~field ~open_it =
  let dir = dir_for case in
  let store, _ = opened "create the root" (open_at dir) in
  let () = closed "close the fresh root" (Disk.close store) in
  let f = open_fault ("a root whose " ^ field ^ " differs") (open_it dir) in
  Alcotest.(check string)
    ("the refusal names " ^ field)
    field
    (mismatched_field field (log_error field f))

let test_a_foreign_epoch_is_refused () =
  foreign_root ~case:"foreign-epoch" ~field:"epoch0" ~open_it:(fun dir ->
      open_at ~epoch:epoch1 dir)

let test_a_foreign_anchor_is_refused () =
  foreign_root ~case:"foreign-anchor" ~field:"anchor0" ~open_it:(fun dir ->
      open_at ~anchor:(number 3) dir)

let test_a_foreign_parent_is_refused () =
  foreign_root ~case:"foreign-parent" ~field:"parent0" ~open_it:(fun dir ->
      open_at ~parent:(Cb.digest b1) dir)

(* {1 W6: the restart path} *)

let test_reopen_epoch_redoes_a_durable_roll () =
  let dir = dir_for "w6" in
  let store, _ = opened "open the root" (open_at dir) in
  let store = receive_all "fill the store" store [ r1; r2; r3; r4 ] in
  let store = wrote "roll to epoch 1" (Disk.open_epoch store ~epoch:epoch1) in
  let () = closed "the crash: close with the roll durable" (Disk.close store) in
  let store, report = opened "restart over the durable roll" (open_at dir) in
  let () =
    Alcotest.(check int) "the roll frame is durable" 5 report.Disk.frames
  in
  let before = profile (Disk.mirror store) in
  let facts = epoch_facts (Disk.mirror store) in
  let length_before = String.length (read_file (log_of dir)) in
  (* The [S]-faithful member refuses the redo, which is exactly why the restart
     path has a name of its own. *)
  let refused =
    costs_nothing "open_epoch on an epoch already open" store (fun () ->
        write_fault "the strict member" (Disk.open_epoch store ~epoch:epoch1))
  in
  let () =
    Alcotest.(check string) "and it refuses with the reference's own arm"
      "epoch_not_advanced"
      (arm_of (refusal "the strict member" refused))
  in
  let again =
    costs_nothing "reopen_epoch on the byte-identical meta" store (fun () ->
        wrote "the restart member" (Disk.reopen_epoch store ~epoch:epoch1))
  in
  let () =
    Alcotest.(check (list string))
      "the store is unchanged by the redo" before
      (profile (Disk.mirror again))
  in
  let () =
    Alcotest.(check (list string))
      "including its epoch facts" facts
      (epoch_facts (Disk.mirror again))
  in
  let () =
    Alcotest.(check int) "and the log did not grow" length_before
      (String.length (read_file (log_of dir)))
  in
  closed "close the restarted root" (Disk.close again)

let test_reopen_epoch_is_idempotent_within_one_handle () =
  let dir = dir_for "w6-live" in
  let store, _ = opened "open the root" (open_at dir) in
  let store = receive_all "fill the store" store [ r1; r2 ] in
  let store = wrote "roll to epoch 1" (Disk.open_epoch store ~epoch:epoch1) in
  let before = profile (Disk.mirror store) in
  let again =
    costs_nothing "reopen_epoch on the epoch just opened" store (fun () ->
        wrote "the restart member" (Disk.reopen_epoch store ~epoch:epoch1))
  in
  let () =
    Alcotest.(check (list string))
      "the store is unchanged" before
      (profile (Disk.mirror again))
  in
  closed "close the root" (Disk.close again)

(* [reopen_epoch] is idempotent about ONE epoch, the one already open. A
   different epoch is a real roll and costs a real frame; a stale one is refused
   exactly as [open_epoch] refuses it. *)
let test_reopen_epoch_is_not_a_blanket_yes () =
  let dir = dir_for "w6-different" in
  let store, _ = opened "open the root" (open_at dir) in
  let store = receive_all "fill the store" store [ r1; r2 ] in
  let store = wrote "roll to epoch 1" (Disk.open_epoch store ~epoch:epoch1) in
  let stale =
    costs_nothing "reopen_epoch at an epoch behind the open one" store
      (fun () ->
        write_fault "a stale redo" (Disk.reopen_epoch store ~epoch:epoch0))
  in
  let () =
    Alcotest.(check string) "a stale epoch is refused, not absorbed"
      "epoch_not_advanced"
      (arm_of (refusal "a stale redo" stale))
  in
  let flushes = Disk.fsyncs store in
  let bytes = Disk.bytes_appended store in
  let advanced =
    wrote "reopen_epoch at a NEW epoch" (Disk.reopen_epoch store ~epoch:epoch2)
  in
  let () =
    Alcotest.(check int) "a different epoch costs a real flush" (flushes + 1)
      (Disk.fsyncs advanced)
  in
  let () =
    Alcotest.(check int) "and a real frame"
      (bytes + frame_width (Rc.Meta.encode true_meta))
      (Disk.bytes_appended advanced)
  in
  let () =
    Alcotest.(check string) "and the store really is at the new epoch"
      (Units.Epoch.to_string epoch2)
      (Units.Epoch.to_string (Store.epoch (Disk.mirror advanced)))
  in
  closed "close the root" (Disk.close advanced)

(* {1 The epoch frame is a cross-check, never a source of truth} *)

let test_a_true_meta_replays_clean () =
  let dir = dir_for "meta-true" in
  let store, _ = opened "create the root" (open_at dir) in
  let () = closed "close the fresh root" (Disk.close store) in
  let () = respell dir (rolled_log true_meta) in
  let store, report = opened "replay the assembled log" (open_at dir) in
  let () = Alcotest.(check int) "all six frames replay" 6 report.Disk.frames in
  let () =
    Alcotest.(check int) "and every record is held" 5
      (Store.cardinal (Disk.mirror store))
  in
  let () =
    Alcotest.(check string) "with the roll applied"
      (Units.Epoch.to_string epoch1)
      (Units.Epoch.to_string (Store.epoch (Disk.mirror store)))
  in
  closed "close the root" (Disk.close store)

let meta_disagrees ~case ~field meta =
  let dir = dir_for case in
  let store, _ = opened "create the root" (open_at dir) in
  let () = closed "close the fresh root" (Disk.close store) in
  let () = respell dir (rolled_log meta) in
  let f = open_fault "a meta frame the tip does not agree with" (open_at dir) in
  let () =
    Alcotest.(check string) "the fault is a meta disagreement" "meta_disagrees"
      (fault_arm f)
  in
  Alcotest.(check string) "and it names the fact that differs" field
    (disagreeing_field field f)

let test_a_stated_epoch_start_is_cross_checked () =
  meta_disagrees ~case:"meta-start" ~field:"epoch_start"
    { true_meta with Rc.Meta.epoch_start = number 9 }

let test_a_stated_epoch_parent_is_cross_checked () =
  meta_disagrees ~case:"meta-parent" ~field:"epoch_parent"
    { true_meta with Rc.Meta.epoch_parent = Cb.digest b1 }

(* A stated epoch has no tip-derived counterpart: it is the frame's own claim,
   and the reference's strict-advance guard is what adjudicates it. A frame that
   claims an epoch the roll cannot reach is therefore a replayed refusal, not a
   disagreement, and it is still refused. *)
let test_a_stated_epoch_is_adjudicated_by_the_strict_guard () =
  let dir = dir_for "meta-epoch" in
  let store, _ = opened "create the root" (open_at dir) in
  let () = closed "close the fresh root" (Disk.close store) in
  let () = respell dir (rolled_log { true_meta with Rc.Meta.epoch = epoch0 }) in
  let f = open_fault "a roll to the epoch already open" (open_at dir) in
  let _at, seq, cause = replayed_parts "a roll that does not advance" f in
  let () =
    Alcotest.(check string) "the reference's own arm" "epoch_not_advanced"
      (arm_of cause)
  in
  Alcotest.(check int) "at the fifth frame" 4 seq

(* {1 A torn tail} *)

let test_a_torn_tail_is_healed_and_reported () =
  let dir = dir_for "torn" in
  let store, _ = opened "open the root" (open_at dir) in
  let store = receive_all "fill the store" store [ r1; r2 ] in
  let () = closed "close before the tear" (Disk.close store) in
  let path = log_of dir in
  let whole = read_file path in
  let () =
    put ~path ~content:(sub_at whole ~off:0 ~len:(String.length whole - 10))
  in
  let store, report = opened "reopen over the tear" (open_at dir) in
  let () =
    Alcotest.(check string) "the tear is cut back and reported"
      (Printf.sprintf "healed to %d, dropped %d" (64 + record_width r1)
         (record_width r2 - 10))
      (heal_to_string report.Disk.heal)
  in
  let () =
    Alcotest.(check int) "only the whole frame is durable" 1 report.Disk.frames
  in
  let () =
    Alcotest.(check (option int)) "and the tip is the record below the tear"
      (Some 1)
      (Option.map Cb.Number.to_int (Disk.durable_tip store))
  in
  (* The caller re-files, and the store takes it: healing is not data loss the
     shell has to work around, it is the tail coming back. *)
  let store = wrote "re-file the torn record" (Disk.receive store r2) in
  let () =
    Alcotest.(check (option int)) "the tip advances again" (Some 2)
      (Option.map Cb.Number.to_int (Disk.durable_tip store))
  in
  closed "close the healed root" (Disk.close store)

(* The counters derive from the handle's OWN log. Flushes and writes by any
   other [Tn_durable] user in this process - here a raw file beside the root -
   never inflate them; a process-wide tally fails both zero checks. The
   accepted receive then moves them by exactly its own frame. *)
let test_counters_are_this_handles_alone () =
  let dir = dir_for "handle-local-counters" in
  let store, _ = opened "create the root" (open_at dir) in
  let noise = Filename.concat dir "noise" in
  let () =
    expect_io ~what:"foreign io beside the root"
      (Io.with_file ~ops:Io_ops.real ~path:noise ~mode:Io.Read_write_create
         (fun fd ->
           Result.bind (Io.write_all fd "not a frame") (fun () -> Io.fsync fd)))
  in
  let () =
    Alcotest.(check int) "a foreign flush is not this handle's" 0
      (Disk.fsyncs store)
  in
  let () =
    Alcotest.(check int) "nor are its bytes" 0 (Disk.bytes_appended store)
  in
  let store = wrote "file r1" (Disk.receive store r1) in
  let () =
    Alcotest.(check int) "an accepted receive costs exactly one" 1
      (Disk.fsyncs store)
  in
  let () =
    Alcotest.(check int) "and appends exactly its frame"
      (frame_width (Rc.encode_record r1))
      (Disk.bytes_appended store)
  in
  closed "close the root" (Disk.close store)

let () =
  Alcotest.run "durable store"
    [
      ( "opening a root",
        [
          Alcotest.test_case "the first open creates, the next adopts" `Quick
            test_open_creates_then_adopts;
          Alcotest.test_case "a second handle is refused" `Quick
            test_a_second_handle_is_refused;
          Alcotest.test_case "a torn tail is healed and reported" `Quick
            test_a_torn_tail_is_healed_and_reported;
        ] );
      ( "close and reopen",
        [
          Alcotest.test_case "the rebuilt mirror renders identically" `Quick
            test_reopen_renders_identically;
          Alcotest.test_case "the profile tells every prefix apart" `Quick
            test_the_profile_tells_the_prefixes_apart;
        ] );
      ( "a refusal is free",
        [
          Alcotest.test_case "a record past the next slot" `Quick
            test_not_next_is_free;
          Alcotest.test_case "a record that does not link to the tip" `Quick
            test_broken_chain_is_free;
          Alcotest.test_case "a different block at a held height" `Quick
            test_conflicting_record_is_free;
          Alcotest.test_case "the epoch guard runs before the number guard"
            `Quick test_wrong_epoch_wins_over_not_next;
          Alcotest.test_case "a roll that does not advance" `Quick
            test_epoch_not_advanced_is_free;
          Alcotest.test_case "an idempotent re-file costs nothing" `Quick
            test_a_re_file_costs_nothing;
        ] );
      ( "one flush per accepted write",
        [
          Alcotest.test_case "every acceptance costs exactly one" `Quick
            test_each_acceptance_costs_one_flush;
          Alcotest.test_case "and it is one write then one flush" `Quick
            test_one_receive_is_write_then_flush;
          Alcotest.test_case "a refused flush publishes nothing" `Quick
            test_an_unflushed_record_is_not_observable;
          Alcotest.test_case "a lying flush is invisible above the vtable"
            `Quick test_a_lying_flush_is_invisible_above_the_vtable;
          Alcotest.test_case "the counters are this handle's alone" `Quick
            test_counters_are_this_handles_alone;
        ] );
      ( "recovery refuses what the live path would refuse",
        [
          Alcotest.test_case "a spliced log with a height missing" `Quick
            test_a_spliced_log_is_refused_with_the_stores_own_error;
          Alcotest.test_case "a roll that was never written down" `Quick
            test_a_spliced_epoch_is_refused_with_the_stores_own_error;
          Alcotest.test_case "an undecodable payload names its offset" `Quick
            test_an_undecodable_payload_is_named;
        ] );
      ( "a foreign root",
        [
          Alcotest.test_case "a different epoch" `Quick
            test_a_foreign_epoch_is_refused;
          Alcotest.test_case "a different anchor" `Quick
            test_a_foreign_anchor_is_refused;
          Alcotest.test_case "a different parent" `Quick
            test_a_foreign_parent_is_refused;
        ] );
      ( "the restart path",
        [
          Alcotest.test_case "reopen_epoch redoes a durable roll for free"
            `Quick test_reopen_epoch_redoes_a_durable_roll;
          Alcotest.test_case "and does so within one handle too" `Quick
            test_reopen_epoch_is_idempotent_within_one_handle;
          Alcotest.test_case "but it is not a blanket yes" `Quick
            test_reopen_epoch_is_not_a_blanket_yes;
        ] );
      ( "the epoch frame is a cross-check",
        [
          Alcotest.test_case "a true meta replays clean" `Quick
            test_a_true_meta_replays_clean;
          Alcotest.test_case "a stated start the tip does not derive" `Quick
            test_a_stated_epoch_start_is_cross_checked;
          Alcotest.test_case "a stated parent the tip does not derive" `Quick
            test_a_stated_epoch_parent_is_cross_checked;
          Alcotest.test_case "a stated epoch meets the strict guard" `Quick
            test_a_stated_epoch_is_adjudicated_by_the_strict_guard;
        ] );
    ]
