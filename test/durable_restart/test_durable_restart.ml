(* Chunk-40 stage S7: restart, end to end, under real kills.

   Every earlier suite in this chunk asks what the bytes are. This one asks
   the only question a durable store exists to answer: after the process that
   was writing is GONE, does the node that starts next hold the same chain?

   The shape of the answer is one differential, run ten times. A child
   process runs the shell protocol - mint, file the record durably, execute,
   publish the checkpoint (OS-F20) - against a real root and leaves through
   [Unix._exit] inside one named crash window, so no [at_exit] runs, no buffer
   is flushed on the way out and no mirror survives. This parent then opens
   the root it left, loads the checkpoint, and rebuilds the driver through
   [Driver.resume]. The row passes when the rebuilt chain is the chain a run
   that never crashed would hold - the same records, the same forwarded
   height, the same world, anchor, BLOCKHASH window, reward counters and
   phase, folded to one digest.

   Three disciplines run through the file.

   Convergence is stated over a CONTROL that really ran: the same child, the
   same fixtures, the same number of turns, with the kill removed. Nothing
   here is compared against a hand-written expectation of what the chain
   ought to be.

   No row may pass vacuously (graft 9). Every row also names a control it
   must DIFFER from - the observation without the injection - and the whole
   observation, heal report included, is compared. A fault table that has
   stopped biting turns a row red at that assertion rather than leaving it
   green for the wrong reason. The child helps: where an injection is
   supposed to fire and does not, it leaves with exit code 85 instead of the
   window's own code, and every row checks the code.

   The root is the suite's own: one fresh directory per case under the
   process's temporary directory, named by the running pid, so two copies of
   this test under a parallel [dune] never meet. Nothing here reads the
   working directory - the child is resolved beside [Sys.executable_name],
   which [(deps restart_child.exe)] puts in the same build directory. Roots
   are PRINTED, and Alcotest shows a case's own output only when the case
   fails, so a red row leaves its evidence behind and a green one is
   silent. *)

module F = Restart_fixtures
module Cb = Tn_execution.Consensus_block
module Store = Tn_execution.Consensus_store
module Replay = Tn_execution.Replay
module Driver = Tn_driver.Driver
module Checkpoint = Tn_driver.Checkpoint
module Outcome = Tn_driver.Outcome
module Io = Tn_durable.Io
module Io_ops = Tn_durable.Io_ops
module Append_log = Tn_durable.Append_log
module Disk = Tn_durable_store.Consensus_store_disk
module Ckpt = Tn_durable_checkpoint.Checkpoint_file
module Units = Tn_types.Units

(* {1 Roots} *)

let io_ok what r =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "%s: %s" what (Io.error_to_string e))
    r

let run_root =
  Filename.concat (Filename.get_temp_dir_name ()) (Printf.sprintf "tn-restart-%d" (Unix.getpid ()))

(* The FILESYSTEM is the register of roots already minted, the idiom
   test_consensus_store.ml settled on: a name is free when nothing is at it,
   and the directory is created before the name is handed out, so nothing
   mutable has to survive between calls. *)
let rec free_root_name base n =
  let path = Printf.sprintf "%s-%d" base n in
  match io_ok "look for a free restart root" (Io.exists ~ops:Io_ops.real ~path) with
  | true -> free_root_name base (Stdlib.succ n)
  | false -> path

let fresh_root label =
  let path = free_root_name (Filename.concat run_root label) 0 in
  let () = io_ok "create a restart root" (Io.mkdir_p ~ops:Io_ops.real ~path) in
  let () = Printf.printf "  restart root: %s\n" path in
  path

(* {1 The child} *)

let child_exe = Filename.concat (Filename.dirname Sys.executable_name) "restart_child.exe"

let child_log root =
  Result.fold ~ok:Fun.id
    ~error:(fun (_ : Io.error) -> "(the child left no log)")
    (Io.read_whole ~ops:Io_ops.real ~path:(Filename.concat root F.child_log_name))

(* Spawn, wait, and answer the exit code. A child that dies to a SIGNAL is a
   different event from a child that leaves through [Unix._exit] at its
   window, and it is reported as one rather than folded into a number. *)
let spawn ~root ~args =
  let log = Filename.concat root F.child_log_name in
  let fd = Unix.openfile log [ Unix.O_WRONLY; Unix.O_CREAT; Unix.O_TRUNC ] 0o644 in
  let pid =
    Unix.create_process child_exe (Array.of_list (child_exe :: args)) Unix.stdin fd fd
  in
  let (_ : int), status = Unix.waitpid [] pid in
  let () = Unix.close fd in
  let () = Printf.printf "  child %s\n%s" (String.concat " " args) (child_log root) in
  match status with
  | Unix.WEXITED code -> code
  | Unix.WSIGNALED signal ->
      Alcotest.failf "the child died to signal %d, which is not a window" signal
  | Unix.WSTOPPED signal -> Alcotest.failf "the child stopped on signal %d" signal

(* A run that is supposed to reach its window and leave with the window's own
   code. Anything else - a clean exit, an unexpected fault, code 85 for an
   injection that did not fire - fails the row here rather than later. *)
let crashed label ~name ~extra ~code =
  let root = fresh_root label in
  let seen = spawn ~root ~args:(name :: root :: extra) in
  let () =
    Alcotest.(check int) (label ^ ": the child left at its own window, and nowhere else") code seen
  in
  root

let controlled label name =
  let root = fresh_root label in
  let seen = spawn ~root ~args:[ name; root ] in
  let () = Alcotest.(check int) (label ^ ": the control child ran to the end") 0 seen in
  root

(* {1 Recovery} *)

let wide = lazy (Lazy.force F.wide_spec)
let short = lazy (Lazy.force F.short_spec)

let render_heal h =
  match h with
  | Append_log.No_heal -> "clean"
  | Append_log.Healed_tail { last_good; dropped } ->
      Printf.sprintf "healed at %d dropping %d" last_good dropped

let miss_name m =
  match m with
  | Store.Below_retained { earliest = _; asked = _ } -> "below retained"
  | Store.Above_tip { expected_next = _; asked = _ } -> "above tip"
  | Store.Forked { number = _; stored = _; offered = _ } -> "forked"
  | Store.Broken b -> "broken: " ^ Replay.break_to_string b

let resume_refusal e =
  match e with
  | Driver.Committee_epoch { supplied = _; checkpoint = _ } -> "committee epoch"
  | Driver.Committee_mismatch { epoch = _ } -> "committee mismatch"
  | Driver.Store_epoch { checkpoint = _; store = _ } -> "store epoch"
  | Driver.Gap m -> "gap: " ^ miss_name m

let open_root root =
  Result.fold ~ok:Fun.id
    ~error:(fun f -> Alcotest.failf "open %s: %s" root (Disk.fault_to_string f))
    (Disk.open_ ~ops:Io_ops.real ~dir:root ~epoch:Units.Epoch.zero ~anchor:Cb.Number.genesis
       ~parent:Cb.genesis_parent ())

let close_root store =
  Result.fold ~ok:Fun.id
    ~error:(fun f -> Alcotest.failf "close: %s" (Disk.fault_to_string f))
    (Disk.close store)

let loaded_at root =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "load %s: %s" root (Ckpt.error_to_string e))
    (Ckpt.load ~dir:root ())

let published_at root =
  match loaded_at root with
  | Ckpt.Absent -> Alcotest.failf "%s: no checkpoint was ever published there" root
  | Ckpt.Loaded { checkpoint; generation } -> (checkpoint, generation)

(* The committee is the CALLER's at every installation site, resume included,
   so it is an argument here too: a root the epoch handoff carried through
   both of its writes is resumed under the epoch-1 committee, and every other
   root under the epoch-0 one. Hard-wiring one of them would make the epoch
   family's control unresumable and would hide the very check
   ([Committee_epoch]) that keeps a persisted committee a witness rather than
   a source. *)
let resumed_at ~spec ~committee ~checkpoint ~mirror =
  Driver.resume spec ~committee ~checkpoint ~store:mirror ~address_of:F.address_of

(* Everything a restart can be observed to have produced, in one value. The
   fields are the crash matrix's own columns: what the open had to repair,
   what the log holds, which epoch the store is open at, what the checkpoint
   says, how far the replay had to reach, and the chain that came out. *)
type observed = {
  heal : string;
  frames : int;
  store_epoch : string;
  durable_tip : string;
  temp : bool;
  checkpoint : string;
  gap : int;
  upto : string;
  outcome : string;
  chain : string;
}

let render_observed o =
  String.concat " "
    [
      "heal=" ^ o.heal;
      "frames=" ^ string_of_int o.frames;
      "epoch=" ^ o.store_epoch;
      "tip=" ^ o.durable_tip;
      "temp=" ^ string_of_bool o.temp;
      "checkpoint=" ^ o.checkpoint;
      "gap=" ^ string_of_int o.gap;
      "upto=" ^ o.upto;
      "outcome=" ^ o.outcome;
      "chain=" ^ o.chain;
    ]

(* THE recovery: open the root the child left, read the checkpoint, collect
   the gap between the two durable values, and rebuild the driver through the
   fold live callers use. The store comes back OPEN, because two rows have
   something more to do with it before it goes away. *)
let recover ~spec ~committee root =
  (* Asked BEFORE the open, because the open sweeps a stale temp itself. *)
  let temp =
    io_ok "look for a stale temp"
      (Io.exists ~ops:Io_ops.real ~path:(Filename.concat root F.checkpoint_temp_name))
  in
  let store, report = open_root root in
  let checkpoint, generation = published_at root in
  let mirror = Disk.mirror store in
  let gap =
    Result.fold ~ok:Fun.id
      ~error:(fun m -> Alcotest.failf "collect the gap: %s" (Store.miss_to_string m))
      (Store.gap mirror ~after:(Checkpoint.last_executed checkpoint))
  in
  let resumed =
    Result.fold ~ok:Fun.id
      ~error:(fun e -> Alcotest.failf "resume: %s" (resume_refusal e))
      (resumed_at ~spec ~committee ~checkpoint ~mirror)
  in
  let driver =
    match resumed with
    | Outcome.Advance { driver; advances = _ } -> driver
    | Outcome.Sealed { driver; advances = _; rest = _ } -> driver
    | Outcome.Halted { advances; error } ->
        Alcotest.failf "resume halted after %d outputs: %s" (List.length advances)
          (Outcome.error_to_string error)
  in
  (* OS-F23, on the arm the design states it over. *)
  let () =
    match resumed with
    | Outcome.Advance { driver = d; advances = _ } ->
        Alcotest.(check string) "OS-F23: last_forwarded is Replay.upto of the collected gap"
          (Cb.Number.to_string (Replay.upto gap))
          (Cb.Number.to_string (Driver.last_forwarded d))
    | Outcome.Sealed { driver = _; advances = _; rest = _ }
    | Outcome.Halted { advances = _; error = _ } ->
        ()
  in
  let observed =
    {
      heal = render_heal report.Disk.heal;
      frames = report.Disk.frames;
      store_epoch = Units.Epoch.to_string (Store.epoch mirror);
      durable_tip =
        Option.fold ~none:"none" ~some:Cb.Number.to_string (Disk.durable_tip store);
      temp;
      checkpoint =
        Printf.sprintf "gen %d at %s" generation
          (Cb.Number.to_string (Checkpoint.watermark checkpoint));
      gap = Replay.length gap;
      upto = Cb.Number.to_string (Replay.upto gap);
      outcome = F.render_outcome resumed;
      chain = F.render_chain ~mirror ~driver;
    }
  in
  (observed, store)

let observe ~spec ~committee root =
  let observed, store = recover ~spec ~committee root in
  let () = close_root store in
  observed

(* {1 The controls} *)

(* Four runs with nothing injected, each forced at most once per process.
   [control3] and [control4] are the record family at three and at four
   turns; [epoch_sealed] stops with the epoch closed and the handoff owed,
   and [epoch_handoff] carries the handoff through both of its durable
   writes. *)
let control3 = lazy (controlled "control3" "control3")
let control4 = lazy (controlled "control4" "control4")
let epoch_sealed = lazy (controlled "epoch-sealed" "epoch-sealed")
let epoch_handoff = lazy (controlled "epoch-handoff" "epoch-handoff")
let control3_obs =
  lazy (observe ~spec:(Lazy.force wide) ~committee:F.committee (Lazy.force control3))

let control4_obs =
  lazy (observe ~spec:(Lazy.force wide) ~committee:F.committee (Lazy.force control4))

let epoch_sealed_obs =
  lazy (observe ~spec:(Lazy.force short) ~committee:F.committee (Lazy.force epoch_sealed))

(* The handoff control is the ONE root resumed under the epoch-1 committee:
   both of its durable writes landed, so its checkpoint is the handed-off
   driver's and its epoch is the next one. *)
let epoch_handoff_obs =
  lazy (observe ~spec:(Lazy.force short) ~committee:F.committee_next (Lazy.force epoch_handoff))

let converges label o control =
  Alcotest.(check string)
    (label ^ ": the resumed chain is the no-crash control's chain, digest for digest")
    control.chain o.chain

let differs label o control =
  Alcotest.(check bool)
    (label ^ ": the same row WITHOUT the injection reaches a different verdict")
    false
    (String.equal (render_observed o) (render_observed control))

(* Agreement is only evidence when disagreement was possible. The four
   controls are four genuinely different chains, so a row that matches one of
   them matched something a rendering can tell apart - the same guard
   test_consensus_store.ml's conformance profile puts in front of its own
   agreements (OS-T14). Were [render_chain] to collapse (a dropped world, a
   constant digest) this case goes red first, and every [converges] in the
   file is downgraded to a claim about nothing until it does. *)
let controls_are_distinct () =
  let chains =
    List.map
      (fun control -> (Lazy.force control).chain)
      [ control3_obs; control4_obs; epoch_sealed_obs; epoch_handoff_obs ]
  in
  Alcotest.(check int)
    "the four no-crash controls are four pairwise distinct chains" 4
    (List.length (List.sort_uniq String.compare chains))

(* {1 Shared assertions} *)

(* D4, and the reason W3's whole-frame outcome is SOUND: the caller never saw
   the [Ok], so it re-files the identical record, and the store answers plain
   success having written nothing at all. *)
let refile_is_free label store =
  let record =
    Result.fold ~ok:Fun.id
      ~error:(fun why -> Alcotest.failf "%s: %s" label why)
      (Option.to_result ~none:"the store holds no record to re-file"
         (Store.latest_received (Disk.mirror store)))
  in
  let refiled =
    Result.fold ~ok:Fun.id
      ~error:(fun e ->
        Alcotest.failf "%s: the re-file was refused: %s" label (Disk.write_error_to_string e))
      (Disk.receive store record)
  in
  let () =
    Alcotest.(check int) (label ^ ": the idempotent re-file appends no bytes") 0
      (Disk.bytes_appended refiled)
  in
  Alcotest.(check int) (label ^ ": the idempotent re-file costs no flushes") 0
    (Disk.fsyncs refiled)

(* An epoch roll rendered to a string, so "it went through" and "it was
   refused, and this is why" are one comparison rather than two shapes. *)
let roll_outcome r =
  Result.fold ~ok:(fun (_ : Disk.t) -> "accepted") ~error:Disk.write_error_to_string r

(* {1 The ten rows} *)

(* W1 - killed after the in-RAM validation and before the first write system
   call. The log is byte-identical to the pre-call store, so there is nothing
   to heal, nothing to replay and no special case anywhere. *)
let w1 () =
  let root = crashed "w1" ~name:"w1" ~extra:[] ~code:11 in
  let o = observe ~spec:(Lazy.force wide) ~committee:F.committee root in
  let () = Alcotest.(check string) "W1: the scan is clean" "clean" o.heal in
  let () = Alcotest.(check int) "W1: the log holds exactly the pre-call frames" 3 o.frames in
  let () = Alcotest.(check string) "W1: the checkpoint is the pre-call one" "gen 3 at 3" o.checkpoint in
  let () = Alcotest.(check int) "W1: there is nothing to replay" 0 o.gap in
  let () = converges "W1" o (Lazy.force control3_obs) in
  differs "W1" o (Lazy.force control4_obs)

(* W2 - killed inside [write_all], with a prefix of the frame on the device.
   No reader ever saw it, because the mirror never advanced; the open finds a
   torn tail, truncates to the last good frame and REPORTS it. *)
let w2 () =
  let root = crashed "w2" ~name:"w2" ~extra:[ "40" ] ~code:12 in
  let o = observe ~spec:(Lazy.force wide) ~committee:F.committee root in
  let () =
    Alcotest.(check bool) "W2: the open healed a torn tail" true
      (String.starts_with ~prefix:"healed at " o.heal)
  in
  let () =
    Alcotest.(check bool) "W2: exactly the forty bytes that reached the device were dropped" true
      (String.ends_with ~suffix:"dropping 40" o.heal)
  in
  let () = Alcotest.(check int) "W2: only whole frames survive" 3 o.frames in
  let () = Alcotest.(check int) "W2: there is nothing to replay" 0 o.gap in
  let () = converges "W2" o (Lazy.force control3_obs) in
  differs "W2" o (Lazy.force control4_obs)

(* W3 - killed after the write returned and before the flush did. On a
   machine that keeps running, the whole frame is on the device, and KEEPING
   it is sound only because the validation ran against the mirror before the
   first byte was written. The caller never got its [Ok], so the shell
   re-files, and the re-file is free. *)
let w3 () =
  let root = crashed "w3" ~name:"w3" ~extra:[] ~code:13 in
  let o, store = recover ~spec:(Lazy.force wide) ~committee:F.committee root in
  let () = Alcotest.(check string) "W3: a whole frame is not a torn one" "clean" o.heal in
  let () = Alcotest.(check int) "W3: the frame the caller never saw acknowledged is there" 4 o.frames in
  let () = Alcotest.(check string) "W3: the checkpoint still names the previous block" "gen 3 at 3" o.checkpoint in
  let () = Alcotest.(check int) "W3: exactly one block is replayed" 1 o.gap in
  let () = refile_is_free "W3" store in
  let () = close_root store in
  let () = converges "W3" o (Lazy.force control4_obs) in
  differs "W3" o (Lazy.force control4_obs)

(* W4 - killed after the flush returned and before the caller observed the
   [Ok]. The record is durable and the caller believes it is not. Reopen
   adopts it and the shell's re-file of the identical record is a no-op:
   divergence-free. *)
let w4 () =
  let root = crashed "w4" ~name:"w4" ~extra:[] ~code:14 in
  let o, store = recover ~spec:(Lazy.force wide) ~committee:F.committee root in
  let () = Alcotest.(check string) "W4: nothing to heal" "clean" o.heal in
  let () = Alcotest.(check int) "W4: the reopen adopts the durable record" 4 o.frames in
  let () = Alcotest.(check int) "W4: exactly one block is replayed" 1 o.gap in
  let () = Alcotest.(check string) "W4: the replay reaches the store's own tip" "4" o.upto in
  let () = refile_is_free "W4" store in
  let () = close_root store in
  let () = converges "W4" o (Lazy.force control4_obs) in
  differs "W4" o (Lazy.force control4_obs)

(* W5 - killed inside [open_epoch] with the epoch-open frame not yet written.
   The store reopens at the old epoch beside a checkpoint sealed at the old
   epoch: the two durable values agree, and the shell's own epoch opening
   re-runs, strictly advancing and hazard-free. *)
let w5 () =
  let root = crashed "w5" ~name:"w5" ~extra:[] ~code:15 in
  let o, store = recover ~spec:(Lazy.force short) ~committee:F.committee root in
  let () = Alcotest.(check string) "W5: the roll left no frame behind" "clean" o.heal in
  let () = Alcotest.(check int) "W5: only the three record frames are durable" 3 o.frames in
  let () = Alcotest.(check string) "W5: the store is still open at the old epoch" "0" o.store_epoch in
  let () =
    Alcotest.(check string) "W5: the handoff is owed, with nothing to replay"
      "sealed replaying 0 with 0 unconsumed" o.outcome
  in
  let rolled = Disk.open_epoch store ~epoch:F.epoch1 in
  let () = Alcotest.(check string) "W5: the shell's own epoch opening re-runs" "accepted" (roll_outcome rolled) in
  let () =
    Result.fold
      ~ok:(fun s ->
        Alcotest.(check int) "W5: the redone roll is a real, flushed append" 1 (Disk.fsyncs s))
      ~error:(fun (_ : Disk.write_error) -> ())
      rolled
  in
  let () = close_root store in
  let () = converges "W5" o (Lazy.force epoch_sealed_obs) in
  differs "W5" o (Lazy.force epoch_handoff_obs)

(* W6 - killed after the epoch-open frame became durable and before the
   checkpoint beside it was republished. This is the one skew [Driver.resume]
   heals: a sealed checkpoint at N against a store open at N+1 with an empty
   gap. The shell re-runs its handoff, and the redo goes through
   [reopen_epoch], which is why that name exists: [open_epoch] would refuse a
   roll it has already made. *)
let w6 () =
  let root = crashed "w6" ~name:"w6" ~extra:[] ~code:16 in
  let o, store = recover ~spec:(Lazy.force short) ~committee:F.committee root in
  let () = Alcotest.(check string) "W6: a complete meta frame is not a torn one" "clean" o.heal in
  let () = Alcotest.(check int) "W6: the epoch-open frame is durable beside the records" 4 o.frames in
  let () = Alcotest.(check string) "W6: the store is open at the NEW epoch" "1" o.store_epoch in
  let () = Alcotest.(check string) "W6: the checkpoint is still the sealed one" "gen 3 at 3" o.checkpoint in
  let () =
    Alcotest.(check string) "W6: resume heals the skew and asks for the handoff"
      "sealed replaying 0 with 0 unconsumed" o.outcome
  in
  let () =
    Alcotest.(check bool) "W6: a strictly advancing open_epoch REFUSES the roll it already made"
      false
      (String.equal "accepted" (roll_outcome (Disk.open_epoch store ~epoch:F.epoch1)))
  in
  let redone = Disk.reopen_epoch store ~epoch:F.epoch1 in
  let () = Alcotest.(check string) "W6: the restart path redoes the roll" "accepted" (roll_outcome redone) in
  let () =
    Result.fold
      ~ok:(fun s ->
        let () = Alcotest.(check int) "W6: the redo writes nothing" 0 (Disk.bytes_appended s) in
        Alcotest.(check int) "W6: the redo costs no flush" 0 (Disk.fsyncs s))
      ~error:(fun (_ : Disk.write_error) -> ())
      redone
  in
  let () = close_root store in
  let () = converges "W6" o (Lazy.force epoch_sealed_obs) in
  differs "W6" o (Lazy.force epoch_sealed_obs)

(* W7 - the designed gap. The record is durable, execution has happened and
   left no durable trace, and the snapshot is owed. Nothing is lost and
   nothing is doubly executed: resume collects the gap above the checkpoint,
   re-executes it through the same fold live callers use, and lands on the
   control's chain. *)
let w7 () =
  let root = crashed "w7" ~name:"w7" ~extra:[] ~code:17 in
  let o = observe ~spec:(Lazy.force wide) ~committee:F.committee root in
  let () = Alcotest.(check int) "W7: the store tip is above the checkpoint" 4 o.frames in
  let () = Alcotest.(check string) "W7: the checkpoint is one block behind" "gen 3 at 3" o.checkpoint in
  let () = Alcotest.(check int) "W7: exactly the designed gap is replayed" 1 o.gap in
  let () = Alcotest.(check string) "W7: and it is replayed to the store's own tip" "4" o.upto in
  let () = Alcotest.(check string) "W7: replay then go live" "advance replaying 1" o.outcome in
  let () = converges "W7" o (Lazy.force control4_obs) in
  differs "W7" o (Lazy.force control4_obs)

(* W8 - killed inside the checkpoint write, before the rename. A garbage
   [checkpoint.tmp] is on disk and the canonical name is untouched. The
   reader sweeps the temp before it reads anything, so the older checkpoint
   is what loads, and an older checkpoint means only a longer gap. *)
let w8 () =
  let root = crashed "w8" ~name:"w8" ~extra:[] ~code:18 in
  let o, store = recover ~spec:(Lazy.force wide) ~committee:F.committee root in
  let () = Alcotest.(check bool) "W8: a partial temp really was left behind" true o.temp in
  let () = Alcotest.(check string) "W8: the canonical checkpoint is untouched" "gen 3 at 3" o.checkpoint in
  let () = Alcotest.(check int) "W8: the record above it is durable" 4 o.frames in
  let () = Alcotest.(check int) "W8: the longer gap is replayed" 1 o.gap in
  let () = close_root store in
  let () =
    Alcotest.(check bool) "W8: and the temp was swept, never adopted" false
      (io_ok "look for the temp"
         (Io.exists ~ops:Io_ops.real ~path:(Filename.concat root F.checkpoint_temp_name)))
  in
  let () = converges "W8" o (Lazy.force control4_obs) in
  differs "W8" o (Lazy.force control4_obs)

(* W9 - killed after [rename_over] returned and before the directory flush.
   The rename is atomic, so the name binds one COMPLETE checkpoint either
   way. The row's two controls are both needed: the four-turn control says
   the checkpoint that landed is whole and at the new generation, and the
   three-turn control says the publish really did land, which is what makes
   the row about the kill rather than about nothing. *)
let w9 () =
  let root = crashed "w9" ~name:"w9" ~extra:[] ~code:19 in
  let o = observe ~spec:(Lazy.force wide) ~committee:F.committee root in
  let () = Alcotest.(check string) "W9: the new checkpoint is published, whole" "gen 4 at 4" o.checkpoint in
  let () = Alcotest.(check string) "W9: the watermark is at the durable tip, never above it" "4" o.durable_tip in
  let () = Alcotest.(check int) "W9: with nothing left to replay" 0 o.gap in
  let () = converges "W9" o (Lazy.force control4_obs) in
  differs "W9" o (Lazy.force control3_obs)

(* W10 - killed inside the heal itself, so the tear is still there. The heal
   is a pure function of the bytes and is therefore idempotent: three
   consecutive opens over one injected tear give [Healed_tail], then [Clean],
   then [Clean]. *)
let w10 () =
  let root = crashed "w10" ~name:"w10" ~extra:[] ~code:20 in
  let heals =
    List.map
      (fun (_ : int) ->
        let store, report = open_root root in
        let heal = render_heal report.Disk.heal in
        let () = close_root store in
        heal)
      [ 1; 2; 3 ]
  in
  let () =
    Alcotest.(check bool) "W10: the first open of three heals the tear" true
      (String.starts_with ~prefix:"healed at "
         (Option.value ~default:"(no open)" (List.nth_opt heals 0)))
  in
  let () =
    Alcotest.(check (list string)) "W10: and the two after it find nothing left to do"
      [ "clean"; "clean" ]
      (List.filteri (fun i (_ : string) -> i > 0) heals)
  in
  let o = observe ~spec:(Lazy.force wide) ~committee:F.committee root in
  let () = Alcotest.(check int) "W10: only whole frames survive" 3 o.frames in
  let () = converges "W10" o (Lazy.force control3_obs) in
  differs "W10" o (Lazy.force control4_obs)

(* {1 The adversarial state a crash cannot produce} *)

(* A3 - a checkpoint whose watermark is above the store's durable tip.
   [Checkpoint_file.save] refuses to CREATE this state, so reaching it means
   real corruption or a spliced root, and the answer must be a loud refusal
   rather than a quietly shortened replay. The pair is built out of two
   controls that really ran: the four-turn checkpoint against the three-turn
   store. Its positive control is the same store under its OWN checkpoint,
   which resumes. *)
let a3 () =
  let store3 = Lazy.force control3 in
  let store4 = Lazy.force control4 in
  let ahead, (_ : int) = published_at store4 in
  let matched, (_ : int) = published_at store3 in
  let store, (_ : Disk.report) = open_root store3 in
  let mirror = Disk.mirror store in
  let verdict checkpoint =
    Result.fold
      ~ok:(fun o -> "resumed: " ^ F.render_outcome o)
      ~error:resume_refusal
      (resumed_at ~spec:(Lazy.force wide) ~committee:F.committee ~checkpoint ~mirror)
  in
  let refused = verdict ahead in
  let allowed = verdict matched in
  let () = close_root store in
  let () =
    Alcotest.(check string) "A3: a checkpoint above the tip is refused, loudly" "gap: above tip"
      refused
  in
  Alcotest.(check string) "A3: the same store under its own checkpoint resumes"
    "resumed: advance replaying 0" allowed

(* {1 The table} *)

let rows =
  [
    ("W1: killed before the first write", w1);
    ("W2: killed mid-write, a torn tail", w2);
    ("W3: killed after the write, before the flush", w3);
    ("W4: killed after the flush, before the acknowledgement", w4);
    ("W5: killed inside the epoch roll, before the flush", w5);
    ("W6: the epoch roll durable, the checkpoint not republished", w6);
    ("W7: the record durable, the snapshot owed", w7);
    ("W8: killed inside the checkpoint write", w8);
    ("W9: killed after the rename, before the directory flush", w9);
    ("W10: killed inside the heal", w10);
  ]

let table_is_the_matrix () =
  Alcotest.(check int) "the parent's table has exactly the matrix's ten rows" 10 (List.length rows)

let () =
  Alcotest.run "durable restart"
    [
      ( "the crash matrix, under real process kills",
        Alcotest.test_case "the table is the matrix" `Quick table_is_the_matrix
        :: Alcotest.test_case "the controls are pairwise distinct" `Quick controls_are_distinct
        :: List.map (fun (name, case) -> Alcotest.test_case name `Quick case) rows );
      ( "adversarial states a crash cannot produce",
        [ Alcotest.test_case "A3: a checkpoint above the durable tip" `Quick a3 ] );
    ]
