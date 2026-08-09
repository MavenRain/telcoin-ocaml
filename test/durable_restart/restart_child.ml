(* Chunk-40 stage S7: the process that dies.

   Every other crash test in this chunk models a kill with a fault table and
   keeps running. That is enough to settle what the bytes are, and it is not
   enough to settle what a RESTART is, because the process that wrote them is
   still alive and still holding a mirror, a driver and a lock. This program
   exists to remove that process. It runs the shell protocol - mint, file the
   record, execute, publish the checkpoint (OS-F20) - against a real root, and
   at the window named on its command line it leaves through [Unix._exit].
   Not [exit]: [exit] runs [at_exit], which flushes, and a kill that flushes is
   not a kill. Nothing above this line ever gets a chance to tidy up.

   Two windows in the ten are reachable only by making a system call fail in
   the middle, so those runs open the store through one of
   {!Durable_faults}'s tables and leave the instant the call returns its
   error. The failure is real: the table provokes a genuine [ENOENT] or a
   genuine short write, never a synthesised one. Where the injection is
   supposed to fire and does not, the child leaves with {!injection_missed}
   instead of with the window's own code, so a table that has stopped biting
   reads as a distinct failure rather than as a green row.

   Command line: [restart_child <window|control> <root> [bytes]]. The exit
   code names the window, so the parent knows the kill landed where it asked
   for it and not somewhere else. *)

module F = Restart_fixtures
module Cb = Tn_execution.Consensus_block
module Store = Tn_execution.Consensus_store
module Driver = Tn_driver.Driver
module Outcome = Tn_driver.Outcome
module Io = Tn_durable.Io
module Io_ops = Tn_durable.Io_ops
module Disk = Tn_durable_store.Consensus_store_disk
module Ckpt = Tn_durable_checkpoint.Checkpoint_file
module Units = Tn_types.Units

(* {1 The ten windows} *)

(* Exactly the ten rows of the design's crash matrix, one constructor each.
   The list is closed on purpose: a window that is not one of these is not a
   process-kill window, it is an adversarial on-disk state, and those are the
   parent's business because a crash cannot produce them. *)
type window =
  | W1_before_write
      (** After the in-RAM validation, before the first write system call. *)
  | W2_mid_write of { bytes : int }
      (** Inside [write_all]: [bytes] of the frame reached the device. *)
  | W3_after_write_before_fsync
      (** The write returned and the flush did not. *)
  | W4_after_fsync_before_ack
      (** The flush returned and the caller never saw the [Ok]. *)
  | W5_epoch_frame_before_fsync
      (** Inside [open_epoch], with the epoch-open frame not yet on the
          device. *)
  | W6_epoch_durable_before_snapshot
      (** The epoch-open frame is durable and the checkpoint beside it is
          still sealed at the previous epoch. *)
  | W7_record_durable_before_snapshot
      (** The designed gap: the record is durable, the snapshot is owed. *)
  | W8_checkpoint_temp  (** Inside the checkpoint write, before the rename. *)
  | W9_after_rename_before_dirsync
      (** The rename returned and the directory flush did not. *)
  | W10_mid_heal  (** Inside the open-time heal of a torn tail. *)

let window_of_name ~bytes name =
  match name with
  | "w1" -> Some W1_before_write
  | "w2" -> Some (W2_mid_write { bytes })
  | "w3" -> Some W3_after_write_before_fsync
  | "w4" -> Some W4_after_fsync_before_ack
  | "w5" -> Some W5_epoch_frame_before_fsync
  | "w6" -> Some W6_epoch_durable_before_snapshot
  | "w7" -> Some W7_record_durable_before_snapshot
  | "w8" -> Some W8_checkpoint_temp
  | "w9" -> Some W9_after_rename_before_dirsync
  | "w10" -> Some W10_mid_heal
  | _ -> None

(* {1 Leaving} *)

(* The exit codes the parent reads. Eleven to twenty are the windows, in
   order; everything at or above eighty means the child did not reach its
   window, which is a failure of the harness rather than a crash. *)
let unexpected_open = 80
let unexpected_receive = 81
let unexpected_drive = 82
let unexpected_publish = 83
let unexpected_close = 84
let injection_missed = 85
let unknown_window = 86
let bad_usage = 87

(* The default torn prefix: long enough to be a real partial frame, far too
   short to be a whole one. *)
let torn_prefix = 40

let leave ~code ~why =
  let () = Printf.eprintf "child: %s\n%!" why in
  Unix._exit code

(* {1 The shell, totalised} *)

let open_store ~ops ~dir ~code =
  Result.fold ~ok:fst
    ~error:(fun f -> leave ~code ~why:("open: " ^ Disk.fault_to_string f))
    (Disk.open_ ~ops ~dir ~epoch:Units.Epoch.zero ~anchor:Cb.Number.genesis
       ~parent:Cb.genesis_parent ())

let close_store store =
  Result.fold ~ok:Fun.id
    ~error:(fun f -> leave ~code:unexpected_close ~why:("close: " ^ Disk.fault_to_string f))
    (Disk.close store)

let mint driver sd =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> leave ~code:unexpected_drive ~why:("mint: " ^ Outcome.error_to_string e))
    (Driver.mint driver sd)

let record_of block =
  Result.fold ~ok:Fun.id
    ~error:(fun e ->
      leave ~code:unexpected_drive ~why:("record: " ^ Store.Record.error_to_string e))
    (Store.Record.create ~consensus:block ~lookup:F.lookup)

let step driver sd =
  Result.fold ~ok:fst
    ~error:(fun e -> leave ~code:unexpected_drive ~why:("step: " ^ Outcome.error_to_string e))
    (Driver.step driver sd ~bodies:F.bodies ~address_of:F.address_of)

let publish ~ops ~dir ~store driver =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> leave ~code:unexpected_publish ~why:("publish: " ^ Ckpt.error_to_string e))
    (Ckpt.save ~ops ~dir ~store (Driver.snapshot driver))

(* One whole turn of the protocol OS-F20 names, with nothing injected: mint
   the block, file its record durably, execute it, publish the checkpoint. *)
let clean_turn ~dir (store, driver) sd =
  let block = mint driver sd in
  let record = record_of block in
  let store =
    Result.fold ~ok:Fun.id
      ~error:(fun e ->
        leave ~code:unexpected_receive ~why:("receive: " ^ Disk.write_error_to_string e))
      (Disk.receive store record)
  in
  let driver = step driver sd in
  let (_ : int) = publish ~ops:Io_ops.real ~dir ~store driver in
  (store, driver)

(* Phase A: the clean prefix every run shares. It ends with the store CLOSED,
   so the turn the child dies in opens its own handle and a fault table's call
   counter starts at the turn rather than at the beginning of the run. *)
let phase_a ~dir ~spec ~sds =
  let store = open_store ~ops:Io_ops.real ~dir ~code:unexpected_open in
  let driver = Driver.create spec ~committee:F.committee in
  let store, driver = List.fold_left (clean_turn ~dir) (store, driver) sds in
  let () = close_store store in
  (store, driver)

(* {1 The record family} *)

(* Where a record-family run leaves. [Never] is the control: the same code
   path with every kill removed, which is what makes a row's verdict a
   verdict about the KILL rather than about the protocol. *)
type leave_at =
  | Before_receive
  | On_receive
  | After_receive
  | After_step
  | On_save
  | Never

let run_records_prefix ~dir =
  let (_ : Disk.t), (_ : Driver.t) =
    phase_a ~dir ~spec:(Lazy.force F.wide_spec) ~sds:F.record_sub_dags_a
  in
  Unix._exit 0

let run_records ~dir ~ops ~save_ops ~leave_at ~code =
  let (_ : Disk.t), driver =
    phase_a ~dir ~spec:(Lazy.force F.wide_spec) ~sds:F.record_sub_dags_a
  in
  let store = open_store ~ops ~dir ~code:unexpected_open in
  let sd = F.record_sub_dag_b in
  let block = mint driver sd in
  let record = record_of block in
  let () =
    match leave_at with
    | Before_receive -> leave ~code ~why:"W1: killed before the first write system call"
    | On_receive | After_receive | After_step | On_save | Never -> ()
  in
  let store =
    Result.fold
      ~ok:(fun s ->
        match leave_at with
        | On_receive -> leave ~code:injection_missed ~why:"the append fault did not fire"
        | Before_receive | After_receive | After_step | On_save | Never -> s)
      ~error:(fun e ->
        match leave_at with
        | On_receive ->
            leave ~code ~why:("killed inside the append: " ^ Disk.write_error_to_string e)
        | Before_receive | After_receive | After_step | On_save | Never ->
            leave ~code:unexpected_receive ~why:("receive: " ^ Disk.write_error_to_string e))
      (Disk.receive store record)
  in
  let () =
    match leave_at with
    | After_receive ->
        leave ~code ~why:"W4: killed after the flush returned, before the caller saw Ok"
    | Before_receive | On_receive | After_step | On_save | Never -> ()
  in
  let driver = step driver sd in
  let () =
    match leave_at with
    | After_step ->
        leave ~code ~why:"W7: killed after the record was durable, before the snapshot"
    | Before_receive | On_receive | After_receive | On_save | Never -> ()
  in
  let (_ : int) =
    Result.fold
      ~ok:(fun g ->
        match leave_at with
        | On_save -> leave ~code:injection_missed ~why:"the publish fault did not fire"
        | Before_receive | On_receive | After_receive | After_step | Never -> g)
      ~error:(fun e ->
        match leave_at with
        | On_save -> leave ~code ~why:("killed inside the publish: " ^ Ckpt.error_to_string e)
        | Before_receive | On_receive | After_receive | After_step | Never ->
            leave ~code:unexpected_publish ~why:("publish: " ^ Ckpt.error_to_string e))
      (Ckpt.save ~ops:save_ops ~dir ~store (Driver.snapshot driver))
  in
  let () = close_store store in
  Unix._exit 0

(* W10 is two kills over one tear, which is why it does not fit the table
   above: the short write leaves a torn tail, the handle goes away, and the
   NEXT open - the one that would heal it - dies inside the heal. What
   survives is the tear, untouched, which is the input the parent's three
   consecutive opens are a statement about. *)
let run_tear ~dir ~ops ~heal_ops ~code =
  let (_ : Disk.t), driver =
    phase_a ~dir ~spec:(Lazy.force F.wide_spec) ~sds:F.record_sub_dags_a
  in
  let torn = open_store ~ops ~dir ~code:unexpected_open in
  let block = mint driver F.record_sub_dag_b in
  let record = record_of block in
  let torn =
    Result.fold
      ~ok:(fun (_ : Disk.t) ->
        leave ~code:injection_missed ~why:"the torn write did not fire")
      ~error:(fun (_ : Disk.write_error) -> torn)
      (Disk.receive torn record)
  in
  let () = close_store torn in
  Result.fold
    ~ok:(fun ((_ : Disk.t), (_ : Disk.report)) ->
      leave ~code:injection_missed ~why:"the heal fault did not fire")
    ~error:(fun f -> leave ~code ~why:("W10: killed inside the heal: " ^ Disk.fault_to_string f))
    (Disk.open_ ~ops:heal_ops ~dir ~epoch:Units.Epoch.zero ~anchor:Cb.Number.genesis
       ~parent:Cb.genesis_parent ())

(* {1 The epoch family} *)

(* The handoff is two durable writes with no transaction around them: the
   store rolls first ([open_epoch]), the handed-off driver's checkpoint is
   republished second. W5 and W6 are the two sides of the first write. *)
let run_epoch_prefix ~dir =
  let (_ : Disk.t), (_ : Driver.t) =
    phase_a ~dir ~spec:(Lazy.force F.short_spec) ~sds:F.epoch_sub_dags
  in
  Unix._exit 0

let run_epoch_roll ~dir ~ops ~handoff ~code =
  let (_ : Disk.t), driver =
    phase_a ~dir ~spec:(Lazy.force F.short_spec) ~sds:F.epoch_sub_dags
  in
  let store = open_store ~ops ~dir ~code:unexpected_open in
  let store =
    Result.fold
      ~ok:(fun s ->
        match handoff with
        | true -> s
        | false -> leave ~code:injection_missed ~why:"the epoch-roll fault did not fire")
      ~error:(fun e ->
        match handoff with
        | true ->
            leave ~code:unexpected_receive ~why:("open_epoch: " ^ Disk.write_error_to_string e)
        | false ->
            leave ~code ~why:("killed inside the epoch roll: " ^ Disk.write_error_to_string e))
      (Disk.open_epoch store ~epoch:F.epoch1)
  in
  let driver =
    Result.fold ~ok:Fun.id
      ~error:(fun e ->
        leave ~code:unexpected_drive ~why:("begin_epoch: " ^ Driver.handoff_error_to_string e))
      (Driver.begin_epoch driver ~committee:F.committee_next)
  in
  let (_ : int) = publish ~ops:Io_ops.real ~dir ~store driver in
  let () = close_store store in
  Unix._exit 0

(* {1 Dispatch} *)

let run_window ~dir w =
  match w with
  | W1_before_write ->
      run_records ~dir ~ops:Io_ops.real ~save_ops:Io_ops.real ~leave_at:Before_receive ~code:11
  | W2_mid_write { bytes } ->
      run_records ~dir
        ~ops:(Durable_faults.short_write_at ~nth:1 ~bytes)
        ~save_ops:Io_ops.real ~leave_at:On_receive ~code:12
  | W3_after_write_before_fsync ->
      run_records ~dir
        ~ops:(Durable_faults.fail_at ~nth:1 ~op:Io.Fsync ~code:Durable_faults.Absent)
        ~save_ops:Io_ops.real ~leave_at:On_receive ~code:13
  | W4_after_fsync_before_ack ->
      run_records ~dir ~ops:Io_ops.real ~save_ops:Io_ops.real ~leave_at:After_receive ~code:14
  | W5_epoch_frame_before_fsync ->
      run_epoch_roll ~dir
        ~ops:(Durable_faults.short_write_at ~nth:1 ~bytes:0)
        ~handoff:false ~code:15
  | W6_epoch_durable_before_snapshot ->
      run_epoch_roll ~dir
        ~ops:(Durable_faults.fail_at ~nth:1 ~op:Io.Fsync ~code:Durable_faults.Absent)
        ~handoff:false ~code:16
  | W7_record_durable_before_snapshot ->
      run_records ~dir ~ops:Io_ops.real ~save_ops:Io_ops.real ~leave_at:After_step ~code:17
  | W8_checkpoint_temp ->
      run_records ~dir ~ops:Io_ops.real
        ~save_ops:(Durable_faults.short_write_at ~nth:1 ~bytes:16)
        ~leave_at:On_save ~code:18
  | W9_after_rename_before_dirsync ->
      run_records ~dir ~ops:Io_ops.real
        ~save_ops:(Durable_faults.fail_at ~nth:2 ~op:Io.Fsync ~code:Durable_faults.Absent)
        ~leave_at:On_save ~code:19
  | W10_mid_heal ->
      run_tear ~dir
        ~ops:(Durable_faults.short_write_at ~nth:1 ~bytes:torn_prefix)
        ~heal_ops:(Durable_faults.fail_at ~nth:1 ~op:Io.Ftruncate ~code:Durable_faults.Absent)
        ~code:20

let run ~name ~dir ~bytes =
  match name with
  | "control3" -> run_records_prefix ~dir
  | "control4" ->
      run_records ~dir ~ops:Io_ops.real ~save_ops:Io_ops.real ~leave_at:Never ~code:0
  | "epoch-sealed" -> run_epoch_prefix ~dir
  | "epoch-handoff" -> run_epoch_roll ~dir ~ops:Io_ops.real ~handoff:true ~code:0
  | other ->
      Result.fold
        ~ok:(fun w -> run_window ~dir w)
        ~error:(fun why -> leave ~code:unknown_window ~why)
        (Option.to_result
           ~none:("unknown window: " ^ other)
           (window_of_name ~bytes other))

let () =
  match Array.to_list Sys.argv with
  | _ :: name :: dir :: rest ->
      run ~name ~dir
        ~bytes:
          (Option.value ~default:torn_prefix
             (Option.bind (List.nth_opt rest 0) int_of_string_opt))
  | [] | [ _ ] | [ _; _ ] ->
      leave ~code:bad_usage ~why:"usage: restart_child <window|control> <root> [bytes]"
