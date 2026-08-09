(* Chunk-40 stage S5: the disk store as a THIRD instance of the durable seam.

   [test/assoc_store.ml] showed that [Consensus_store.S] is satisfiable by
   something other than the reference. This file goes one step further: the same
   questions are answered from bytes on a filesystem, and - the rung no pure
   store can offer - from bytes RE-READ after the handle that wrote them was
   closed. A profile that survives a close and an open was rebuilt by the scan,
   not remembered in RAM, and no in-memory implementation can fake that.

   Why [t] is a result. [S.create] is total and [S.error] has exactly five
   protocol arms, so a disk backend cannot honestly ascribe [S] in production:
   an operating-system fault has no arm to report itself through. Making [t] a
   result HERE keeps [create] total, needs no exception, and leaves the
   production surface ([Tn_durable_store.Consensus_store_disk]) strictly larger
   and strictly honest. The price is that a fault would otherwise be invisible
   to a profile - every read member would quietly answer a poisoned value - so
   {!Make.fault} and {!Make.render_error} exist to be read BEFORE any comparison
   is made. A differential that compares first and diagnoses later would score a
   dead instance as agreement.

   No virtual library: three implementations have to coexist in one executable,
   which a virtual library forbids ([consensus_store.mli:284-287]). Concrete
   module, explicit ascription, exactly the [assoc_store.ml] idiom. *)

open Tn_types
open Tn_execution
module Disk = Tn_durable_store.Consensus_store_disk

(** What one instance needs from its harness: somewhere to live, and a table of
    system calls to live through. *)
module type ROOTS = sig
  val fresh_root : unit -> string
  (** A directory that already EXISTS, holds no store, and that no other live
      handle owns. Called exactly once per [create]. The single-writer register
      inside [Tn_durable.Store_lock] is per PROCESS, so two live instances on
      one root is [Lock Held] rather than a race - which is why every instance
      gets its own. *)

  val ops : unit -> Tn_durable.Io_ops.t
  (** The system-call table one instance opens through, built afresh per call
      because a fault table counts its own calls. [Io_ops.real] for the
      conformance instances; a fault-injecting table for the negative control
      that proves a dead instance cannot pass as agreement. *)
end

(** The adapter. [t] is deliberately transparent, so a harness can close a
    handle, read its {!Disk.origin} and sweep its root without a second
    member. *)
module Make (R : ROOTS) : sig
  include Consensus_store.S with type t = (Disk.t, Disk.fault) result

  val fault : t -> Disk.fault option
  (** The fault a dead instance is holding, if it is holding one. *)

  val render_error : t -> string
  (** The fault PRE-RENDERED: [""] when the instance is live, and the fault's
      own one-line rendering otherwise. A caller therefore never needs a second
      error type to report an instance that never opened, and an empty
      rendering means exactly one thing. *)

  val reopen : t -> t
  (** Close the handle and open the SAME root again, with the same chain
      identity ({!Disk.origin}) and a fresh table from {!ROOTS.ops}. The rung no
      pure store can offer: what comes back was rebuilt by the replay scan over
      durable bytes, so a store that agreed only because it was remembered in
      memory stops agreeing here. A dead instance stays dead. *)
end = struct
  type t = (Disk.t, Disk.fault) result

  (* Re-exported rather than restated: [Disk.Refused] already carries the
     reference's own error, so an adapter with five arms of its own would have
     to convert between two spellings of one taxonomy and could get the
     conversion wrong in exactly the direction a differential cannot see. *)
  type error = Consensus_store.error =
    | Not_next of {
        expected : Consensus_block.Number.t;
        got : Consensus_block.Number.t;
      }
    | Broken_chain of {
        expected : Digests.Output_digest.t;
        got : Digests.Output_digest.t;
      }
    | Conflicting_record of {
        number : Consensus_block.Number.t;
        stored : Digests.Output_digest.t;
        offered : Digests.Output_digest.t;
      }
    | Wrong_epoch of { open_epoch : Units.Epoch.t; offered : Units.Epoch.t }
    | Epoch_not_advanced of {
        open_epoch : Units.Epoch.t;
        proposed : Units.Epoch.t;
      }

  let error_to_string = Consensus_store.error_to_string
  let fault t = Result.fold ~ok:(fun (_ : Disk.t) -> None) ~error:Option.some t

  let render_error t =
    Result.fold ~ok:(fun (_ : Disk.t) -> "") ~error:Disk.fault_to_string t

  (* Every read member is the reference's own, applied to the mirror, with one
     value for the dead case. [cardinal]'s dead value is negative on purpose:
     no live store can answer it, so a poisoned instance shows up as a
     DISAGREEMENT in the profile even when nobody read [fault] first. That is a
     second line of defence, never the first one. *)
  let read ~dead f t =
    Result.fold
      ~ok:(fun d -> f (Disk.mirror d))
      ~error:(fun (_ : Disk.fault) -> dead)
      t

  let create ~epoch ~anchor ~parent =
    Result.map fst
      (Disk.open_ ~ops:(R.ops ()) ~dir:(R.fresh_root ()) ~epoch ~anchor ~parent
         ())

  (* A device failure is not a protocol refusal and must not be dressed as one:
     none of the five arms can honestly say "the flush did not return". So a
     write that meets a fault POISONS the instance and answers [Ok], and the
     fault check above the profile is what turns that into a failure. A refusal
     is passed through verbatim, which is what keeps the write side of the
     differential exact. *)
  let write f t =
    Result.fold
      ~ok:(fun d ->
        Result.fold
          ~ok:(fun advanced -> Ok (Ok advanced))
          ~error:(fun e ->
            match e with
            | Disk.Refused refusal -> Error refusal
            | Disk.Fault met -> Ok (Error met))
          (f d))
      ~error:(fun (_ : Disk.fault) -> Ok t)
      t

  let receive t record = write (fun d -> Disk.receive d record) t
  let open_epoch t ~epoch = write (fun d -> Disk.open_epoch d ~epoch) t

  let reopen t =
    Result.bind t (fun d ->
        let o = Disk.origin d in
        Result.bind (Disk.close d) (fun () ->
            Result.map fst
              (Disk.open_ ~ops:(R.ops ()) ~dir:o.Disk.dir ~epoch:o.Disk.epoch
                 ~anchor:o.Disk.anchor ~parent:o.Disk.parent ())))

  let epoch t = read ~dead:Units.Epoch.zero Consensus_store.epoch t

  let epoch_start t =
    read ~dead:Consensus_block.Number.genesis Consensus_store.epoch_start t

  let epoch_parent t =
    read ~dead:Consensus_block.genesis_parent Consensus_store.epoch_parent t

  let expected_next t =
    read ~dead:Consensus_block.Number.genesis Consensus_store.expected_next t

  let earliest t = read ~dead:None Consensus_store.earliest t
  let latest_received t = read ~dead:None Consensus_store.latest_received t
  let cardinal t = read ~dead:(-1) Consensus_store.cardinal t

  let record_at t number =
    read
      ~dead:(Error (Consensus_store.Broken (Replay.Hole { number })))
      (fun s -> Consensus_store.record_at s number)
      t

  let record_by_digest t digest =
    read ~dead:None (fun s -> Consensus_store.record_by_digest s digest) t

  let gap t ~after =
    read
      ~dead:
        (Error
           (Consensus_store.Broken
              (Replay.Hole { number = Consensus_block.Number.genesis })))
      (fun s -> Consensus_store.gap s ~after)
      t
end
