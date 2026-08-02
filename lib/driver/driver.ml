module Cb = Tn_execution.Consensus_block
module Engine = Tn_engine.Engine
module Units = Tn_types.Units

(* Running or sealed: the driver's own record of the epoch phase, carrying
   the one fact the engine does not expose - the commit timestamp of the
   output whose execution sealed the epoch, which is what the next boundary
   is anchored to (H9). *)
type phase = Running | Sealed of { closed_at : Units.Timestamp.t }

type t = {
  spec : Chain_spec.t;
  subscriber : Subscriber.t;
  engine : Engine.t;
  last_forwarded : Cb.Number.t;
  phase : phase;
}

type handoff_error =
  | Not_sealed
  | Committee_epoch of { installed : Units.Epoch.t; proposed : Units.Epoch.t }
  | Engine_refused of Engine.error

let handoff_error_to_string = function
  | Not_sealed ->
      "epoch handoff refused: the epoch is still running, so no closing \
       block has rooted the leader counts begin_epoch would clear"
  | Committee_epoch { installed; proposed } ->
      Printf.sprintf
        "epoch handoff refused: proposed committee epoch %s does not advance \
         past the installed epoch %s"
        (Units.Epoch.to_string proposed)
        (Units.Epoch.to_string installed)
  | Engine_refused e ->
      "epoch handoff refused by the engine: " ^ Engine.error_to_string e

let create spec ~committee =
  {
    spec;
    subscriber = Subscriber.create Tn_execution.Consensus_chain.genesis;
    engine = Engine.create (Chain_spec.engine_config spec ~committee);
    last_forwarded = Cb.Number.genesis;
    phase = Running;
  }

(* H9/D3: the next boundary is anchored to the closing output's commit
   timestamp - which IS the closing block's own timestamp
   ([tn-reth/src/payload.rs:93-106]) - never to the previous boundary and
   never to a clock ([tn-reth/src/lib.rs:1832-1836], [run_epoch.rs:140-145]).
   A closing commit that overshoots the old boundary carries the overshoot
   into the next epoch's length rather than silently shortening it. *)
let boundary_after t closed_at =
  Units.Timestamp.add_secs closed_at
    (Chain_spec.Epoch_duration.to_secs (Chain_spec.epoch_duration t.spec))

(* Mint-and-attach, execute, and only then advance the watermark: the
   receive error and the execute error both return the error ALONE, so the
   pre-step driver is the only driver a failing caller ever holds. Guard
   order: a sealed driver refuses up front, before minting anything (the
   handoff is owed first, and the engine is never consulted just to repeat
   the refusal); then the output's leader epoch must BE the installed
   committee's epoch (H8's InvalidPackEpoch, [storage/src/consensus.rs:
   732-765]) - also before minting, so a refused output consumes no
   consensus number. *)
let step t sub_dag ~bodies ~address_of =
  match t.phase with
  | Sealed _ -> Error Outcome.Sealed_needs_handoff
  | Running ->
      let installed = Tn_types.Committee.epoch (Engine.committee t.engine) in
      let output_epoch = Tn_consensus.Sub_dag.leader_epoch sub_dag in
      if not (Units.Epoch.equal output_epoch installed) then
        Error (Outcome.Epoch_mismatch { installed; output = output_epoch })
      else
        Result.bind
          (Result.map_error
             (fun e -> Outcome.Receive e)
             (Subscriber.receive t.subscriber sub_dag ~bodies ~address_of))
          (fun (subscriber, consensus, output) ->
            Result.map
              (fun (engine, blocks) ->
                let sealed = Engine.is_sealed engine in
                ( {
                    t with
                    subscriber;
                    engine;
                    last_forwarded = Cb.number consensus;
                    phase =
                      (if sealed then
                         Sealed
                           { closed_at = Tn_batch.Output.committed_at output }
                       else Running);
                  },
                  { Outcome.consensus; output; blocks; closes_epoch = sealed }
                ))
              (Result.map_error
                 (fun e -> Outcome.Execute e)
                 (Engine.execute t.engine output)))

(* The seal is the fold's OTHER exit: stepping a sealed driver is refused
   ([Sealed_needs_handoff]), so the walk tests the phase FIRST and returns
   the sealed driver with the unconsumed suffix instead of manufacturing
   that refusal - upstream the boundary crossing merely marks the epoch
   done and the outer loop re-enters ([subscriber.rs:362],
   [run_epoch.rs:142]). Halted is reserved for genuine defects, which is
   what lets it carry no driver at all. *)
let fold t sub_dags ~bodies ~address_of =
  let rec go t advances_rev remaining =
    match (t.phase, remaining) with
    | Sealed _, _ ->
        Outcome.Sealed
          { driver = t; advances = List.rev advances_rev; rest = remaining }
    | Running, [] ->
        Outcome.Advance { driver = t; advances = List.rev advances_rev }
    | Running, sub_dag :: rest ->
        Result.fold
          ~ok:(fun (t, advance) -> go t (advance :: advances_rev) rest)
          ~error:(fun error ->
            Outcome.Halted { advances = List.rev advances_rev; error })
          (step t sub_dag ~bodies ~address_of)
  in
  go t [] sub_dags

let last_forwarded t = t.last_forwarded
let engine t = t.engine
let is_sealed t = Engine.is_sealed t.engine

let closed_at t =
  match t.phase with
  | Running -> None
  | Sealed { closed_at } -> Some closed_at

let next_boundary t = Option.map (boundary_after t) (closed_at t)

(* Guard order (the deliverable's): refuse unless sealed (H12: the engine
   deliberately does NOT have this guard, and called mid-epoch it would
   clear unrooted leader counts silently); refuse a committee whose epoch
   does not strictly advance (H8's InvalidPackEpoch analogue); only then
   hand the engine the H9 boundary. The accumulator and the watermark are
   untouched: consensus numbering is global across epochs (H8). *)
let begin_epoch t ~committee =
  match t.phase with
  | Running -> Error Not_sealed
  | Sealed { closed_at } ->
      let installed = Tn_types.Committee.epoch (Engine.committee t.engine) in
      let proposed = Tn_types.Committee.epoch committee in
      if Units.Epoch.compare proposed installed > 0 then
        Result.map
          (fun engine -> { t with engine; phase = Running })
          (Result.map_error
             (fun e -> Engine_refused e)
             (Engine.begin_epoch t.engine
                ~boundary:(boundary_after t closed_at)
                ~committee))
      else Error (Committee_epoch { installed; proposed })
