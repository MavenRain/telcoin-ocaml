module Cb = Tn_execution.Consensus_block
module Engine = Tn_engine.Engine
module Units = Tn_types.Units

(* Chunk 38 deletes the driver's own [phase] field. Chunk 37 carried one
   because it read the commit timestamp of the sealing output off the very
   output it had just stepped; the engine records the SAME value from the
   SAME output in the same step ([engine.ml:328-333] against
   [driver.ml:90]), so two copies could only ever disagree by defect. Both
   [is_sealed] and [closed_at] now project [Engine.phase], which makes the
   disagreement unrepresentable rather than merely absent - and it is what
   lets [Checkpoint.is_sealed]/[Checkpoint.closed_at], derived from the same
   phase through [Engine.persisted], be the same two facts by construction.

   [last_forwarded] becomes the BLOCK rather than its number: [snapshot] owes
   a checkpoint the digest that anchors the gap's floor as well as its
   height, and deriving the number from the block keeps the two from drifting
   the way a stored scalar beside a stored block would. [None] is "nothing
   executed", which the public accessor reports as [Number.genesis]. *)
type t = {
  spec : Chain_spec.t;
  subscriber : Subscriber.t;
  engine : Engine.t;
  last_forwarded : Cb.t option;
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
    last_forwarded = None;
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

(* The two refusals that fire BEFORE anything is minted, in ONE place so
   [mint] and [step] cannot drift on which one fires first: a sealed driver
   refuses up front (the handoff is owed, and the engine is never consulted
   just to repeat the refusal); then the output's leader epoch must BE the
   installed committee's epoch (H8's InvalidPackEpoch, [storage/src/consensus.
   rs:732-765]). Sharing them is what makes "a record [step] will refuse can
   never be filed in the first place" a structural fact: the shell's [mint]
   applies the very guard the later [step] will. *)
let pre_mint_guards t sub_dag =
  match Engine.phase t.engine with
  | Engine.Sealed { closed_at = _; committee = _ } ->
      Error Outcome.Sealed_needs_handoff
  | Engine.Running { boundary = _; committee } ->
      let installed = Tn_types.Committee.epoch committee in
      let output = Tn_consensus.Sub_dag.leader_epoch sub_dag in
      if Units.Epoch.equal output installed then Ok ()
      else Error (Outcome.Epoch_mismatch { installed; output })

(* Mint-and-attach, execute, and only then advance the watermark: the
   receive error and the execute error both return the error ALONE, so the
   pre-step driver is the only driver a failing caller ever holds. The two
   pre-mint guards are [pre_mint_guards]', in their original order, so a
   refused output consumes no consensus number. *)
let step t sub_dag ~bodies ~address_of =
  Result.bind (pre_mint_guards t sub_dag) (fun () ->
      Result.bind
        (Result.map_error
           (fun e -> Outcome.Receive e)
           (Subscriber.receive t.subscriber sub_dag ~bodies ~address_of))
        (fun (subscriber, consensus, output) ->
          Result.map
            (fun (engine, blocks) ->
              ( { t with subscriber; engine; last_forwarded = Some consensus },
                {
                  Outcome.consensus;
                  output;
                  blocks;
                  closes_epoch = Engine.is_sealed engine;
                } ))
            (Result.map_error
               (fun e -> Outcome.Execute e)
               (Engine.execute t.engine output))))

(* The block [step] would mint, advancing nothing: the accumulator, the
   engine and the watermark are all untouched, so minting leaves no trace
   anywhere until the shell writes one. *)
let mint t sub_dag =
  Result.map
    (fun () -> Subscriber.mint t.subscriber sub_dag)
    (pre_mint_guards t sub_dag)

(* The seal is the fold's OTHER exit: stepping a sealed driver is refused
   ([Sealed_needs_handoff]), so the walk tests the phase FIRST and returns
   the sealed driver with the unconsumed suffix instead of manufacturing
   that refusal - upstream the boundary crossing merely marks the epoch
   done and the outer loop re-enters ([subscriber.rs:362],
   [run_epoch.rs:142]). Halted is reserved for genuine defects, which is
   what lets it carry no driver at all. *)
let fold t sub_dags ~bodies ~address_of =
  let rec go t advances_rev remaining =
    match (Engine.phase t.engine, remaining) with
    | Engine.Sealed { closed_at = _; committee = _ }, _ ->
        Outcome.Sealed
          { driver = t; advances = List.rev advances_rev; rest = remaining }
    | Engine.Running { boundary = _; committee = _ }, [] ->
        Outcome.Advance { driver = t; advances = List.rev advances_rev }
    | Engine.Running { boundary = _; committee = _ }, sub_dag :: rest ->
        Result.fold
          ~ok:(fun (t, advance) -> go t (advance :: advances_rev) rest)
          ~error:(fun error ->
            Outcome.Halted { advances = List.rev advances_rev; error })
          (step t sub_dag ~bodies ~address_of)
  in
  go t [] sub_dags

(* Derived off the block, so the height and the digest the checkpoint pairs
   cannot drift; [Number.genesis] is a constant, so the eager [~none] is a
   value and not a computation. *)
let last_forwarded t =
  Option.fold ~none:Cb.Number.genesis ~some:Cb.number t.last_forwarded

let engine t = t.engine
let is_sealed t = Engine.is_sealed t.engine

let closed_at t =
  match Engine.phase t.engine with
  | Engine.Running { boundary = _; committee = _ } -> None
  | Engine.Sealed { closed_at; committee = _ } -> Some closed_at

let next_boundary t = Option.map (boundary_after t) (closed_at t)

(* File what execution left behind. The two halves are read out of ONE driver
   value in ONE expression, which is where [Checkpoint.of_execution]'s pairing
   obligation is discharged. *)
let snapshot t =
  Checkpoint.of_execution (Engine.snapshot t.engine)
    ~last_executed:t.last_forwarded

(* Guard order (the deliverable's): refuse unless sealed (H12: the engine
   deliberately does NOT have this guard, and called mid-epoch it would
   clear unrooted leader counts silently); refuse a committee whose epoch
   does not strictly advance (H8's InvalidPackEpoch analogue); only then
   hand the engine the H9 boundary. The accumulator and the watermark are
   untouched: consensus numbering is global across epochs (H8). *)
let begin_epoch t ~committee =
  match Engine.phase t.engine with
  | Engine.Running { boundary = _; committee = _ } -> Error Not_sealed
  | Engine.Sealed { closed_at; committee = installed_committee } ->
      let installed = Tn_types.Committee.epoch installed_committee in
      let proposed = Tn_types.Committee.epoch committee in
      if Units.Epoch.compare proposed installed > 0 then
        Result.map
          (fun engine -> { t with engine })
          (Result.map_error
             (fun e -> Engine_refused e)
             (Engine.begin_epoch t.engine
                ~boundary:(boundary_after t closed_at)
                ~committee))
      else Error (Committee_epoch { installed; proposed })

type resume_error =
  | Committee_epoch of {
      supplied : Units.Epoch.t;
      checkpoint : Units.Epoch.t;
    }
  | Committee_mismatch of { epoch : Units.Epoch.t }
  | Store_epoch of { checkpoint : Units.Epoch.t; store : Units.Epoch.t }
  | Gap of Tn_execution.Consensus_store.miss

let resume_error_to_string (e : resume_error) =
  match e with
  | Committee_epoch { supplied; checkpoint } ->
      Printf.sprintf
        "resume refused: the supplied committee is of epoch %s but the \
         checkpoint's blocks executed under epoch %s"
        (Units.Epoch.to_string supplied)
        (Units.Epoch.to_string checkpoint)
  | Committee_mismatch { epoch } ->
      Printf.sprintf
        "resume refused: the supplied committee and the checkpoint's are both \
         of epoch %s but are not the same committee, so the persisted leader \
         counts did not accrue under the supplied seats"
        (Units.Epoch.to_string epoch)
  | Store_epoch { checkpoint; store } ->
      Printf.sprintf
        "resume refused: the checkpoint executed under epoch %s but the \
         store's open epoch is %s, so the two durable values are not a \
         matched pair"
        (Units.Epoch.to_string checkpoint)
        (Units.Epoch.to_string store)
  | Gap m ->
      "resume refused, the gap could not be collected: "
      ^ Tn_execution.Consensus_store.miss_to_string m

(* Rebuild-and-heal, in the documented order: the three committee/epoch
   cross-checks fire BEFORE anything replays - the caller's committee must be
   of the checkpoint's epoch AND be the checkpoint's committee whole-value
   (epoch equality alone cannot witness identity), and the store's open epoch
   must be the checkpoint's, save the ONE redo-able skew below - then the gap
   is collected with its floor the checkpoint's own executed block and its
   ceiling the store's own tip, then the driver is seated - engine from
   [Engine.resume], accumulator from the checkpoint (the EXECUTED tip, never
   the store tip: see the .mli's seed divergence), watermark from the same
   block that seeded both - and the gap is folded through the SAME [fold]
   live callers use, with each step's bodies drawn from the gap's own records
   ([Replay.bodies]) rather than from any ambient map. The three terminal
   shapes are chunk 37's; a defect during replay is [Ok (Halted _)], never a
   [resume_error].

   The redo-able skew is the epoch handoff's own crash window: the shell
   rolls the store ([Consensus_store.open_epoch], durable write 1) and only
   then snapshots the handed-off driver (durable write 2), so a crash between
   them leaves Sealed-at-N beside a store open at N+1 - a pair the strict
   equality would refuse FOREVER, with no healing API. It is accepted exactly
   when the checkpoint is sealed, the store's epoch is the successor of the
   checkpoint's, and the collected gap above the checkpoint is EMPTY; the
   resume then lands on [Outcome.Sealed] with nothing to replay, and the
   caller re-runs [begin_epoch] (idempotent, pinned by C6/C7) and skips the
   already-done roll. A deeper skew is not one crashed handoff, and a skewed
   store holding records above the sealed checkpoint carries a next epoch
   this checkpoint cannot replay - both stay [Store_epoch]. *)
let resume spec ~committee ~checkpoint ~store ~address_of =
  let supplied = Tn_types.Committee.epoch committee in
  let cp_epoch = Checkpoint.epoch checkpoint in
  let store_epoch = Tn_execution.Consensus_store.epoch store in
  let matched = Units.Epoch.equal cp_epoch store_epoch in
  let handoff_window =
    Checkpoint.is_sealed checkpoint
    && Units.Epoch.equal store_epoch (Units.Epoch.succ cp_epoch)
  in
  if not (Units.Epoch.equal supplied cp_epoch) then
    Error (Committee_epoch { supplied; checkpoint = cp_epoch })
  else if
    not (Tn_types.Committee.equal committee (Checkpoint.committee checkpoint))
  then Error (Committee_mismatch { epoch = cp_epoch })
  else if not (matched || handoff_window) then
    Error (Store_epoch { checkpoint = cp_epoch; store = store_epoch })
  else
    Result.bind
      (Result.map_error
         (fun m -> Gap m)
         (Tn_execution.Consensus_store.gap store
            ~after:(Checkpoint.last_executed checkpoint)))
      (fun run ->
        let replayable = Tn_execution.Replay.sub_dags run in
        let consumable =
          match replayable with [] -> true | _ :: _ -> matched
        in
        if not consumable then
          Error (Store_epoch { checkpoint = cp_epoch; store = store_epoch })
        else
          let t =
            {
              spec;
              subscriber =
                Subscriber.create (Checkpoint.accumulator checkpoint);
              engine =
                Engine.resume
                  ~chain_id:(Chain_spec.chain_id spec)
                  ~basefee_address:(Chain_spec.basefee_address spec)
                  (Checkpoint.engine checkpoint);
              last_forwarded = Checkpoint.last_executed checkpoint;
            }
          in
          Ok
            (fold t replayable
               ~bodies:(Batch_store.of_bodies (Tn_execution.Replay.bodies run))
               ~address_of))
