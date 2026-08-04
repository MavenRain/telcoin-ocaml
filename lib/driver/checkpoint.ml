(* The execution side's durable value: the engine's persisted facts paired
   with the consensus block whose execution produced them. Everything else
   here is DERIVED off one of those two halves - no watermark scalar, no epoch
   scalar, no sealed flag - so a checkpoint cannot disagree with itself. *)

module Cb = Tn_execution.Consensus_block
module Consensus_chain = Tn_execution.Consensus_chain
module Engine = Tn_engine.Engine
module Units = Tn_types.Units

type t = { engine : Engine.persisted; last_executed : Cb.t option }

(* The engine exactly as [Driver.create] seats it, and nothing executed. The
   spec is read through [Chain_spec.engine_config] rather than re-derived, so
   the cold-start checkpoint and the cold-start driver cannot drift. *)
let genesis spec ~committee =
  {
    engine = Engine.snapshot (Engine.create (Chain_spec.engine_config spec ~committee));
    last_executed = None;
  }

let of_execution engine ~last_executed = { engine; last_executed }
let engine t = t.engine
let last_executed t = t.last_executed

(* Derived, never stored: [Number.genesis] is a constant, so the eager [~none]
   costs nothing and cannot hide a recursive call. *)
let watermark t =
  Option.fold ~none:Cb.Number.genesis ~some:Cb.number t.last_executed

(* The seed IS the executed tip. [Consensus_chain.resume] numbers the NEXT
   block one above its [~number] argument, so passing the executed block's own
   number is what makes the first replayed block land at watermark + 1; see
   [Driver.resume]'s divergence on upstream's last-consensus-parent max. Both
   arms are constructors of an immutable value, so the eager [~none] is a
   value and not a computation. *)
let accumulator t =
  Option.fold ~none:Consensus_chain.genesis
    ~some:(fun block ->
      Consensus_chain.resume ~parent:(Cb.digest block) ~number:(Cb.number block))
    t.last_executed

(* One phase, read once, projected four ways - the disagreement a boolean plus
   two option fields would make constructible. *)
let phase t = (t.engine : Engine.persisted).Engine.phase

let committee t =
  match phase t with
  | Engine.Running { boundary = _; committee } -> committee
  | Engine.Sealed { closed_at = _; committee } -> committee

let epoch t = Tn_types.Committee.epoch (committee t)

let is_sealed t =
  match phase t with
  | Engine.Running { boundary = _; committee = _ } -> false
  | Engine.Sealed { closed_at = _; committee = _ } -> true

let closed_at t =
  match phase t with
  | Engine.Running { boundary = _; committee = _ } -> None
  | Engine.Sealed { closed_at; committee = _ } -> Some (closed_at : Units.Timestamp.t)
