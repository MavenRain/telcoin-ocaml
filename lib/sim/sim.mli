(** The deterministic discrete-event simulator — the imperative shell that runs
    the pure consensus core.

    Each consensus role is a pure {!Tn_consensus.Node} Mealy machine that never
    performs IO: given an {!Tn_consensus.Node.event} it returns the next state and
    a list of {!Tn_consensus.Node.command}s. This module is the {e shell} that
    closes the loop. It holds a committee of nodes, interprets every command into
    future events — a {!Tn_consensus.Node.command.Broadcast_header} becomes a
    {!Tn_consensus.Node.event.Vote_request} delivered to each peer after a network
    delay, an {!Tn_consensus.Node.command.Arm_timer} becomes a
    {!Tn_consensus.Node.event.Timer_fired} delivered to the same node after the
    armed span — and drives a time-ordered event queue until a horizon is reached.

    {b Determinism.} The sources of jitter are per-message network latency and,
    when the network is lossy, per-message drop coins — each drawn from its own
    {!Tn_std.Prng} stream derived from the {!config} seed (the drop stream is
    scattered clear of the latency stream, and is untouched when loss is off).
    Events at the same delivery time are ordered by a monotonic scheduling counter,
    so a run is a pure function of its seed and config: the same inputs replay the
    same schedule and the same committed output. A divergence in the committed
    sub-DAGs across honest nodes, or a {!Tn_consensus.Node.error}, is therefore a
    real safety bug rather than a flake — which is exactly what {!agreement} and
    {!error} report.

    {b Fault model.} By default every node follows the protocol and the network
    is fully connected and reliable. Two optional, honest-node-preserving faults
    are available on {!config} for the property tests: [crashed] authorities are
    {e crash-stopped} — silent from time zero, never proposing, voting, or
    certifying — and [drop_permille] makes each network message independently lost
    with that per-mille probability (timers are local and never drop). Both are
    off by default, and with both off a run is byte-for-byte identical to the
    reliable slice. Neither models {e Byzantine} behaviour (equivocation, forged
    votes): a crash-stop node withholds messages but never sends a conflicting
    one, so consensus safety must hold — the honest survivors still agree — and
    the interesting failure mode is degraded liveness, not a fork. Parent
    certificates a peer needs to vote are offered on the vote request (resolved
    from the set of certificates broadcast so far), and a
    {!Tn_consensus.Node.command.Send_missing_parents} is answered from that same
    resolvable set — the shell's stand-in for the fetch protocol a later
    networking chunk will add. *)

open Tn_types
open Tn_vertex
open Tn_consensus
open Tn_execution

type t
(** A simulation: the committee's nodes, the pending event queue, the clock, and
    the committed output accumulated so far. *)

type config
(** Static run parameters: the network latency band, the stop horizon and step
    fuse, and the {!Tn_std.Prng} seed. *)

type batch_plan
(** A pure description of batch traffic to inject: how many bodies each live
    authority's worker seals, how often, and what they carry. A plan describes
    {e local} worker announcements — each synthesised {!Tn_types.Batch} is
    revealed to its own authority's node as a
    {!Tn_consensus.Node.event.Our_digest}, never sent across the network — so
    injection perturbs no message latency and draws nothing from the
    {!Tn_std.Prng} streams. *)

val batch_plan :
  per_authority:int ->
  period:Units.Duration.t ->
  worker_id:Units.Worker_id.t ->
  epoch:Units.Epoch.t ->
  base_fee_per_gas:Units.Base_fee.t ->
  transactions:(Authority_id.t -> int -> string list) ->
  unit ->
  batch_plan
(** Each live authority seals [per_authority] bodies (negative values clamp to
    none), body [k] (zero-based) announced at time [(k + 1) * period]. Every
    body carries [epoch], [base_fee_per_gas] and [worker_id], is beneficiaried
    to its authority's execution address, and holds
    [transactions authority_id k] — vary that answer per authority and index
    for pairwise-distinct bodies; a constant answer makes an authority's bodies
    (and, under equal execution addresses, all bodies) collide into one digest.
    The announced digest and worker id are read off the synthesised body
    itself, so an announcement can never disagree with its body. *)

val config :
  min_latency:Units.Duration.t ->
  max_latency:Units.Duration.t ->
  horizon:Units.Duration.t ->
  max_steps:int ->
  seed:int64 ->
  ?crashed:Authority_id.t list ->
  ?drop_permille:int ->
  ?batches:batch_plan ->
  unit ->
  config
(** Every message crossing the network is delayed by a uniform draw in
    [\[min_latency, max_latency\]]. {!run} stops once the next event's delivery
    time would exceed [horizon] (timers re-arm forever, so a horizon is what makes
    a run finite), or once [max_steps] events have been delivered (a safety fuse
    against a zero-latency cascade), whichever comes first.

    [crashed] (default none) lists crash-stopped authorities — they are built into
    the committee but never run, so the live committee is the remaining members.
    [drop_permille] (default [0], clamped to [\[0, 1000\]]) is the per-message loss
    probability in parts per thousand. See the {e fault model} note above; with
    the defaults the run is the reliable honest slice. When some authorities are
    [crashed], {!agreement} — which ranges over the whole committee — collapses to
    [Agree 0] because a silent node commits nothing; test the survivors' agreement
    with {!For_testing.agree_of_logs} over their logs alone.

    [batches] (default absent) injects the plan's synthesised batch bodies as
    worker announcements, scheduled at {!create} after the startup commands.
    Absent means {e zero} extra scheduled events and {e zero} PRNG draws — the
    run takes literally the no-injection code path, so it replays byte-for-byte
    against a pre-injection run at the same seed and config. A [crashed]
    authority's plan entries are dropped exactly as its startup commands are. *)

val create :
  committee:Committee.t ->
  secret_key:(Authority_id.t -> Tn_crypto.Secret_key.t) ->
  proposer_config:Proposer.config ->
  sub_dags_per_schedule:int ->
  gc_depth:int ->
  config:config ->
  t
(** Build one {!Tn_consensus.Node} per committee authority (each signing with the
    key [secret_key] returns for its id), seed the resolvable certificate set with
    the committee's genesis certificates, and schedule every {e live} node's
    startup commands (the round-1 proposal and its armed timers) at time zero. A
    [crashed] authority's node is still built, but its startup commands are dropped
    here, so it is silent from time zero. *)

val run : t -> t
(** Drive the event queue to the horizon: repeatedly deliver the earliest pending
    event to its target node and interpret the resulting commands, until the queue
    drains, the horizon is passed, the step fuse blows, or a node reports an
    invariant-break {!error} (which halts the run immediately). *)

val committed : t -> Authority_id.t -> Sub_dag.t list
(** The sub-DAGs [authority] has committed, in commit order (empty for a
    non-member). This is the node's consensus output. *)

val commit_count : t -> Authority_id.t -> int
(** [List.length (committed t authority)]. *)

val executed : t -> Authority_id.t -> Consensus_block.t list
(** The consensus-chain blocks [authority]'s committed output produces, in chain
    order (block number one first). Each committed {!Tn_consensus.Sub_dag} folds
    to one {!Tn_execution.Consensus_block} through the
    {!Tn_execution.Engine.Noop} engine. Because that engine is a deterministic
    fold and honest nodes share a committed prefix ({!agreement}), honest nodes'
    chains coincide wherever their committed logs do. This is derived on demand
    from {!committed} rather than run in the event loop, so it never perturbs the
    run's determinism. Empty for a non-member or a node that committed nothing. *)

val execution_tip : t -> Authority_id.t -> Consensus_block.t option
(** The head of [authority]'s consensus chain — the last block of {!executed} —
    or [None] if it has committed nothing. *)

val batch_bodies : t -> Tn_types.Batch.t list
(** The batch bodies the run's {!batch_plan} synthesised, in build order
    (committee order, then plan index) — empty when [batches] was absent. Every
    injected announcement's digest is [Tn_types.Batch.digest] of exactly one of
    these bodies, so a payload entry a committed sub-DAG carries is answerable
    from this list; a store built over it is the run's body tier. *)

val error : t -> (Authority_id.t * Node.error) option
(** The node and invariant-break error that halted the run, or [None] for a clean
    run. In the honest slice a clean run always yields [None]; a [Some] is a bug in
    the core or the shell wiring. *)

val elapsed : t -> Units.Duration.t
(** Simulated time at the point the run stopped. *)

val steps : t -> int
(** The number of events delivered. *)

type agreement =
  | Agree of int
      (** No two committed logs disagree on their common prefix; the payload is
          the length of the shortest log, i.e. the prefix every node has
          committed. *)
  | Diverge of { left : Authority_id.t; right : Authority_id.t; index : int }
      (** Two nodes committed different sub-DAGs at the same commit index — a
          consensus-safety violation. *)

val agreement : t -> agreement
(** Whether every pair of nodes' committed logs is prefix-consistent. For the
    honest slice this must be {!Agree}; a {!Diverge} means safety broke. *)

(** {1 Testing seam} *)

module For_testing : sig
  val agree_of_logs : (Authority_id.t * Sub_dag.t list) list -> agreement
  (** The pure oracle {!agreement} runs, over already-extracted committed logs.
      Exposed only so its divergence-detection path — which an honest simulation
      never produces — can be unit-tested against constructed forks and
      prefix-lags. Not part of the running protocol. *)
end
