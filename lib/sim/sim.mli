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

    {b Determinism.} The only source of jitter is per-message network latency,
    drawn from a single {!Tn_std.Prng} stream seeded from the {!config}. Events at
    the same delivery time are ordered by a monotonic scheduling counter, so a run
    is a pure function of its seed: the same seed replays the same schedule and the
    same committed output. A divergence in the committed sub-DAGs across honest
    nodes, or a {!Tn_consensus.Node.error}, is therefore a real safety bug rather
    than a flake — which is exactly what {!agreement} and {!error} report.

    {b Honest slice.} Every node follows the protocol and the network is fully
    connected and reliable; there are no Byzantine or dropped-message models yet.
    Parent certificates a peer needs to vote are offered on the vote request
    (resolved from the set of certificates broadcast so far), and a
    {!Tn_consensus.Node.command.Send_missing_parents} is answered from that same
    resolvable set — the shell's stand-in for the fetch protocol a later
    networking chunk will add. *)

open Tn_types
open Tn_vertex
open Tn_consensus

type t
(** A simulation: the committee's nodes, the pending event queue, the clock, and
    the committed output accumulated so far. *)

type config
(** Static run parameters: the network latency band, the stop horizon and step
    fuse, and the {!Tn_std.Prng} seed. *)

val config :
  min_latency:Units.Duration.t ->
  max_latency:Units.Duration.t ->
  horizon:Units.Duration.t ->
  max_steps:int ->
  seed:int64 ->
  config
(** Every message crossing the network is delayed by a uniform draw in
    [\[min_latency, max_latency\]]. {!run} stops once the next event's delivery
    time would exceed [horizon] (timers re-arm forever, so a horizon is what makes
    a run finite), or once [max_steps] events have been delivered (a safety fuse
    against a zero-latency cascade), whichever comes first. *)

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
    the committee's genesis certificates, and schedule every node's startup
    commands (the round-1 proposal and its armed timers) at time zero. *)

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
