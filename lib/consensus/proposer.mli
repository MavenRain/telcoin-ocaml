(** The header proposer — the pure port of the primary [Proposer] task.

    Each DAG round this node builds one {!Tn_vertex.Header.t}: its payload is the
    worker batch digests drained (oldest first) from a FIFO queue, and its
    parents are the header digests of a {b 2f+1} quorum of the previous round's
    certificates. The machine is a Mealy machine over discrete inputs — worker
    digests, released parent quorums, timer expiries, commit notifications — with
    no IO: it never sleeps and never sends; instead it {e arms} timers and {e
    emits} headers as output actions that a shell (the deterministic simulator,
    later a real node) interprets.

    Two behaviours from the Rust task are load-bearing:

    - {b timer generation counters}. Rust re-arms two [tokio::time::Interval]s on
      every proposal and relies on [Interval::reset] discarding the pending tick.
      A pure port cannot cancel an in-flight timer, so every {!Arm_timer} carries
      a monotonically increasing generation, and a {!Timer_fired} whose
      generation is not the current one is discarded. This closes the race where
      a timer armed for a round the machine has already left would otherwise fire
      a spurious proposal.
    - {b digests are never dropped}. A proposed header not yet known committed is
      kept; when a commit skips past its round without including it, its payload
      digests are re-queued to the front of the FIFO so those batches are
      proposed again, exactly like the Rust [process_committed_headers] re-queue.

    Two further Rust behaviours are ported here (they were deferred in the
    vertical slice and land with this timing chunk; both need the leader
    schedule, which the proposer now holds and the node refreshes after every
    commit):

    - {b the leader fast path}. When this node is the anticipated leader of the
      round it is about to build (an even round), it shortens its own header
      spacing so its proposal is likelier to be committed: the max delay is
      halved and the min delay collapses to zero. Every other round takes the
      full configured delays. The shortened delays are chosen at re-arm time,
      under the current timer generation, so a stale {!Timer_fired} is still
      discarded exactly as before.
    - {b the [advance_round] readiness gate}. An early proposal — one fired
      before the max deadline, on a full batch or the min timer — is withheld
      until the round is {e ready} to advance: on an even round the round's own
      leader certificate must be present in the held parents, on an odd round the
      votes on the previous leader must have settled (f+1 for it, or a 2f+1
      quorum against). The max-delay deadline overrides the gate, so liveness is
      unchanged — a round always eventually proposes — but a node no longer races
      ahead of the leader it is meant to certify. The gate is recomputed only
      when parents are processed (Rust's [process_parents]) and cleared on every
      proposal.

    {b Deliberate slice simplification that remains} (liveness/timing domain the
    simulator controls, safety-neutral):

    - The equivocation guard (re-emit of a stored header for a round already
      proposed) is unreachable in forward operation, where the round only ever
      advances, so {!step} needs no error result. It becomes reachable through
      {!recover}: a restart resumes at the recovered round with the persisted
      header loaded, and the first proposal for that round re-emits it verbatim
      rather than building a divergent one. *)

open Tn_types
open Tn_vertex

type config
(** Static proposer parameters: the header spacing delays and the batch-count
    thresholds. Durations are simulator milliseconds and never enter a digest. *)

val config :
  min_header_delay:Units.Duration.t ->
  max_header_delay:Units.Duration.t ->
  header_batch_threshold:int ->
  max_batches_per_header:int ->
  config
(** [header_batch_threshold] is the queued-digest count that lets a proposal fire
    without waiting for the min-delay timer; [max_batches_per_header] caps how
    many digests one header drains, leaving the rest queued. *)

val default_config : config
(** Rust's defaults scaled to the slice: min delay 500ms, max delay 1000ms, a
    batch threshold of 32, and 1000 digests per header. *)

type timer_kind =
  | Min_delay  (** Earliest a header may be proposed after the previous one. *)
  | Max_delay  (** Forced proposal deadline — overrides all other conditions. *)

type input =
  | Our_digest of {
      batch : Digests.Batch_digest.t;
      worker_id : Units.Worker_id.t;
    }  (** A worker sealed a batch available for inclusion. *)
  | Parents of { certs : Certificate.t list; round : Round.t }
      (** A released quorum (or later straggler delta) of round-[round]
          certificates, to parent the header for [round + 1]. *)
  | Timer_fired of { kind : timer_kind; gen : int }
      (** An armed timer elapsed. Discarded unless [gen] is the current
          generation. *)
  | Committed_headers of { committed : Round.t list }
      (** Consensus committed this node's headers at these rounds; prune them and
          re-queue the digests of any header skipped below the highest of them. *)

type action =
  | Ack_digest
      (** Acknowledge an {!Our_digest} — the node keeps proposing a digest until
          it is committed. Internal to the primary; the shell may ignore it. *)
  | Broadcast_header of Header.t
      (** Send a freshly proposed header to the committee for votes. *)
  | Arm_timer of { kind : timer_kind; gen : int; after : Units.Duration.t }
      (** Schedule a {!Timer_fired} [after] the given span, stamped [gen]. *)

type t

val create :
  config:config ->
  committee:Committee.t ->
  authority:Authority_id.t ->
  schedule:Leader_schedule.t ->
  genesis:Certificate.t list ->
  now:Units.Timestamp.t ->
  t * action list
(** A proposer seeded with the genesis certificates as its round-0 parents and
    the current leader [schedule] (read for the fast-path delays and the
    readiness gate). The returned actions are the immediate round-1 proposal: at
    startup both timers are already expired (Rust's first interval tick is
    immediate) and the readiness gate starts open (Rust's [advance_round = true]
    default), so with a non-empty parent set the machine proposes at once. *)

val update_schedule : t -> Leader_schedule.t -> t
(** Install a new leader schedule — the node calls this after a commit that may
    have changed the swap table, mirroring Rust's shared
    [Arc<RwLock<LeaderSchedule>>] the proposer reads live. Affects only the
    fast-path delays and the readiness gate; no header is built here. *)

val step : t -> now:Units.Timestamp.t -> input -> t * action list
(** Advance the machine. The returned state must be used in place of the argument
    — an input can change state (recording a digest, a parent, a fired timer)
    even when it emits no action. *)

val recover :
  config:config ->
  committee:Committee.t ->
  authority:Authority_id.t ->
  schedule:Leader_schedule.t ->
  genesis:Certificate.t list ->
  now:Units.Timestamp.t ->
  recovered_round:Round.t ->
  last_proposed:Header.t option ->
  t * action list
(** Restart the proposer from persistence — Rust's cold [Proposer::new] combined
    with the recovered primary round and the [LastProposed] slot. [recovered_round]
    is the last committed leader round (the proposer resumes proposing
    [recovered_round + 1]); [last_proposed] is the persisted header. A node that
    never committed or proposed (genesis round, no stored header) recovers exactly
    as {!create}. Otherwise no action is returned: parent aggregators are volatile,
    so the (re-)proposal waits for a fresh parent quorum, at which point {!step}
    re-emits the stored header when it matches the round or builds a fresh one. *)

val last_proposed : t -> Header.t option
(** The most recently proposed header, the [LastProposed] slot to persist. *)

val round : t -> Round.t
(** The round of the most recently proposed header (0 before the first
    proposal). Observability for the node and tests. *)

val pending_digests : t -> (Digests.Batch_digest.t * Units.Worker_id.t) list
(** The batch digests queued for inclusion, oldest first. Observability. *)

val proposed_rounds : t -> Round.t list
(** The rounds of proposed headers not yet known committed, ascending.
    Observability. *)
