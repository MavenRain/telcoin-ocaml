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

    {b Deliberate slice simplifications} (both live in the liveness/timing domain
    the deterministic simulator controls, and neither affects safety):

    - The min/max delays are uniform. Rust shortens them when this node leads the
      next even round (min to zero, max halved); that leader-fast-path is deferred
      with the timing chunk, keeping the proposer independent of the schedule.
    - The [advance_round] readiness gate is dropped. Rust withholds an early
      (pre-max-timeout) proposal until [ready] holds — a leader certificate is
      present on an even round, or enough leader votes on an odd round — which
      needs the schedule. The slice proposes on a held parent quorum plus the min
      timer or a full batch, so it is strictly more eager. This is liveness-only:
      it can propose a round sooner than Rust, never later, and the Bullshark
      commit rule's safety is unaffected. It is deferred with the leader-fast-path.
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
  genesis:Certificate.t list ->
  now:Units.Timestamp.t ->
  t * action list
(** A proposer seeded with the genesis certificates as its round-0 parents. The
    returned actions are the immediate round-1 proposal: at startup both timers
    are already expired (Rust's first interval tick is immediate), so with a
    non-empty parent set the machine proposes at once. *)

val step : t -> now:Units.Timestamp.t -> input -> t * action list
(** Advance the machine. The returned state must be used in place of the argument
    — an input can change state (recording a digest, a parent, a fired timer)
    even when it emits no action. *)

val recover :
  config:config ->
  committee:Committee.t ->
  authority:Authority_id.t ->
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
