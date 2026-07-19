(** The primary hot path, composed into one pure machine.

    A node folds the three consensus roles into a single Mealy machine over
    node-boundary events: the {!Tn_consensus.Proposer} builds this validator's
    headers, the {!Tn_consensus.Voter} answers peers' headers, the already-ported
    {!Tn_vertex.Vote_aggregator} turns votes on our own header into a certificate,
    the {!Tn_consensus.Parent_aggregator}s release parent quorums back to the
    proposer, and {!Tn_consensus.Bullshark} turns DAG insertions into committed
    output. In the Rust node these are five tokio tasks glued by channels; here
    every intra-node channel collapses into direct function composition, leaving
    only true message crossings as {!event}s in and {!command}s out.

    {b Errors are for invariant breaks only.} A {!Certificate_equivocation} — two
    conflicting certificates for one slot — is always an error: safety is already
    lost, so a hard stop is right. A {!Missing_parent} / {!Missing_parent_round},
    by contrast, is fatal only on the {e strict} spine, which just our own freshly
    formed certificate self-inserts through — there an absent parent means the
    node's own routing broke. A certificate arriving from {e outside} before its
    ancestors are synced (offered on a vote request, or gossiped while an ancestor
    was lost) is protocol-normal catch-up: it is dropped, never fatal (Rust buffers
    and fetches; the slice has no fetcher yet). Everything else a Byzantine peer can
    do within the protocol — an invalid vote, an equivocating {e header}, a
    certificate below the GC round, a vote for a superseded proposal — is likewise
    a command or a no-op, never an error. *)

open Tn_types
open Tn_vertex

type event =
  | Our_digest of {
      batch : Digests.Batch_digest.t;
      worker_id : Units.Worker_id.t;
    }  (** A worker of ours sealed a batch available for inclusion. *)
  | Vote_request of {
      from_ : Authority_id.t;
      header : Header.t;
      parents : Certificate.t list;
    }  (** A peer proposes [header] and asks us to vote, offering [parents] (its
           certificates) in case we are missing them. *)
  | Vote_received of Vote.t
      (** A peer's vote answering our own header's vote request. *)
  | Certificate_received of Certificate.t
      (** A certificate delivered by gossip, to insert into the DAG. *)
  | Timer_fired of { kind : Proposer.timer_kind; gen : int }
      (** A previously armed proposer timer elapsed. *)

type command =
  | Broadcast_header of Header.t
      (** Send our freshly proposed header to the committee for votes. *)
  | Send_vote of { to_ : Authority_id.t; vote : Vote.t }
      (** Answer a peer's vote request. *)
  | Send_missing_parents of {
      to_ : Authority_id.t;
      digests : Digests.Header_digest.t list;
    }  (** Ask a peer for the parent certificates we could not resolve. *)
  | Broadcast_certificate of Certificate.t
      (** Publish a certificate we just formed on our own header. *)
  | Arm_timer of {
      kind : Proposer.timer_kind;
      after : Units.Duration.t;
      gen : int;
    }  (** Schedule a {!Timer_fired} [after] the given span, stamped [gen]. *)
  | Emit_committed of Sub_dag.t
      (** Consensus output: a committed sub-DAG, emitted in commit order. *)

type error =
  | Certificate_equivocation of Round.t * Authority_id.t
      (** Two conflicting certificates for one (round, author) slot. *)
  | Missing_parent of Digests.Header_digest.t
      (** An inserted certificate names a parent absent from the previous round. *)
  | Missing_parent_round of Round.t
      (** The entire previous round is absent for an inserted certificate. *)

type t

val create :
  committee:Committee.t ->
  secret_key:Tn_crypto.Secret_key.t ->
  self_id:Authority_id.t ->
  proposer_config:Proposer.config ->
  sub_dags_per_schedule:int ->
  gc_depth:int ->
  now:Units.Timestamp.t ->
  t * command list
(** A node for [self_id], signing with [secret_key]. The leader schedule starts
    as pure round-robin (default swap threshold) and the DAG is seeded with the
    committee's genesis certificates. The returned commands are the startup
    round-1 proposal (a {!Broadcast_header} and the two {!Arm_timer}s). *)

val step : t -> now:Units.Timestamp.t -> event -> (t * command list, error) result
(** Advance the node by one event, yielding the outgoing commands or the
    invariant-break error that stops it. *)

type persisted = {
  certificates : Certificate.t list;
      (** The DAG certificate slice — post-GC by construction. *)
  last_proposed : Header.t option;  (** The proposer's [LastProposed] slot. *)
  votes : (Authority_id.t * Voter.persisted) list;
      (** The voter's per-author vote-once records. *)
}
(** The node-owned persisted state. The committed sub-DAG log is separate — it is
    the node's {!Emit_committed} output, recorded by whatever consumes it. *)

val snapshot : t -> persisted
(** Extract the node-owned persisted state for storage. *)

val recover :
  committee:Committee.t ->
  secret_key:Tn_crypto.Secret_key.t ->
  self_id:Authority_id.t ->
  proposer_config:Proposer.config ->
  sub_dags_per_schedule:int ->
  gc_depth:int ->
  now:Units.Timestamp.t ->
  persisted:persisted ->
  committed:Committed_log.t ->
  (t * command list, error) result
(** Rebuild a node from persistence at restart — the composed port of Rust's node
    recovery. [committed] is the persisted commit log (the {!Emit_committed}
    stream): the leader schedule ({!Leader_schedule.from_store}), the committed
    watermark, and the last committed sub-DAG all derive from it, while the DAG
    rebuilds from [persisted.certificates]. [sub_dags_per_schedule], [gc_depth],
    and [proposer_config] must match the pre-crash configuration (Rust reads them
    from config, not the store). The returned commands are the resumed proposal:
    for a node with a rebuilt DAG the parent quorum at the recovered frontier is
    replayed so the proposer re-proposes at once — re-emitting the persisted header
    or building the next round — while a node that never committed or proposed
    (empty DAG, no stored header) returns the round-1 proposal, as {!create}. Fails
    with the DAG's {!error} if the persisted certificate slice equivocates. *)

val dag : t -> Dag.t
(** The current DAG (committed certificates pruned by GC). Observability. *)

val last_committed : t -> Sub_dag.t option
(** The most recently committed sub-DAG, if any. Observability. *)
