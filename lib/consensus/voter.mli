(** The header voter — the pure port of the primary's peer-header voting logic.

    When a peer proposes a header, this node decides at most once whether to sign
    a {!Tn_vertex.Vote.t} attesting the header — and, transitively, the causal
    history its parents point to — is available. The decision is a pure function
    of the header, the current {!Tn_consensus.Dag}, and a persistent per-author
    vote-once record.

    The {b vote-once} invariant is the safety-critical part: for a given header
    author and round this node signs a single header. An identical re-request is
    answered with the very same vote (idempotent {!Recast}). A {e different}
    header for a round already voted is refused ({!Reject} [Equivocating_header])
    {b when a certificate already exists} for that (author, round): the earlier
    vote then helped form a real quorum, so a second signature would abet a forged
    certificate. When no certificate exists the earlier vote never aggregated (the
    proposer was killed before quorum, then restarted with a fresh header), and
    re-voting is safe and liveness-preserving — matching Rust's [read_by_index]
    carve-out. A peer equivocating on a header does not poison this node's state —
    a Byzantine proposer is protocol-normal — so no path here is an error; every
    outcome is an {!decision}. The genuine invariant break, two conflicting {e
    certificates} (each a proof a quorum signed), is caught later, on DAG
    insertion, and is the {!Tn_consensus.Node}'s concern.

    {b Slice scope.} The full node also syncs missing worker batches, bounds the
    evaluation with a timeout, and waits on execution results. Those are IO
    concerns deferred with the networking, storage, and execution chunks; here a
    header whose parents are not yet resolvable yields {!Need_parents} (the peer
    re-requests with them attached) and everything else is decided synchronously. *)

open Tn_types
open Tn_vertex

type t

val create :
  committee:Committee.t ->
  secret_key:Tn_crypto.Secret_key.t ->
  self_id:Authority_id.t ->
  genesis:Certificate.t list ->
  t
(** A voter that signs with [secret_key] as [self_id]. [genesis] are the round-0
    certificates a round-1 header legitimately parents; they resolve those
    parents even though genesis certificates are never stored in the DAG. *)

type reject_reason =
  | Header_invalid of Header.error
      (** Failed {!Tn_vertex.Header.validate}: wrong epoch, unknown author, or
          empty parents past round 0. *)
  | Round_zero  (** Round 0 is genesis-only and is never voted on. *)
  | Invalid_parent_round
      (** A parent does not sit exactly one round below the header. *)
  | Inquorate_parents
      (** The distinct parent authorities fall short of {b 2f+1} voting power. *)
  | Non_monotone_timestamp
      (** The header's [created_at] precedes a parent's, which would break the
          committed-sub-DAG timestamp monotonicity. *)
  | Future_timestamp
      (** The header claims a [created_at] ahead of this node's clock. The slice
          uses a strict bound; the Rust drift-tolerance window (accept up to
          [now + max_header_time_drift_tolerance]) is deferred with the timing
          chunk. Unreachable in the deterministic simulator, where a proposer
          clamps [created_at] to its own [now], never ahead of a later voter. *)
  | Already_voted_higher
      (** This node has already voted for this author at a strictly higher
          round; the stale request is dropped. *)
  | Equivocating_header
      (** A different header for a round this node already voted, {e and} a
          certificate already exists for that (author, round) — the peer is
          equivocating on an already-certified slot. Without such a certificate
          the node instead re-votes (see the vote-once note above). *)

type decision =
  | Vote of Vote.t
      (** A fresh vote; the returned state has recorded it for the vote-once
          guard. *)
  | Recast of Vote.t
      (** The identical request seen before; the stored vote is replayed and no
          state changes. *)
  | Need_parents of Digests.Header_digest.t list
      (** Named parents this node cannot yet resolve; a protocol-normal response,
          not an error. The peer re-requests with the certificates attached. *)
  | Reject of reject_reason  (** The header is not votable; no vote is produced. *)

val vote :
  t -> dag:Dag.t -> now:Units.Timestamp.t -> Header.t -> t * decision
(** Decide this node's vote on [header] against the current [dag]. Only a {!Vote}
    changes state (recording the vote-once entry); {!Recast}, {!Need_parents}, and
    {!Reject} leave the voter unchanged. *)

val has_voted : t -> Authority_id.t -> Round.t -> bool
(** Whether this node has recorded a vote for an author at or above a round.
    Observability for the node and tests. *)
