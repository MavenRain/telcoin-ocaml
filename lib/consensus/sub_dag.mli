(** A committed sub-DAG — the port of Rust's [CommittedSubDag].

    One commit's worth of the DAG: the certificates a leader's causal history
    flattens to, stored as bare headers in commit order (ascending round,
    {e leader last}), the running {!Reputation_scores}, a monotone commit
    timestamp, and a randomness value derived from the leader's aggregate
    signature. Two Rust panics become structure:

    - {b leader-last}: Rust passes the leader redundantly and asserts it equals
      the last certificate of the sequence. Here the leader {e is} the last
      element of a {!Tn_std.Nonempty.t} — nothing to assert, and {!leader} is
      total ([Nonempty.last]).
    - {b non-emptiness}: the empty sub-DAG whose [leader()] panics in Rust
      cannot be built.

    The commit timestamp is clamped monotone against the previous sub-DAG:
    [max previous.stored leader.created_at] (a leader whose clock regressed is
    silently overridden, as in Rust). Rust keeps two views of the value — the
    raw stored field feeds the digest, while the accessor falls back to the
    leader's [created_at] when the stored value is zero (an upgraded-node replay
    quirk). {!stored_timestamp} and {!commit_timestamp} keep the two views as
    two functions, never fused. *)

open Tn_std
open Tn_types
open Tn_vertex

type t

val create :
  sequence:Certificate.t Nonempty.t ->
  scores:Reputation_scores.t ->
  previous:t option ->
  t
(** [sequence] is the flattened sub-DAG in commit order with the leader as its
    last certificate — the shape the commit rule's traversal produces by
    construction: every other certificate is a strict ancestor of the leader, so
    the ascending stable sort puts the unique highest-round certificate, the
    leader, last. Certificates are stripped to their headers, the counterpart of
    Rust's [Certificate::into_header]. The randomness is the protocol hash of the
    leader's aggregate signature bytes; a certificate without one (only genesis,
    which cannot lead) hashes fixed empty bytes, the analogue of Rust's
    default-signature fallback. *)

val of_persisted :
  headers:Header.t Nonempty.t ->
  scores:Reputation_scores.t ->
  stored:Units.Timestamp.t ->
  randomness:Tn_crypto.Digest.t ->
  t
(** Rebuild a sub-DAG field-wise from its persisted representation, recomputing
    the cached digest from the same {!preimage} {!create} hashes. RESERVED for
    the storage chunk's decoder, the precedent {!Dag.insert_recovered} sets.

    It cannot be replaced by {!create}: [create] takes certificates and a
    [previous] sub-DAG, and neither survives into the value. Stripping
    certificates to headers is not invertible, and re-running the monotone
    timestamp clamp against a [previous] a resumed reader does not have would
    move the digest. So the stored fields are handed over as they were stored,
    and only the digest — never a stored field — is re-derived. *)

val leader : t -> Header.t
(** Total: the last header of the sequence. *)

val leader_round : t -> Round.t
val leader_author : t -> Authority_id.t
val leader_epoch : t -> Units.Epoch.t

val sequence_number : t -> Units.Sequence_number.t
(** The leader's nonce, [(epoch << 32) | round] — what the reputation schedule
    cadence divides by two. Derived from the leader, never stored: Rust accepts a
    [sub_dag_index] argument and then discards it. *)

val headers : t -> Header.t Nonempty.t
(** Ascending round, traversal-discovery order within a round, leader last. *)

val payload_digests : t -> Digests.Batch_digest.t list
(** Every batch digest this sub-DAG's certificates carry, flattened in commit
    order (headers ascending by round, leader last) and preserving duplicates:
    a digest under two certificates appears twice, because it is one body
    resolved twice and executed as two blocks whose transactions
    self-invalidate ([subscriber.rs:480-509]).

    Chunk 38 needs this so the durable store can derive a record's bodies from
    the block alone, without a store-local re-implementation of the flatten
    that could drift from the one attachment performs. It cannot literally
    share [Tn_batch.Output.attach]'s walk, which groups per header to build the
    per-certificate beneficiary entries ([lib/batch/output.mli:26-30]); the
    agreement between this list and [Tn_batch.Output.batch_digests] is pinned
    by a test instead, and stated here so a reader knows it is pinned rather
    than structural. *)

val scores : t -> Reputation_scores.t

val stored_timestamp : t -> Units.Timestamp.t
(** The raw clamped value — the digest input, and what the {e next} sub-DAG's
    monotone clamp reads. *)

val commit_timestamp : t -> Units.Timestamp.t
(** The accessor view: the stored value, or the leader's [created_at] when the
    stored value is zero — Rust's replay fallback, kept out of the digest. *)

val randomness : t -> Tn_crypto.Digest.t
(** Protocol hash of the leader's aggregate signature bytes (Rust hashes with
    keccak256; here it goes through the {!Tn_crypto} seam like every other
    digest). Epoch-boundary shuffle entropy. *)

val preimage : t -> string
(** The digest pre-image, {e without} the domain tag: every header digest in
    sequence order, then the canonically BCS-encoded scores, then the 8-byte
    little-endian stored timestamp, then the raw randomness bytes — no length
    prefixes or separators between sections. This byte layout is the frozen
    wire-compatibility contract (the exact Rust [CommittedSubDag] pre-image field
    order); a future codec/crypto chunk may change only the hash function and the
    domain-tag policy around it, never this layout. *)

val digest : t -> Digests.Sub_dag_digest.t
(** Domain-tagged protocol hash of {!preimage}. The sequence number is
    deliberately absent, matching Rust: two sub-DAGs differing only in index are
    identical. *)

val codec : t Tn_codec.Bcs.t
(** The persisted wire codec. RESERVED for the storage chunk. The four stored
    fields in {!preimage} order — the header sequence, the
    {!Reputation_scores}, the 8-byte stored timestamp, the raw randomness —
    rebuilt through {!of_persisted}.

    The cached {!digest} is {e not} on the wire: it is recomputed from the
    decoded fields on every read, so no byte a reader is handed can install a
    digest that disagrees with the fields beside it, and tampering with a
    digest that is not there is inert. This mirrors Rust's own [Header]
    deserialize, which recomputes and discards whatever the wire carried. An
    empty sequence and an out-of-range timestamp are refused rather than
    repaired. *)

val equal : t -> t -> bool
(** By digest. *)

val compare : t -> t -> int
