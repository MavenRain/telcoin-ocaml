(** A DAG vertex: one authority's proposal for one round.

    A header names its author, round and epoch, the worker batch digests it
    carries as payload, and the digests of the parent headers it extends. Its
    own digest is computed once at construction over the canonical BCS encoding
    of those fields and cached — the OCaml counterpart of Rust's
    [#[serde(skip)] digest] field, but as a smart-constructor invariant rather
    than a mutable cache that must be kept in sync.

    Validation against a committee is a separate, pure step: constructing a
    header never fails, but a header may still be rejected by {!validate}. *)

open Tn_types

type t

val make :
  author:Authority_id.t ->
  round:Round.t ->
  epoch:Units.Epoch.t ->
  created_at:Units.Timestamp.t ->
  payload:(Digests.Batch_digest.t * Units.Worker_id.t) list ->
  parents:Digests.Header_digest.t list ->
  latest_execution_block:Block_num_hash.t ->
  t
(** Parents are canonicalised (sorted, de-duplicated) so the digest does not
    depend on their presentation order, matching Rust's [BTreeSet] parents. The
    payload is canonicalised the way Rust's [IndexMap] payload is: a repeated
    batch digest keeps its first position and takes the last worker id, so one
    key never occupies two entries of the digest pre-image.
    [latest_execution_block] is mandatory on purpose: it is inside the digest
    pre-image (field 7), so a caller that forgot it would produce a header no
    Rust node agrees with, and a mandatory label makes the compiler ask. *)

val digest : t -> Digests.Header_digest.t
val author : t -> Authority_id.t
val round : t -> Round.t
val epoch : t -> Units.Epoch.t
val created_at : t -> Units.Timestamp.t
val payload : t -> (Digests.Batch_digest.t * Units.Worker_id.t) list
val parents : t -> Digests.Header_digest.t list

val latest_execution_block : t -> Block_num_hash.t
(** The execution block the author had already executed when it proposed
    (Rust [HeaderInner::latest_execution_block], primary/header.rs:31,173-174).
    Peers use it to refuse a header that runs ahead of the execution results
    they hold (network/handler.rs), so it is a real protocol field, not
    telemetry, and it is field 7 of the digest pre-image. *)

val codec : t Tn_codec.Bcs.t
(** The wire codec. Encodes exactly the seven fields that enter the digest
    pre-image (the cached digest is not on the wire, matching Rust's
    [#[serde(skip)]] on it); decoding recomputes the digest, so a decoded
    header's cached digest is always consistent with its bytes.

    The 32-byte legs are NOT uniform. The author is a bare 32 bytes
    ([AuthorityIdentifier] serializes as an array); every payload key, every
    parent and the execution block hash are LENGTH-PREFIXED, [0x20] then 32
    bytes, because each is a [Digest<32>] or a [B256] and serde reaches those
    through [serialize_bytes]. A bare 32-byte value in a prefixed slot is
    refused on decode rather than re-framed.

    Decoding repairs nothing that would move the digest. A repeated payload key
    collapses exactly as Rust's [IndexMap] collapses it, and a [created_at]
    beyond the representable range of {!Units.Timestamp} is refused rather than
    replaced by a default, because Rust digests the value it read. *)

val equal : t -> t -> bool
(** By digest — two headers with the same digest are the same proposal. *)

val compare : t -> t -> int

type error =
  | Wrong_epoch
  | Author_not_in_committee
  | Empty_parents_after_genesis
      (** A non-genesis header must reference parents. *)

val error_to_string : error -> string

val validate : Committee.t -> t -> (unit, error) result
(** Structural validation against a committee: correct epoch, known author, and
    non-empty parents past round 0. Parent-quorum and per-parent checks live in
    the consensus layer, which owns the DAG the parents refer to. *)
