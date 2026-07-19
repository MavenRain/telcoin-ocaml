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
  t
(** Parents are canonicalised (sorted, de-duplicated) so the digest does not
    depend on their presentation order, matching Rust's [BTreeSet] parents. *)

val digest : t -> Digests.Header_digest.t
val author : t -> Authority_id.t
val round : t -> Round.t
val epoch : t -> Units.Epoch.t
val created_at : t -> Units.Timestamp.t
val payload : t -> (Digests.Batch_digest.t * Units.Worker_id.t) list
val parents : t -> Digests.Header_digest.t list

val codec : t Tn_codec.Bcs.t
(** The wire codec. Encodes exactly the fields that enter the digest pre-image
    (the cached digest is not on the wire); decoding recomputes the digest, so
    a decoded header's cached digest is always consistent with its bytes. *)

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
