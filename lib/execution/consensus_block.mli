(** The consensus-chain block — the port of Rust's [ConsensusHeader].

    The consensus chain is the hash-linked ledger of committed consensus output
    that the execution layer extends. Each block wraps exactly one committed
    {!Tn_consensus.Sub_dag} (the unit of consensus output), carries a {!Number}
    that counts its ancestors (the genesis anchor is zero, the first committed
    block is one), and links to its predecessor by that predecessor's {!digest}.

    Rust assembles this stream in the executor's subscriber, folding each
    committed sub-DAG into the next header with [number = previous + 1] and
    [parent_hash = previous.digest()]. The port keeps that fold in {!Engine} and
    this module is the block it produces. Only {!create} builds a block, so its
    cached digest is always consistent with its fields. *)

open Tn_types
open Tn_consensus

(** The block number: the count of ancestor blocks, genesis anchor {!genesis}
    (Rust's [u64], documented as "the number of ancestor blocks; the genesis
    block has a number of zero"). A monotone counter, never an index into a
    collection, so it is its own type. *)
module Number : sig
  type t

  val genesis : t
  (** Zero — the genesis anchor's number, below the first committed block. *)

  val succ : t -> t
  (** The next block's number. Total (saturates at the maximum representable
      value, unreachable in any finite run). *)

  val to_int : t -> int
  (** The height as a plain integer, for display and assertions. *)

  val to_int64 : t -> int64
  (** The value as it enters the digest pre-image: an 8-byte little-endian
      field, matching Rust's [number.to_le_bytes()]. *)

  val equal : t -> t -> bool
  (** Numeric equality of two heights. *)

  val compare : t -> t -> int
  (** Numeric ordering of two heights. *)

  val to_string : t -> string
  (** The height rendered in decimal. *)
end

type t

val genesis_parent : Digests.Output_digest.t
(** The parent digest the {e first} committed block links to — the anchor of the
    chain. Rust uses the digest of the default [ConsensusHeader] (number zero,
    wrapping a default sub-DAG built from a default certificate); reproducing
    that byte-for-byte would need a [Certificate::default] escape hatch this
    port's types deliberately forbid — a certificate exists only as proof of a
    verified quorum — so the anchor is a distinct documented constant.
    Aligning it with Rust's exact bytes is deferred to the codec/crypto chunk,
    alongside the concrete-hash swap the whole port defers. *)

val create :
  parent_hash:Digests.Output_digest.t ->
  sub_dag:Sub_dag.t ->
  number:Number.t ->
  t
(** A block at height [number] extending [parent_hash] with [sub_dag]. The digest
    is computed once from the frozen pre-image and cached. *)

val parent_hash : t -> Digests.Output_digest.t
(** The digest of the block this one extends (the chain anchor for the first). *)

val sub_dag : t -> Sub_dag.t
(** The committed sub-DAG this block records. *)

val number : t -> Number.t
(** This block's height in the chain. *)

val preimage : t -> string
(** The digest pre-image, {e without} the domain tag: the 32-byte [parent_hash],
    then the 32-byte {!Tn_consensus.Sub_dag.digest}, then the 8-byte
    little-endian {!Number}, then 32 zero bytes — Rust's currently-unused [extra]
    ([B256::default()]) field, folded in exactly as Rust folds it. This byte
    layout is the frozen wire-compatibility contract: the exact field order of
    Rust's [ConsensusHeader::digest_from_parts]. A later codec/crypto chunk may
    change only the hash function, never this layout. *)

val digest : t -> Digests.Output_digest.t
(** Domain-tagged protocol hash of {!preimage}. Rust's [ConsensusHeader] hashes
    the pre-image with no domain tag; the tag is prepended here for the same
    port-wide digest domain separation every other {!Tn_types.Digests} kind
    uses, and that tag (like the concrete hash) is byte-compatibility-deferred. *)

val equal : t -> t -> bool
(** By digest. *)

val compare : t -> t -> int
(** Total order by digest. *)
