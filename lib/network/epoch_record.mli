(** [EpochRecord] (crates/types/src/primary/epoch.rs:21-39, GT:154), the
    epoch-boundary record a primary serves from the [EpochRecord] request and
    gossips beside its certificate.

    Six fields, no options and no serde attributes, so the BCS form is the
    concatenation of the field codecs in declaration order. The type is new to
    the port; it is hosted in [tn_network] for now because nothing below the
    network layer consumes it. *)

open Tn_types

type consensus_num_hash = private {
  number : int64;  (** Consensus chain height, u64 LE. *)
  hash : Tn_crypto.Digest.t;  (** [ConsensusHeaderDigest], ULEB128(32)+32B. *)
}
(** [ConsensusNumHash] (primary/block.rs:104-110). *)

type t = private {
  epoch : Units.Epoch.t;  (** u32 LE. *)
  committee : Bls_public_key.t list;  (** The epoch's committee keys, in order. *)
  next_committee : Bls_public_key.t list;  (** The next epoch's keys. *)
  parent_hash : Tn_crypto.Digest.t;  (** The previous [EpochRecord]'s digest. *)
  final_state : Block_num_hash.t;  (** The execution anchor at the boundary. *)
  final_consensus : consensus_num_hash;  (** The consensus anchor. *)
}

val make_consensus_num_hash :
  number:int64 -> hash:Tn_crypto.Digest.t -> consensus_num_hash
(** The only constructor of {!consensus_num_hash}. *)

val make :
  epoch:Units.Epoch.t ->
  committee:Bls_public_key.t list ->
  next_committee:Bls_public_key.t list ->
  parent_hash:Tn_crypto.Digest.t ->
  final_state:Block_num_hash.t ->
  final_consensus:consensus_num_hash ->
  t
(** The only constructor: the record carries no invariant beyond its field
    types, and going through a function keeps the literal out of callers so a
    field added later cannot be silently defaulted. *)

val codec : t Tn_codec.Bcs.t
(** Fields in declaration order. Both committee lists are plain sequences: a
    [Vec] carries no order or uniqueness check on decode (design section 2,
    line 181). *)

val equal : t -> t -> bool
