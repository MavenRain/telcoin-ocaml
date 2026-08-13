(** [ConsensusResult] (crates/types/src/primary/block.rs:120-136, GT:160),
    the signed consensus-output announcement gossiped on the
    consensus-output topic.

    Six fields, no attributes. New to the port. *)

open Tn_types

type t = private {
  epoch : Units.Epoch.t;  (** u32 LE. *)
  round : Round.t;  (** u32 LE. *)
  number : int64;  (** Consensus chain height, u64 LE. *)
  hash : Tn_crypto.Digest.t;  (** [ConsensusHeaderDigest], ULEB128(32)+32B. *)
  validator : Bls_public_key.t;  (** The announcing validator's BLS key. *)
  signature : Bls_signature.t;  (** Its signature over the result. *)
}

val make :
  epoch:Units.Epoch.t ->
  round:Round.t ->
  number:int64 ->
  hash:Tn_crypto.Digest.t ->
  validator:Bls_public_key.t ->
  signature:Bls_signature.t ->
  t
(** The only constructor. The executor layer that would verify the signature
    is not ported (design section 6), so this is a wire value only. *)

val codec : t Tn_codec.Bcs.t
val equal : t -> t -> bool
