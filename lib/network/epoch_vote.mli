(** [EpochVote] (crates/types/src/primary/epoch.rs:169-182, GT:156), the
    signed vote a validator gossips on the epoch-vote topic.

    Four fields, no attributes. New to the port. *)

open Tn_types

type t = private {
  epoch : Units.Epoch.t;  (** u32 LE. *)
  epoch_hash : Tn_crypto.Digest.t;  (** [EpochDigest], ULEB128(32)+32B. *)
  public_key : Bls_public_key.t;  (** The voter's BLS key, ULEB128(96)+96B. *)
  signature : Bls_signature.t;  (** Its signature, ULEB128(48)+48B. *)
}

val make :
  epoch:Units.Epoch.t ->
  epoch_hash:Tn_crypto.Digest.t ->
  public_key:Bls_public_key.t ->
  signature:Bls_signature.t ->
  t
(** The only constructor. Signature verification is NOT performed here: the
    epoch-manager layer that would verify it is not ported (design section 6),
    so this type is a wire value and never a proof. *)

val codec : t Tn_codec.Bcs.t
val equal : t -> t -> bool
