(** [EpochCertificate] (crates/types/src/primary/epoch.rs:199-211, GT:158):
    an aggregate signature over an epoch hash plus the roaring bitmap of the
    authorities that signed.

    The bitmap field carries [#\[serde_as(as = "RoaringBitmapSerde")\]], the
    same adapter [Certificate.signed_authorities] uses, so its bytes are a
    ULEB128 length then {!Roaring.to_bytes}. *)

type t = private {
  epoch_hash : Tn_crypto.Digest.t;  (** [EpochDigest], ULEB128(32)+32B. *)
  signature : Bls_signature.t;  (** The aggregate, ULEB128(48)+48B. *)
  signed_authorities : Roaring.t;  (** Committee indices that signed. *)
}

val make :
  epoch_hash:Tn_crypto.Digest.t ->
  signature:Bls_signature.t ->
  signed_authorities:Roaring.t ->
  t
(** The only constructor. As with {!Epoch_vote}, no verification happens
    here: the quorum rule for epoch certificates lives in the unported
    epoch-manager layer. *)

val codec : t Tn_codec.Bcs.t
val equal : t -> t -> bool
