(** The scalar codecs every chunk-44 wire leaf shares.

    Each one states a Rust byte class ONCE, so a leaf module never restates
    the [sized_bytes] versus [fixed_bytes] asymmetry that GT:167-169 warns
    about: a [Digest<32>] and a [BlockHash] are length-prefixed
    ([0x20] then 32 bytes) while an [AuthorityIdentifier] is 32 BARE bytes. *)

val digest : Tn_crypto.Digest.t Tn_codec.Bcs.t
(** A Rust [Digest<32>]: ULEB128(32) then 32 bytes (GT:167). The port has no
    dedicated newtype for [EpochDigest] or [ConsensusHeaderDigest], so those
    two fields carry the bare {!Tn_crypto.Digest.t} and the distinction lives
    in the field name. *)

val header_digest : Tn_types.Digests.Header_digest.t Tn_codec.Bcs.t
(** {!digest} carried into the port's header-digest newtype. *)

val batch_digest : Tn_types.Digests.Batch_digest.t Tn_codec.Bcs.t
(** {!digest} carried into the port's batch-digest newtype, which is Rust's
    [BlockHash] on the worker surfaces (GT:87, GT:112). *)

val epoch : Tn_types.Units.Epoch.t Tn_codec.Bcs.t
(** [Epoch = u32] little-endian (GT:173). *)

val round : Tn_types.Round.t Tn_codec.Bcs.t
(** [Round = u32] little-endian (GT:173). *)

val authority_id : Tn_types.Authority_id.t Tn_codec.Bcs.t
(** [AuthorityIdentifier]: 32 bytes with NO length prefix, the one asymmetry
    of the digest family (GT:169). *)
