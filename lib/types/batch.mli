(** Worker batch: the port of Rust [Batch] and [SealedBatch]
    (crates/types/src/worker/sealed_batch.rs:61-200, telcoin-network @
    5dbb764e).

    FROZEN PREIMAGE CONTRACT: {!preimage} is the exact BCS byte string Rust
    hashes ([bcs::to_bytes], codec.rs:69-71): ULEB128 tx count, then per tx a
    ULEB128 length + the raw EIP-2718 bytes; epoch as u32 LE; beneficiary as
    a LENGTH-PREFIXED byte string (0x14 then 20 raw bytes, the alloy
    [FixedBytes] serde routes through bcs [serialize_bytes]); base fee as u64
    LE; worker id as u16 LE. [received_at] contributes ZERO bytes
    ([#[serde(skip)]], sealed_batch.rs:86-88). Pinned by golden vectors V1-V7
    (test/batch_vectors.ml, emitted by a Rust oracle pinned to bcs 0.1.6,
    blake3 1.8.3, alloy-primitives 1.5.7). A future crypto chunk may change
    only the hash function and the domain-tag policy around it, never this
    layout. *)

type t
(** A batch: raw EIP-2718 transaction byte strings plus the epoch,
    beneficiary, base fee, and worker id that peers validate against.
    Immutable. *)

val make :
  transactions:string list ->
  epoch:Units.Epoch.t ->
  beneficiary:Units.Address.t ->
  base_fee_per_gas:Units.Base_fee.t ->
  worker_id:Units.Worker_id.t ->
  t
(** Total; [received_at] starts [None]. An empty [transactions] list is
    representable on purpose: peers reject it as [Empty_batch] (a
    Fatal-penalty VALIDATION error, reachable when the builder skips every
    pending tx), so the type must not forbid it. *)

val default : t
(** Rust [Batch::default()] (sealed_batch.rs:165-176): no transactions, epoch
    0, zero beneficiary, worker 0, base fee {!Units.Base_fee.min_protocol}.
    Its preimage is golden vector V1. *)

val transactions : t -> string list
(** Raw EIP-2718 encodings, in batch order. *)

val epoch : t -> Units.Epoch.t
(** The epoch the batch was built for (Rust [u32]). *)

val beneficiary : t -> Units.Address.t
(** The building worker's own fee-recipient address. *)

val base_fee_per_gas : t -> Units.Base_fee.t
(** The base fee the batch was built against; epoch-constant per worker. *)

val worker_id : t -> Units.Worker_id.t
(** The producing worker's index (Rust [u16]). *)

val received_at : t -> Units.Timestamp.t option
(** Stamped only by a RECEIVING node (worker handler.rs:284-285 and the batch
    fetcher); metrics-only, excluded from both the digest and the wire. *)

val with_received_at : t -> Units.Timestamp.t -> t
(** Rust [set_received_at], persistent-update style. *)

val codec : t Tn_codec.Bcs.t
(** The BCS wire codec, byte-exact with Rust bcs 0.1.6 (the sync stream's
    [Data] payload carries a bare [Batch], stream_codec.rs:80-113).
    [encode] = {!preimage}; decode sets [received_at] to [None] (the
    serde-skip default) and rejects trailing bytes. *)

val preimage : t -> string
(** The frozen digest preimage: [Bcs.encode codec t]. See the module
    comment. *)

val digest : t -> Digests.Batch_digest.t
(** Protocol hash of [Batch_digest.domain ^ preimage] through the [Tn_crypto]
    seam, following [Header]'s precedent (header.ml:96-97). Rust hashes the
    BARE preimage with blake3 and no domain tag (sealed_batch.rs:116-124);
    hash byte-compat (real BLAKE3, tag dropped) is [tn_crypto_blst]'s
    obligation, while the preimage bytes are frozen already. *)

val max_batch_gas : Units.Epoch.t -> int64
(** 30_000_000. Fork-blind: the epoch argument is accepted and ignored,
    mirroring sealed_batch.rs:190-194 ("can change in the future at a
    fork"). *)

val max_batch_size : Units.Epoch.t -> int
(** 1_000_000 bytes, fork-blind likewise (sealed_batch.rs:196-200). *)

val equal : t -> t -> bool
(** Structural on all six fields INCLUDING [received_at], mirroring the Rust
    derive (sealed_batch.rs:62). *)

(** A batch paired with a CLAIMED digest. Deliberately not correct by
    construction: Rust's [SealedBatch::new] "does not verify the provided
    digest matches" (sealed_batch.rs:26-31), and validator rule 1
    ([Invalid_digest]) exists precisely to catch a wrong claim. The verified
    witness is the validator's [Valid.t]. *)
module Sealed : sig
  type nonrec batch = t
  (** The unsealed batch type, re-exported for this signature. *)

  type t
  (** A {!batch} paired with its claimed digest. *)

  val seal : batch -> t
  (** Compute the digest and pair it: Rust [Batch::seal_slow]
      (sealed_batch.rs:159-162). The one constructor that guarantees digest
      correctness. *)

  val claim : batch:batch -> digest:Digests.Batch_digest.t -> t
  (** Pair WITHOUT verification: Rust [SealedBatch::new] / [Batch::seal].
      For wire ingress and adversarial tests. *)

  val batch : t -> batch
  (** The carried batch, digest claim dropped (Rust [unseal]). *)

  val digest : t -> Digests.Batch_digest.t
  (** The claimed digest, verified only by validator rule 1. *)

  val split : t -> batch * Digests.Batch_digest.t
  (** Both components; the inverse of {!seal} only when the claim is honest
      (Rust [split], sealed_batch.rs:48-53). *)

  val equal : t -> t -> bool
  (** Structural on both components. *)
end
