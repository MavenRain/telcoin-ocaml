(** ConsensusOutput's payload attachment (crates/types/src/primary/
    output.rs:42-64, executor subscriber.rs:430-551, telcoin-network @
    5dbb764e) made pure: the worker batch fetch becomes a [lookup]
    dependency, and the authority execution-address table becomes
    [address_of]. The port's sub-DAGs carry batch digests only; this module
    is where batch BODIES join them, WITHOUT touching
    {!Tn_consensus.Sub_dag}'s frozen preimage. *)

type t
(** A committed consensus block with every referenced batch body attached,
    certificate-by-certificate in sub-DAG header order (leader last). *)

(** The two ways attachment can fail, both protocol-fatal upstream. *)
type error =
  | Missing_batch of Tn_types.Digests.Batch_digest.t
      (** A payload digest [lookup] could not supply: TN's fatal
          [MissingFetchedBatch] protocol violation (subscriber.rs:510-514). *)
  | Unknown_authority of Tn_types.Authority_id.t
      (** No execution address for a header author or the leader: TN's
          [UnknownAuthority]. *)

val error_to_string : error -> string
(** Human rendering, one arm per variant; digests and authority ids render
    as lowercase hex. *)

val attach :
  consensus:Tn_execution.Consensus_block.t ->
  lookup:(Tn_types.Digests.Batch_digest.t -> Tn_types.Batch.t option) ->
  address_of:(Tn_types.Authority_id.t -> Tn_types.Units.Address.t option) ->
  (t, error) result
(** Walk every header's [(digest, worker_id)] payload in commit order,
    resolving each digest through [lookup]. A digest under two certificates
    resolves TWICE, mirroring TN's duplicate-clone (subscriber.rs:480-509;
    the adiri epoch carve-out is not ported): the engine later executes it
    as a second block whose transactions self-invalidate. WITHIN one header
    TN's payload is an [IndexMap] keyed on digest (header.rs:22-24), which
    cannot hold a duplicate; the port's [Header.payload] is a plain list and
    neither this function nor the header builder re-checks uniqueness, so a
    hand-built duplicate pair resolves twice and plans one block more than
    TN would emit. Such a header is unrepresentable to TN (its recomputed
    digest would differ, so it cannot certify), leaving an accept-what-TN-
    cannot-express asymmetry rather than a live split (chunk-34 review).
    One more edge: this function resolves every header author and the
    leader unconditionally, where TN resolves no address on an all-empty
    output (subscriber.rs:439-442) and the leader only on the close-epoch
    branch, so a missing address-table entry halts here where TN skips;
    unreachable while [address_of] is total on the committee. The digest
    list and the certified batches are derived together, so TN's
    [ConsensusOutputUnevenBatches] guard (engine payload_builder.rs:60-86)
    is discharged by construction. *)

val consensus : t -> Tn_execution.Consensus_block.t
(** The consensus-chain block the payload was attached to. *)

val output_digest : t -> Tn_types.Digests.Output_digest.t
(** [Consensus_block.digest]: both the [parent_beacon_block_root] slot and
    the XOR operand of every block's mix_hash. *)

val batch_digests : t -> Tn_types.Digests.Batch_digest.t list
(** Flat digest list in execution order; its length equals the flattened
    batch count by construction. *)

val certified : t -> (Tn_types.Units.Address.t * Tn_types.Batch.t list) list
(** Per-certificate beneficiary address and batches, header order: the
    [CertifiedBatch] image (output.rs:31-40). *)

val leader_address : t -> Tn_types.Units.Address.t
(** The leader's execution address: the beneficiary of a close-epoch empty
    block (payload_builder.rs:116-160). *)

val leader_epoch : t -> Tn_types.Units.Epoch.t
(** The leader header's epoch: the argument TN feeds [max_batch_gas]
    (payload_builder.rs:41,172). NOT interchangeable with a batch's own
    epoch field, which certified batches may set freely (rule 3 never runs
    on this path). *)

val committed_at : t -> Tn_types.Units.Timestamp.t
(** [Sub_dag.commit_timestamp]: every block in this output carries it. *)

val nonce : t -> Tn_types.Units.Sequence_number.t
(** The leader nonce [(epoch << 32) | round] every block header carries
    ([Sub_dag.sequence_number]). *)

val closes_epoch : t -> epoch_boundary:Tn_types.Units.Timestamp.t -> bool
(** The recompute rule and nothing else: [committed_at >= boundary]
    (run_epoch.rs:553-556, [>=] not [>]). [close_epoch] is never on the
    wire; a deserialized output always starts false and MUST be recomputed
    by the caller, exactly as Rust's [EpochManager::process_output] does
    (output.rs:79-83). *)
