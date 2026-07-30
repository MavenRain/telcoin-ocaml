(** The batch-to-block mapping (engine payload_builder.rs:99-224,
    tn-reth/src/payload.rs:30-120, telcoin-network @ 5dbb764e) as pure
    data: exactly one spec per flattened batch, plus TN's two empty-output
    behaviors. This chunk stops at the spec; constructing
    [Env.Block]/[Block_context] and executing belongs to the engine chunk,
    which alone holds parent state (parent hash/number/base fee for the
    close block) and the material for [Epoch_boundary] commitments
    (withdrawals, keccak of leader BLS sigs). *)

(** One execution block's consensus-derived parameters. *)
module Spec : sig
  type t
  (** The parameters for one batch's block, in flat execution order. *)

  val batch : t -> Tn_types.Batch.t
  (** The batch this block executes. *)

  val batch_digest : t -> Tn_types.Digests.Batch_digest.t
  (** The header's ommers slot (payload.rs:30-107). *)

  val beneficiary : t -> Tn_types.Units.Address.t
  (** The certificate authority's execution address, NOT the batch's own
      beneficiary field (payload_builder.rs:173). *)

  val base_fee : t -> Tn_types.Units.Base_fee.t
  (** The batch's own fee (payload_builder.rs:170-171). *)

  val gas_limit : t -> int64
  (** Always [Batch.max_batch_gas] at the OUTPUT LEADER's epoch
      (payload_builder.rs:41,172), never the batch's own epoch field
      (unpinned on this path: certified batches bypass rule 3) and never
      the batch's gas sum. Identical values while [max_batch_gas] is
      fork-blind; the sourcing matters at the first epoch-dependent
      fork. *)

  val mix_hash : t -> string
  (** 32 bytes: [output_digest XOR batch_digest], the prev_randao
      (payload_builder.rs:191-196). Both operands are [Digest.to_bytes] of
      32-byte digests, so the width is invariant. *)

  val position : t -> Tn_evm.Batch_position.t
  (** Packed [(batch_index lsl 16) lor worker_id] difficulty word
      (config.rs:191), with [batch_index] global across the output. *)

  val nonce : t -> Tn_types.Units.Sequence_number.t
  (** The leader nonce every block of the output carries. *)

  val consensus_root : t -> Tn_types.Digests.Output_digest.t
  (** The [parent_beacon_block_root] slot (payload.rs:117-120). *)

  val timestamp : t -> Tn_types.Units.Timestamp.t
  (** The output's commit timestamp, shared by every block. *)

  val closes_epoch : t -> bool
  (** True only on the LAST spec of a closing output
      ([close_epoch_for_last_batch], output.rs:235-244); the engine chunk
      turns this into an [Epoch_boundary] commitment. *)
end

(** The close-epoch empty block (payload_builder.rs:116-160): zero batch
    digest, mix_hash = the output digest alone, worker 0, leader
    beneficiary; base fee and gas limit come from the PARENT header and are
    therefore the engine chunk's to supply. *)
module Close_spec : sig
  type t
  (** The parameters this chunk can derive for the one empty block. *)

  val beneficiary : t -> Tn_types.Units.Address.t
  (** The leader's execution address. *)

  val mix_hash : t -> string
  (** The raw 32 output-digest bytes, with no batch digest to XOR in. *)

  val consensus_root : t -> Tn_types.Digests.Output_digest.t
  (** The [parent_beacon_block_root] slot, as for every batch block. *)

  val nonce : t -> Tn_types.Units.Sequence_number.t
  (** The leader nonce. *)

  val timestamp : t -> Tn_types.Units.Timestamp.t
  (** The output's commit timestamp. *)
end

(** TN's three output shapes (payload_builder.rs:99-224). *)
type t =
  | Skip
      (** Empty output, epoch not closing: no block at all
          (payload_builder.rs:99-114). *)
  | Close_block of Close_spec.t
      (** Empty output, epoch closing: exactly one empty block. *)
  | Batch_blocks of Spec.t Tn_std.Nonempty.t
      (** One block per batch, execution order. *)

(** The one way planning can fail. *)
type error =
  | Position_out_of_range of { batch_index : int }
      (** {!Tn_evm.Batch_position.of_batch} refused the packed word: the
          flat index's shift would leave the native [int]. *)

val error_to_string : error -> string
(** Human rendering of the one arm. *)

val plan : Output.t -> closes_epoch:bool -> (t, error) result
(** Derive the whole output's block plan. [closes_epoch] comes from
    {!Output.closes_epoch}; passing it explicitly keeps the boundary
    recompute a visible caller obligation, as upstream demands of
    deserializers (output.rs:79-83). *)
