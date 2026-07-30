(** The port of [BatchValidator::validate_batch]
    (crates/batch-validator/src/validator.rs:39-82, telcoin-network @
    5dbb764e): TN's exact rule order, all 12 error variants in Rust
    declaration order, and the peer-penalty map that makes error identity
    observable. Pure: no clock, no chain state, no signature-of-authorship
    check (TN trusts libp2p for batch provenance, validator.rs:14-17).
    [submit_txn_if_mine] is dead code upstream (no production call site at
    the pinned commit) and is not ported.

    Fork-blind on purpose: the only transaction-type denylist is EIP-4844.
    KNOWN GAP, NOT FIXED: TN has no EIP-7702 filter, so type-4 transactions
    pass batch validation; the port models testnet and a test pins the
    pass. *)

(** Peer penalty severities ([Penalty] from tn_network_libp2p), the currency
    the worker network charges a peer for an invalid batch. *)
type penalty = Mild | Medium | Severe | Fatal

(** All 12 arms of Rust [BatchValidationError], declaration order preserved
    (crates/types/src/worker/sealed_batch.rs:261-309). [Canonical_chain] and
    [Calculate_max_possible_gas] are DEAD at 5dbb764e (constructed nowhere in
    production) and are kept so the penalty map stays total and 1:1 with the
    exhaustive match a networking chunk must mirror (worker
    network/error.rs:83-103). *)
type error =
  | Invalid_digest
      (** Rule 1: the recomputed digest differs from the claimed one. *)
  | Canonical_chain of { block_hash : Tn_keccak.t }
      (** DEAD upstream: parent-not-found on a disabled check. *)
  | Empty_batch
      (** Rule 4: the transaction list is empty. *)
  | Header_max_gas_exceeds_gas_limit of
      { total_possible_gas : int64; gas_limit : int64 }
      (** Rule 7: unsigned u64 gas sum > [Batch.max_batch_gas]; equality
          passes. Both fields carry raw u64 bits. *)
  | Calculate_max_possible_gas
      (** DEAD upstream: never constructed. *)
  | Header_transaction_bytes_exceeds_max of int
      (** Rule 4: summed raw tx byte length > [Batch.max_batch_size];
          equality passes. Carries the offending total. *)
  | Recover_transaction of
      { digest : Tn_types.Digests.Batch_digest.t; message : string }
      (** Rule 5: some tx failed decode or signer recovery. The digest is the
          BATCH digest; the message is human-only (reth discards the alloy
          error before stringifying). *)
  | Invalid_base_fee of
      { expected_base_fee : Tn_types.Units.Base_fee.t;
        base_fee : Tn_types.Units.Base_fee.t
      }
      (** Rule 8: strict inequality with the epoch-constant snapshot. *)
  | Invalid_worker_id of
      { expected_worker_id : Tn_types.Units.Worker_id.t;
        worker_id : Tn_types.Units.Worker_id.t
      }
      (** Rule 2: the batch names another worker. *)
  | Invalid_tx_4844 of Tn_keccak.t
      (** Rule 6: the FIRST EIP-4844 transaction, by ITS OWN tx hash (not
          the batch digest). *)
  | Gas_overflow
      (** Rule 7: the u64 gas sum overflowed before the cap compare. *)
  | Invalid_epoch of
      { expected : Tn_types.Units.Epoch.t; found : Tn_types.Units.Epoch.t }
      (** Rule 3: the batch names another epoch. *)

val error_to_string : error -> string
(** Human rendering, one arm per variant, mirroring each thiserror display
    string verbatim (sealed_batch.rs:261-309). Hashes render as
    [0x]-prefixed full lowercase hex, alloy [FixedBytes] Display's
    non-alternate form; u64 payloads render as unsigned decimal. *)

val penalty : error -> penalty
(** The exact map of the worker network's error.rs:83-103:
    [Canonical_chain] Mild; [Invalid_epoch] and [Invalid_tx_4844] Medium;
    [Recover_transaction] Severe; every other arm Fatal. Exhaustive match,
    NO catch-all: adding a variant must force a decision here. Enforcement
    (peer scoring) is a networking-chunk concern; this is the pure map. *)

(** What validation needs from a transaction decoder. Production instance:
    {!Tx_shape_decoder}. Tests may inject counterfeits to probe rule order
    without crafting full wire bytes. *)
module type TX_DECODER = sig
  type tx
  (** A decoded batch transaction. *)

  val decode_and_recover : string -> (tx, string) result
  (** Accept iff TN's rule-5 composite (EIP-2718 decode then checked signer
      recovery) accepts; the string is message-only. *)

  val hash : tx -> Tn_keccak.t
  (** The TN tx hash, for [Invalid_tx_4844]. *)

  val is_eip4844 : tx -> bool
  (** The rule-6 classifier. *)

  val gas_limit : tx -> int64
  (** Declared gas, raw u64 bits, for rule 7. *)
end

(** The validator's decoder-independent surface. *)
module type S = sig
  (** Proof that a specific sealed batch passed all eight rules: obtainable
      only from {!validate}. Deliberately NOT demanded by the execution
      seam: TN executes certified batches without re-validation (the
      is_certified bypass), so threading this witness into execution would
      misstate the trust boundary. Its consumer is the (deferred) vote/ack
      path. *)
  module Valid : sig
    type t
    (** The validated batch paired with its now-verified digest. *)

    val batch : t -> Tn_types.Batch.t
    (** The batch every rule passed on. *)

    val digest : t -> Tn_types.Digests.Batch_digest.t
    (** The claimed digest, now verified equal to the recomputation. *)
  end

  type t
  (** The per-epoch snapshot: Rust [BatchValidator]'s three pure fields
      (worker_id, epoch, base_fee); reth_env/tx_pool serve only the dead
      [submit_txn_if_mine] and are not ported. *)

  val make :
    worker_id:Tn_types.Units.Worker_id.t ->
    epoch:Tn_types.Units.Epoch.t ->
    base_fee_per_gas:Tn_types.Units.Base_fee.t ->
    t
  (** Snapshot taken at epoch start; TN recreates the validator each epoch
      (validator.rs:18-33). *)

  val validate : t -> Tn_types.Batch.Sealed.t -> (Valid.t, error) result
  (** The eight rules in TN's exact order (validator.rs:39-82),
      short-circuiting on the FIRST failure so a multiply-invalid batch
      reports the same arm (and earns the same peer penalty) as Rust:
      (1) digest recompute; (2) worker id; (3) epoch; (4) summed raw bytes,
      [Empty_batch] on the empty list, equality allowed at the cap;
      (5) per-tx decode + signer recovery in list order, deterministic
      first failure (pinned where Rust's rayon order is unobservable);
      (6) first EIP-4844 by tx hash; (7) u64-checked gas sum then cap,
      equality allowed; (8) strict base-fee equality. *)
end

module Make (D : TX_DECODER) : S
(** Build a validator over any decoder honouring {!TX_DECODER}. *)

module Tx_shape_decoder : TX_DECODER with type tx = Tx_shape.t
(** The production decoder: {!Tx_shape}'s composite, with
    [decode_and_recover] mapped through {!Tx_shape.error_to_string}. *)

module Validator : S
(** The production validator: [Make (Tx_shape_decoder)]. *)
