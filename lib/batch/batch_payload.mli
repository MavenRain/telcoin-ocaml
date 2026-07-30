(** The engine-side decode layer TN runs on certified batches
    (tn-reth/src/lib.rs:808-848, telcoin-network @ 5dbb764e): drop
    undecodable transactions and continue, never error, so every honest
    node derives the same block from the same certified bytes (issue #933).
    Sits ABOVE {!Tn_evm.Block_execution}, which by its own contract errors
    instead of skipping (block_execution.mli punts the drop to "a builder
    above"); a builder that drops simply hands it a shorter list. *)

val executable_txs : Tn_types.Batch.t -> Tn_evm.Tx_envelope.t list
(** For each raw transaction, in batch order: accept iff
    {!Tx_shape.decode_and_recover} accepts (TN's exact gate), then
    materialise the executable envelope via {!Tn_evm.Tx_envelope.decode_2718}
    on the canonical bytes (stripping a [0x00] legacy tag first, so a
    tagged-legacy transaction executes here exactly as in TN, under the
    untagged hash). Dropped classes, each deterministic:
    - TN-undecodable or unrecoverable bytes: TN drops them too
      (lib.rs:821-835).
    - TN-decodable but port-unrepresentable: a well-formed EIP-4844
      envelope, or a nonce or gas limit in [2^62, 2^64). The drop's
      equivalence with TN partitions by reachability through honest
      validation. The nonce class passes all eight validator rules, and
      there it holds: no account can reach nonce [2^62], reth wraps
      NonceTooHigh as InvalidTx and hits the skip-and-continue arm
      (lib.rs:855-865). The 4844 and high-gas classes are blocked BEFORE
      certification (validator rules 6 and 7), so they reach this layer
      only under a Byzantine quorum, and for them execute-then-skip is
      UNVERIFIED from this repository (revm is not vendored; TN's header
      shape is post-Cancun, so a type-3 whose blob fee clears
      [excess_blob_gas = 0] may execute rather than skip). Equivalence is
      an argument pinned here and by test, not a differential run; any
      future differential gate against a Rust node must include one batch
      from EACH class. *)
