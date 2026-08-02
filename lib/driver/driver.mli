(** The execution driver's core: a pure, fail-stop fold that owns the
    consensus-chain accumulator and the engine and never owns the world.

    One {!step} is the whole pipeline in the upstream order: mint-and-attach
    through {!Subscriber.receive} (the subscriber's eager locals,
    [executor/src/subscriber.rs:367-371]), execute through
    [Tn_engine.Engine.execute], and only AFTER the execute succeeds advance
    the forwarding watermark ([run_epoch.rs:547-567]) - the consensus NUMBER
    that [check_output_continuity] keys recovery on
    ([run_epoch.rs:883-908]). A driver that mints its own numbers always
    hands the engine the next contiguous output, so no continuity classifier
    sits in front of the engine (design patch P1): contiguity is a property
    of the mint, not a runtime check.

    Cold start only (D4): {!create} seats the engine at a {!Chain_spec.t}'s
    genesis facts. There is no resumed constructor, because
    [Tn_engine.Engine.create] unconditionally starts from the configured
    anchor and the port has no durable body store to re-fold from; the
    consensus-chain half of resumption already exists
    ([Tn_execution.Consensus_chain.resume]) and waits on an engine
    counterpart. No inconsistent (engine, chain) pair is constructible.

    Fail-stop: every error arm returns NO driver ({!Outcome.error},
    {!Outcome.t}), mirroring telcoin's engine task halting in process with no
    retry and no skip arm ([executor/src/subscriber.rs:588-605]). The epoch
    seal is deliberately NOT an error under this rule: {!fold} returns a
    sealed driver ([Outcome.Sealed]) because the seal demands
    {!begin_epoch}, and that demand is a function of the very driver a
    halted arm would have destroyed. *)

type t
(** The driver: the subscriber's accumulator, the engine, and the forwarding
    watermark, advanced together or not at all. Immutable: {!step} returns
    the advanced driver and never touches its argument. *)

val create : Chain_spec.t -> committee:Tn_types.Committee.t -> t
(** Cold start from one chain's starting facts: the engine over
    {!Chain_spec.engine_config} (so the chain id, basefee address, genesis
    anchor, ancestor hashes and world all come from the spec), the
    accumulator at [Tn_execution.Consensus_chain.genesis], and the watermark
    at the consensus genesis number. The committee stays the caller's
    argument: upstream reads it back from the registry at epoch entry, and
    the port has no registry reader ([tn-reth/src/lib.rs:1867-1913]). *)

val step :
  t ->
  Tn_consensus.Sub_dag.t ->
  bodies:Batch_store.t ->
  address_of:(Tn_types.Authority_id.t -> Tn_types.Units.Address.t option) ->
  (t * Outcome.advance, Outcome.error) result
(** Fold ONE committed sub-DAG: mint, attach, execute, then advance the
    watermark. Bodies and the address table arrive per call - the driver
    must not pretend to own a database. On [Error] nothing else comes back:
    the mint and the speculative execution are discarded together, so a
    caller holds either the driver before the output or the driver after
    it, never a half-stepped one. Two refusals fire BEFORE minting, in this
    order: a SEALED driver refuses every output with
    [Outcome.Sealed_needs_handoff], without consulting the engine (the
    epoch handoff, {!begin_epoch}, is owed first); and an output whose
    leader epoch is not the installed committee's epoch is refused with
    [Outcome.Epoch_mismatch] (H8's [InvalidPackEpoch],
    [storage/src/consensus.rs:732-765]) - so neither refusal consumes a
    consensus number. *)

val fold :
  t ->
  Tn_consensus.Sub_dag.t list ->
  bodies:Batch_store.t ->
  address_of:(Tn_types.Authority_id.t -> Tn_types.Units.Address.t option) ->
  t Outcome.t
(** {!step} over a committed stream, with three terminal shapes. A genuine
    defect halts the fold with the contiguous prefix of {!Outcome.advance}s
    that DID execute and no driver ([Halted], fail-stop). An epoch seal is
    NOT a defect: the fold stops BEFORE stepping the sealed driver and
    returns it with the executed prefix and the unconsumed suffix
    ([Sealed]) - {!begin_epoch} on that driver and a fold of that suffix
    resume the chain, upstream's routine boundary crossing
    ([subscriber.rs:362], [run_epoch.rs:142]). An all-good, still-running
    stream returns the advanced driver with every advance in order
    ([Advance]). [Outcome.Sealed_needs_handoff] therefore never reaches a
    fold caller: it is {!step}'s refusal, and the fold pre-empts it. *)

val last_forwarded : t -> Tn_execution.Consensus_block.Number.t
(** The forwarding watermark (D5): the consensus number of the last output
    the engine successfully executed, [Number.genesis] before the first.
    Advanced strictly AFTER [Tn_engine.Engine.execute] succeeds - the leader
    ROUND upstream also tracks is a different scalar for a different job
    (bounding the recovery rescan) and deliberately has no counterpart
    here. *)

val engine : t -> Tn_engine.Engine.t
(** The engine as of the last successful step: how a caller reaches the
    execution tip, the rolling [BLOCKHASH] window, the accrued leader counts
    and the epoch phase without this module re-exporting them. *)

val is_sealed : t -> bool
(** Whether the engine's epoch has sealed ([Tn_engine.Engine.is_sealed]): the
    next {!step} would be refused, and the epoch handoff is owed. *)

val closed_at : t -> Tn_types.Units.Timestamp.t option
(** The commit timestamp of the output whose execution sealed the epoch -
    [Tn_batch.Output.committed_at] of the closing output, which IS the
    closing block's own timestamp, because every execution block takes the
    output's commit time ([tn-reth/src/payload.rs:93-106]). [None] while the
    epoch is running. *)

val next_boundary : t -> Tn_types.Units.Timestamp.t option
(** The boundary {!begin_epoch} would install: {!closed_at} plus the spec's
    epoch duration (H9: anchored to the closing BLOCK's timestamp, never to
    the previous boundary and never to a clock,
    [tn-reth/src/lib.rs:1832-1836], [run_epoch.rs:140-145]), so a closing
    commit that overshoots the old boundary lengthens the next epoch's
    window rather than silently shortening it. [None] while running:
    mid-epoch there is no closing commit to anchor to. *)

(** Why {!begin_epoch} can refuse. The first two arms are the driver's own
    guards; the third passes the engine's refusal through unchanged. *)
type handoff_error =
  | Not_sealed
      (** The epoch is still running. [Tn_engine.Engine.begin_epoch]
          deliberately does NOT check this (H12): called mid-epoch it clears
          leader counts no closing block has rooted, silently. The driver
          owns the guard, so that silence is unreachable through it. *)
  | Committee_epoch of {
      installed : Tn_types.Units.Epoch.t;
          (** The installed committee's epoch. *)
      proposed : Tn_types.Units.Epoch.t;
          (** The argument committee's epoch. *)
    }
      (** The proposed committee's epoch does not strictly exceed the
          installed one: a stale committee must never install silently.
          This is the HANDOFF-side epoch guard; the per-output analogue of
          TN's hard [InvalidPackEpoch] refusal
          ([storage/src/consensus.rs:732-765], H8) is {!step}'s
          [Outcome.Epoch_mismatch]. *)
  | Engine_refused of Tn_engine.Engine.error
      (** [Tn_engine.Engine.begin_epoch] itself refused. Through THIS
          function the proposed boundary is {!next_boundary} =
          [closed_at + duration], strictly past the sealed frontier for any
          positive duration - but the strict-advance comparison belongs to
          the engine, nothing here re-derives it, and this library does not
          claim the arm unreachable (P12). *)

val handoff_error_to_string : handoff_error -> string
(** Human rendering, one arm per variant; epochs and timestamps render as
    decimal. *)

val begin_epoch :
  t -> committee:Tn_types.Committee.t -> (t, handoff_error) result
(** The epoch handoff, in guard order: refuse unless sealed ({!Not_sealed} -
    the guard the engine deliberately lacks, H12); refuse a committee whose
    epoch does not strictly advance ({!Committee_epoch}, H8); then
    [Tn_engine.Engine.begin_epoch] at {!next_boundary} =
    [closed_at + epoch_duration] (H9/D3). On [Ok] the driver runs again with
    the counts cleared and [committee] installed, while the accumulator, the
    watermark, the execution tip, the world and the BLOCKHASH window all
    survive (H13): the consensus chain is global across epochs (H8) and the
    engine is threaded, never re-created. The committee stays the CALLER's
    argument: upstream reads it back from the registry at epoch entry, and
    the port has no registry reader ([tn-reth/src/lib.rs:1867-1913]). *)
