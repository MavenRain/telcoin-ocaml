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

val mint :
  t ->
  Tn_consensus.Sub_dag.t ->
  (Tn_execution.Consensus_block.t, Outcome.error) result
(** The consensus block {!step} would mint for this sub-DAG, advancing nothing.
    THE HOOK THAT CREATES THE RECOVERY GAP: a shell mints, files the block and
    its bodies into a durable store, and only then steps - upstream's
    persist-strictly-before-execute ordering ([state-sync/src/lib.rs:106-121],
    "Make sure we have persisted the consensus output before we execute").
    Without a value available before {!step}, the only thing a shell could
    persist is an {!Outcome.advance}, which exists only after execution, so
    store tip and executed watermark would be equal by construction and no gap
    could exist.

    It applies {!step}'s two pre-mint refusals, in the same order and with the
    same arms - a SEALED driver refuses with [Outcome.Sealed_needs_handoff],
    and an output whose leader epoch is not the installed committee's is
    refused with [Outcome.Epoch_mismatch] - so a record {!step} will refuse can
    never be filed in the first place. The remaining misuse a type cannot
    prevent is minting one sub-DAG and stepping a different one; the shell
    protocol is stated once, here: [mint] -> file -> {!step} -> {!snapshot},
    one sub-DAG at a time. A shell that files and never steps leaves the store
    permanently ahead, which the next [resume] heals by replaying it. *)

val snapshot : t -> Checkpoint.t
(** File what execution left behind: the engine's persisted facts paired with
    the consensus block whose execution produced them. THE SECOND DURABLE
    WRITE, and the one that closes the gap the first opened. The only caller
    of [Checkpoint.of_execution], and with [Checkpoint.genesis] one of the
    only two ways a {!Checkpoint.t} is made in this port - see that
    function's own divergence note for why the pairing is discharged here
    rather than made unrepresentable. The exact counterpart of
    [Tn_consensus.Node.snapshot] ([lib/consensus/node.mli:104-105]). *)

(** Why a resumed driver could not be built. Every arm fires BEFORE anything
    replays, so an [Error] means no output was re-executed and there is no
    driver to speak of; a defect DURING replay comes back as
    [Ok (Outcome.Halted ...)] instead, carrying the prefix that genuinely
    executed. *)
type resume_error =
  | Committee_epoch of {
      supplied : Tn_types.Units.Epoch.t;
          (** The epoch of the committee the caller passed. *)
      checkpoint : Tn_types.Units.Epoch.t;
          (** The epoch the persisted blocks actually executed under. *)
    }
      (** The caller re-supplied a committee from a different epoch than the
          one whose leader counts the checkpoint carries. Refused rather than
          absorbed, because a leader outside the installed committee resolves
          to no execution address and so to no withdrawal, which means a driver
          that installs the wrong committee silently pays nobody rather than
          failing ([lib/engine/engine.mli:131-136]). *)
  | Committee_mismatch of { epoch : Tn_types.Units.Epoch.t }
      (** The caller re-supplied a committee of the RIGHT epoch that is not
          the committee the persisted counts accrued under: the same epoch, a
          different roster. Epoch equality alone cannot witness identity —
          two committees of one epoch differ freely in protocol keys and
          execution addresses ([Tn_types.Committee.equal]) — and resuming
          under the imposter would resolve leaders against the wrong seats,
          the same silent mis-pay {!Committee_epoch} refuses
          ([lib/engine/engine.mli:131-136]). The whole-value comparison
          against [Checkpoint.committee] completes the witness; see the
          epoch-identity divergence on {!resume}. *)
  | Store_epoch of {
      checkpoint : Tn_types.Units.Epoch.t;
      store : Tn_types.Units.Epoch.t;
    }
      (** The checkpoint and the store disagree about which epoch is open, so
          the two durable values are not a matched pair. Deliberately mirrors
          no single upstream site: with {!Committee_epoch} it is one of the
          two persisted witnesses standing in for upstream's fail-hard
          pinned-vs-tip epoch tripwire ([tn-reth/src/lib.rs:1892-1910]), which
          is not ported; see the epoch-identity divergence on {!resume}. One
          skew is NOT this error: a sealed checkpoint at [N] beside a store
          open at [N+1] with nothing filed above the checkpoint is the epoch
          handoff's own crash window, healed rather than refused — see the
          handoff-window divergence on {!resume}. *)
  | Gap of Tn_execution.Consensus_store.miss
      (** The gap could not be collected: the checkpoint is below the store's
          retention, above its tip, forked against it, or the run itself has a
          hole or a broken link. Lifted unchanged, so the store's four
          diagnoses reach the operator intact. *)

val resume_error_to_string : resume_error -> string
(** Human rendering, one arm per variant; delegates to
    [Tn_execution.Consensus_store.miss_to_string] for the lifted arm. *)

val resume :
  Chain_spec.t ->
  committee:Tn_types.Committee.t ->
  checkpoint:Checkpoint.t ->
  store:Tn_execution.Consensus_store.t ->
  address_of:(Tn_types.Authority_id.t -> Tn_types.Units.Address.t option) ->
  (t Outcome.t, resume_error) result
(** Rebuild a driver from its two durable values and heal the gap between them
    — the constructor {!create}'s doc named as missing
    ([lib/driver/driver.mli:15-21]).

    The shape is [Tn_consensus.Node.recover]'s, argument for argument: every
    cold-start argument, plus the persisted state, plus the separate replay
    source, returning a result ([lib/consensus/node.mli:76-129]).
    [checkpoint] plays [persisted]; [store] plays [Committed_log.t].

    In order: refuse unless [committee]'s epoch is the checkpoint's
    ({!Committee_epoch}), [committee] IS the checkpoint's committee
    whole-value ({!Committee_mismatch}), and the checkpoint's epoch is the
    store's ({!Store_epoch}) — save the one healed skew of the
    handoff-window divergence below; collect the gap as
    [Consensus_store.gap store ~after:(Checkpoint.last_executed checkpoint)],
    whose floor is the checkpoint's own executed block and whose ceiling is the
    store's own tip, so neither end is a caller's guess; seat the engine with
    [Engine.resume] and the accumulator with the checkpoint's; then fold the
    gap's sub-DAGs through {!fold} — the SAME function live callers use, with
    each step's bodies coming from the gap's own records rather than from any
    ambient map. Three terminal shapes, all chunk 37's: [Advance] is replay
    then go live, [Sealed] is replay-and-close (upstream's own first-class
    terminal, [run_epoch.rs:224-247]) with the handoff owed before the rest,
    and [Halted] is a defect with the good prefix and no driver.

    POST-CONDITION on [Advance]: {!last_forwarded} equals
    [Replay.upto] of the collected gap, i.e. the store's tip. That is upstream's
    [last_consensus_parent] max recovered as a consequence rather than adopted
    as an anchor; see the divergence below.

    {b Divergence, stated once here — the seed.} Upstream anchors a restarting
    node at [max(store tip, executed tip)], ties to the executed value
    ([state-sync/src/lib.rs:135-151]), and its replay re-forwards each stored
    output VERBATIM ([start_epoch.rs:93-100]) so the max is safe. This function
    RE-MINTS the gap through [Consensus_chain.append], so it must seed strictly
    at the EXECUTED tip: seeding at the store tip would mint the first replayed
    sub-DAG one number too high and fork the chain silently. Re-minting is
    itself an import from a different upstream path — the state-sync forward
    consumer re-derives [digest_from_parts] against its own loop counter and
    hard-errors on a mismatch ([state-sync/src/lib.rs:339-349, 391-401]) — and
    it is taken deliberately, because the port keeps exactly ONE mint
    ([lib/execution/consensus_chain.mli:13-20]) and replay must not become a
    second. The fork check that mint buys upstream is discharged here at
    collection time by [Replay.collect]'s chain verification, so no mid-replay
    comparison remains.

    {b Divergence, stated once here — what replay does not redo.} Six upstream
    replay-vs-live differences, each disposed of: bodies come from the gap's
    records rather than from peers, which is FOLDED because the driver already
    takes bodies per call and owns no database
    ([lib/driver/batch_store.mli:32-33]); the [save_consensus] bypass is FOLDED
    because this function writes nothing; the [check_output_continuity] bypass
    ([run_epoch.rs:895-908]) is DISSOLVED because the port has no continuity
    classifier at all ([lib/driver/driver.mli:10-13]); replay's legitimate
    re-forwarding at or below the watermark is DISSOLVED because the gap's
    floor is strictly above it, which is also why upstream's digest-walk
    THROUGH already-applied heights ([state-sync/src/lib.rs:402-407]) has no
    expression here; the per-step [wait_for_execution] gate
    ([state-sync/src/lib.rs:409-427], [run_epoch.rs:240-252]) is IRREDUCIBLE
    BUT VACUOUS, because {!step} returns only after [Engine.execute] returned
    [Ok] so "the engine has caught up" is the fold's own sequencing; and the
    consensus-output broadcast and signature publication replay bypasses
    ([subscriber.rs:284-329]) are IRREDUCIBLE AND REAL but EMPTY today, since
    the port has neither networking nor signing at this seam — a future network
    chunk inherits that asymmetry and is told so here rather than discovering
    it as a recovery bug. The follower/validator ExEx asymmetry
    ([subscriber.rs:174-180]) is in the same class.

    {b Divergence, stated once here — the epoch boundary.} A gap whose entries
    cross an epoch boundary is NOT a hard error here. Upstream refuses one
    outright ("Crossed epoch boundary with missing execution!",
    [start_epoch.rs:83-92]) because at that point it has not yet read the next
    committee from the registry. The port's committee is the caller's argument
    at every installation site, so the crossing is returned as
    [Outcome.Sealed], a demand for {!begin_epoch} before the rest — which is
    the same arm a live fold returns and carries the same driver. The two
    guards this rests on are cited, not assumed: {!step} tests the phase FIRST
    and refuses a sealed driver before minting ([lib/driver/driver.ml:65-73]),
    and an output whose leader epoch is not the installed committee's is
    refused with [Outcome.Epoch_mismatch] before minting
    ([lib/driver/driver.ml:69-72]). Weakening either turns the epoch-boundary
    sweep red rather than turning this divergence unsafe.

    {b Divergence, stated once here — the handoff window.} The epoch handoff
    is two durable writes with no transaction around them: the shell rolls
    the store ([Consensus_store.open_epoch], write 1) and only then files the
    handed-off driver's checkpoint ({!snapshot}, write 2). A crash between
    them leaves a sealed checkpoint at [N] beside a store open at [N+1] — a
    pair strict epoch equality would refuse forever, with no healing API,
    and one the six step-scoped crash sites C1–C6 cannot cover because it
    lies between steps. [resume] therefore accepts exactly that one
    redo-able skew — the checkpoint is sealed, the store's epoch is the
    SUCCESSOR of the checkpoint's, and the collected gap above the
    checkpoint is empty — by resuming to the sealed driver
    ([Outcome.Sealed] with nothing to replay), so the caller re-runs
    {!begin_epoch} (idempotent on this driver, pinned by the C6 and C7
    crash-site tests) and skips the already-done roll. Every other
    inequality stays {!Store_epoch}: a skew of two or more epochs is not one
    crashed handoff, and a skewed store holding records above the sealed
    checkpoint carries a next epoch this checkpoint cannot replay. Reversing
    the shell's two writes would not close the window, only move it (a
    running checkpoint at [N+1] against a store still at [N] is refused by
    the same guard), which is why the write order and the acceptance are
    stated here, once, so shell and driver cannot drift.

    {b Divergence, stated once here — epoch identity.} [committee] is the
    caller's, as at cold start and as at {!begin_epoch}, because "the committee
    stays the caller's argument" is a documented convention repeated at every
    installation site ([lib/driver/chain_spec.mli:35-41],
    [lib/driver/driver.mli:36-43, 148-160]) and upstream itself refuses to
    learn the committee from a persisted artefact, treating its [EpochRecord]
    as a derived summary and re-reading the registry pinned to the previous
    epoch's closing header ([tn-reth/src/lib.rs:1820-1845, 1847-1913]). What is
    NOT ported is that pinned read and its fail-hard tip cross-check
    ([tn-reth/src/lib.rs:1892-1910]): the port has no registry reader, and
    building one would need four new ABI encoder/decoder pairs including a
    nested-dynamic-array head/tail decode path the port has nowhere
    ([system_calls.rs:76-98] against [lib/evm/registry_abi.mli:60-64]), while
    the registry's four-epoch ring buffer ([tn-reth/src/lib.rs:2320-2322])
    means it could not answer for a node down longer than four epochs anyway.
    The port's substitute is the three cross-checks above: the caller
    supplies the committee, and resume proceeds only when its epoch matches
    the checkpoint's, the committee itself equals the checkpoint's
    whole-value ({!Committee_mismatch} otherwise — epoch equality alone
    cannot tell two rosters of one epoch apart), and the store's epoch
    corroborates. The persisted copy is a WITNESS, never a source: the
    committee the resumed driver runs under is the one the caller supplied,
    because any other is refused before anything replays. *)
