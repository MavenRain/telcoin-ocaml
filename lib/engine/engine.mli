(** The execution engine: one committed consensus output in, the execution
    blocks it produces out.

    This is the implementation of {!Tn_execution.Engine.ENGINE} that actually
    executes, as against {!Tn_execution.Engine.Noop}, which only forms the
    consensus-chain header for each commit. The conformance is not a comment:
    the signature below {e includes} the seam with its abstract members
    instantiated, so drift in the seam is a build error here rather than a
    silent divergence.

    What the engine owns is the chain: the anchor it builds on, the world its
    blocks execute against, the [BLOCKHASH] window they see, the per-authority
    leader counts a closing epoch pays out, and the epoch boundary it recomputes
    each output against. What it does not own is the consensus chain: telcoin
    threads the consensus parent and number in its subscriber
    ([executor/src/subscriber.rs:347-371]) before an output is ever built, and
    the port puts that fold strictly upstream, in
    {!Tn_execution.Consensus_chain}, driven by the [Tn_driver] subscriber
    (named in brackets on purpose: it sits ABOVE this library).

    The epoch is a PHASE inside this engine and not a member of the shared seam:
    an execution seam whose other implementation is a consensus-chain fold has
    no business knowing what an epoch is. The phase runs until an output closes
    the epoch, then seals; {!is_sealed} reads it and {!begin_epoch} restarts
    it.

    {b Divergence, stated once here.} A closing output's epoch commitment is
    attached to the LAST block of the output and to no other, by splitting the
    plan's spec list at its last element rather than by consulting
    {!Tn_batch.Block_plan.Spec.closes_epoch} on each spec. Telcoin sets that
    flag at the last index and nowhere else
    ([crates/engine/src/payload_builder.rs:163-186]), so the two agree on every
    plan the planner produces; what this engine gives up is the ability to
    notice a planner that flagged some other spec, which is instead pinned
    where it can be seen, on {!Tn_batch.Block_plan.plan} itself. *)

(** Everything folding one output can fail on. Three of the arms carry the
    EXECUTION block number, so a forty-block output's failure is locatable
    without re-running it. Attaching bodies and certificate addresses to an
    output is the caller's step and owns its own errors
    ([lib/batch/output.mli:14-30]), so none of them appear here. *)
type error =
  | Epoch_sealed
      (** The epoch's closing block has already been built. Telcoin's engine
          stops consuming output at an epoch boundary and waits to be told the
          next epoch's committee; an engine that kept folding would pay the
          next epoch's leaders out of this epoch's counts. *)
  | Boundary_not_advanced of {
      closed_at : Tn_types.Units.Timestamp.t;
      proposed : Tn_types.Units.Timestamp.t;
    }
      (** {!begin_epoch} was handed a boundary at or before the one that just
          closed, which would close the next epoch on its first output. *)
  | Plan of Tn_batch.Block_plan.error
      (** The output could not be turned into a block plan. *)
  | Withdrawals of Tn_evm.Rewards_counter.error
      (** The leader counts could not be turned into withdrawal records. *)
  | Context of { number : int; error : Tn_evm.Block_context.error }
      (** Block [number]'s execution context was refused. *)
  | Execution of { number : int; error : Tn_evm.Block_execution.error }
      (** Block [number] failed to execute. A transaction the builder could
          skip is not this: it is recorded on the block
          ({!Executed_block.skipped}) and the block goes on. *)
  | Assembly of { number : int; error : Tn_evm.Block_header.error }
      (** Block [number] executed but its header could not be assembled. *)

(** The seam, with every abstract member instantiated: the engine is configured
    with a {!Config.t}, consumes the attached {!Tn_batch.Output.t}, produces
    {!Executed_block.t}s and numbers its chain in {!Block_number.t}. The
    [include] itself IS the conformance proof.

    {b Divergence, stated once here,} against [execute] because it changes every
    closing block this engine produces and not merely an error path: the engine
    CONVERTS {!Tn_consensus.Sub_dag.randomness} to a [Hash32.t] and never
    recomputes it, so it inherits a value already known-divergent from telcoin.
    Upstream takes [keccak256] of the leader certificate's aggregate signature
    ([types/src/primary/output.rs:378-382]); this port routes the same bytes
    through the {!Tn_crypto} seam ([lib/consensus/sub_dag.ml:77-87]), which is a
    stub, so every closing block's [extra_data], its block hash and the shuffle
    entropy that hangs off it differ from a Rust node's today. Fixing it here
    would put a second derivation of the same rule in a second chunk, free to
    drift from the first; it belongs to whichever chunk makes the crypto seam
    real. *)
include
  Tn_execution.Engine.ENGINE
    with type config = Config.t
     and type output = Tn_batch.Output.t
     and type block = Executed_block.t
     and type height = Block_number.t
     and type error := error

val config : t -> Config.t
(** The facts the engine was created with, unchanged since. The world, the
    anchor and the epoch boundary all move as outputs are folded; these do not.
*)

val anchor : t -> Anchor.t
(** The block the next output builds on: the last block produced, or the
    configured genesis anchor before there is one. This is how a caller reaches
    the genesis parent that {!tip} cannot show it, since no header for a genesis
    the engine did not execute exists. *)

val world : t -> Tn_state.World_state.t
(** The state the next block executes against, which is the state the last
    produced block left behind. A skipped output leaves it exactly as it was. *)

val recent_hashes : t -> Recent_hashes.t
(** The rolling [BLOCKHASH] window, newest first. It rolls across outputs, not
    just within one. *)

val rewards : t -> Tn_evm.Rewards_counter.t
(** The per-authority leader counts, which become the closing block's
    withdrawals. Exposed because the counts advance on outputs that produce no
    block at all ([payload_builder.rs:19-40]), so no block and no header of this
    engine's own witnesses that advance until the epoch closes.

    {b Divergence, stated once here:} leader counts are the WHOLE of what this
    engine accumulates. Telcoin's [GasAccumulator] keeps a second per-block
    tally, [inc_block], advanced inside the batch loop
    ([payload_builder.rs:219-223]) and, notably, not on the close-epoch empty
    block; nothing in the port has a counterpart, and nothing reads one. Its
    absence is safe for the surface this chunk commits to, because
    [generate_withdrawals] roots the LEADER counts and only those, and it is
    recorded here rather than left implicit because a later chunk that ports the
    per-epoch gas reporting will need it and will not find it. *)

val committee : t -> Tn_types.Committee.t
(** The committee whose leaders this engine is counting: the configured one
    until {!begin_epoch} replaces it, and after the epoch seals the one that
    just finished. A leader outside it resolves to no execution address and so
    to no withdrawal, which is why a driver that installs the wrong committee
    silently pays nobody rather than failing. *)

val is_sealed : t -> bool
(** Whether the epoch's closing block has already been built, so the next output
    would be refused with {!Epoch_sealed}. A driver tests this rather than
    discovering it through a failed {!execute}. *)

(** Where the engine stands in the epoch it is executing. Chunk 37 kept this
    private; chunk 38 publishes it because a resumed engine must be seated in
    the same phase it crashed in, and a boolean plus two option fields would
    make "sealed with no closing time" and "running with a closing time" both
    constructible. Upstream has no counterpart at all: it tears the epoch task
    down and restarts it with a fresh boundary, a fresh committee and a cleared
    accumulator ([run_epoch.rs:142, 227, 675]), and a phase is that teardown
    expressed as a type. *)
type phase =
  | Running of {
      boundary : Tn_types.Units.Timestamp.t;
          (** The timestamp an output must reach to close the epoch. *)
      committee : Tn_types.Committee.t;
          (** Whose leader counts are accruing. *)
    }
  | Sealed of {
      closed_at : Tn_types.Units.Timestamp.t;
          (** The COMMIT timestamp of the output that closed the epoch — not
              the boundary it crossed. The boundary is the frontier the epoch
              was measured against; the commit timestamp is where the epoch
              actually ended, and only the latter is past every output this
              epoch saw. *)
      committee : Tn_types.Committee.t;
          (** The committee that just finished, still readable so a driver can
              decide the next one. *)
    }

val phase : t -> phase
(** Where the engine stands. {!is_sealed} is this read as a boolean and stays
    for the callers that only need that much. *)

type persisted = {
  anchor : Anchor.t;
      (** The block the next output builds on, carried WHOLE. Not a
          [(hash, number, base_fee, gas_limit)] tuple: {!Anchor.of_header} is
          the only non-genesis producer and it needs a real header, so a tuple
          could only be turned back into an anchor by claiming genesis, which
          would tell the engine its parent has no header when it has one
          ([lib/engine/anchor.mli:12-25, 42-44]). Carrying the value also
          removes upstream's choice between two head reads with different
          staleness and different empty behaviour, one of which collapses a
          read error to 0 ([tn-reth/src/lib.rs:1212-1222, 952-960]); this is
          the analog of the [parent_state] value upstream writes atomically
          with the executed output's consensus hash and documents as never
          leading the true tip ([close_epoch.rs:217-234]). *)
  world : Tn_state.World_state.t;
      (** The state the next block executes against, carried as a value.

          {b Divergence, stated once here:} nothing in the port
          cryptographically binds this world to {!anchor}'s [state_root].
          [Tn_state.World_state] exposes no root accessor, so there is no
          restore-time reconstruction to hard-fail on, which is upstream's only
          real check ([tn-reth/src/snapshot.rs:492-549] — its export side
          deliberately does not recompute either, [snapshot.rs:31-37]). The
          honest property is "the world is carried, not proven". This is NOT
          the exec-state pack: that artefact is opt-in
          ([telcoin-network-cli/src/node.rs:61-64]), has zero external call
          sites, and its restorer refuses a populated datadir
          ([snapshot.rs:250-257]) — i.e. it refuses exactly the node that is
          resuming. The check becomes cheap and additive the moment a state
          root is exposed above [World_state]: one arm and one comparison
          against [Block_header.state_root] of {!anchor}'s header, with no
          change to this record or to {!resume}. *)
  hashes : Recent_hashes.t;
      (** The rolling [BLOCKHASH] window, carried WHOLE rather than as a
          [Tn_keccak.t list]. This is the type fact the whole resumed-engine
          design turns on: {!Recent_hashes.of_genesis}'s own doc says a short
          ancestor list "is not an error, it silently reads zero for the
          ancestors it omits, which describes a chain that does not exist"
          ([lib/engine/recent_hashes.mli:18-25]), so a list-shaped field makes
          a state-root divergence with no symptom typecheck. The window value
          is capped, never empty and has no list-taking function after
          creation, so a short window is unsayable here rather than refused. *)
  rewards : Tn_evm.Rewards_counter.t;
      (** The per-authority leader counts the closing block's [withdrawals_root]
          commits to.

          {b Divergence, stated once here:} upstream recovers these by REPLAY —
          the port's own [Rewards_counter] doc cites it
          ([lib/evm/rewards_counter.mli:23-28], "startup recovery replays the
          same increments from the consensus DB",
          [consensus_pack.rs:1284-1291]). Carrying the value instead is a
          deliberate override, on chunk 14's precedent: [Node.persisted]
          carries the accumulated node state and replays only the SEPARATE
          append-only log ([lib/consensus/node.mli:94-103, 118-122]), and this
          is accumulated state, not a log. Replaying it would mean re-folding
          increments over in-epoch records at or BELOW the executed watermark —
          outside the gap entirely — through a second projection of the credit
          rule beside [execute]'s own ([lib/engine/engine.ml:445-449]), free to
          drift from it. No mutator is added: the value is still reachable only
          through [empty]/[clear]/[set_committee]/[inc_leader_count], so what is
          persisted is the counter, never a scalar of ints. *)
  phase : phase;
      (** Running or sealed, with whichever timestamp is meaningful. One sum,
          so a resumed engine cannot be both, neither, or sealed without a
          closing time. *)
}
(** Everything an engine carries that MOVES. Deliberately [Engine.t] minus
    [config] (which never changes and is reconstructed by {!resume} from the
    two facts that genuinely are configuration) and minus [tip] (which a
    resumed engine legitimately lacks — the block behind {!anchor} was produced
    in a previous life, the exact symmetry of
    [Tn_execution.Consensus_chain.resume]'s [None] tip). Transparent, per the
    chunk-14 store-facing convention ([lib/consensus/node.mli:94-103]): a
    future serializing chunk must reach every field, and each field is itself
    an abstract type whose own producers forbid internal disagreement. *)

val snapshot : t -> persisted
(** Extract the engine's moving state for storage — the exact counterpart of
    [Tn_consensus.Node.snapshot]. The INTENDED producer of a {!persisted},
    which is what keeps {!hashes} full and {!rewards} earned by the engine that
    accumulated them — intended rather than only, because the record is
    transparent and nothing stops a caller hand-building one. The one
    cross-field fact a hand-built value could skew — that the window's newest
    entry is the anchor's own hash — is therefore re-derived by {!resume}
    instead of trusted; see its doc. *)

val resume :
  chain_id:Tn_state.U256.t ->
  basefee_address:Tn_types.Units.Address.t ->
  persisted ->
  t
(** Rebuild an engine from persistence. TOTAL, mirroring {!create}: every field
    of [persisted] is an abstract value whose own producers already discharge
    every INTRA-field obligation — the anchor cannot disagree with its header,
    the window cannot be short or empty, the phase cannot be both. The one
    genuinely CROSS-field obligation — the window's newest entry must be the
    anchor's own hash, because [build_block] reads the [BLOCKHASH] window and
    the parent hash out of the two fields in the same block — is not left to
    trust: resume re-seats the window as [Recent_hashes.of_genesis
    (Anchor.hash anchor)] over the persisted window's ancestors, so the
    invariant holds as a POST-fact of resume. On a {!snapshot}-produced value
    the re-seat is the identity; on a hand-built value whose pair is skewed it
    silently NORMALIZES — the newest entry is replaced by the anchor's hash,
    the ancestors are kept — rather than refusing, because a fallible
    signature would ship an arm no snapshot can produce and ripple through
    [Tn_driver.Checkpoint] and [Tn_driver.Driver.resume]. What remains
    unvalidatable is stated at the fields themselves ({!persisted.world}'s
    divergence note); with the window derived, there is nothing left to
    validate.

    [chain_id] and [basefee_address] are the only two facts that are genuinely
    configuration rather than state, and they arrive the same way at cold start
    and at resume, exactly as [Node.recover] repeats its config-class arguments
    ([lib/consensus/node.mli:122-124]). No [Config.t] is taken:
    [Tn_driver.Chain_spec.engine_config] hard-codes epoch 0's [first_boundary]
    and every later boundary is minted from a closing output's commit time
    ([lib/driver/chain_spec.mli:124-136]), so passing a spec-built config to a
    resumed engine past epoch 0 would silently reinstall epoch 0's boundary and
    close the epoch on the first output. Taking the two immutable facts
    explicitly makes that reuse unsayable rather than discouraged.

    {b Divergence, stated once here:} the [Config.t] this engine reports through
    {!config} is reconstructed, and its [epoch_boundary] is the phase's
    FRONTIER — the installed boundary while Running, the closing commit time
    while Sealed. A resumed engine was never created with a boundary, and
    {!begin_epoch} reads the frontier out of the phase and never out of the
    config, so the reconstructed value describes the engine rather than
    misreporting it.

    {b Open item, recorded not resolved:} how many real ancestors the window
    must hold to be correct depends on whether revm still consults a
    client-side window for distances at or under 256 once EIP-2935 is active
    from genesis — a revm/reth fact outside both repos, which the in-repo
    evidence only brackets ([tn-reth/src/snapshot.rs:272-275] requires real
    hashes "so BLOCKHASH and the base-fee walk resolve"). The port does not
    depend on the answer: in-port [BLOCKHASH] is served exclusively by the
    supplied window, because revm answers the opcode through a host "which
    reaches a chain database this port does not have"
    ([lib/evm/block_hashes.mli:1-22]). Carrying the whole window costs one
    field and makes the external answer a question about RETENTION, never about
    correctness. Settling it needs an external read or an empirical test. *)

val begin_epoch :
  t ->
  boundary:Tn_types.Units.Timestamp.t ->
  committee:Tn_types.Committee.t ->
  (t, error) result
(** Start the next epoch: clear the leader counts, install [committee], and set
    [boundary] as the timestamp the next closing output must reach. The order is
    load-bearing. Clearing happens strictly AFTER the closing block, because the
    counts that block rooted into [withdrawals_root] are this epoch's; the
    committee is replaced before the next output, because a leader resolves to a
    withdrawal address through the INSTALLED committee.

    {b Divergence, stated once here:} telcoin derives neither argument at this
    point. It tears the epoch task down and restarts it with a boundary and a
    committee read back from the consensus registry after [concludeEpoch]
    ([run_epoch.rs:142,227]); this port has no post-[concludeEpoch] registry
    reader and {!Tn_evm.Epoch_close.disposition} exposes calldata and outcomes
    rather than a {!Tn_types.Committee.t}, so both are the CALLER's to supply.
    What the engine can prove it checks: the boundary must strictly advance past
    the commit timestamp that closed the epoch, or nothing here would stop a
    caller reinstalling a boundary every later output would close again
    ([Boundary_not_advanced]). Called on a still-running engine the same
    comparison is made against the boundary now installed, so the frontier never
    walks backwards.

    {b Caller obligation:} the "strictly AFTER the closing block" ordering above
    is the CALLER's to honour; this function does not check it. It clears the
    counts on a RUNNING engine too, where no closing block has rooted them, so a
    driver that advances the boundary mid-epoch silently discards every leader
    credit earned so far and the eventual closing block pays those leaders
    nothing rather than failing. Test {!is_sealed} first: only a sealed engine
    stands at a real epoch transition. *)
