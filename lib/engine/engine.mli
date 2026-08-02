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
  | Randomness_width of int
      (** The sub-DAG's randomness was not 32 bytes, so the closing block's
          [Epoch_boundary] commitment cannot be formed. Carries the width
          seen. *)
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
