(** The execution side's durable value: what a shell files AFTER a step
    succeeds, and what a resumed driver is rebuilt from.

    THE SECOND OF THE TWO DURABLE WRITES. Upstream has no persisted
    last-executed-consensus field at all: it reconstructs one by reading the
    canonical execution tip's header, whose [parent_beacon_block_root] is
    repurposed to carry the ConsensusHeaderDigest that produced it, and looking
    that digest up in the durable chain ([consensus_bus.rs:710-729]); the
    in-memory watch it reads from is advanced only by the engine-update task,
    strictly after execution completes ([node.rs:1317-1341]). This module keeps
    the SEMANTICS of that watermark — it moves on execute-success and never on
    receipt — and drops the derivation, because the port can file the block
    itself.

    {b Divergence, stated once here.} Dropping the derivation is not a
    convenience: it is a correctness requirement. An output that carries no
    batches and does not close the epoch produces ZERO execution blocks
    ([lib/driver/outcome.mli:35-36]), so the anchor — and therefore its
    [parent_beacon_block_root] — legitimately names an EARLIER output. A
    watermark derived from the anchor alone would replay every intervening
    empty; and because this port RE-MINTS a replayed gap rather than
    re-forwarding it verbatim as upstream does ([start_epoch.rs:93-100]), each
    replayed empty would consume a number the chain already spent, shifting
    every later block and forking the chain with no error. Upstream's
    derivation survives here only as the suite's independent oracle, where the
    predicate it checks is deliberately "at or BELOW the watermark", never
    equal. The related [nonce] half of that derivation — upstream's
    [(epoch << 32) | round] decoded by [deconstruct_nonce]
    ([types/src/helpers.rs:283-288]) — is not used at all, and the doc/code
    contradiction around it is resolved here in favour of the CODE: the round
    IS recoverable, both upstream (whose [try_restore_state] docstring claims
    otherwise while its body decodes and forwards it, [node.rs:1289-1311]) and
    in-port, where [Tn_evm.Block_header.nonce] stores the pair TYPED as
    [Tn_types.Units.Sequence_number.t] with [epoch] and [round] accessors
    ([lib/evm/block_header.mli:194-197], [lib/types/units.mli:76-88]). Nothing
    here restores a round because nothing in the port consumes one: the
    forwarding watermark is a consensus NUMBER and the leader round
    "deliberately has no counterpart here" ([lib/driver/driver.mli:83-89]).
    Stated so a later chunk does not re-import the stale docstring.

    {b Divergence from chunk 14, stated once here.} [Tn_consensus.Node.persisted]
    is a fully transparent record ([lib/consensus/node.mli:94-103]) and this
    type is ABSTRACT with transparent projections. The reason is that this is
    the one place two independently-derived facts are PAIRED — the engine's
    whole state and the consensus block whose execution produced it — and
    nothing else in the type system pins that pairing. A transparent record
    would make "the engine after output k+1 filed against the block from output
    k" constructible, which is double execution with the store silently
    agreeing. Chunk 14's rule exists so a store-facing type can be inspected
    and serialized; the projections below satisfy both, and transparency here
    would not. Every field of {!Tn_engine.Engine.persisted} stays transparent
    for exactly that reason: each is an abstract type whose own producers
    already forbid internal disagreement. *)

type t
(** One resumable execution state: the engine's persisted facts, paired with
    the consensus block whose execution produced them. Abstract, with exactly
    two producers ({!genesis} and [Tn_driver.Driver.snapshot]), so a mispaired
    checkpoint is unconstructible. *)

val genesis : Chain_spec.t -> committee:Tn_types.Committee.t -> t
(** The checkpoint of a node that has executed nothing: the engine as
    [Tn_driver.Driver.create] would seat it, and no last-executed block. This
    is the fresh-node branch of upstream's resumed-node-vs-fresh-node split,
    where a brand-new node takes the chain-spec genesis fallback because
    genesis deliberately stays unfinalized ([tn-reth/src/lib.rs:958-969]). It
    exists so a shell's startup path is uniform: resume from ({!genesis},
    empty store) is a cold start, and every later restart is the same call with
    different values. *)

val of_execution :
  Tn_engine.Engine.persisted ->
  last_executed:Tn_execution.Consensus_block.t option ->
  t
(** Pair what execution left behind. THE MECHANISM [Tn_driver.Driver.snapshot]
    is made of, and its only call site in the port.

    {b Divergence from the plan, stated once here.} The type comment above
    claims exactly two producers, {!genesis} and [Tn_driver.Driver.snapshot];
    OCaml has no library-private producer, so the second one needs a declared
    entry point and this is it. What the abstraction still buys is unchanged in
    kind and smaller in degree: [Tn_engine.Engine.persisted] has exactly one
    INTENDED producer of its own ([Tn_engine.Engine.snapshot],
    [lib/engine/engine.mli:250-258]) but is a transparent record, so the one
    cross-field fact a hand-built engine half could skew — window newest versus
    anchor hash — is normalized by [Tn_engine.Engine.resume] itself, which
    re-derives the window's newest entry from the anchor rather than trusting
    it; the pairing obligation THIS function adds is named here rather than
    left implicit at a transparent record. The obligation itself — that
    [last_executed] is the block whose execution produced this engine and not
    the one before or after it — is discharged at the single call site, where
    both halves are read out of one driver value in one expression, and pinned
    by the suite's own snapshot assertion. A caller outside the driver can
    mispair, exactly as it could have under a transparent record; what it
    cannot do is mispair silently, because reaching this function means naming
    it. *)

val engine : t -> Tn_engine.Engine.persisted
(** The engine's persisted facts: the anchor, the world, the [BLOCKHASH]
    window, the leader counts and the epoch phase. *)

val last_executed : t -> Tn_execution.Consensus_block.t option
(** The consensus block whose execution produced {!engine}, or [None] if
    nothing has executed. The gap's floor, handed to
    [Tn_execution.Consensus_store.gap] as its [~after] so the height and the
    digest that anchors the chain travel together. [None] is the only no-parent
    representation on this path: no synthetic default header is manufactured
    anywhere, because reproducing upstream's [ConsensusHeader::default()] —
    which is not a null sentinel but a real, deterministic, hash-meaningful
    digest that its callers silently substitute for "nothing found"
    ([types/src/primary/block.rs:34-75]) — would need a [Certificate::default]
    escape hatch this port's types forbid
    ([lib/execution/consensus_block.mli:53-61]). *)

val watermark : t -> Tn_execution.Consensus_block.Number.t
(** The executed watermark: {!last_executed}'s number, or
    [Consensus_block.Number.genesis] when nothing has executed. DERIVED, never
    a stored scalar, so it cannot disagree with the block that justifies it —
    the redundant-persisted-derived-field desync chunk 14 designs out by
    deriving every watermark from one log ([lib/consensus/node.mli:118-122]). *)

val accumulator : t -> Tn_execution.Consensus_chain.t
(** The consensus-chain accumulator a resumed driver starts from:
    [Consensus_chain.resume] seeded at {!last_executed}'s digest and number, or
    [Consensus_chain.genesis] when nothing has executed. The seed IS the
    executed tip, never the store tip; see [Tn_driver.Driver.resume]'s
    divergence paragraph for why the port must depart from upstream's
    [last_consensus_parent] max rule here. *)

val epoch : t -> Tn_types.Units.Epoch.t
(** The epoch the executed blocks ran under: the epoch of the committee inside
    {!engine}'s phase. What [Tn_driver.Driver.resume] cross-checks the caller's
    committee against, so a caller cannot silently resume under a committee
    that did not accrue the persisted leader counts. *)

val committee : t -> Tn_types.Committee.t
(** The committee inside {!engine}'s phase: the one whose leaders the persisted
    counts credit. Readable so a shell can see what it is being asked to
    re-supply, and the value [Tn_driver.Driver.resume] holds the caller's
    argument against whole-value ([Committee_mismatch] on any difference,
    [Tn_types.Committee.equal]): upstream refuses to learn the committee from
    a persisted artefact ([tn-reth/src/lib.rs:1820-1845]) and the port's
    convention is that the committee is the caller's argument at every
    installation site, so this copy is the WITNESS that the caller supplied
    the right one, never a source resume falls back to. *)

val is_sealed : t -> bool
(** Whether the epoch had already sealed when this checkpoint was taken, read
    off {!engine}'s phase. A resumed driver whose phase disagreed with its
    engine would mis-mint an output upstream refuses
    ([lib/driver/driver.ml:65-73]); deriving both from one phase makes the
    disagreement unrepresentable rather than merely checked. *)

val closed_at : t -> Tn_types.Units.Timestamp.t option
(** The commit timestamp of the output whose execution sealed the epoch, or
    [None] while running. Verified identical to the driver's own copy: the
    engine seals with [closed_at = Tn_batch.Output.committed_at output]
    ([lib/engine/engine.ml:328-333]) and chunk 37's driver recorded the same
    value from the same output in the same step ([lib/driver/driver.ml:90]),
    which is why chunk 38 deletes the driver's copy rather than persisting
    two. *)
