(** The durable seam: the append-only consensus-header chain with its batch
    bodies, as a module signature plus one pure in-memory reference
    implementation.

    Upstream this is one per-epoch pack directory holding a data log of
    [PackRecord::{EpochMeta, Batch, Consensus}] plus three indices — by number,
    by header digest, by batch digest ([consensus_pack.rs:618-637]). Header and
    all bodies are written together as one unit ([consensus_pack.rs:1003-1082])
    and read back together by number ([consensus.rs:767-773]), so once persisted
    no reader ever consults a worker again — which matters because at restart
    the workers may be long gone ([subscriber.rs:424-464]). This module keys on
    the same two indices the recovery path uses and models the third (batch
    digest) not at all: a record already carries its bodies, so replay never
    performs a second lookup to reunite them.

    "Durable" here means "outside the driver's own value". The port has no IO
    and this chunk introduces none. What the reference gives up, and what a disk
    implementation therefore owes, is stated below rather than implied.

    {b Precondition, carried across from upstream:} every record a reader can
    observe is COMPLETE. Upstream earns this: a record becomes discoverable only
    once its positional index entry is written, after both header and batch
    appends ([consensus_pack.rs:1059-1082]), and a hard kill between the write
    and the durability call loses the bytes and the in-process index entries
    together, so the reopened store is internally self-consistent and the
    recovery gap only ever contains records that were fully durable
    ([consensus_pack.rs:1071-1079]). An in-memory value has no partial state, so
    the reference satisfies this trivially; it is stated so a disk
    implementation knows it is an obligation and not an accident, and so
    {!Tn_execution.Replay} is never asked to reason about a torn record.

    {b Divergence, stated once here.} Three simplifications, each with the
    upstream mechanism it drops. (1) Upstream's write protocol is TWO awaited
    calls — [save_consensus_output] then [persist_current], with the comment
    "Make sure we have persisted the consensus output before we execute"
    ([state-sync/src/lib.rs:106-121]) — because only the second flushes and
    fsyncs data plus index files ([archive/pack.rs:298-312]); the first can
    return [Ok] with the bytes still in an in-process [Vec]
    ([archive/data_file.rs:47-60]). Here {!receive} is durable on return, and a
    disk implementation owes the barrier before it returns rather than in a
    second call, because a [persist] that is a no-op in the only implementation
    teaches every caller to omit it. Nothing about the recovery gap is lost:
    the gap comes from {!receive} and [Driver.snapshot] happening at two times,
    not from write and persist happening at two times. (2) Upstream retries a
    STAGING pack before declaring a live-epoch number missing
    ([storage/src/consensus.rs:823-834]), and a staged partial pack is written
    into an isolated directory, never swapped over live data, read transparently
    through the same accessor ([state-sync/src/consensus.rs:243-247]); this
    store is flat single-tier, so absence is final one tier earlier, and a
    later peer-catch-up chunk attaches its retry in front of {!record_at}.
    [stream_import]'s own by-number idempotency guard
    ([storage/src/consensus.rs:484-499]) is likewise absent. (3) There is no
    open/reopen distinction and no scratch tier: a store is a value, so
    upstream's non-idempotent [open_table] wipe hazard ([mem_db.rs:124-127]) and
    its rescan-on-open ([layered_db.rs:373-382]) have no analog — a disk
    implementation owes an unconditional-but-non-destructive open, the shape
    [init_genesis] already has ([tn-reth/src/lib.rs:719-741]) — and the
    [ConsensusCache] table, which is wiped at task startup and never trusted
    across a crash ([state-sync/src/consensus.rs:630-637]), is deliberately not
    modelled, so no resume path can read rows upstream discards.

    {b Divergence, on isolation.} Upstream's production write path applies to a
    shared RAM mirror synchronously, commits from a background thread, and a
    transaction dropped without [commit] commits anyway — "there is no rollback
    machinery and the writes are already visible in the mem layer"
    ([layered_db.rs:60-69, 204-223]). The reference must NOT reproduce that: it
    is an immutable value, a refused {!receive} returns the error alone and the
    caller keeps the pre-call store, so rollback is total and free. The
    statement is here because the inverse error is the dangerous one — a reader
    assuming the reference gives transactional isolation that its production
    counterpart does not ([mem_db.rs:45-79]).

    {b Divergence, on what this store does NOT serve.} Upstream's
    [ConsensusChainReader] also carries [read_last_committed(epoch)], the
    consensus side's own recovery read, which silently returns an empty map for
    an epoch with no static pack — indistinguishable from genuinely zero
    committed rounds ([storage/src/consensus.rs:1063-1077]). It has no member
    here on purpose: the port's consensus-side recovery sources its watermarks
    from [Tn_consensus.Committed_log.t], passed separately to [Node.recover]
    ([lib/consensus/node.mli:118-122]), and an execution-side store answering a
    consensus-side question would be a second source of truth for a value chunk
    14 derives from one log. *)

open Tn_types
open Tn_consensus

(** One durable unit: a consensus block and every batch body its sub-DAG
    references. Shared by every implementation of {!S}, so a record written
    through one is readable through another and a conformance differential is
    expressible. *)
module Record : sig
  type t
  (** A header and its bodies as one value. Abstract, with exactly one
      producer, so a record whose bodies disagree with its header is
      unrepresentable — the invariant upstream enforces at runtime in the pack
      reader, which requires batch records in the exact order the header's own
      sub-dag declares and hard-errors otherwise
      ([consensus_pack.rs:1560-1583]). *)

  type error =
    | Missing_body of Digests.Batch_digest.t
        (** A payload digest [lookup] could not supply, named. The same
            protocol-fatal condition [Tn_batch.Output.attach] reports as
            [Missing_batch] ([subscriber.rs:510-514]), refused here one step
            earlier so a header can never be filed without its bodies. *)

  val error_to_string : error -> string
  (** Human rendering; digests render as lowercase hex. *)

  val create :
    consensus:Consensus_block.t ->
    lookup:(Digests.Batch_digest.t -> Batch.t option) ->
    (t, error) result
  (** Derive the record from the block alone: walk
      {!Tn_consensus.Sub_dag.payload_digests} of the block's own sub-DAG, in
      commit order, resolving each through [lookup]. The body list is never
      caller-supplied and never caller-ordered, so a mismatched, short or
      reordered set has no representation to file — the key-derived idiom
      [Tn_driver.Batch_store.add] already establishes, applied one level up
      ([lib/driver/batch_store.mli:23-26]). Duplicates are preserved: a digest
      under two certificates resolves twice, exactly as attachment does
      ([subscriber.rs:480-509]). *)

  val consensus : t -> Consensus_block.t
  (** The durable consensus block. *)

  val sub_dag : t -> Sub_dag.t
  (** The committed sub-DAG, for a resumed driver to re-mint from. *)

  val number : t -> Consensus_block.Number.t
  (** The block's height, which is also its key in the store. *)

  val digest : t -> Digests.Output_digest.t
  (** The block's digest: the store's second index, and the value a conflicting
      re-submission is compared against. *)

  val parent_hash : t -> Digests.Output_digest.t
  (** The digest this record's block links to — what the write path checks
      against the store's current tip, upstream's [HeaderExpectation::Parent]
      strength ([consensus_pack.rs:1411-1441]). *)

  val epoch : t -> Units.Epoch.t
  (** {!Tn_consensus.Sub_dag.leader_epoch} of the record's own sub-DAG.
      DERIVED, never a stored field, so a record cannot be labelled with an
      epoch it does not belong to. *)

  val bodies : t -> Batch.t list
  (** Every referenced body, in the flat commit-order payload sequence
      {!create} derived them from. *)

  val to_wire : t -> Consensus_block.t * Batch.t list
  (** The two components a storage encoder writes: the block, and the bodies in
      the order {!create} derived. RESERVED for the storage chunk, the
      precedent {!Tn_consensus.Dag.insert_recovered} sets. Nothing else is
      written because nothing else is stored — {!number}, {!digest},
      {!parent_hash} and {!epoch} are all projections of the block. *)

  val of_wire : Consensus_block.t * Batch.t list -> (t, error) result
  (** The inverse a storage decoder needs, and the reason it is not a plain
      pairing: {!create} needs a [lookup] that a decoder must synthesise. The
      decoded bodies are indexed by their own {!Tn_types.Batch.digest} and that
      index is handed to {!create}, so the header still orders the bodies and
      still fixes their multiplicity. RESERVED for the storage chunk.

      Two consequences, and they are exactly what the byte stream is not
      trusted for. A body list that cannot supply a digest the block's own
      sub-DAG names is {!Missing_body}, never a record. A body list that is
      merely re-ordered, or that carries a repeated digest only once, is
      neither trusted nor refused: it decodes to the same record the canonical
      body list decodes to, with commit order and multiplicity re-derived. *)
end

(** Why the store cannot answer as asked. Four diagnoses, deliberately not
    collapsed, because each drives a different operational response and two of
    them reach opposite conclusions from the same symptom. *)
type miss =
  | Below_retained of {
      earliest : Consensus_block.Number.t;
      asked : Consensus_block.Number.t;
    }
      (** The number is below everything retained: the checkpoint predates this
          store's history. Upstream's [ConsensusNumberTooLow]
          ([consensus_pack.rs:1126-1139]). The reference never prunes, so this
          arm fires only against a store opened above genesis; a pruning
          implementation makes it routine. *)
  | Above_tip of {
      expected_next : Consensus_block.Number.t;
      asked : Consensus_block.Number.t;
    }
      (** The number is at or above the next slot the store expects, so the
          store has never held it. Upstream's [ConsensusNumberTooHigh]. Under
          persist-before-execute ([subscriber.rs:154, 182]) a checkpoint AHEAD
          of the log can only mean the log was lost, which is the opposite
          conclusion from {!Below_retained} and is why the two are not one arm.
          It carries [expected_next] rather than a tip number so an EMPTY store
          is expressible without an option. *)
  | Forked of {
      number : Consensus_block.Number.t;
      stored : Digests.Output_digest.t;
      offered : Digests.Output_digest.t;
    }
      (** The store holds [number], but under a different digest than the
          checkpoint's own last-executed block: the two durable values came
          from different runs. Upstream detects the same condition one layer up
          as "possible fork detected" ([state-sync/src/lib.rs:391-401]). *)
  | Broken of Replay.break
      (** Collection walked into a hole or a broken link. Lifted rather than
          restated, so the run-level check has one definition
          ({!Tn_execution.Replay.collect}). *)

val miss_to_string : miss -> string
(** Human rendering, delegating to {!Tn_execution.Replay.break_to_string} for
    the lifted arm. *)

(** The seam a future disk implementation conforms to. Declared as a signature
    and immediately included below, so the reference implementation's
    conformance is a build error if it drifts — the idiom
    [Tn_engine.Engine] already uses against [Tn_execution.Engine.ENGINE]
    ([lib/engine/engine.mli:88-96]). *)
module type S = sig
  type t
  (** The durable chain. Immutable: every operation returns a new value and
      never touches its argument. *)

  (** Why a write is refused. Five causes, one arm each, per the house
      taxonomy. *)
  type error =
    | Not_next of {
        expected : Consensus_block.Number.t;
        got : Consensus_block.Number.t;
      }
        (** Strict gapless sequential append: a write is accepted only at the
            next expected slot, or at an already-filled one as a no-op
            ([consensus_pack.rs:1053-1058]). *)
    | Broken_chain of {
        expected : Digests.Output_digest.t;
        got : Digests.Output_digest.t;
      }
        (** The record's [parent_hash] is not the store's current tip digest
            (or, for the first record of an epoch, {!epoch_parent}). Upstream's
            [HeaderExpectation::Parent] check ([consensus_pack.rs:1411-1441]),
            applied on the WRITE side, which is what lets the recovery read
            trust that a collected run is a chain. *)
    | Conflicting_record of {
        number : Consensus_block.Number.t;
        stored : Digests.Output_digest.t;
        offered : Digests.Output_digest.t;
      }
        (** An occupied number was offered a DIFFERENT block.

            {b Divergence, stated once here:} upstream skips an already-seen
            number without any content check, at both the chain layer
            ([storage/src/consensus.rs:732-765]) and the pack layer
            ([consensus_pack.rs:1046-1058]), because it cannot compare cheaply
            — the stored form is bytes on disk and the caller may be replaying
            from a downloaded pack. The port has both digests in hand, and
            every re-submission upstream legitimately tolerates is
            byte-identical by construction, so this arm can fire only on a
            genuine fork — the condition upstream detects one layer up and
            calls fatal. Skipping the check would make the store's own
            idempotency the mechanism that hides a divergence. *)
    | Wrong_epoch of { open_epoch : Units.Epoch.t; offered : Units.Epoch.t }
        (** The record's leader epoch is not the store's open epoch. Upstream
            checks this twice, at the chain guard and inside the pack
            ([storage/src/consensus.rs:738-750;
            consensus_pack.rs:1035-1045]). *)
    | Epoch_not_advanced of {
        open_epoch : Units.Epoch.t;
        proposed : Units.Epoch.t;
      }
        (** {!open_epoch} was handed an epoch that does not strictly advance,
            which would let a stale epoch reopen over a sealed one. *)

  val error_to_string : error -> string
  (** Human rendering, one arm per variant. *)

  val create :
    epoch:Units.Epoch.t ->
    anchor:Consensus_block.Number.t ->
    parent:Digests.Output_digest.t ->
    t
  (** An empty store anchored on the block [parent] names: [anchor] is that
      block's NUMBER, and the first record is expected at
      [Consensus_block.Number.succ anchor], linking to [parent]. The anchor
      arrives as the parent's number rather than as a start height because
      [Consensus_block.Number] has [succ] and no [pred], and {!epoch_start} and
      the floor a from-nothing {!gap} collects above must agree — deriving both
      from the one value makes their skew unrepresentable, exactly how
      {!open_epoch} derives both from the tip it rolls over. The facts are
      still the three fields upstream writes into every per-epoch pack's
      leading [EpochMeta] record — [start_consensus_number] (here [succ
      anchor]) and [genesis_consensus], plus the epoch itself
      ([consensus_pack.rs:50-64]) — minus [genesis_exec_state], which is an
      EXECUTION fact written after execute and therefore lives in
      [Tn_driver.Checkpoint], not here. For a chain starting at genesis,
      [anchor] is [Consensus_block.Number.genesis] and [parent] is
      {!Consensus_block.genesis_parent}. *)

  val receive : t -> Record.t -> (t, error) result
  (** File one record. THE FIRST OF THE TWO DURABLE WRITES: a shell calls this
      between [Driver.mint] and [Driver.step], so a record is durable strictly
      before the output it describes is executed — the ordering that CREATES
      the recovery gap ([subscriber.rs:154, 182]; the active-validator path
      saves before publishing too, [subscriber.rs:283-299]).

      Re-filing a number the store already holds under the SAME digest is a
      plain success returning the store unchanged: upstream's 0-byte
      already-persisted signal ([state-sync/src/lib.rs:111-114]), and what
      makes a shell's retry after a partial crash safe. Under a different
      digest it is {!Conflicting_record}.

      Durable on return; see the module comment's first divergence. *)

  val open_epoch : t -> epoch:Units.Epoch.t -> (t, error) result
  (** Roll to the next epoch: records already held are RETAINED, and the store
      begins expecting records of [epoch] linking to the current tip. Upstream
      opens a fresh per-epoch pack directory instead ([consensus_pack.rs:1-2]);
      the port keeps one value because its consensus numbering is global across
      epochs — [Driver.begin_epoch] leaves the accumulator, the watermark and
      the chain untouched ([lib/driver/driver.mli:154-158]) — and because a
      resumed node's gap can legitimately span the boundary, which an
      epoch-partitioned read space would report as a hole. Retention is
      unbounded, matching the archive-mode assumption upstream relies on for
      historical reads ([tn-reth/src/lib.rs:2046-2058]).

      {b Divergence, stated once here:} upstream pairs this transition with an
      [EpochRecord] write and a per-epoch table clear, in that order, because
      clear-then-crash-before-record would leave epoch 0 with no durable record
      and brick the node ([run_epoch.rs:229-239]). The port models no
      [EpochRecord] at all: its two load-bearing fields are the epoch's final
      execution state, which is [Tn_driver.Checkpoint]'s anchor and survives
      the handoff because the engine is threaded rather than rebuilt, and the
      committee, which is the caller's argument at every installation site
      ([lib/driver/driver.mli:36-43, 148-160]) and which upstream itself
      refuses to learn from the record ([tn-reth/src/lib.rs:1820-1845]). With
      no record there is nothing to clear before and nothing to recover from a
      peer, so upstream's 30-second peer wait and hard error for epoch > 0
      ([run_epoch.rs:461-537]) and its epoch-0 synthetic dummy
      ([run_epoch.rs:197-215]) both have no analog. *)

  val epoch : t -> Units.Epoch.t
  (** The open epoch: the one {!receive} accepts records of. *)

  val epoch_start : t -> Consensus_block.Number.t
  (** The first number of the open epoch. *)

  val epoch_parent : t -> Digests.Output_digest.t
  (** The digest the open epoch's first record links to: the previous epoch's
      final block, or {!Consensus_block.genesis_parent} at epoch 0. Upstream's
      [genesis_consensus] ([consensus_pack.rs:50-64]). *)

  val expected_next : t -> Consensus_block.Number.t
  (** The number the next {!receive} must carry: {!epoch_start} while the store
      is empty, one past the tip otherwise. The store's own bound, which is what
      lets {!Above_tip} describe an empty store without an option. *)

  val earliest : t -> Consensus_block.Number.t option
  (** The lowest number retained, or [None] when nothing is. *)

  val latest_received : t -> Record.t option
  (** The last record FILED — never the last executed. Named for what it holds
      because upstream's [consensus_header_latest] is documented as "the last
      known ConsensusHeader that was executed" while its implementation
      reflects the last-saved cursor, which advances BEFORE execution
      ([storage/src/consensus.rs:1020-1025]); a port following that doc
      literally mis-seeds a resumed engine. There is no second, cursor-based
      reader to choose wrongly between ([consensus.rs:1045-1047]), because
      there is no cursor to lag. *)

  val record_at :
    t -> Consensus_block.Number.t -> (Record.t, miss) result
  (** The record at a height, or the diagnosis. Produces {!Below_retained},
      {!Above_tip} or [Broken (Hole _)]; never {!Forked}, which is a
      {!gap}-only comparison. Result-shaped rather than option-shaped
      deliberately: upstream's own by-number lookup reports a not-yet-written
      number in the open epoch as an [Err] and reserves [Ok None] for
      cross-epoch misses ([storage/src/consensus.rs:814-850]), and collapsing
      the two would make "this store has been truncated" and "you asked past
      the tip" the same answer at the one call site that must tell them
      apart. *)

  val record_by_digest : t -> Digests.Output_digest.t -> Record.t option
  (** The record with a given block digest. Option-shaped, because this is the
      genuinely clean absence case at every layer upstream too
      ([storage/src/consensus.rs:776-811]) — contrast {!record_at}. The suite
      uses it as an independent oracle, resolving an executed block's
      [parent_beacon_block_root] back to the record that produced it, which is
      upstream's own executed-watermark derivation
      ([consensus_bus.rs:710-729]) reached by a route the production path never
      takes. *)

  val cardinal : t -> int
  (** How many records are retained. *)

  val gap :
    t -> after:Consensus_block.t option -> (Replay.t, miss) result
  (** THE RECOVERY READ: the contiguous run this store holds above a resuming
      node's last executed block, up to its own tip — upstream's inclusive
      [last_executed.number + 1 ..= last_db.number]
      ([state-sync/src/lib.rs:155-189]).

      [after] is the BLOCK, not a bare height, so the floor and the digest that
      anchors the chain arrive together: the store's record at that height must
      exist and must carry that block's digest, or the answer is {!Forked} —
      the only place a checkpoint and a store from two different runs are
      caught. [None] means nothing has executed, and collection starts at
      {!epoch_start}'s chain anchor.

      Both ends are DERIVED — the floor from the caller's own checkpoint, the
      ceiling from this store's tip — so neither under-replay nor over-replay
      has a representation. Upstream's first gossip-driven backfill instead
      defaults its walk floor to genesis and carries safety entirely on an
      earlier already-have short-circuit ([state-sync/src/consensus.rs:540-543]);
      a floor that is not the watermark makes every restart's cost a function
      of chain length and its correctness a function of a short-circuit
      elsewhere.

      Collection and the chain check are {!Tn_execution.Replay.collect}'s, so
      every implementation of this signature shares one definition of the only
      operation here with a correctness argument. *)
end

include S
(** The pure in-memory reference implementation: two [Map.Make] instances, one
    over {!Consensus_block.Number} and one over
    {!Tn_types.Digests.Output_digest} — upstream's [idx] and [hash] indices
    ([consensus_pack.rs:618-637]) — this module instantiating its own maps
    because the number and digest modules are bare signatures with no [Map]
    submodule, the precedent [Tn_driver.Batch_store] sets
    ([lib/driver/batch_store.mli:1-41]). The batch-digest index has no
    counterpart: a record already carries its bodies, so nothing ever looks a
    body up separately.

    Its honest status is upstream's own: [MemDatabase] is documented
    "impermanent storage in memory — useful for tests" and is never the
    production backend ([storage/src/mem_db.rs:1, 77-79]), which is exactly the
    status this implementation occupies. Naming it concretely rather than
    behind a virtual library is deliberate: a virtual library would forbid two
    implementations coexisting in one executable, and the conformance test that
    proves {!S} is satisfiable by something other than this module is precisely
    that. *)
