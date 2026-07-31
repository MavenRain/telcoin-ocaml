(** The execution-layer seam.

    An execution engine consumes committed consensus output, one commit at a
    time, and extends a chain of its own blocks, returning each block as it is
    produced. What a commit {e is} to an engine is the engine's own business:
    the seam leaves [output] abstract, so {!Noop}, which does no execution,
    folds the bare {!Tn_consensus.Sub_dag}s the consensus core emits, while an
    engine that executes batch bodies folds an output whose bodies and
    certificate addresses were already attached upstream.

    The vertical slice links {!Noop}: it only forms the consensus-chain header
    for each committed sub-DAG, so it {e cannot fail} and says so by making its
    [error] the uninhabited {!Nothing.t}. [Tn_engine.Engine] links here as of
    the engine chunk, executing each output's batched transactions against the
    world state and returning populated execution blocks, with a genuine
    [error] for a block it cannot execute. It is named in brackets rather than
    as a reference on purpose: it sits ABOVE this library and this library must
    not depend on it.

    Because every honest node commits the same sub-DAG prefix (the consensus
    safety property {!Tn_sim.Sim.agreement} checks) and an engine is a
    deterministic fold over that prefix, every honest node's chain is identical
    wherever the committed logs coincide: execution agreement is a corollary of
    consensus agreement, not a fresh assumption. *)

open Tn_consensus

(** What every execution engine offers the shell. *)
module type ENGINE = sig
  type t
  (** The engine's running state: everything a restart would need to resume the
      chain it extends. *)

  type config
  (** What an engine must be TOLD before its first output, in place of the bare
      [genesis : t] this signature used to carry. An engine that executes cannot
      invent its anchor: telcoin seeds the first parent from [lookup_head()] at
      engine spawn, and this port has no producer of a genesis execution header
      at all ({!Tn_evm.Block_header.assemble} is the only constructor and it
      needs a [Finished.t]). {!Noop} needs nothing and sets this to [unit]. *)

  type output
  (** One committed consensus output, as THIS engine consumes it.

      Abstract because it must be, not because abstraction is nice here:
      [lib/batch/dune] already lists [tn_execution] among [tn_batch]'s
      libraries, so this file cannot name [Tn_batch.Output.t] without a dune
      cycle. {!Noop} instantiates it at the bare {!Sub_dag.t} it folds; an
      engine that executes batch bodies instantiates it at an output whose
      bodies and certificate addresses are already attached, which is also why
      no [Unknown_authority] or [Missing_batch] arm belongs in an engine's
      [error]: attaching is the caller's step and owns both
      ([lib/batch/output.mli:14-30]). *)

  type block
  (** The unit the engine produces. *)

  type height
  (** The numbering of {e this} engine's chain. Abstract because the consensus
      chain and the execution chain are different chains with different numbers,
      and one accessor typed for both guarantees a wrong caller. {!Noop} folds
      the consensus chain, as telcoin's subscriber does
      ([executor/src/subscriber.rs:347-371]), and instantiates this at
      {!Consensus_block.Number.t}; an engine that executes instantiates it at
      its own execution block number, which advances by the output's batch count
      and does not advance at all on a skipped output. *)

  type error
  (** A genuine execution failure. {!Noop} makes this {!Nothing.t}: it cannot
      occur. *)

  val create : config -> t
  (** The engine before any output is folded. *)

  val execute : t -> output -> (t * block list, error) result
  (** Fold ONE committed consensus output into the chain, returning the advanced
      engine and the blocks it produced, in chain order.

      The list may be EMPTY and it may be long. Telcoin executes nothing at all
      for an output that carries no batches and does not close the epoch
      ([crates/engine/src/payload_builder.rs:99-114]), builds exactly one empty
      block when such an output DOES close it ([:116-150]), and otherwise builds
      one block per flattened batch ([:89,163]). A caller must not assume one
      block per commit.

      An output is ALL-OR-NOTHING and an error is TERMINAL. On [Error] no engine
      state comes back at all: telcoin's per-block in-memory advance is
      speculative and is reorged back to the pre-output anchor on any failure
      ([:200-212,300-308]), its single durable commit happens after the whole
      loop ([:229-238]), and the error halts the engine task in process with no
      retry and no skip-this-output arm ([crates/engine/src/lib.rs:262-266]).
      {b Divergence, stated once here:} the one piece of state telcoin
      deliberately does not rewind, the leader count it increments before every
      branch ([:31-40]), is dropped with the state on this path. It is
      unobservable for telcoin's own stated reason ("no later output is ever
      processed"), and a telcoin restart loses the in-memory accumulator too; a
      caller that resumes folding after an [Error] diverges in
      [withdrawals_root] and must not. *)

  val tip : t -> block option
  (** The most recently produced block, or [None] before the first one. An
      output that produces no block leaves this unchanged. *)

  val height : t -> height
  (** The number of the chain this engine extends; its genesis number before the
      first block. *)

  val error_to_string : error -> string
  (** Diagnostic rendering, so a shell can report a failure without knowing
      which engine produced it. {!Noop} discharges it with {!Nothing.absurd}. *)
end

(** The no-op execution engine: it forms the consensus-chain header for each
    committed sub-DAG and does nothing else. Three of its members say the whole
    of it: [config] is [unit] because it needs telling nothing, [error] is
    uninhabited because it cannot fail, and [height] is the CONSENSUS chain's
    number, not an execution block number. *)
module Noop :
  ENGINE
    with type config = unit
     and type output = Sub_dag.t
     and type block = Consensus_block.t
     and type height = Consensus_block.Number.t
     and type error = Nothing.t
