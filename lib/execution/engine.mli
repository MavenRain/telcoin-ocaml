(** The execution-layer seam.

    An execution engine consumes committed consensus output — the ordered stream
    of {!Tn_consensus.Sub_dag}s the consensus core emits, one commit at a time —
    and extends a chain of {!Consensus_block}s, returning each block as it is
    produced. The vertical slice links {!Noop}, which does no execution: it only
    forms the consensus-chain header for each committed sub-DAG, so it {e cannot
    fail} and says so by making its [error] the uninhabited {!Nothing.t}. A real
    OCaml EVM will link here later, executing each sub-DAG's batched transactions
    against a state trie and returning a populated execution block, with a genuine
    [error] for a reverted or otherwise invalid batch.

    Because every honest node commits the same sub-DAG prefix (the consensus
    safety property {!Tn_sim.Sim.agreement} checks) and an engine is a
    deterministic fold over that prefix, every honest node's chain is identical
    wherever the committed logs coincide — execution agreement is a corollary of
    consensus agreement, not a fresh assumption. *)

open Tn_consensus

(** What every execution engine offers the shell. *)
module type ENGINE = sig
  type t
  (** The engine's running state — everything a restart would need to resume the
      chain (for {!Noop}, just the tip). *)

  type block
  (** The unit the engine produces per committed sub-DAG. *)

  type error
  (** A genuine execution failure. {!Noop} makes this {!Nothing.t}: it cannot
      occur. *)

  val genesis : t
  (** The engine before any sub-DAG is committed: the chain sits at its genesis
      anchor, with no block produced yet. *)

  val execute : t -> Sub_dag.t -> (t * block, error) result
  (** Fold one committed sub-DAG into the chain, returning the advanced engine
      and the block it produced, or an [error]. The caller feeds sub-DAGs in
      commit order. *)

  val tip : t -> block option
  (** The most recently produced block, or [None] before the first commit. *)

  val height : t -> Consensus_block.Number.t
  (** The number of the last produced block; {!Consensus_block.Number.genesis}
      before the first commit. *)
end

(** The no-op execution engine: it forms the consensus-chain header for each
    committed sub-DAG and does nothing else. It never fails — its [error] is
    {!Nothing.t} — so {!ENGINE.execute} always returns [Ok] and a caller can
    discharge the impossible error branch with {!Nothing.absurd}. This is the
    execution seam for the simulation slice; the block it produces is exactly the
    {!Consensus_block}. *)
module Noop :
  ENGINE with type block = Consensus_block.t and type error = Nothing.t
