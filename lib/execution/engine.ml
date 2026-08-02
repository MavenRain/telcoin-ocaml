open Tn_consensus

module type ENGINE = sig
  type t
  type config
  type output
  type block
  type height
  type error

  val create : config -> t
  val execute : t -> output -> (t * block list, error) result
  val tip : t -> block option
  val height : t -> height
  val error_to_string : error -> string
end

module Noop = struct
  type config = unit
  type output = Sub_dag.t
  type block = Consensus_block.t
  type height = Consensus_block.Number.t
  type error = Nothing.t

  (* The engine is the consensus-chain accumulator itself: Noop does nothing
     but fold that chain, and the fold lives in ONE place, [Consensus_chain],
     which the execution driver above this library shares. *)
  type t = Consensus_chain.t

  let create () = Consensus_chain.genesis
  let tip = Consensus_chain.tip
  let height = Consensus_chain.number
  let error_to_string = Nothing.absurd

  let execute t sub_dag =
    (* Exactly one block per commit: this engine is the port of the subscriber's
       output-to-header fold, which forms one consensus-chain header per
       committed sub-DAG. *)
    let chain, block = Consensus_chain.append t sub_dag in
    Ok (chain, [ block ])
end
