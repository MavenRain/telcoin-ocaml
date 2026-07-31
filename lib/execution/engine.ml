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

  (* The chain is fully determined by its tip: [None] is the genesis anchor,
     [Some b] is the last block produced. *)
  type t = Consensus_block.t option

  let create () = None
  let tip t = t

  let height =
    Option.fold ~none:Consensus_block.Number.genesis
      ~some:Consensus_block.number

  let error_to_string = Nothing.absurd

  let execute t sub_dag =
    let parent_hash =
      Option.fold ~none:Consensus_block.genesis_parent
        ~some:Consensus_block.digest t
    in
    let number = Consensus_block.Number.succ (height t) in
    let block = Consensus_block.create ~parent_hash ~sub_dag ~number in
    (* Exactly one block per commit: this engine is the port of the subscriber's
       output-to-header fold, which forms one consensus-chain header per
       committed sub-DAG. *)
    Ok (Some block, [ block ])
end
