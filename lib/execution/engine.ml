open Tn_consensus

module type ENGINE = sig
  type t
  type block
  type error

  val genesis : t
  val execute : t -> Sub_dag.t -> (t * block, error) result
  val tip : t -> block option
  val height : t -> Consensus_block.Number.t
end

module Noop = struct
  type block = Consensus_block.t
  type error = Nothing.t

  (* The chain is fully determined by its tip: [None] is the genesis anchor,
     [Some b] is the last block produced. *)
  type t = Consensus_block.t option

  let genesis = None
  let tip t = t

  let height =
    Option.fold ~none:Consensus_block.Number.genesis
      ~some:Consensus_block.number

  let execute t sub_dag =
    let parent_hash =
      Option.fold ~none:Consensus_block.genesis_parent
        ~some:Consensus_block.digest t
    in
    let number = Consensus_block.Number.succ (height t) in
    let block = Consensus_block.create ~parent_hash ~sub_dag ~number in
    Ok (Some block, block)
end
