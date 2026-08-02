open Tn_types
open Tn_consensus

type t = {
  parent : Digests.Output_digest.t;
  number : Consensus_block.Number.t;
  tip : Consensus_block.t option;
}

let genesis =
  {
    parent = Consensus_block.genesis_parent;
    number = Consensus_block.Number.genesis;
    tip = None;
  }

let resume ~parent ~number = { parent; number; tip = None }

let append t sub_dag =
  let number = Consensus_block.Number.succ t.number in
  let block = Consensus_block.create ~parent_hash:t.parent ~sub_dag ~number in
  ({ parent = Consensus_block.digest block; number; tip = Some block }, block)

let tip t = t.tip
let parent t = t.parent
let number t = t.number
