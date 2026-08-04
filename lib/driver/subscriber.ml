(* The executor subscriber's receive arm (subscriber.rs:360-371,430-529 at
   telcoin-network 5dbb764e) made pure: mint the consensus block from the
   running accumulator FIRST, then attach bodies through the frozen
   [Output.attach]. *)

module Consensus_chain = Tn_execution.Consensus_chain
module Output = Tn_batch.Output

type t = { chain : Consensus_chain.t }
type error = Attach of Output.error

let error_to_string (Attach e) = "attach: " ^ Output.error_to_string e
let create chain = { chain }

(* The ONE call to [Consensus_chain.append] this module makes. Both [mint] and
   [receive] route through it, so the block a shell files before executing and
   the block the driver then executes are the same block by definition of a
   total pure function of (accumulator, sub_dag) - never by assertion. *)
let append t sub_dag = Consensus_chain.append t.chain sub_dag

(* The block [receive] WOULD mint, with the advanced accumulator discarded:
   nothing here returns a subscriber, so minting cannot move the chain. *)
let mint t sub_dag = snd (append t sub_dag)

let receive t sub_dag ~bodies ~address_of =
  (* Mint first: the (parent, number) pair is decided at receipt, before any
     body is looked up (subscriber.rs:367-371), so numbering is
     body-independent and an empty output consumes a number like any other. *)
  let chain, block = append t sub_dag in
  Output.attach ~consensus:block ~lookup:(Batch_store.find bodies) ~address_of
  |> Result.map (fun output -> ({ chain }, block, output))
  |> Result.map_error (fun e -> Attach e)

let number t = Consensus_chain.number t.chain
