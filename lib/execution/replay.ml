open Tn_types
open Tn_consensus

(* One durable record: the consensus block and every body its sub-DAG names, in
   that sub-DAG's own payload order. Deliberately NOT exported - the run
   publishes projections ([blocks], [sub_dags], [bodies]), never a per-record
   type, so nothing outside can assemble a run from parts and skip [collect]'s
   chain check. *)
type record = { block : Consensus_block.t; bodies : Batch.t list }

type t = {
  after : Consensus_block.Number.t;
  upto : Consensus_block.Number.t;
  records : record list; (* ascending: one per height in (after, upto] *)
}

type break =
  | Hole of { number : Consensus_block.Number.t }
  | Broken_link of {
      number : Consensus_block.Number.t;
      expected : Digests.Output_digest.t;
      found : Digests.Output_digest.t;
    }

let break_to_string = function
  | Hole { number } ->
      Printf.sprintf "hole at consensus block %s: the store has no record there"
        (Consensus_block.Number.to_string number)
  | Broken_link { number; expected; found } ->
      Printf.sprintf
        "broken link at consensus block %s: expected parent %s, found %s"
        (Consensus_block.Number.to_string number)
        (Digests.Output_digest.to_hex expected)
        (Digests.Output_digest.to_hex found)

let collect ~after ~parent ~upto ~fetch =
  (* [link] is the digest the block at [number] must carry as its parent: the
     caller's [parent] at the floor, then each block's own digest. The walk
     stops one past [upto], so the range is (after, upto] and never includes
     [after] itself - the already-executed block is never replayed. *)
  let rec walk number link acc =
    if Consensus_block.Number.compare number upto > 0 then
      Ok { after; upto; records = List.rev acc }
    else
      (* [~none] is eager, so it holds a bare constructor and no recursion; the
         walk continues only inside [~some], which is a closure. *)
      Option.fold
        ~none:(Error (Hole { number }))
        ~some:(fun (block, bodies) ->
          let found = Consensus_block.parent_hash block in
          if Digests.Output_digest.equal found link then
            walk
              (Consensus_block.Number.succ number)
              (Consensus_block.digest block)
              ({ block; bodies } :: acc)
          else Error (Broken_link { number; expected = link; found }))
        (fetch number)
  in
  if Consensus_block.Number.compare upto after <= 0 then
    (* Nothing outstanding. [upto] is normalised to [after] rather than kept as
       the caller passed it, so an empty run reports the watermark it leaves the
       resumed node at, exactly as a non-empty one does. *)
    Ok { after; upto = after; records = [] }
  else walk (Consensus_block.Number.succ after) parent []

let after t = t.after
let upto t = t.upto
let is_empty t = match t.records with [] -> true | _ :: _ -> false
let length t = List.length t.records
let blocks t = List.map (fun r -> r.block) t.records
let sub_dags t = List.map (fun r -> Consensus_block.sub_dag r.block) t.records
let bodies t = List.concat_map (fun r -> r.bodies) t.records

(* The final block without a reversal or a partial accessor: the fold keeps the
   last [Some] it saw and answers [None] on the empty run. *)
let last t = List.fold_left (fun _ r -> Some r.block) None t.records
