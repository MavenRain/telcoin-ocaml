open Tn_std
open Tn_types
open Tn_vertex

(* Newest first: [append] prepends, so [latest] and the final-scores scan read the
   head, and [to_list] reverses back to commit order. *)
type t = Sub_dag.t list

let empty = []
let append t sub_dag = sub_dag :: t
let of_list l = List.rev l
let to_list t = List.rev t

let latest = function [] -> None | sub_dag :: _ -> Some sub_dag

(* Per-author max round over every header of every sub-DAG. Each sub-DAG's headers
   already include its leader as the last element, so the leader is covered without
   a separate pass — the exact set the live [Dag.update] watermark accumulates. *)
let last_committed t =
  let keep_max r existing =
    Some (Option.fold existing ~none:r ~some:(fun r0 -> if Round.compare r r0 > 0 then r else r0))
  in
  List.fold_left
    (fun m sub_dag ->
      Nonempty.to_list (Sub_dag.headers sub_dag)
      |> List.fold_left
           (fun m header ->
             Authority_id.Map.update (Header.author header) (keep_max (Header.round header)) m)
           m)
    Authority_id.Map.empty t

let last_committed_round t =
  Authority_id.Map.fold
    (fun _ r acc -> if Round.compare r acc > 0 then r else acc)
    (last_committed t) Round.genesis

let latest_final_scores t =
  List.find_opt (fun sub_dag -> Reputation_scores.is_final (Sub_dag.scores sub_dag)) t
