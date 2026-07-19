open Tn_types

type t = { scores : int Authority_id.Map.t; final : bool }

let fresh committee =
  let scores =
    List.fold_left
      (fun m a -> Authority_id.Map.add (Authority.id a) 0 m)
      Authority_id.Map.empty
      (Committee.authorities committee)
  in
  { scores; final = false }

(* [Option.map succ] on an absent key yields [None], so [update] is a no-op for
   an id the committee never seeded: the key set is provably closed under [bump]
   and no partiality or membership match is needed. Rust's [add_score] instead
   inserts a fresh entry in its else branch (reputation.rs); the certificates
   whose origins are bumped here are always committee members, so the reachable
   behaviour is identical while the coverage invariant stays airtight. *)
let bump t id = { t with scores = Authority_id.Map.update id (Option.map succ) t.scores }

let with_final final t = { t with final }
let is_final t = t.final
let get t id = Authority_id.Map.find_opt id t.scores |> Option.value ~default:0
let bindings t = Authority_id.Map.bindings t.scores

let by_score_desc t =
  (* Descending score; ties descending id — no match on the [compare] result,
     just the guard-free [if]. Ties-desc-by-id is load-bearing: it fixes the
     good-node order the swap table is carved from. *)
  List.sort
    (fun (id1, s1) (id2, s2) ->
      let c = Int.compare s2 s1 in
      if c <> 0 then c else Authority_id.compare id2 id1)
    (bindings t)

let total_authorities t = Authority_id.Map.cardinal t.scores
let all_zero t = Authority_id.Map.for_all (fun _ s -> s = 0) t.scores

let equal a b =
  Authority_id.Map.equal Int.equal a.scores b.scores && Bool.equal a.final b.final
