open Tn_std
open Tn_types
open Tn_vertex

module Threshold = struct
  type t = int

  let of_percent p = if p >= 0 && p <= 33 then Some p else None
  let to_percent t = t
  let default = 33
end

(* [No_swaps] is the default table and also every table whose bad set turned out
   empty (or, unreachably, whose good set did): behaviourally identical to a
   Rust table whose bad map never matches. [Swaps] carries its good nodes as a
   {!Nonempty} so the "there must be a good node" expectation is structural. *)
type table =
  | No_swaps
  | Swaps of { good : Authority.t Nonempty.t; bad : Authority_id.Set.t }

type t = { committee : Committee.t; threshold : Threshold.t; table : table }

let create committee ~threshold = { committee; threshold; table = No_swaps }
let committee t = t.committee

(* Floor of the integer square root by binary search — equals Rust's
   [(v as f64).sqrt() as u64] for every v below 2^52, and scores are tiny
   (bounded by commits per schedule window), so the equivalence holds with vast
   headroom. *)
let isqrt x =
  if x <= 0 then 0
  else
    let rec go lo hi =
      if lo >= hi then lo
      else
        let mid = (lo + hi + 1) / 2 in
        if mid * mid <= x then go mid hi else go lo (mid - 1)
    in
    go 0 x

(* Build a swap table from final scores, mirroring [LeaderSwapTable::new]'s
   integer arithmetic. Bad nodes are the low scorers (score <= a ceiling that
   descends by one std until at most [cap] remain, or bottoms out oversized);
   good nodes are the high scorers (score >= a floor that descends but never
   below [bad_ceil + 1]). Uniform or near-uniform scores short-circuit to
   [No_swaps]. *)
let build_table committee threshold scores =
  let entries = Reputation_scores.by_score_desc scores in
  let n = List.length entries in
  if n = 0 then No_swaps
  else
    let cap = max 1 (n * Threshold.to_percent threshold / 100) in
    let highest = List.nth_opt entries 0 |> Option.fold ~none:0 ~some:snd in
    let lowest = List.fold_left (fun _ (_, s) -> s) 0 entries in
    let sum = List.fold_left (fun acc (_, s) -> acc + s) 0 entries in
    let mean = sum / n in
    let variance =
      List.fold_left (fun acc (_, s) -> acc + ((s - mean) * (s - mean))) 0 entries / n
    in
    let std = isqrt variance in
    if std = 0 || lowest > max 0 (highest - (2 * std)) then No_swaps
    else
      (* ascending score, ascending id — the exact reverse of the desc list,
         matching Rust's [.rev()] collection order. *)
      let ascending = List.rev entries in
      let rec bad_of ceil =
        let picked = List.filter (fun (_, s) -> s <= ceil) ascending in
        if List.length picked <= cap then (picked, ceil)
        else
          let ceil' = max 0 (ceil - std) in
          if ceil' = ceil then (picked, ceil) else bad_of ceil'
      in
      let bad_list, bad_ceil = bad_of (max 0 (highest - (2 * std))) in
      let rec good_of floor =
        let picked = List.filter (fun (_, s) -> s >= floor) entries in
        if List.length picked >= cap then picked
        else
          let floor' = max (max 0 (floor - std)) (bad_ceil + 1) in
          if floor' = floor then picked else good_of floor'
      in
      let good_list = good_of (max (max 0 (highest - std)) (bad_ceil + 1)) in
      let bad = Authority_id.Set.of_list (List.map fst bad_list) in
      if Authority_id.Set.is_empty bad then No_swaps
      else
        let good_auths =
          List.filter_map (fun (id, _) -> Committee.authority committee id) good_list
        in
        (* Bad non-empty implies some score <= bad_ceil <= highest - 2*std <
           highest (std > 0 on this path), so the top-scored authority clears the
           good floor: the good list is non-empty here. The [None] arm degrades
           safely to [No_swaps] regardless. *)
        Nonempty.of_list good_auths
        |> Option.fold ~none:No_swaps ~some:(fun good -> Swaps { good; bad })

(* Draw a replacement from the good nodes, seeded by the queried round (Rust
   seeds from the round being elected, not the table's activation round).
   DOCUMENTED DIVERGENCE: Rust seeds ChaCha12 (rand 0.9 StdRng) with 24 zero
   bytes ++ LE round and draws via Lemire rejection; this port seeds the house
   SplitMix64 {!Prng} with the round. Determinism is identical (same round +
   same table => same swap); the concrete choice differs only when the good list
   has more than one element — cross-implementation agreement is deferred behind
   the {!Tn_std.Prng} seam. *)
let pick good lr =
  let g = Prng.of_seed (Int64.of_int (Round.to_int (Leader_round.to_round lr))) in
  let i, _ = Prng.int_in g ~lo:0 ~hi:(Nonempty.length good - 1) in
  List.nth_opt (Nonempty.to_list good) i |> Option.value ~default:(Nonempty.head good)

let leader t lr =
  let base = Committee.nth_mod t.committee (Leader_round.schedule_index lr) in
  match t.table with
  | No_swaps -> base
  | Swaps { good; bad } ->
      if Authority_id.Set.mem (Authority.id base) bad then pick good lr else base

let leader_certificate t dag lr =
  let a = leader t lr in
  (a, Dag.get dag (Leader_round.to_round lr) (Authority.id a))

let note_final_scores t ~activation scores =
  (* [activation] is the leader round this table takes effect from. The Rust
     [from_store] rebuild keys on it; nothing in this pure port consults it yet,
     so it is reserved rather than stored. *)
  ignore (activation : Leader_round.t);
  if not (Reputation_scores.is_final scores) then None
  else Some { t with table = build_table t.committee t.threshold scores }

(* Rebuild the schedule at startup — the port of [LeaderSchedule::from_store].
   The swap table in force at the crash was the one built from the last committed
   sub-DAG whose scores were final, so recovery finds that sub-DAG in the log and
   replays exactly the [note_final_scores] the commit rule ran then. No final-scores
   commit (a fresh epoch) recovers to the round-robin [No_swaps] schedule. The
   [note_final_scores] [None] branch cannot fire here — the scan already filtered on
   [is_final] — but is folded away to keep [from_store] total. *)
let from_store committee ~threshold log =
  let base = create committee ~threshold in
  Committed_log.latest_final_scores log
  |> Option.fold ~none:base ~some:(fun sub_dag ->
         Leader_round.of_round (Sub_dag.leader_round sub_dag)
         |> Option.fold ~none:base ~some:(fun activation ->
                note_final_scores base ~activation (Sub_dag.scores sub_dag)
                |> Option.value ~default:base))

let good_nodes t =
  match t.table with No_swaps -> [] | Swaps { good; _ } -> Nonempty.to_list good

let bad_nodes t =
  match t.table with No_swaps -> Authority_id.Set.empty | Swaps { bad; _ } -> bad
