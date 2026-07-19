type t = {
  epoch : Units.Epoch.t;
  sorted : Authority.t list; (* ascending Authority_id *)
  by_id : Authority.t Authority_id.Map.t;
  total : Units.Stake.t;
  quorum : Units.Stake.t;
  validity : Units.Stake.t;
}

type error = Too_small of int | Duplicate_public_key

let error_to_string = function
  | Too_small n ->
      Printf.sprintf "committee needs at least 2 authorities, got %d" n
  | Duplicate_public_key -> "committee has a duplicate protocol key"

(* Narwhal/Bullshark thresholds over total stake s:
   quorum   = 2s/3 + 1   (>= 2f+1)
   validity = (s+2)/3     (= f+1)
   Reproduces 4->3/2, 7->5/3, 10->7/4 for equal unit stake. *)
let quorum_of total = (2 * total / 3) + 1
let validity_of total = (total + 2) / 3

let create ~epoch authorities =
  let n = List.length authorities in
  if n < 2 then Error (Too_small n)
  else
    (* Fold into an id-keyed map; a collision means a duplicate key. *)
    let add acc a =
      Result.bind acc (fun map ->
          let id = Authority.id a in
          if Authority_id.Map.mem id map then Error Duplicate_public_key
          else Ok (Authority_id.Map.add id a map))
    in
    Result.map
      (fun by_id ->
        let sorted =
          Authority_id.Map.bindings by_id |> List.map snd
          |> List.sort Authority.compare
        in
        let total =
          List.fold_left
            (fun acc a -> Units.Stake.add acc (Authority.voting_power a))
            Units.Stake.zero sorted
        in
        let ts = Units.Stake.to_int total in
        let quorum =
          Units.Stake.of_int (quorum_of ts) |> Option.value ~default:total
        in
        let validity =
          Units.Stake.of_int (validity_of ts) |> Option.value ~default:total
        in
        { epoch; sorted; by_id; total; quorum; validity })
      (List.fold_left add (Ok Authority_id.Map.empty) authorities)

let epoch t = t.epoch
let size t = List.length t.sorted
let total_stake t = t.total
let quorum_threshold t = t.quorum
let validity_threshold t = t.validity
let authorities t = t.sorted
let authority t id = Authority_id.Map.find_opt id t.by_id
let contains t id = Authority_id.Map.mem id t.by_id

let index_of t id =
  (* Position in the id-sorted list; folds carrying the running index and stop
     on the first match. *)
  let _, found =
    List.fold_left
      (fun (i, found) a ->
        match found with
        | Some _ -> (i + 1, found)
        | None -> if Authority_id.equal (Authority.id a) id then (i + 1, Some i) else (i + 1, None))
      (0, None) t.sorted
  in
  found

let nth t i = List.nth_opt t.sorted i

let stake_of t ids =
  List.fold_left
    (fun acc a ->
      if Authority_id.Set.mem (Authority.id a) ids then
        Units.Stake.add acc (Authority.voting_power a)
      else acc)
    Units.Stake.zero t.sorted

let reaches_quorum t s = Units.Stake.(s >= t.quorum)
let reaches_validity t s = Units.Stake.(s >= t.validity)
