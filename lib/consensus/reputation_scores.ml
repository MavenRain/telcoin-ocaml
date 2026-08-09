open Tn_types
module Bcs = Tn_codec.Bcs

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

(* The storage decoder's producer. A fold of [add] over the decoded bindings:
   nothing is derived from a committee, because a decoder has none. *)
let of_persisted ~bindings ~final =
  {
    scores =
      List.fold_left
        (fun m (id, score) -> Authority_id.Map.add id score m)
        Authority_id.Map.empty bindings;
    final;
  }

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

(* Rust's [ReputationScores] (primary/reputation.rs:8-18) is two fields: a
   [BTreeMap<AuthorityIdentifier, u64>] and [final_of_schedule: bool]. So the
   wire is a ULEB128-counted map of BARE 32-byte keys ([AuthorityIdentifier]
   serialises through serde's array impl, which bcs writes unprefixed) to
   little-endian u64 values in ascending key order, then one bool byte, and
   nothing else. [sorted_map] re-checks ascending order on decode, which also
   rules out a repeated key.

   These are the very bytes [Sub_dag.preimage] hashes for its scores section,
   so the two share this codec rather than agreeing by coincidence. *)
let wire_codec =
  Bcs.pair
    (Bcs.sorted_map (Bcs.fixed_bytes 32) Bcs.u64 ~compare:String.compare)
    Bcs.bool

let to_wire t =
  ( List.map
      (fun (id, score) -> (Authority_id.to_bytes id, Int64.of_int score))
      (bindings t),
    is_final t )

(* A u64 the host int cannot hold is refused rather than wrapped. *)
let fits_host s =
  Int64.compare s 0L >= 0 && Int64.compare s (Int64.of_int max_int) <= 0

(* [fixed_bytes 32] fixes the width, so [of_bytes] cannot miss; the default is
   a constant, which keeps the eager [~default:] honest. *)
let id_of_raw raw =
  Authority_id.of_bytes raw |> Option.value ~default:Authority_id.zero

let of_wire (entries, final) =
  if not (List.for_all (fun (_, score) -> fits_host score) entries) then
    Error "reputation scores: a score does not fit a host integer"
  else
    Ok
      (of_persisted ~final
         ~bindings:
           (List.map
              (fun (raw, score) -> (id_of_raw raw, Int64.to_int score))
              entries))

let codec : t Bcs.t = Bcs.refine ~inject:of_wire ~project:to_wire wire_codec

let equal a b =
  Authority_id.Map.equal Int.equal a.scores b.scores && Bool.equal a.final b.final
