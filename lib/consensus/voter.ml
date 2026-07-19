open Tn_types
open Tn_vertex

(* The persistent vote-once entry: the latest header this node signed for an
   author, keyed by author. Rust's VoteDigestStore keeps only the latest vote per
   author, so the dedup key is the author, not (author, round). *)
type record = {
  round : Round.t;
  header_digest : Digests.Header_digest.t;
  vote : Vote.t;
}

type t = {
  committee : Committee.t;
  secret_key : Tn_crypto.Secret_key.t;
  self_id : Authority_id.t;
  genesis : Certificate.t list;
  last_votes : record Authority_id.Map.t;
}

let create ~committee ~secret_key ~self_id ~genesis =
  { committee; secret_key; self_id; genesis; last_votes = Authority_id.Map.empty }

let has_voted t author round =
  Option.fold (Authority_id.Map.find_opt author t.last_votes) ~none:false
    ~some:(fun r -> Round.compare r.round round >= 0)

type reject_reason =
  | Header_invalid of Header.error
  | Round_zero
  | Invalid_parent_round
  | Inquorate_parents
  | Non_monotone_timestamp
  | Future_timestamp
  | Already_voted_higher
  | Equivocating_header

type decision =
  | Vote of Vote.t
  | Recast of Vote.t
  | Need_parents of Digests.Header_digest.t list
  | Reject of reject_reason

let ( let* ) = Result.bind

(* Resolve a parent digest to its certificate: the genesis certificates first
   (round-1 parents point at them and they are never in the DAG), then the DAG. *)
let resolve t dag digest =
  let from_genesis =
    List.find_opt
      (fun c -> Digests.Header_digest.equal (Certificate.digest c) digest)
      t.genesis
  in
  Option.fold from_genesis
    ~none:(Dag.get_by_digest dag digest)
    ~some:(fun c -> Some c)

(* Vote-once gate. An unseen author proceeds; a header below the round we last
   voted for the author drops the stale request; at the same round an identical
   digest recasts the stored vote. A {e different} digest at the same round is
   equivocation only when a certificate already exists for that (author, round):
   the earlier vote then contributed to a real quorum, so signing a conflicting
   header would help forge a second certificate. When no certificate exists the
   earlier vote never aggregated (the proposer was killed before quorum, then
   restarted with a new header), and re-voting is safe — this mirrors Rust's
   [read_by_index] carve-out and keeps liveness under proposer restarts. *)
let check_vote_once t dag header header_digest =
  Option.fold
    (Authority_id.Map.find_opt (Header.author header) t.last_votes)
    ~none:(Ok ())
    ~some:(fun r ->
      let cmp = Round.compare (Header.round header) r.round in
      if cmp < 0 then Error (Reject Already_voted_higher)
      else if cmp > 0 then Ok ()
      else if Digests.Header_digest.equal header_digest r.header_digest then
        Error (Recast r.vote)
      else if
        Option.is_some (Dag.get dag (Header.round header) (Header.author header))
      then Error (Reject Equivocating_header)
      else Ok ())

(* Parent existence, one-round-below layering, quorum by distinct origin, and
   timestamp monotonicity. Missing parents short-circuit to [Need_parents]. *)
let check_parents t dag header =
  let resolved = List.map (fun d -> (d, resolve t dag d)) (Header.parents header) in
  let missing =
    List.filter_map (fun (d, o) -> if Option.is_none o then Some d else None) resolved
  in
  if not (List.is_empty missing) then Error (Need_parents missing)
  else
    let parents = List.filter_map (fun (_, o) -> o) resolved in
    let expected = Round.pred (Header.round header) in
    let layering_ok =
      Option.fold expected ~none:false ~some:(fun pr ->
          List.for_all (fun c -> Round.equal (Certificate.round c) pr) parents)
    in
    if not layering_ok then Error (Reject Invalid_parent_round)
    else
      let origins =
        List.fold_left
          (fun s c -> Authority_id.Set.add (Certificate.origin c) s)
          Authority_id.Set.empty parents
      in
      if
        not
          (Committee.reaches_quorum t.committee
             (Committee.stake_of t.committee origins))
      then Error (Reject Inquorate_parents)
      else
        let parent_max =
          List.fold_left
            (fun acc c ->
              Units.Timestamp.max acc (Header.created_at (Certificate.header c)))
            Units.Timestamp.zero parents
        in
        if Units.Timestamp.compare (Header.created_at header) parent_max < 0 then
          Error (Reject Non_monotone_timestamp)
        else Ok ()

let vote t ~dag ~now header =
  let header_digest = Header.digest header in
  let outcome : (unit, decision) result =
    let* () =
      Result.map_error
        (fun e -> Reject (Header_invalid e))
        (Header.validate t.committee header)
    in
    let* () =
      if Round.equal (Header.round header) Round.genesis then
        Error (Reject Round_zero)
      else Ok ()
    in
    let* () = check_vote_once t dag header header_digest in
    let* () = check_parents t dag header in
    if Units.Timestamp.compare (Header.created_at header) now > 0 then
      Error (Reject Future_timestamp)
    else Ok ()
  in
  Result.fold outcome
    ~error:(fun decision -> (t, decision))
    ~ok:(fun () ->
      let v = Vote.sign t.secret_key ~voter:t.self_id header in
      let record =
        { round = Header.round header; header_digest; vote = v }
      in
      let last_votes =
        Authority_id.Map.add (Header.author header) record t.last_votes
      in
      ({ t with last_votes }, Vote v))
