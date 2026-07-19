open Tn_std
open Tn_types
open Tn_vertex

(* Header digests are a valid set element because [Digests.Header_digest]
   supplies [compare]; the flatten and linkage walks test membership against a
   frontier's parent set in log time, mirroring dag.ml's local [Digest_map]. *)
module Digest_set = Set.Make (Digests.Header_digest)

type t = {
  committee : Committee.t;
  schedule : Leader_schedule.t;
  sub_dags_per_schedule : int; (* >= 1, clamped in create *)
  dag : Dag.t;
  last_sub_dag : Sub_dag.t option;
  max_inserted : Round.t;
}

type no_commit =
  | Certificate_below_commit_round
  | No_leader_round
  | Leader_below_commit_round
  | Leader_not_found
  | Not_enough_support

type outcome = Committed of Sub_dag.t Nonempty.t | No_commit of no_commit

let no_commit_to_string = function
  | Certificate_below_commit_round -> "certificate below commit round"
  | No_leader_round -> "no leader round"
  | Leader_below_commit_round -> "leader below commit round"
  | Leader_not_found -> "leader not found"
  | Not_enough_support -> "not enough support for leader"

let outcome_to_string = function
  | No_commit r -> Printf.sprintf "no commit: %s" (no_commit_to_string r)
  | Committed sub_dags ->
      Nonempty.to_list sub_dags
      |> List.map (fun sd -> Round.to_string (Sub_dag.leader_round sd))
      |> String.concat ", "
      |> Printf.sprintf "committed leader rounds [%s]"

let equal_outcome a b =
  match (a, b) with
  | No_commit x, No_commit y -> x = y
  | Committed xs, Committed ys -> Nonempty.equal Sub_dag.equal xs ys
  | No_commit _, Committed _ | Committed _, No_commit _ -> false

(* The internal per-attempt result of the commit loop. It is a closed sum with
   no options: [Chain_committed] and [Schedule_changed] both carry a non-empty
   batch (a schedule only changes after committing at least one sub-DAG), so the
   "commit implies sub-DAGs" invariant is structural, not a convention. *)
type step =
  | Stopped of no_commit
  | Chain_committed of Sub_dag.t Nonempty.t
  | Schedule_changed of Sub_dag.t Nonempty.t

let ( let* ) = Result.bind
let round_max a b = if Round.compare a b >= 0 then a else b

let create ~committee ~schedule ~sub_dags_per_schedule ~gc_depth =
  {
    committee;
    schedule;
    sub_dags_per_schedule = max 1 sub_dags_per_schedule;
    dag = Dag.create ~gc_depth;
    last_sub_dag = None;
    max_inserted = Round.genesis;
  }

(* Reconstruct the commit state from persistence — Rust's
   [ConsensusState::new_from_store]. The committed watermark, committed round, and
   last committed sub-DAG derive from the log ([read_last_committed] /
   [latest_consensus_header]); the DAG rebuilds from the certificate slice; and
   the schedule is recovered separately (installed before this call, as Rust
   installs the swap table before spawning consensus). [max_inserted] is
   bookkeeping only, restored to the highest recovered certificate round. *)
let of_store ~committee ~schedule ~sub_dags_per_schedule ~gc_depth ~certificates ~committed =
  let last_committed = Committed_log.last_committed committed in
  let last_committed_round = Committed_log.last_committed_round committed in
  Dag.recover ~gc_depth ~last_committed_round ~last_committed ~certificates
  |> Result.map (fun dag ->
         let max_inserted =
           List.fold_left
             (fun acc c -> round_max acc (Certificate.round c))
             Round.genesis certificates
         in
         {
           committee;
           schedule;
           sub_dags_per_schedule = max 1 sub_dags_per_schedule;
           dag;
           last_sub_dag = Committed_log.latest committed;
           max_inserted;
         })

(* Is there a parent-edge path from [leader] down to [prev] entirely through
   certificates currently in the DAG? The frontier starts at the leader and, for
   each round from [leader.round - 1] down to [prev.round], becomes the
   certificates at that round named as a parent by some frontier member; a round
   with nothing stored empties it permanently. *)
let linked t leader_cert prev_cert =
  let target = Certificate.round prev_cert in
  let rec walk frontier r =
    let parent_set =
      List.fold_left
        (fun s c ->
          List.fold_left
            (fun s d -> Digest_set.add d s)
            s
            (Header.parents (Certificate.header c)))
        Digest_set.empty frontier
    in
    let frontier' =
      Dag.round_certificates t.dag r
      |> List.filter (fun c -> Digest_set.mem (Certificate.digest c) parent_set)
    in
    if Round.equal r target then frontier'
    else walk frontier' (Round.sub_saturating r 1)
  in
  let final = walk [ leader_cert ] (Round.sub_saturating (Certificate.round leader_cert) 1) in
  List.exists (Certificate.equal prev_cert) final

(* The chain of past uncommitted leaders linked to [leader_cert], oldest first
   and ending with [(lr, leader_cert)]. Descends by even rounds via
   [Leader_round.prev]; a missing leader certificate skips the round keeping the
   current anchor, a present-but-unlinked one is permanently skipped, a linked
   one is prepended and becomes the new anchor. *)
let order_leaders t leader_cert lr =
  let rec scan anchor acc lr' =
    Leader_round.prev lr'
    |> Option.fold ~none:acc ~some:(fun r ->
           if Round.compare (Leader_round.to_round r) (Dag.committed_round t.dag) <= 0 then acc
           else
             let _authority, prev_opt = Leader_schedule.leader_certificate t.schedule t.dag r in
             prev_opt
             |> Option.fold ~none:(scan anchor acc r) ~some:(fun prev_cert ->
                    if linked t anchor prev_cert then scan prev_cert ((r, prev_cert) :: acc) r
                    else scan anchor acc r))
  in
  scan leader_cert [ (lr, leader_cert) ] lr

(* Flatten the sub-DAG rooted at [leader_cert] — a pre-order DFS over parent
   edges, stopping expansion at the leader-relative GC band and skipping any
   certificate already ordered or below its author's committed watermark. The
   result is round-sorted (stable), so the leader, the unique highest round,
   lands last. *)
let order_dag t leader_cert =
  let local_gc = Round.sub_saturating (Certificate.round leader_cert) (Dag.gc_depth t.dag) in
  let rec walk stack discovered seen =
    match stack with
    | [] -> List.rev discovered
    | cert :: rest ->
        let discovered = cert :: discovered in
        if Round.equal (Certificate.round cert) (Round.succ local_gc) then walk rest discovered seen
        else
          let prev_round = Round.sub_saturating (Certificate.round cert) 1 in
          let retained, seen =
            List.fold_left
              (fun (kept, seen) parent_digest ->
                Dag.get_by_digest t.dag parent_digest
                |> Option.fold ~none:(kept, seen) ~some:(fun p ->
                       (* [dag[round - 1]]-only semantics: a parent found at any
                          other round counts as missing. Then drop it if already
                          ordered or at/below its author's watermark. *)
                       if not (Round.equal (Certificate.round p) prev_round) then (kept, seen)
                       else if Digest_set.mem parent_digest seen then (kept, seen)
                       else if
                         Round.compare (Certificate.round p)
                           (Dag.last_committed_round t.dag (Certificate.origin p))
                         <= 0
                       then (kept, seen)
                       else (p :: kept, Digest_set.add parent_digest seen)))
              ([], seen)
              (Header.parents (Certificate.header cert))
          in
          (* [retained] is reverse-parents order (head = last parent), so
             prepending it reproduces Rust's push-in-order / pop-the-end DFS. *)
          walk (retained @ rest) discovered seen
  in
  (* Stable round sort keeps DFS discovery order within a round and puts the
     leader — the unique highest round — last, which is what lets
     {!Sub_dag.create} recover it as [Nonempty.last]. *)
  walk [ leader_cert ] [] Digest_set.empty
  |> List.stable_sort (fun a b -> Round.compare (Certificate.round a) (Certificate.round b))

(* The reputation scores stored alongside a sub-DAG: cloned from the previous
   commit (or reset at each schedule window boundary), then one point per
   authority whose certificate at the previous leader's round + 1 named that
   leader as a parent, and finally marked final at the window boundary. Unsigned
   64-bit division mirrors Rust exactly (a high epoch can set int64's sign bit).
   The reset branch still takes the bumps, so the first commit of a window scores
   one, not zero. *)
let resolve_scores t leader_cert sequence =
  let idx =
    Units.Sequence_number.of_epoch_round (Certificate.epoch leader_cert)
      (Certificate.round leader_cert)
  in
  let half = Int64.unsigned_div (Units.Sequence_number.to_int64 idx) 2L in
  let k = Int64.of_int t.sub_dags_per_schedule in
  let base =
    if Int64.equal (Int64.unsigned_rem half k) 0L then Reputation_scores.fresh t.committee
    else
      t.last_sub_dag
      |> Option.fold ~none:(Reputation_scores.fresh t.committee) ~some:Sub_dag.scores
  in
  let bumped =
    t.last_sub_dag
    |> Option.fold ~none:base ~some:(fun prev ->
           let pl_round = Sub_dag.leader_round prev in
           let pl_digest = Header.digest (Sub_dag.leader prev) in
           List.fold_left
             (fun sc c ->
               if
                 Round.equal (Certificate.round c) (Round.succ pl_round)
                 && List.exists
                      (Digests.Header_digest.equal pl_digest)
                      (Header.parents (Certificate.header c))
               then Reputation_scores.bump sc (Certificate.origin c)
               else sc)
             base sequence)
  in
  Reputation_scores.with_final (Int64.equal (Int64.unsigned_rem (Int64.add half 1L) k) 0L) bumped

(* Commit one leader: flatten its sub-DAG, garbage-collect and advance watermarks
   per certificate, tally scores against the still-previous sub-DAG, build and
   chain the sub-DAG, then install a new schedule if the scores are final.
   Returns the advanced state, the sub-DAG, and whether the schedule changed. *)
let rec commit_one t (leader_lr, leader_cert) =
  let sequence = order_dag t leader_cert in
  let dag' = List.fold_left Dag.update t.dag sequence in
  let scores = resolve_scores t leader_cert sequence in
  (* [sequence] always contains the leader, so [of_list] is [Some]; the default
     is dead and only keeps the construction total. *)
  let seq_ne = Nonempty.of_list sequence |> Option.value ~default:(Nonempty.singleton leader_cert) in
  let sub_dag = Sub_dag.create ~sequence:seq_ne ~scores ~previous:t.last_sub_dag in
  let t = { t with dag = dag'; last_sub_dag = Some sub_dag } in
  Leader_schedule.note_final_scores t.schedule ~activation:leader_lr scores
  |> Option.fold
       ~none:(t, sub_dag, false)
       ~some:(fun schedule' -> ({ t with schedule = schedule' }, sub_dag, true))

(* Fold the rest of the leader chain onto an accumulated batch. A schedule change
   with more leaders still queued exits early so the caller retries them under
   the new schedule; a change with nothing left is simply absorbed. *)
and continue_chain t acc changed rest =
  match (changed, rest) with
  | true, _ :: _ -> (t, Schedule_changed acc)
  | true, [] -> (t, Chain_committed acc)
  | false, [] -> (t, Chain_committed acc)
  | false, next :: rest' ->
      let t, sub_dag, changed' = commit_one t next in
      continue_chain t (Nonempty.append_list acc [ sub_dag ]) changed' rest'

(* Attempt to commit the leader of [lr]: it must have a certificate and at least
   [f+1] child support, then its linked chain of past leaders commits oldest
   first. *)
let commit_leader t lr =
  let _authority, leader_opt = Leader_schedule.leader_certificate t.schedule t.dag lr in
  leader_opt
  |> Option.fold ~none:(t, Stopped Leader_not_found) ~some:(fun leader_cert ->
         let leader_digest = Certificate.digest leader_cert in
         let support =
           Dag.round_certificates t.dag (Round.succ (Leader_round.to_round lr))
           |> List.filter (fun c ->
                  List.exists
                    (Digests.Header_digest.equal leader_digest)
                    (Header.parents (Certificate.header c)))
           |> List.map Certificate.origin
           |> Authority_id.Set.of_list
           |> Committee.stake_of t.committee
         in
         if not (Committee.reaches_validity t.committee support) then (t, Stopped Not_enough_support)
         else
           match order_leaders t leader_cert lr with
           | [] -> (t, Stopped Not_enough_support) (* unreachable: chain includes the leader *)
           | first :: rest ->
               let t, sub_dag, changed = commit_one t first in
               continue_chain t (Nonempty.singleton sub_dag) changed rest)

(* Retry [commit_leader lr] while it reports a schedule change, accumulating the
   sub-DAGs. Terminates because each retry has strictly advanced the committed
   round toward [lr]. *)
let rec run_commit t lr =
  let t, step = commit_leader t lr in
  match step with
  | Stopped reason -> (t, No_commit reason)
  | Chain_committed committed -> (t, Committed committed)
  | Schedule_changed committed ->
      let t, tail = run_commit t lr in
      let merged =
        match tail with
        | Committed more -> Committed (Nonempty.append_list committed (Nonempty.to_list more))
        | No_commit _ -> Committed committed
      in
      (t, merged)

let process_certificate t certificate =
  let* dag', relevant = Dag.try_insert t.dag certificate in
  if not relevant then Ok ({ t with dag = dag' }, No_commit Certificate_below_commit_round)
  else
    let round = Certificate.round certificate in
    let t = { t with dag = dag'; max_inserted = round_max t.max_inserted round } in
    let result =
      Option.bind (Round.pred round) Leader_round.of_round
      |> Option.fold ~none:(t, No_commit No_leader_round) ~some:(fun lr ->
             if Round.compare (Leader_round.to_round lr) (Dag.committed_round t.dag) <= 0 then
               (t, No_commit Leader_below_commit_round)
             else run_commit t lr)
    in
    Ok result

let dag t = t.dag
let schedule t = t.schedule
let last_sub_dag t = t.last_sub_dag
let max_inserted_round t = t.max_inserted
