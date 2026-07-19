(* Consensus-layer tests. The DAG cases mirror the Rust [dag_state_tests]:
   equivocation, parent verification, GC of old rounds, idempotent insert, and
   rejection of certificates below the GC round, plus the missing-previous-round
   and GC-boundary cases the Rust suite leaves implicit. The aggregator cases pin
   quorum detection, the vote-rejection matrix (including that a rejected author
   is burned for the header), and the parent aggregator's defining property that
   its weight never resets: stragglers keep re-releasing, a post-quorum duplicate
   does not. *)

open Tn_std
open Tn_types
open Tn_vertex
open Tn_consensus

let get = function Some x -> x | None -> Alcotest.fail "expected Some"
let first = function x :: _ -> x | [] -> Alcotest.fail "expected non-empty list"

(* A fixed committee of n validators plus a lookup from id to secret key. *)
let setup n =
  let sks = List.init n (fun i -> Tn_crypto.Secret_key.derive (Int64.of_int i)) in
  let authorities =
    List.map
      (fun sk ->
        Authority.make
          ~protocol_key:(Tn_crypto.Secret_key.public_key sk)
          ~execution_address:Units.Address.zero)
      sks
  in
  let committee =
    match Committee.create ~epoch:Units.Epoch.zero authorities with
    | Ok c -> c
    | Error e -> Alcotest.failf "committee: %s" (Committee.error_to_string e)
  in
  let sk_of id =
    List.find_map
      (fun sk ->
        let a_id = Authority_id.of_public_key (Tn_crypto.Secret_key.public_key sk) in
        if Authority_id.equal a_id id then Some sk else None)
      sks
    |> get
  in
  (committee, sk_of)

let ids committee = List.map Authority.id (Committee.authorities committee)

let a_header committee ~author ~round ?(created_at = 0) ~parents () =
  Header.make ~author
    ~round:(get (Round.of_int round))
    ~epoch:(Committee.epoch committee)
    ~created_at:(get (Units.Timestamp.of_sec (Int64.of_int created_at)))
    ~payload:[] ~parents

(* A certificate on a header, signed by every authority (always past quorum). *)
let certify committee sk_of header =
  let votes = List.map (fun id -> Vote.sign (sk_of id) ~voter:id header) (ids committee) in
  match Certificate.assemble committee header votes with
  | Ok c -> c
  | Error e -> Alcotest.failf "certify: %s" (Certificate.error_to_string e)

let genesis_digests committee = List.map Certificate.digest (Certificate.genesis committee)

(* One certificate per authority for a round, extending the given parents. *)
let round_certs committee sk_of ~round ~parents =
  List.map
    (fun author -> certify committee sk_of (a_header committee ~author ~round ~parents ()))
    (ids committee)

let insert dag cert =
  match Dag.try_insert dag cert with
  | Ok (dag, inserted) -> (dag, inserted)
  | Error e -> Alcotest.failf "insert: %s" (Dag.error_to_string e)

(* ---- vote aggregator ---- *)

let test_vote_quorum_certifies () =
  let committee, sk_of = setup 4 in
  let header = a_header committee ~author:(first (ids committee)) ~round:2
                 ~parents:(genesis_digests committee) () in
  let _, emitted =
    List.fold_left
      (fun (agg, acc) id ->
        let vote = Vote.sign (sk_of id) ~voter:id header in
        let agg, res = Vote_aggregator.add agg committee header vote in
        match res with
        | Ok out -> (agg, out :: acc)
        | Error e -> Alcotest.failf "add: %s" (Certificate.error_to_string e))
      (Vote_aggregator.empty, []) (ids committee)
  in
  (* quorum for size 4 is 3: the third vote certifies, and every accepted vote
     past quorum certifies again (the caller stops at the first). *)
  match List.rev emitted with
  | [ None; None; Some cert; Some _ ] ->
      Alcotest.(check bool) "quorum certificate re-verifies" true
        (Result.is_ok (Certificate.check committee cert));
      Alcotest.(check bool) "certificate is for the voted header" true
        (Digests.Header_digest.equal (Certificate.digest cert) (Header.digest header))
  | _ -> Alcotest.fail "expected certificates at the third and fourth votes only"

let vote_error committee header agg id_signing ~voter =
  let _, res = Vote_aggregator.add agg committee header (Vote.sign id_signing ~voter header) in
  match res with Ok _ -> None | Error e -> Some e

let test_vote_duplicate () =
  let committee, sk_of = setup 4 in
  let header = a_header committee ~author:(first (ids committee)) ~round:2
                 ~parents:(genesis_digests committee) () in
  let id0 = first (ids committee) in
  let agg, _ =
    Vote_aggregator.add Vote_aggregator.empty committee header (Vote.sign (sk_of id0) ~voter:id0 header)
  in
  Alcotest.(check bool) "duplicate voter rejected" true
    (vote_error committee header agg (sk_of id0) ~voter:id0 = Some Certificate.Duplicate_voter)

let test_vote_wrong_header () =
  let committee, sk_of = setup 4 in
  let parents = genesis_digests committee in
  let header = a_header committee ~author:(first (ids committee)) ~round:2 ~parents () in
  let other = a_header committee ~author:(first (ids committee)) ~round:4 ~parents () in
  let id0 = first (ids committee) in
  (* the vote signs [other] but is added to an aggregator certifying [header] *)
  let _, res = Vote_aggregator.add Vote_aggregator.empty committee header
                 (Vote.sign (sk_of id0) ~voter:id0 other) in
  Alcotest.(check bool) "wrong header rejected" true
    (match res with Error Certificate.Wrong_header -> true | _ -> false)

let test_vote_unknown () =
  let committee, _ = setup 4 in
  let header = a_header committee ~author:(first (ids committee)) ~round:2
                 ~parents:(genesis_digests committee) () in
  let outsider = Tn_crypto.Secret_key.derive 999L in
  let outsider_id = Authority_id.of_public_key (Tn_crypto.Secret_key.public_key outsider) in
  Alcotest.(check bool) "unknown voter rejected" true
    (vote_error committee header Vote_aggregator.empty outsider ~voter:outsider_id
     = Some Certificate.Unknown_voter)

let test_vote_bad_signature () =
  let committee, sk_of = setup 4 in
  let header = a_header committee ~author:(first (ids committee)) ~round:2
                 ~parents:(genesis_digests committee) () in
  let id0 = first (ids committee) in
  let id1 = List.nth (ids committee) 1 in
  (* id1 signs but the vote claims to be from id0: it will not verify under id0 *)
  Alcotest.(check bool) "bad signature rejected" true
    (vote_error committee header Vote_aggregator.empty (sk_of id1) ~voter:id0
     = Some Certificate.Bad_signature)

let test_vote_rejected_author_is_burned () =
  let committee, sk_of = setup 4 in
  let header = a_header committee ~author:(first (ids committee)) ~round:2
                 ~parents:(genesis_digests committee) () in
  let id0 = first (ids committee) in
  let id1 = List.nth (ids committee) 1 in
  (* id0's first vote is badly signed (id1 signs as id0) and is rejected *)
  let agg, res1 =
    Vote_aggregator.add Vote_aggregator.empty committee header (Vote.sign (sk_of id1) ~voter:id0 header)
  in
  Alcotest.(check bool) "the bad vote is rejected" true
    (res1 = Error Certificate.Bad_signature);
  (* id0's genuine vote is now refused, because the slot was claimed on first sight *)
  let _, res2 = Vote_aggregator.add agg committee header (Vote.sign (sk_of id0) ~voter:id0 header) in
  Alcotest.(check bool) "the author's later valid vote is a duplicate" true
    (res2 = Error Certificate.Duplicate_voter)

(* ---- parent aggregator ---- *)

let test_parent_quorum_no_reset () =
  let committee, sk_of = setup 4 in
  let certs = round_certs committee sk_of ~round:2 ~parents:(genesis_digests committee) in
  (* four distinct authors, then a repeat of the first *)
  let sequence = certs @ [ first certs ] in
  let _, lengths =
    List.fold_left
      (fun (agg, acc) cert ->
        let agg, released = Parent_aggregator.add agg committee cert in
        (agg, Option.map Nonempty.length released :: acc))
      (Parent_aggregator.empty, []) sequence
  in
  (* quorum for size 4 is 3. The third add releases the three buffered parents;
     the fourth (a straggler past quorum) re-releases just its own delta of one,
     proving the weight did not reset; the fifth (a repeat author) releases
     nothing. *)
  Alcotest.(check (list (option int)))
    "delta release at quorum, re-fire on straggler, ignore post-quorum duplicate"
    [ None; None; Some 3; Some 1; None ] (List.rev lengths)

let test_parent_duplicate_ignored () =
  let committee, sk_of = setup 4 in
  let cert = first (round_certs committee sk_of ~round:2 ~parents:(genesis_digests committee)) in
  let agg, _ = Parent_aggregator.add Parent_aggregator.empty committee cert in
  let agg, released = Parent_aggregator.add agg committee cert in
  Alcotest.(check bool) "repeat author releases nothing" true (Option.is_none released);
  Alcotest.(check int) "repeat author does not grow the buffer" 1
    (List.length (Parent_aggregator.pending agg))

(* ---- dag ---- *)

let test_dag_equivocation () =
  let committee, sk_of = setup 4 in
  let author = first (ids committee) in
  let parents = genesis_digests committee in
  let cert1 = certify committee sk_of (a_header committee ~author ~round:1 ~parents ()) in
  let cert2 =
    certify committee sk_of (a_header committee ~author ~round:1 ~created_at:1 ~parents ())
  in
  Alcotest.(check bool) "the two certificates differ" false
    (Certificate.equal cert1 cert2);
  let dag, inserted = insert (Dag.create ~gc_depth:50) cert1 in
  Alcotest.(check bool) "first insert accepted" true inserted;
  Alcotest.(check bool) "second, different certificate equivocates" true
    (match Dag.try_insert dag cert2 with
     | Error (Dag.Equivocation _) -> true
     | _ -> false);
  (* the equivocator is not stored; the original is kept *)
  Alcotest.(check bool) "the original certificate is still the stored one" true
    (match Dag.get dag (Certificate.round cert1) author with
     | Some c -> Certificate.equal c cert1
     | None -> false)

let test_dag_parent_verification () =
  let committee, sk_of = setup 4 in
  let dag = Dag.create ~gc_depth:50 in
  let round1 = round_certs committee sk_of ~round:1 ~parents:(genesis_digests committee) in
  let dag = List.fold_left (fun dag c -> fst (insert dag c)) dag round1 in
  let round2 =
    round_certs committee sk_of ~round:2 ~parents:(List.map Certificate.digest round1)
  in
  let dag = List.fold_left (fun dag c -> fst (insert dag c)) dag round2 in
  (* a round-3 certificate naming a parent that was never stored *)
  let fake = Digests.Header_digest.of_digest (Tn_crypto.Digest.hash "nonexistent parent") in
  let orphan =
    certify committee sk_of
      (a_header committee ~author:(first (ids committee)) ~round:3 ~parents:[ fake ] ())
  in
  Alcotest.(check bool) "certificate with a missing parent is rejected" true
    (match Dag.try_insert dag orphan with
     | Error (Dag.Missing_parent _) -> true
     | _ -> false)

let test_dag_missing_parent_round () =
  let committee, sk_of = setup 4 in
  let dag = Dag.create ~gc_depth:50 in
  let round1 = round_certs committee sk_of ~round:1 ~parents:(genesis_digests committee) in
  let dag = List.fold_left (fun dag c -> fst (insert dag c)) dag round1 in
  (* jump to round 3, so the whole previous round (2) is absent from the dag *)
  let orphan =
    certify committee sk_of
      (a_header committee ~author:(first (ids committee)) ~round:3
         ~parents:(List.map Certificate.digest round1) ())
  in
  Alcotest.(check bool) "a certificate whose previous round is absent is rejected" true
    (match Dag.try_insert dag orphan with
     | Error (Dag.Missing_parent_round _) -> true
     | _ -> false)

(* Build rounds 1..last, committing the first authority's certificate on even
   rounds, returning the resulting DAG. *)
let build_committed_dag committee sk_of ~gc_depth ~last =
  List.fold_left
    (fun (dag, parents) round ->
      let certs = round_certs committee sk_of ~round ~parents in
      let dag = List.fold_left (fun dag c -> fst (insert dag c)) dag certs in
      let dag = if round mod 2 = 0 then Dag.update dag (first certs) else dag in
      (dag, List.map Certificate.digest certs))
    (Dag.create ~gc_depth, genesis_digests committee)
    (List.init last (fun i -> i + 1))
  |> fst

let test_dag_gc_removes_old_rounds () =
  let committee, sk_of = setup 4 in
  let dag = build_committed_dag committee sk_of ~gc_depth:5 ~last:10 in
  Alcotest.(check int) "gc round is committed(10) - depth(5)" 5
    (Round.to_int (Dag.gc_round dag));
  Alcotest.(check bool) "every retained round is above the gc round" true
    (List.for_all (fun r -> Round.compare r (Dag.gc_round dag) > 0) (Dag.rounds dag));
  Alcotest.(check (list int)) "only rounds 6..10 remain" [ 6; 7; 8; 9; 10 ]
    (List.map Round.to_int (Dag.rounds dag))

let test_dag_idempotent_insert () =
  let committee, sk_of = setup 4 in
  let cert =
    certify committee sk_of
      (a_header committee ~author:(first (ids committee)) ~round:1
         ~parents:(genesis_digests committee) ())
  in
  let dag, first_ok = insert (Dag.create ~gc_depth:50) cert in
  let dag, second_ok = insert dag cert in
  Alcotest.(check bool) "both inserts report newly relevant" true (first_ok && second_ok);
  Alcotest.(check int) "the certificate is stored exactly once" 1
    (List.length (Dag.round_certificates dag (Certificate.round cert)))

let test_dag_rejects_old_certificates () =
  let committee, sk_of = setup 4 in
  let dag = build_committed_dag committee sk_of ~gc_depth:5 ~last:10 in
  let old_cert =
    certify committee sk_of
      (a_header committee ~author:(first (ids committee)) ~round:1
         ~parents:(genesis_digests committee) ())
  in
  let dag, inserted = insert dag old_cert in
  Alcotest.(check bool) "a certificate below the gc round is not inserted" false inserted;
  Alcotest.(check bool) "and is not stored" true
    (Option.is_none (Dag.get dag (Certificate.round old_cert) (Certificate.origin old_cert)))

let test_dag_rejects_at_gc_boundary () =
  let committee, sk_of = setup 4 in
  let dag = build_committed_dag committee sk_of ~gc_depth:5 ~last:10 in
  (* gc round is 5; a certificate exactly at the gc round is dropped (round <= gc) *)
  let boundary =
    certify committee sk_of
      (a_header committee ~author:(first (ids committee)) ~round:5
         ~parents:(genesis_digests committee) ())
  in
  let dag, inserted = insert dag boundary in
  Alcotest.(check bool) "a certificate exactly at the gc round is dropped" false inserted;
  Alcotest.(check bool) "and is not stored" true
    (Option.is_none (Dag.get dag (Certificate.round boundary) (Certificate.origin boundary)))

let test_dag_update_never_regresses () =
  let committee, sk_of = setup 4 in
  let author = first (ids committee) in
  let leader round =
    certify committee sk_of
      (a_header committee ~author ~round ~parents:(genesis_digests committee) ())
  in
  let dag = Dag.update (Dag.create ~gc_depth:2) (leader 6) in
  (* committing an earlier round must not move committed or gc backwards *)
  let dag = Dag.update dag (leader 4) in
  Alcotest.(check int) "committed round holds at the maximum" 6
    (Round.to_int (Dag.committed_round dag));
  Alcotest.(check int) "gc round holds at committed(6) - depth(2)" 4
    (Round.to_int (Dag.gc_round dag))

(* ---- part 2 shared fixtures ---- *)

let get_ne l =
  match Nonempty.of_list l with Some x -> x | None -> Alcotest.fail "expected non-empty"

let id_at committee i = List.nth (ids committee) i

let lr_of r = get (Leader_round.of_round (get (Round.of_int r)))

(* Bump each authority (ascending id order) by the matching count. *)
let make_scores committee counts =
  List.fold_left2
    (fun s id n ->
      let rec bumpn s k = if k <= 0 then s else bumpn (Reputation_scores.bump s id) (k - 1) in
      bumpn s n)
    (Reputation_scores.fresh committee)
    (ids committee) counts

(* Optimal DAG: rounds 1..upto, every authority present, each round's parents the
   whole previous round (round 1 extends genesis). Returns [(round, certs)]. *)
let optimal_rounds committee sk_of ~upto =
  let rec go round parents acc =
    if round > upto then List.rev acc
    else
      let certs = round_certs committee sk_of ~round ~parents in
      go (round + 1) (List.map Certificate.digest certs) ((round, certs) :: acc)
  in
  go 1 (genesis_digests committee) []

let bullshark committee ~k ~gc =
  Bullshark.create ~committee
    ~schedule:(Leader_schedule.create committee ~threshold:Leader_schedule.Threshold.default)
    ~sub_dags_per_schedule:k ~gc_depth:gc

(* Fold [process_certificate] over certs, collecting per-insert outcomes. *)
let feed b certs =
  let b, outs =
    List.fold_left
      (fun (b, outs) c ->
        match Bullshark.process_certificate b c with
        | Ok (b, o) -> (b, o :: outs)
        | Error e -> Alcotest.failf "process: %s" (Dag.error_to_string e))
      (b, []) certs
  in
  (b, List.rev outs)

let nc = function
  | Bullshark.No_commit r -> r
  | Bullshark.Committed _ -> Alcotest.fail "expected No_commit"

let committed = function
  | Bullshark.Committed sds -> Nonempty.to_list sds
  | Bullshark.No_commit r ->
      Alcotest.failf "expected Committed, got %s" (Bullshark.no_commit_to_string r)

let header_rounds sd =
  Nonempty.to_list (Sub_dag.headers sd) |> List.map (fun h -> Round.to_int (Header.round h))

(* ---- reputation scores ---- *)

let test_scores_fresh_and_bump () =
  let committee, _ = setup 4 in
  let id = id_at committee in
  let s = Reputation_scores.fresh committee in
  Alcotest.(check int) "fresh total authorities" 4 (Reputation_scores.total_authorities s);
  Alcotest.(check bool) "fresh all zero" true (Reputation_scores.all_zero s);
  Alcotest.(check int) "fresh get id0" 0 (Reputation_scores.get s (id 0));
  let s =
    Reputation_scores.bump
      (Reputation_scores.bump (Reputation_scores.bump s (id 2)) (id 2))
      (id 0)
  in
  Alcotest.(check (list int)) "bindings ascending id" [ 1; 0; 2; 0 ]
    (List.map snd (Reputation_scores.bindings s));
  Alcotest.(check bool) "by_score_desc: ids2, ids0, then ties desc id ids3, ids1" true
    (List.map fst (Reputation_scores.by_score_desc s) = [ id 2; id 0; id 3; id 1 ]);
  let outsider =
    Authority_id.of_public_key (Tn_crypto.Secret_key.public_key (Tn_crypto.Secret_key.derive 999L))
  in
  let s2 = Reputation_scores.bump s outsider in
  Alcotest.(check int) "bumping a non-member keeps the committee coverage" 4
    (Reputation_scores.total_authorities s2);
  Alcotest.(check bool) "bumping a non-member is a no-op" true (Reputation_scores.equal s s2)

(* ---- leader schedule ---- *)

let test_schedule_round_robin () =
  let committee, _ = setup 4 in
  let id = id_at committee in
  let sched = Leader_schedule.create committee ~threshold:Leader_schedule.Threshold.default in
  let leader_id r = Authority.id (Leader_schedule.leader sched (lr_of r)) in
  List.iteri
    (fun k r ->
      Alcotest.(check bool)
        (Printf.sprintf "round-robin leader of round %d" r)
        true
        (Authority_id.equal (leader_id r) (id (k mod 4))))
    [ 2; 4; 6; 8; 10 ];
  Alcotest.(check bool) "threshold 34 rejected" true
    (Option.is_none (Leader_schedule.Threshold.of_percent 34));
  Alcotest.(check bool) "threshold 0 accepted" true
    (Option.is_some (Leader_schedule.Threshold.of_percent 0));
  Alcotest.(check bool) "threshold 33 accepted" true
    (Option.is_some (Leader_schedule.Threshold.of_percent 33))

let test_schedule_swap_table_4nodes () =
  let committee, _ = setup 4 in
  let id = id_at committee in
  let scores = Reputation_scores.with_final true (make_scores committee [ 0; 1; 2; 3 ]) in
  let sched = Leader_schedule.create committee ~threshold:Leader_schedule.Threshold.default in
  match Leader_schedule.note_final_scores sched ~activation:(lr_of 2) scores with
  | None -> Alcotest.fail "final scores should install a swap table"
  | Some sched' ->
      Alcotest.(check bool) "bad nodes = {ids0}" true
        (Authority_id.Set.equal (Leader_schedule.bad_nodes sched')
           (Authority_id.Set.of_list [ id 0 ]));
      Alcotest.(check bool) "good nodes = [ids3; ids2]" true
        (List.map Authority.id (Leader_schedule.good_nodes sched') = [ id 3; id 2 ]);
      let swapped = Authority.id (Leader_schedule.leader sched' (lr_of 2)) in
      Alcotest.(check bool) "round-2 leader swapped into the good set" true
        (Authority_id.equal swapped (id 2) || Authority_id.equal swapped (id 3));
      Alcotest.(check bool) "swap is deterministic across queries" true
        (Authority_id.equal swapped (Authority.id (Leader_schedule.leader sched' (lr_of 2))));
      Alcotest.(check bool) "non-final scores install nothing" true
        (Option.is_none
           (Leader_schedule.note_final_scores sched ~activation:(lr_of 2)
              (make_scores committee [ 0; 1; 2; 3 ])))

let test_schedule_swap_table_10nodes () =
  let committee, _ = setup 10 in
  let id = id_at committee in
  let sched = Leader_schedule.create committee ~threshold:Leader_schedule.Threshold.default in
  let scores =
    Reputation_scores.with_final true (make_scores committee [ 0; 1; 2; 3; 4; 5; 6; 7; 8; 9 ])
  in
  (match Leader_schedule.note_final_scores sched ~activation:(lr_of 2) scores with
  | None -> Alcotest.fail "should install"
  | Some sched' ->
      Alcotest.(check bool) "bad = {ids0, ids1}" true
        (Authority_id.Set.equal (Leader_schedule.bad_nodes sched')
           (Authority_id.Set.of_list [ id 0; id 1 ]));
      Alcotest.(check bool) "good = [ids9; ids8; ids7]" true
        (List.map Authority.id (Leader_schedule.good_nodes sched') = [ id 9; id 8; id 7 ]));
  (* second shape: seven nodes tied at the top, the 33% cap binds at 3 bad *)
  let scores2 =
    Reputation_scores.with_final true (make_scores committee [ 0; 1; 2; 10; 10; 10; 10; 10; 10; 10 ])
  in
  match Leader_schedule.note_final_scores sched ~activation:(lr_of 2) scores2 with
  | None -> Alcotest.fail "should install"
  | Some sched' ->
      Alcotest.(check int) "cap binds the bad set at 3" 3
        (Authority_id.Set.cardinal (Leader_schedule.bad_nodes sched'))

let test_schedule_uniform_scores_no_swaps () =
  let committee, _ = setup 4 in
  let id = id_at committee in
  let scores = Reputation_scores.with_final true (make_scores committee [ 2; 2; 2; 2 ]) in
  let sched = Leader_schedule.create committee ~threshold:Leader_schedule.Threshold.default in
  match Leader_schedule.note_final_scores sched ~activation:(lr_of 2) scores with
  | None -> Alcotest.fail "uniform final scores still count as a schedule change"
  | Some sched' ->
      Alcotest.(check bool) "no bad nodes" true
        (Authority_id.Set.is_empty (Leader_schedule.bad_nodes sched'));
      Alcotest.(check bool) "no good nodes" true (Leader_schedule.good_nodes sched' = []);
      Alcotest.(check bool) "round-12 leader stays round-robin (ids1)" true
        (Authority_id.equal (Authority.id (Leader_schedule.leader sched' (lr_of 12))) (id 1))

(* ---- sub_dag ---- *)

let test_sub_dag_shape () =
  let committee, sk_of = setup 4 in
  let rounds = optimal_rounds committee sk_of ~upto:2 in
  let r1 = List.assoc 1 rounds and r2 = List.assoc 2 rounds in
  let leader2 = first r2 in
  let sd =
    Sub_dag.create
      ~sequence:(get_ne (r1 @ [ leader2 ]))
      ~scores:(Reputation_scores.fresh committee) ~previous:None
  in
  Alcotest.(check int) "leader round 2" 2 (Round.to_int (Sub_dag.leader_round sd));
  Alcotest.(check bool) "leader author ids0" true
    (Authority_id.equal (Sub_dag.leader_author sd) (id_at committee 0));
  Alcotest.(check int) "five headers" 5 (Nonempty.length (Sub_dag.headers sd));
  Alcotest.(check int) "last header round 2" 2
    (Round.to_int (Header.round (Nonempty.last (Sub_dag.headers sd))));
  Alcotest.(check int) "sequence number round 2" 2
    (Round.to_int (Units.Sequence_number.round (Sub_dag.sequence_number sd)));
  Alcotest.(check bool) "scores start all zero" true
    (Reputation_scores.all_zero (Sub_dag.scores sd))

let test_sub_dag_timestamp_and_digest () =
  let committee, sk_of = setup 4 in
  let mk ca =
    let r1 = round_certs committee sk_of ~round:1 ~parents:(genesis_digests committee) in
    let leader =
      certify committee sk_of
        (a_header committee ~author:(id_at committee 0) ~round:2 ~created_at:ca
           ~parents:(List.map Certificate.digest r1) ())
    in
    get_ne (r1 @ [ leader ])
  in
  let fresh = Reputation_scores.fresh committee in
  let prev = Sub_dag.create ~sequence:(mk 9) ~scores:fresh ~previous:None in
  Alcotest.(check int) "previous stored timestamp 9" 9
    (Int64.to_int (Units.Timestamp.to_sec (Sub_dag.stored_timestamp prev)));
  let cur = Sub_dag.create ~sequence:(mk 5) ~scores:fresh ~previous:(Some prev) in
  Alcotest.(check int) "current clamped monotone up to 9" 9
    (Int64.to_int (Units.Timestamp.to_sec (Sub_dag.stored_timestamp cur)));
  Alcotest.(check int) "commit timestamp view is 9" 9
    (Int64.to_int (Units.Timestamp.to_sec (Sub_dag.commit_timestamp cur)));
  let cur2 = Sub_dag.create ~sequence:(mk 5) ~scores:fresh ~previous:(Some prev) in
  Alcotest.(check bool) "identical inputs, identical digest" true (Sub_dag.equal cur cur2);
  let cur_final =
    Sub_dag.create ~sequence:(mk 5) ~scores:(Reputation_scores.with_final true fresh)
      ~previous:(Some prev)
  in
  Alcotest.(check bool) "flipping only the final flag changes the digest" false
    (Sub_dag.equal cur cur_final);
  let cur_noprev = Sub_dag.create ~sequence:(mk 5) ~scores:fresh ~previous:None in
  Alcotest.(check bool) "changing only the previous (stored ts) changes the digest" false
    (Sub_dag.equal cur cur_noprev)

(* ---- bullshark commit rule ---- *)

(* Certificates for a specific subset of authors at a round. *)
let certs_for committee sk_of ~round ~authors ~parents =
  List.map
    (fun author -> certify committee sk_of (a_header committee ~author ~round ~parents ()))
    authors

let committed_leaders outs =
  List.concat_map
    (function Bullshark.Committed sds -> Nonempty.to_list sds | Bullshark.No_commit _ -> [])
    outs

let test_bullshark_commit_one () =
  let committee, sk_of = setup 4 in
  let id = id_at committee in
  let rounds = optimal_rounds committee sk_of ~upto:2 in
  let r2 = List.assoc 2 rounds in
  let b, outs12 = feed (bullshark committee ~k:100 ~gc:50) (List.concat_map snd rounds) in
  Alcotest.(check bool) "rounds 1 and 2 elect no leader" true
    (List.for_all (fun o -> nc o = Bullshark.No_leader_round) outs12);
  let r3 = certs_for committee sk_of ~round:3 ~authors:[ id 0; id 1 ] ~parents:(List.map Certificate.digest r2) in
  let _, outs3 = feed b r3 in
  match outs3 with
  | [ o1; o2 ] ->
      Alcotest.(check bool) "first round-3 cert: not enough support" true
        (nc o1 = Bullshark.Not_enough_support);
      let sd = first (committed o2) in
      Alcotest.(check int) "one sub-dag committed" 1 (List.length (committed o2));
      Alcotest.(check (list int)) "header rounds [1;1;1;1;2]" [ 1; 1; 1; 1; 2 ] (header_rounds sd);
      Alcotest.(check bool) "leader author ids0" true
        (Authority_id.equal (Sub_dag.leader_author sd) (id 0));
      Alcotest.(check bool) "scores all zero" true (Reputation_scores.all_zero (Sub_dag.scores sd))
  | _ -> Alcotest.fail "expected exactly two round-3 outcomes"

let test_bullshark_round_robin_run () =
  let committee, sk_of = setup 4 in
  let id = id_at committee in
  let rounds = optimal_rounds committee sk_of ~upto:11 in
  let _, outs = feed (bullshark committee ~k:3 ~gc:50) (List.concat_map snd rounds) in
  let leaders = committed_leaders outs in
  Alcotest.(check bool) "committed leader authors: ids0, ids1, ids2, ids3, ids0" true
    (List.map Sub_dag.leader_author leaders = [ id 0; id 1; id 2; id 3; id 0 ]);
  Alcotest.(check (list int)) "leader rounds 2,4,6,8,10" [ 2; 4; 6; 8; 10 ]
    (List.map (fun sd -> Round.to_int (Sub_dag.leader_round sd)) leaders);
  List.iter
    (function
      | Bullshark.Committed sds ->
          Alcotest.(check int) "each commit carries one sub-dag" 1 (Nonempty.length sds)
      | Bullshark.No_commit _ -> ())
    outs

let test_bullshark_missing_leader () =
  let committee, sk_of = setup 4 in
  let id = id_at committee in
  let authors123 = [ id 1; id 2; id 3 ] in
  let r1 = certs_for committee sk_of ~round:1 ~authors:authors123 ~parents:(genesis_digests committee) in
  let r2 = certs_for committee sk_of ~round:2 ~authors:authors123 ~parents:(List.map Certificate.digest r1) in
  let r3 = round_certs committee sk_of ~round:3 ~parents:(List.map Certificate.digest r2) in
  let r4 = round_certs committee sk_of ~round:4 ~parents:(List.map Certificate.digest r3) in
  let r5 = certs_for committee sk_of ~round:5 ~authors:[ id 0; id 1 ] ~parents:(List.map Certificate.digest r4) in
  let b, o3 = feed (bullshark committee ~k:100 ~gc:50) (r1 @ r2 @ r3) in
  Alcotest.(check bool) "round-3 inserts: leader (ids0 at round 2) not found" true
    (List.for_all (fun o -> nc o = Bullshark.Leader_not_found)
       (List.filteri (fun i _ -> i >= List.length (r1 @ r2)) o3));
  let b, o4 = feed b r4 in
  Alcotest.(check bool) "round-4 inserts: odd leader round" true
    (List.for_all (fun o -> nc o = Bullshark.No_leader_round) o4);
  let _, o5 = feed b r5 in
  match o5 with
  | [ o1; o2 ] ->
      Alcotest.(check bool) "first round-5 cert: not enough support" true
        (nc o1 = Bullshark.Not_enough_support);
      let sd = first (committed o2) in
      Alcotest.(check int) "leader round 4" 4 (Round.to_int (Sub_dag.leader_round sd));
      Alcotest.(check bool) "leader author ids1" true
        (Authority_id.equal (Sub_dag.leader_author sd) (id 1));
      Alcotest.(check (list int)) "header rounds [1;1;1;2;2;2;3;3;3;3;4]"
        [ 1; 1; 1; 2; 2; 2; 3; 3; 3; 3; 4 ] (header_rounds sd);
      Alcotest.(check bool) "scores all zero" true (Reputation_scores.all_zero (Sub_dag.scores sd))
  | _ -> Alcotest.fail "expected exactly two round-5 outcomes"

let test_bullshark_dead_node () =
  let committee, sk_of = setup 4 in
  let id = id_at committee in
  let authors = [ id 0; id 1; id 2 ] in
  let rec build round parents acc =
    if round > 11 then List.rev acc
    else
      let certs = certs_for committee sk_of ~round ~authors ~parents in
      build (round + 1) (List.map Certificate.digest certs) (certs :: acc)
  in
  let all = List.concat (build 1 (genesis_digests committee) []) in
  let _, outs = feed (bullshark committee ~k:100 ~gc:50) all in
  let leaders = committed_leaders outs in
  Alcotest.(check (list int)) "committed leader rounds 2,4,6,10" [ 2; 4; 6; 10 ]
    (List.map (fun sd -> Round.to_int (Sub_dag.leader_round sd)) leaders);
  let concatenated = List.concat_map header_rounds leaders in
  let expected = List.concat_map (fun r -> [ r; r; r ]) [ 1; 2; 3; 4; 5; 6; 7; 8; 9 ] @ [ 10 ] in
  Alcotest.(check (list int)) "28 headers: rounds 1..9 thrice, then round 10" expected concatenated;
  List.iteri
    (fun j sd ->
      let s = Sub_dag.scores sd in
      if j = 0 then Alcotest.(check bool) "sub-dag 1 scores all zero" true (Reputation_scores.all_zero s)
      else begin
        Alcotest.(check int) "the dead node never scores" 0 (Reputation_scores.get s (id 3));
        List.iter
          (fun i ->
            Alcotest.(check int)
              (Printf.sprintf "sub-dag %d, author %d scores %d" (j + 1) i j)
              j (Reputation_scores.get s (id i)))
          [ 0; 1; 2 ]
      end)
    leaders

let test_bullshark_below_commit_and_equivocation () =
  let committee, sk_of = setup 4 in
  let id = id_at committee in
  let rounds = optimal_rounds committee sk_of ~upto:5 in
  let b, outs = feed (bullshark committee ~k:100 ~gc:10) (List.concat_map snd rounds) in
  Alcotest.(check (list int)) "committed leader rounds 2, 4" [ 2; 4 ]
    (List.map (fun sd -> Round.to_int (Sub_dag.leader_round sd)) (committed_leaders outs));
  let low = List.concat_map snd (List.filter (fun (r, _) -> r <= 3) rounds) in
  let _, reouts = feed b low in
  Alcotest.(check bool) "re-fed committed certs are below the commit round, no error" true
    (List.for_all (fun o -> nc o = Bullshark.Certificate_below_commit_round) reouts);
  let b2 = bullshark committee ~k:100 ~gc:10 in
  let r1 = List.assoc 1 rounds in
  let b2, o1 = feed b2 r1 in
  Alcotest.(check bool) "round-1 inserts: no leader round" true
    (List.for_all (fun o -> nc o = Bullshark.No_leader_round) o1);
  let _, o1' = feed b2 r1 in
  Alcotest.(check bool) "byte-identical re-insert stays Ok" true
    (List.for_all (fun o -> nc o = Bullshark.No_leader_round) o1');
  let equiv =
    certify committee sk_of
      (a_header committee ~author:(id 0) ~round:1 ~created_at:100
         ~parents:(genesis_digests committee) ())
  in
  Alcotest.(check bool) "an equivocating round-1 cert errors with its (round, author)" true
    (match Bullshark.process_certificate b2 equiv with
     | Error (Dag.Equivocation (r, a)) -> Round.to_int r = 1 && Authority_id.equal a (id 0)
     | _ -> false)

let test_bullshark_max_inserted_and_genesis_guard () =
  let committee, sk_of = setup 4 in
  let b = bullshark committee ~k:100 ~gc:50 in
  let g0 = first (Certificate.genesis committee) in
  let b =
    match Bullshark.process_certificate b g0 with
    | Ok (b, o) ->
        Alcotest.(check bool) "genesis certificate is below the commit round" true
          (nc o = Bullshark.Certificate_below_commit_round);
        Alcotest.(check int) "max inserted stays at genesis" 0
          (Round.to_int (Bullshark.max_inserted_round b));
        b
    | Error e -> Alcotest.failf "process: %s" (Dag.error_to_string e)
  in
  let rounds = optimal_rounds committee sk_of ~upto:3 in
  let b, _ = feed b (List.concat_map snd rounds) in
  Alcotest.(check int) "max inserted round advances to 3" 3 (Round.to_int (Bullshark.max_inserted_round b))

let cert_of author certs =
  List.find (fun c -> Authority_id.equal (Certificate.origin c) author) certs

(* Certificates for a subset of authors, optionally weakening or dropping a
   leader digest: [weak_leader] keeps that digest only in ids0's parents,
   [drop_leader] removes it from everyone's. *)
let certs_with_config committee sk_of ~round ~authors ~parents ?weak_leader ?drop_leader () =
  let id0 = id_at committee 0 in
  let without d = List.filter (fun p -> not (Digests.Header_digest.equal p d)) parents in
  List.map
    (fun author ->
      let filtered =
        match (weak_leader, drop_leader) with
        | Some d, _ -> if Authority_id.equal author id0 then parents else without d
        | None, Some d -> without d
        | None, None -> parents
      in
      certify committee sk_of (a_header committee ~author ~round ~parents:filtered ()))
    authors

(* A DAG where [slow] references everyone but no one references [slow]. *)
let slow_chain committee sk_of ~slow ~upto =
  let rec go round tagged acc =
    if round > upto then List.rev acc
    else
      let slow_prev =
        List.filter_map (fun (a, d) -> if Authority_id.equal a slow then Some d else None) tagged
      in
      let all = List.map snd tagged in
      let non_slow =
        List.filter (fun d -> not (List.exists (Digests.Header_digest.equal d) slow_prev)) all
      in
      let certs =
        List.map
          (fun author ->
            let p = if Authority_id.equal author slow then all else non_slow in
            certify committee sk_of (a_header committee ~author ~round ~parents:p ()))
          (ids committee)
      in
      go (round + 1)
        (List.map (fun c -> (Certificate.origin c, Certificate.digest c)) certs)
        ((round, certs) :: acc)
  in
  let gen = Certificate.genesis committee in
  go 1 (List.map (fun c -> (Certificate.origin c, Certificate.digest c)) gen) []

let leader_rounds sds = List.map (fun sd -> Round.to_int (Sub_dag.leader_round sd)) sds

let test_bullshark_not_enough_support () =
  let committee, sk_of = setup 4 in
  let id = id_at committee in
  let dg = List.map Certificate.digest in
  let three = [ id 0; id 1; id 2 ] in
  let r1 = certs_for committee sk_of ~round:1 ~authors:three ~parents:(genesis_digests committee) in
  let r2 = round_certs committee sk_of ~round:2 ~parents:(dg r1) in
  let leader2 = cert_of (id 0) r2 in
  let r3 =
    certs_with_config committee sk_of ~round:3 ~authors:three ~parents:(dg r2)
      ~weak_leader:(Certificate.digest leader2) ()
  in
  let r4 = round_certs committee sk_of ~round:4 ~parents:(dg r3) in
  let r5 = certs_for committee sk_of ~round:5 ~authors:[ id 0; id 1 ] ~parents:(dg r4) in
  let b, o3 = feed (bullshark committee ~k:100 ~gc:50) (r1 @ r2 @ r3 @ r4) in
  Alcotest.(check bool) "round-3 inserts are all not-enough-support" true
    (List.exists (fun o -> nc o = Bullshark.Not_enough_support) o3);
  let _, o5 = feed b r5 in
  match o5 with
  | [ o1; o2 ] -> (
      Alcotest.(check bool) "first round-5 not enough support" true
        (nc o1 = Bullshark.Not_enough_support);
      match committed o2 with
      | [ sd2; sd4 ] ->
          Alcotest.(check (list int)) "two sub-dags, leaders 2 then 4" [ 2; 4 ]
            (leader_rounds [ sd2; sd4 ]);
          Alcotest.(check bool) "sub-dag 1 leader ids0" true
            (Authority_id.equal (Sub_dag.leader_author sd2) (id 0));
          Alcotest.(check (list int)) "sub-dag 1 headers [1;1;1;2]" [ 1; 1; 1; 2 ]
            (header_rounds sd2);
          Alcotest.(check bool) "sub-dag 2 leader ids1" true
            (Authority_id.equal (Sub_dag.leader_author sd4) (id 1));
          Alcotest.(check (list int)) "sub-dag 2 headers [2;2;2;3;3;3;4]" [ 2; 2; 2; 3; 3; 3; 4 ]
            (header_rounds sd4);
          Alcotest.(check int) "sub-dag 2 scores: ids0 is the sole supporter of leader 2" 1
            (Reputation_scores.get (Sub_dag.scores sd4) (id 0));
          List.iter
            (fun i ->
              Alcotest.(check int) "the others score zero" 0
                (Reputation_scores.get (Sub_dag.scores sd4) (id i)))
            [ 1; 2; 3 ]
      | _ -> Alcotest.fail "expected two sub-dags")
  | _ -> Alcotest.fail "expected two round-5 outcomes"

let test_bullshark_gc_basic () =
  let committee, sk_of = setup 4 in
  let id = id_at committee in
  let rounds = slow_chain committee sk_of ~slow:(id 3) ~upto:7 in
  let b, outs = feed (bullshark committee ~k:100 ~gc:4) (List.concat_map snd rounds) in
  let leaders = committed_leaders outs in
  Alcotest.(check (list int)) "committed leader rounds 2,4,6" [ 2; 4; 6 ] (leader_rounds leaders);
  Alcotest.(check bool) "the slow node never appears in a sub-dag" true
    (List.for_all
       (fun sd ->
         List.for_all
           (fun h -> not (Authority_id.equal (Header.author h) (id 3)))
           (Nonempty.to_list (Sub_dag.headers sd)))
       leaders);
  let d = Bullshark.dag b in
  Alcotest.(check int) "gc round is committed(6) - depth(4) = 2" 2 (Round.to_int (Dag.gc_round d));
  Alcotest.(check bool) "nothing remains at or below the gc round" true
    (List.for_all (fun r -> Round.to_int r > 2) (Dag.rounds d));
  Alcotest.(check bool) "every retained round holds four certificates" true
    (List.for_all (fun r -> List.length (Dag.round_certificates d r) = 4) (Dag.rounds d))

let test_bullshark_mixed_gc_and_missing () =
  let committee, sk_of = setup 4 in
  let id = id_at committee in
  let dg = List.map Certificate.digest in
  let three = [ id 0; id 1; id 2 ] in
  let r1 = certs_for committee sk_of ~round:1 ~authors:three ~parents:(genesis_digests committee) in
  let r2 = certs_for committee sk_of ~round:2 ~authors:three ~parents:(dg r1) in
  let leader2 = cert_of (id 0) r2 in
  let r3 =
    certs_with_config committee sk_of ~round:3 ~authors:three ~parents:(dg r2)
      ~weak_leader:(Certificate.digest leader2) ()
  in
  let r4 = certs_for committee sk_of ~round:4 ~authors:[ id 0; id 2; id 3 ] ~parents:(dg r3) in
  let without d = List.filter (fun x -> not (Digests.Header_digest.equal x d)) in
  let slow_round ~round ~prev =
    let slow_prev = Certificate.digest (cert_of (id 0) prev) in
    List.map
      (fun author ->
        let p = if Authority_id.equal author (id 0) then dg prev else without slow_prev (dg prev) in
        certify committee sk_of (a_header committee ~author ~round ~parents:p ()))
      (ids committee)
  in
  let r5 = round_certs committee sk_of ~round:5 ~parents:(dg r4) in
  let r6 = slow_round ~round:6 ~prev:r5 in
  let r7 = slow_round ~round:7 ~prev:r6 in
  let b, _ = feed (bullshark committee ~k:100 ~gc:4) (r1 @ r2 @ r3 @ r4 @ r5 @ r6) in
  (* [r7] is authored in id order [ids0; ids1; ids2; ids3]; the second (ids1) is
     the one that lifts leader-4's would-be support to a commit. The dag-shape
     assertion is taken right after that insert, before the last two arrive. *)
  match r7 with
  | c0 :: c1 :: tail ->
      let b, o0 = feed b [ c0 ] in
      Alcotest.(check bool) "first round-7 cert: not enough support" true
        (nc (first o0) = Bullshark.Not_enough_support);
      let b, o1 = feed b [ c1 ] in
      let sds = committed (first o1) in
      Alcotest.(check (list int)) "two sub-dags, leaders 2 then 6" [ 2; 6 ] (leader_rounds sds);
      (match sds with
      | [ sd2; sd6 ] ->
          Alcotest.(check (list int)) "leader-2 sub-dag headers [1;1;1;2]" [ 1; 1; 1; 2 ]
            (header_rounds sd2);
          Alcotest.(check bool) "leader-6 author ids2" true
            (Authority_id.equal (Sub_dag.leader_author sd6) (id 2));
          Alcotest.(check (list int)) "leader-6 sub-dag headers [3;3;3;4;4;4;5;5;5;6]"
            [ 3; 3; 3; 4; 4; 4; 5; 5; 5; 6 ] (header_rounds sd6)
      | _ -> Alcotest.fail "expected two sub-dags");
      let d = Bullshark.dag b in
      Alcotest.(check (list int)) "dag rounds after commit are [3;4;5;6;7]" [ 3; 4; 5; 6; 7 ]
        (List.map Round.to_int (Dag.rounds d));
      Alcotest.(check (list int)) "per-round certificate counts [3;3;4;4;2]" [ 3; 3; 4; 4; 2 ]
        (List.map (fun r -> List.length (Dag.round_certificates d r)) (Dag.rounds d));
      let _, orest = feed b tail in
      Alcotest.(check bool) "the last two round-7 certs are below the commit round" true
        (List.for_all (fun o -> nc o = Bullshark.Leader_below_commit_round) orest)
  | _ -> Alcotest.fail "expected four round-7 certificates"

let test_bullshark_score_reset_cadence () =
  let committee, sk_of = setup 4 in
  let id = id_at committee in
  let rounds = optimal_rounds committee sk_of ~upto:23 in
  let _, outs = feed (bullshark committee ~k:5 ~gc:10) (List.concat_map snd rounds) in
  let leaders = committed_leaders outs in
  Alcotest.(check (list int)) "eleven committed leaders, rounds 2..22"
    [ 2; 4; 6; 8; 10; 12; 14; 16; 18; 20; 22 ] (leader_rounds leaders);
  let uniform sd =
    let v = Reputation_scores.get (Sub_dag.scores sd) (id 0) in
    if List.for_all (fun i -> Reputation_scores.get (Sub_dag.scores sd) (id i) = v) [ 1; 2; 3 ] then v
    else Alcotest.fail "scores are not uniform across authorities"
  in
  Alcotest.(check (list int)) "per-sub-dag uniform score cadence"
    [ 0; 1; 2; 3; 1; 2; 3; 4; 5; 1; 2 ] (List.map uniform leaders);
  Alcotest.(check (list bool)) "final-of-schedule flags at leader rounds 8 and 18"
    [ false; false; false; true; false; false; false; false; true; false; false ]
    (List.map (fun sd -> Reputation_scores.is_final (Sub_dag.scores sd)) leaders)

let test_bullshark_recursive_weak_chain () =
  let committee, sk_of = setup 4 in
  let id = id_at committee in
  let dg = List.map Certificate.digest in
  let rounds = optimal_rounds committee sk_of ~upto:6 in
  let r6 = List.assoc 6 rounds in
  let leader6 = cert_of (id 2) r6 in
  let r7 =
    certs_with_config committee sk_of ~round:7 ~authors:(ids committee) ~parents:(dg r6)
      ~weak_leader:(Certificate.digest leader6) ()
  in
  let r8 = round_certs committee sk_of ~round:8 ~parents:(dg r7) in
  let leader8 = cert_of (id 3) r8 in
  let r9 =
    certs_with_config committee sk_of ~round:9 ~authors:(ids committee) ~parents:(dg r8)
      ~drop_leader:(Certificate.digest leader8) ()
  in
  let r10 = round_certs committee sk_of ~round:10 ~parents:(dg r9) in
  let leader10 = cert_of (id 0) r10 in
  let r11 =
    certs_with_config committee sk_of ~round:11 ~authors:(ids committee) ~parents:(dg r10)
      ~weak_leader:(Certificate.digest leader10) ()
  in
  let r12 = round_certs committee sk_of ~round:12 ~parents:(dg r11) in
  let r13 = round_certs committee sk_of ~round:13 ~parents:(dg r12) in
  let prefix = List.concat_map snd rounds @ r7 @ r8 @ r9 @ r10 @ r11 @ r12 in
  let b, _ = feed (bullshark committee ~k:4 ~gc:50) prefix in
  let _, o13 = feed b r13 in
  let leaders = committed_leaders o13 in
  Alcotest.(check (list int)) "committed leader rounds 6, 10, 12 (leader 8 skipped)" [ 6; 10; 12 ]
    (leader_rounds leaders);
  match leaders with
  | [ sd6; sd10; sd12 ] ->
      Alcotest.(check bool) "sub-dag 6 is uniform and final" true
        (Reputation_scores.is_final (Sub_dag.scores sd6)
        && List.for_all (fun i -> Reputation_scores.get (Sub_dag.scores sd6) (id i) = 2) [ 0; 1; 2; 3 ]);
      Alcotest.(check int) "sub-dag 10: ids0 alone rose to 3" 3
        (Reputation_scores.get (Sub_dag.scores sd10) (id 0));
      List.iter
        (fun i ->
          Alcotest.(check int) "sub-dag 10 others at 2" 2
            (Reputation_scores.get (Sub_dag.scores sd10) (id i)))
        [ 1; 2; 3 ];
      Alcotest.(check (list int)) "sub-dag 12 score bindings [4;2;2;2]" [ 4; 2; 2; 2 ]
        (List.map snd (Reputation_scores.bindings (Sub_dag.scores sd12)))
  | _ -> Alcotest.fail "expected three sub-dags"

let test_bullshark_long_asynchrony_swap () =
  let committee, sk_of = setup 4 in
  let id = id_at committee in
  let dg = List.map Certificate.digest in
  let rounds = optimal_rounds committee sk_of ~upto:6 in
  let weak ~round ~prev ~leader =
    certs_with_config committee sk_of ~round ~authors:(ids committee) ~parents:(dg prev)
      ~weak_leader:(Certificate.digest leader) ()
  in
  let r6 = List.assoc 6 rounds in
  let r7 = weak ~round:7 ~prev:r6 ~leader:(cert_of (id 2) r6) in
  let r8 = round_certs committee sk_of ~round:8 ~parents:(dg r7) in
  let r9 = weak ~round:9 ~prev:r8 ~leader:(cert_of (id 3) r8) in
  let r10 = round_certs committee sk_of ~round:10 ~parents:(dg r9) in
  let r11 = weak ~round:11 ~prev:r10 ~leader:(cert_of (id 0) r10) in
  let r12 = round_certs committee sk_of ~round:12 ~parents:(dg r11) in
  let r13 = weak ~round:13 ~prev:r12 ~leader:(cert_of (id 1) r12) in
  let r14 = round_certs committee sk_of ~round:14 ~parents:(dg r13) in
  let r15 = round_certs committee sk_of ~round:15 ~parents:(dg r14) in
  let prefix = List.concat_map snd rounds @ r7 @ r8 @ r9 @ r10 @ r11 @ r12 @ r13 @ r14 in
  let b, _ = feed (bullshark committee ~k:4 ~gc:50) prefix in
  let b, o15 = feed b r15 in
  let leaders = committed_leaders o15 in
  Alcotest.(check (list int)) "committed leader rounds 6,8,10,12,14" [ 6; 8; 10; 12; 14 ]
    (leader_rounds leaders);
  Alcotest.(check bool) "authors ids2,ids3,ids0,ids1,ids2" true
    (List.map Sub_dag.leader_author leaders = [ id 2; id 3; id 0; id 1; id 2 ]);
  (match List.rev leaders with
  | sd14 :: _ ->
      Alcotest.(check int) "sub-dag 14: ids0 alone at 4" 4
        (Reputation_scores.get (Sub_dag.scores sd14) (id 0));
      List.iter
        (fun i ->
          Alcotest.(check int) "the rest stay at zero" 0
            (Reputation_scores.get (Sub_dag.scores sd14) (id i)))
        [ 1; 2; 3 ]
  | [] -> Alcotest.fail "expected sub-dags");
  Alcotest.(check bool) "installed swap table bad = {ids1, ids2, ids3}" true
    (Authority_id.Set.equal
       (Leader_schedule.bad_nodes (Bullshark.schedule b))
       (Authority_id.Set.of_list [ id 1; id 2; id 3 ]));
  Alcotest.(check bool) "installed swap table good = [ids0] (singleton, RNG-independent)" true
    (List.map Authority.id (Leader_schedule.good_nodes (Bullshark.schedule b)) = [ id 0 ]);
  let r16 = round_certs committee sk_of ~round:16 ~parents:(dg r15) in
  let r17 = round_certs committee sk_of ~round:17 ~parents:(dg r16) in
  let _, o17 = feed b (r16 @ r17) in
  match committed_leaders o17 with
  | [ sd16 ] ->
      Alcotest.(check int) "leader round 16" 16 (Round.to_int (Sub_dag.leader_round sd16));
      Alcotest.(check bool) "round-16 leader ids3 swapped to the only good node ids0" true
        (Authority_id.equal (Sub_dag.leader_author sd16) (id 0))
  | _ -> Alcotest.fail "expected exactly one committed sub-dag from rounds 16-17"

let test_bullshark_slow_node_late_commit () =
  let committee, sk_of = setup 4 in
  let id = id_at committee in
  let dg = List.map Certificate.digest in
  let rounds = slow_chain committee sk_of ~slow:(id 3) ~upto:8 in
  let round_certs_of r = List.assoc r rounds in
  let without_slow certs = List.filter (fun c -> not (Authority_id.equal (Certificate.origin c) (id 3))) certs in
  let only_slow certs = List.filter (fun c -> Authority_id.equal (Certificate.origin c) (id 3)) certs in
  (* feed everyone but the slow node first: commits leaders 2, 4, 6 *)
  let early = List.concat_map (fun (_, certs) -> without_slow certs) rounds in
  let b, outs = feed (bullshark committee ~k:100 ~gc:4) early in
  Alcotest.(check (list int)) "early commit reaches leaders 2, 4, 6" [ 2; 4; 6 ]
    (leader_rounds (committed_leaders outs));
  Alcotest.(check bool) "nothing at or below the gc round remains" true
    (List.for_all (fun r -> Round.to_int r > 2) (Dag.rounds (Bullshark.dag b)));
  (* now feed the slow node's withheld certificates, round by round *)
  let b, slow_outs =
    List.fold_left
      (fun (b, acc) round ->
        let sc = only_slow (round_certs_of round) in
        let b, o = feed b sc in
        (b, acc @ List.map (fun x -> (round, nc x)) o))
      (b, []) [ 1; 2; 3; 4; 5; 6; 7; 8 ]
  in
  let expected =
    [
      (1, Bullshark.Certificate_below_commit_round);
      (2, Bullshark.Certificate_below_commit_round);
      (3, Bullshark.Leader_below_commit_round);
      (4, Bullshark.No_leader_round);
      (5, Bullshark.Leader_below_commit_round);
      (6, Bullshark.No_leader_round);
      (7, Bullshark.Leader_below_commit_round);
      (8, Bullshark.No_leader_round);
    ]
  in
  Alcotest.(check bool) "late slow-node inserts follow the gc/parity outcomes" true (slow_outs = expected);
  (* round 9 references all round-8 including the slow node: leader 8 (ids3) commits *)
  let r9 = round_certs committee sk_of ~round:9 ~parents:(dg (round_certs_of 8)) in
  let _, o9 = feed b r9 in
  match o9 with
  | o1 :: o2 :: _ ->
      Alcotest.(check bool) "first round-9 cert: not enough support" true
        (nc o1 = Bullshark.Not_enough_support);
      let sd = first (committed o2) in
      Alcotest.(check int) "leader round 8" 8 (Round.to_int (Sub_dag.leader_round sd));
      Alcotest.(check bool) "leader author ids3" true
        (Authority_id.equal (Sub_dag.leader_author sd) (id 3));
      (* The leader-local GC bound (8 - 4 = 4) stops expansion at round 5. ids0
         and ids1's round-6 certs survive because their last-committed watermark
         is only 5 (their round-6 certs were siblings of leader-6, never
         committed), so round 6 > 5 keeps them, matching Rust's order_dag. *)
      Alcotest.(check (list int)) "nine headers [5;6;6;6;7;7;7;7;8]"
        [ 5; 6; 6; 6; 7; 7; 7; 7; 8 ] (header_rounds sd);
      Alcotest.(check int) "exactly four headers authored by the slow node" 4
        (List.length
           (List.filter
              (fun h -> Authority_id.equal (Header.author h) (id 3))
              (Nonempty.to_list (Sub_dag.headers sd))))
  | _ -> Alcotest.fail "expected round-9 outcomes"

let () =
  Alcotest.run "tn_consensus"
    [
      ( "vote_aggregator",
        [
          Alcotest.test_case "quorum certifies" `Quick test_vote_quorum_certifies;
          Alcotest.test_case "duplicate voter" `Quick test_vote_duplicate;
          Alcotest.test_case "wrong header" `Quick test_vote_wrong_header;
          Alcotest.test_case "unknown voter" `Quick test_vote_unknown;
          Alcotest.test_case "bad signature" `Quick test_vote_bad_signature;
          Alcotest.test_case "rejected author is burned" `Quick test_vote_rejected_author_is_burned;
        ] );
      ( "parent_aggregator",
        [
          Alcotest.test_case "quorum, no weight reset" `Quick test_parent_quorum_no_reset;
          Alcotest.test_case "duplicate author ignored" `Quick test_parent_duplicate_ignored;
        ] );
      ( "dag",
        [
          Alcotest.test_case "equivocation same round" `Quick test_dag_equivocation;
          Alcotest.test_case "parent verification" `Quick test_dag_parent_verification;
          Alcotest.test_case "missing previous round" `Quick test_dag_missing_parent_round;
          Alcotest.test_case "gc removes old rounds" `Quick test_dag_gc_removes_old_rounds;
          Alcotest.test_case "idempotent insert" `Quick test_dag_idempotent_insert;
          Alcotest.test_case "rejects old certificates" `Quick test_dag_rejects_old_certificates;
          Alcotest.test_case "rejects at gc boundary" `Quick test_dag_rejects_at_gc_boundary;
          Alcotest.test_case "update never regresses" `Quick test_dag_update_never_regresses;
        ] );
      ( "reputation_scores",
        [ Alcotest.test_case "fresh and bump" `Quick test_scores_fresh_and_bump ] );
      ( "leader_schedule",
        [
          Alcotest.test_case "round robin" `Quick test_schedule_round_robin;
          Alcotest.test_case "swap table, 4 nodes" `Quick test_schedule_swap_table_4nodes;
          Alcotest.test_case "swap table, 10 nodes" `Quick test_schedule_swap_table_10nodes;
          Alcotest.test_case "uniform scores, no swaps" `Quick test_schedule_uniform_scores_no_swaps;
        ] );
      ( "sub_dag",
        [
          Alcotest.test_case "shape" `Quick test_sub_dag_shape;
          Alcotest.test_case "timestamp and digest" `Quick test_sub_dag_timestamp_and_digest;
        ] );
      ( "bullshark",
        [
          Alcotest.test_case "commit one" `Quick test_bullshark_commit_one;
          Alcotest.test_case "round-robin run" `Quick test_bullshark_round_robin_run;
          Alcotest.test_case "missing leader" `Quick test_bullshark_missing_leader;
          Alcotest.test_case "dead node" `Quick test_bullshark_dead_node;
          Alcotest.test_case "below commit and equivocation" `Quick
            test_bullshark_below_commit_and_equivocation;
          Alcotest.test_case "max inserted and genesis guard" `Quick
            test_bullshark_max_inserted_and_genesis_guard;
          Alcotest.test_case "not enough support, recursive commit" `Quick
            test_bullshark_not_enough_support;
          Alcotest.test_case "garbage collection" `Quick test_bullshark_gc_basic;
          Alcotest.test_case "mixed gc and missing leaders" `Quick
            test_bullshark_mixed_gc_and_missing;
          Alcotest.test_case "score reset cadence" `Quick test_bullshark_score_reset_cadence;
          Alcotest.test_case "recursive weak chain, schedule change" `Quick
            test_bullshark_recursive_weak_chain;
          Alcotest.test_case "long asynchrony, singleton swap" `Quick
            test_bullshark_long_asynchrony_swap;
          Alcotest.test_case "slow node late commit" `Quick test_bullshark_slow_node_late_commit;
        ] );
    ]
