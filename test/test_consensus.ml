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
    ]
