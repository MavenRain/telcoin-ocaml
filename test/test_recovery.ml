(* Tests for the recovery-storage seam (roadmap step 14): the port of Rust's
   [ConsensusState::new_from_store], [LeaderSchedule::from_store], the
   parent-check-disabled [try_insert_in_dag], and the proposer/voter persistence.

   The load-bearing property is a recovery ROUNDTRIP: rebuilding consensus state
   from a snapshot of a running node reproduces that node's DAG, commit state, and
   leader schedule exactly, and feeding further certificates to the recovered
   state commits identically to the original. The individual cases pin the DAG
   rebuild (parent-check-disabled, watermark-seeded), the leader-schedule rebuild
   from persisted final scores (including a genuine swap table), the proposer
   re-propose equivocation guard made reachable by [recover], and the voter's
   vote-once invariant surviving a restart. *)

open Tn_std
open Tn_types
open Tn_vertex
open Tn_consensus

let get = function Some x -> x | None -> Alcotest.fail "expected Some"
let ok_dag = function Ok x -> x | Error e -> Alcotest.failf "dag: %s" (Dag.error_to_string e)
let r n = get (Round.of_int n)
let ts n = get (Units.Timestamp.of_sec (Int64.of_int n))
let dur ms = get (Units.Duration.of_ms ms)

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
let id_at committee i = List.nth (ids committee) i

let a_header committee ~author ~round ?(created_at = 0) ~parents () =
  Header.make ~author ~round:(r round)
    ~epoch:(Committee.epoch committee)
    ~created_at:(ts created_at) ~payload:[] ~parents

let certify committee sk_of header =
  let votes = List.map (fun id -> Vote.sign (sk_of id) ~voter:id header) (ids committee) in
  match Certificate.assemble committee header votes with
  | Ok c -> c
  | Error e -> Alcotest.failf "certify: %s" (Certificate.error_to_string e)

let genesis_digests committee = List.map Certificate.digest (Certificate.genesis committee)

let round_certs committee sk_of ~round ~parents =
  List.map
    (fun author -> certify committee sk_of (a_header committee ~author ~round ~parents ()))
    (ids committee)

(* Optimal DAG rounds 1..upto: every authority present, each round parenting the
   whole previous round (round 1 extends genesis). Flattened to a cert list in
   round order. *)
let optimal_certs committee sk_of ~upto =
  let rec go round parents acc =
    if round > upto then List.rev acc
    else
      let certs = round_certs committee sk_of ~round ~parents in
      go (round + 1) (List.map Certificate.digest certs) (List.rev_append certs acc)
  in
  go 1 (genesis_digests committee) []

let pconfig () =
  Proposer.config ~min_header_delay:(dur 500) ~max_header_delay:(dur 1000)
    ~header_batch_threshold:1 ~max_batches_per_header:1000

let schedule_of committee =
  Leader_schedule.create committee ~threshold:Leader_schedule.Threshold.default

(* ---- shared observation of Bullshark commit state ---- *)

let cert_hexes b =
  Dag.all_certificates (Bullshark.dag b)
  |> List.map (fun c -> Digests.Header_digest.to_hex (Certificate.digest c))
  |> List.sort String.compare

let bad_ids sched = Authority_id.Set.elements (Leader_schedule.bad_nodes sched)

(* Feed certificates through Bullshark, threading the state and accumulating every
   emitted sub-DAG into a committed log — the persistence the shell would record. *)
let feed_bullshark b log certs =
  List.fold_left
    (fun (b, log) c ->
      match Bullshark.process_certificate b c with
      | Error e -> Alcotest.failf "process: %s" (Dag.error_to_string e)
      | Ok (b, Bullshark.No_commit _) -> (b, log)
      | Ok (b, Bullshark.Committed sds) ->
          (b, List.fold_left Committed_log.append log (Nonempty.to_list sds)))
    (b, log) certs

(* ---- dag recovery ---- *)

let test_dag_recover_roundtrip () =
  let committee, sk_of = setup 4 in
  (* build a live DAG by inserting an optimal rounds-1..4 slice *)
  let certs = optimal_certs committee sk_of ~upto:4 in
  let live =
    List.fold_left (fun d c -> fst (ok_dag (Dag.try_insert d c))) (Dag.create ~gc_depth:50) certs
  in
  (* snapshot and rebuild: no committed rounds yet, so the watermark map is empty
     and the committed round is genesis *)
  let snap = Dag.all_certificates live in
  let recovered =
    ok_dag
      (Dag.recover ~gc_depth:50 ~last_committed_round:Round.genesis
         ~last_committed:Authority_id.Map.empty ~certificates:snap)
  in
  Alcotest.(check (list string)) "the same certificates are stored"
    (List.map (fun c -> Digests.Header_digest.to_hex (Certificate.digest c)) snap)
    (List.map (fun c -> Digests.Header_digest.to_hex (Certificate.digest c))
       (Dag.all_certificates recovered));
  Alcotest.(check bool) "every stored certificate resolves by digest through the rebuilt index" true
    (List.for_all
       (fun c -> Option.is_some (Dag.get_by_digest recovered (Certificate.digest c)))
       snap)

let test_insert_recovered_skips_parent_check () =
  let committee, sk_of = setup 4 in
  (* a round-3 certificate whose round-2 parents are NOT in the store: try_insert
     rejects it (missing parents), insert_recovered accepts it *)
  let r1 = round_certs committee sk_of ~round:1 ~parents:(genesis_digests committee) in
  let r2 = round_certs committee sk_of ~round:2 ~parents:(List.map Certificate.digest r1) in
  let orphan =
    List.hd (round_certs committee sk_of ~round:3 ~parents:(List.map Certificate.digest r2))
  in
  let dag = Dag.create ~gc_depth:50 in
  Alcotest.(check bool) "try_insert rejects a certificate whose parents are absent" true
    (Result.is_error (Dag.try_insert dag orphan));
  let dag', relevant = ok_dag (Dag.insert_recovered dag orphan) in
  Alcotest.(check bool) "insert_recovered accepts it regardless" true
    (Option.is_some (Dag.get dag' (r 3) (Certificate.origin orphan)));
  Alcotest.(check bool) "and reports it newly relevant (above the genesis watermark)" true relevant

let test_insert_recovered_still_guards_equivocation () =
  let committee, sk_of = setup 4 in
  let self = id_at committee 0 in
  let h1 = a_header committee ~author:self ~round:1 ~parents:(genesis_digests committee) () in
  let h2 = a_header committee ~author:self ~round:1 ~created_at:1 ~parents:(genesis_digests committee) () in
  let c1 = certify committee sk_of h1 and c2 = certify committee sk_of h2 in
  let dag, _ = ok_dag (Dag.insert_recovered (Dag.create ~gc_depth:50) c1) in
  Alcotest.(check bool) "a second, different certificate for the slot is still rejected" true
    (match Dag.insert_recovered dag c2 with
     | Error (Dag.Equivocation (_, _)) -> true
     | _ -> false);
  Alcotest.(check bool) "re-inserting the identical certificate is idempotent" true
    (Result.is_ok (Dag.insert_recovered dag c1))

(* ---- bullshark recovery (new_from_store) ---- *)

let test_bullshark_recover_roundtrip () =
  let committee, sk_of = setup 4 in
  let sub_dags_per_schedule = 3 and gc_depth = 50 in
  let bull () = Bullshark.create ~committee ~schedule:(schedule_of committee) ~sub_dags_per_schedule ~gc_depth in
  let certs = optimal_certs committee sk_of ~upto:6 in
  let live, log = feed_bullshark (bull ()) Committed_log.empty certs in
  Alcotest.(check bool) "the live run committed at least one leader" true
    (Option.is_some (Bullshark.last_sub_dag live));
  (* snapshot -> recover *)
  let sched' = Leader_schedule.from_store committee ~threshold:Leader_schedule.Threshold.default log in
  let recovered =
    match
      Bullshark.of_store ~committee ~schedule:sched' ~sub_dags_per_schedule ~gc_depth
        ~certificates:(Dag.all_certificates (Bullshark.dag live)) ~committed:log
    with
    | Ok b -> b
    | Error e -> Alcotest.failf "of_store: %s" (Dag.error_to_string e)
  in
  Alcotest.(check int) "the committed round matches"
    (Round.to_int (Dag.committed_round (Bullshark.dag live)))
    (Round.to_int (Dag.committed_round (Bullshark.dag recovered)));
  Alcotest.(check int) "the gc round matches"
    (Round.to_int (Dag.gc_round (Bullshark.dag live)))
    (Round.to_int (Dag.gc_round (Bullshark.dag recovered)));
  Alcotest.(check (list string)) "the certificate set matches" (cert_hexes live) (cert_hexes recovered);
  Alcotest.(check bool) "the last committed sub-DAG matches" true
    (Option.equal Sub_dag.equal (Bullshark.last_sub_dag live) (Bullshark.last_sub_dag recovered));
  Alcotest.(check (list string)) "the recovered leader schedule matches"
    (List.map Authority_id.to_hex (bad_ids (Bullshark.schedule live)))
    (List.map Authority_id.to_hex (bad_ids sched'));
  (* behavioural equivalence: feeding the next two rounds commits identically *)
  let more = List.filteri (fun _ _ -> true) (optimal_certs committee sk_of ~upto:8) in
  let tail = List.filter (fun c -> Round.to_int (Certificate.round c) > 6) more in
  let live2, _ = feed_bullshark live Committed_log.empty tail in
  let recovered2, _ = feed_bullshark recovered Committed_log.empty tail in
  Alcotest.(check int) "further certificates advance the committed round identically"
    (Round.to_int (Dag.committed_round (Bullshark.dag live2)))
    (Round.to_int (Dag.committed_round (Bullshark.dag recovered2)));
  Alcotest.(check bool) "and reach the same last committed sub-DAG" true
    (Option.equal Sub_dag.equal (Bullshark.last_sub_dag live2) (Bullshark.last_sub_dag recovered2))

let test_bullshark_recover_after_gc () =
  let committee, sk_of = setup 4 in
  (* a tight GC window so garbage collection actually purges committed rounds:
     recovery must rebuild only the surviving post-GC slice and still match *)
  let sub_dags_per_schedule = 3 and gc_depth = 2 in
  let bull () = Bullshark.create ~committee ~schedule:(schedule_of committee) ~sub_dags_per_schedule ~gc_depth in
  let live, log = feed_bullshark (bull ()) Committed_log.empty (optimal_certs committee sk_of ~upto:8) in
  Alcotest.(check bool) "garbage collection actually advanced the GC round past genesis" true
    (Round.to_int (Dag.gc_round (Bullshark.dag live)) > 0);
  let sched' = Leader_schedule.from_store committee ~threshold:Leader_schedule.Threshold.default log in
  let recovered =
    match
      Bullshark.of_store ~committee ~schedule:sched' ~sub_dags_per_schedule ~gc_depth
        ~certificates:(Dag.all_certificates (Bullshark.dag live)) ~committed:log
    with
    | Ok b -> b
    | Error e -> Alcotest.failf "of_store: %s" (Dag.error_to_string e)
  in
  Alcotest.(check int) "the committed round matches after GC"
    (Round.to_int (Dag.committed_round (Bullshark.dag live)))
    (Round.to_int (Dag.committed_round (Bullshark.dag recovered)));
  Alcotest.(check int) "the gc round matches after GC"
    (Round.to_int (Dag.gc_round (Bullshark.dag live)))
    (Round.to_int (Dag.gc_round (Bullshark.dag recovered)));
  Alcotest.(check (list string)) "the surviving certificate set matches" (cert_hexes live) (cert_hexes recovered);
  Alcotest.(check bool) "the last committed sub-DAG matches after GC" true
    (Option.equal Sub_dag.equal (Bullshark.last_sub_dag live) (Bullshark.last_sub_dag recovered));
  (* per-author committed watermarks must be reconstructed identically, or a later
     commit would dedup differently — feed round 9 and 10 and compare *)
  let tail = List.filter (fun c -> Round.to_int (Certificate.round c) > 8) (optimal_certs committee sk_of ~upto:10) in
  let live2, _ = feed_bullshark live Committed_log.empty tail in
  let recovered2, _ = feed_bullshark recovered Committed_log.empty tail in
  Alcotest.(check int) "post-GC recovery keeps committing identically"
    (Round.to_int (Dag.committed_round (Bullshark.dag live2)))
    (Round.to_int (Dag.committed_round (Bullshark.dag recovered2)))

(* ---- leader schedule recovery (from_store) with a real swap ---- *)

let test_leader_schedule_from_store_swaps () =
  let committee, sk_of = setup 7 in
  (* non-uniform, final scores: one high scorer, the rest zero -> a swap table *)
  let scores =
    let base = Reputation_scores.fresh committee in
    let leader_id = id_at committee 0 in
    let bumped = List.fold_left (fun s _ -> Reputation_scores.bump s leader_id) base (List.init 20 Fun.id) in
    Reputation_scores.with_final true bumped
  in
  (* a round-2 leader certificate to carry the sub-DAG *)
  let r1 = round_certs committee sk_of ~round:1 ~parents:(genesis_digests committee) in
  let leader_cert =
    certify committee sk_of
      (a_header committee ~author:(id_at committee 0) ~round:2 ~parents:(List.map Certificate.digest r1) ())
  in
  let sub_dag = Sub_dag.create ~sequence:(Nonempty.singleton leader_cert) ~scores ~previous:None in
  let log = Committed_log.append Committed_log.empty sub_dag in
  let recovered = Leader_schedule.from_store committee ~threshold:Leader_schedule.Threshold.default log in
  (* the reference: note_final_scores on a fresh schedule with the same scores *)
  let activation = get (Leader_round.of_round (r 2)) in
  let reference =
    get (Leader_schedule.note_final_scores (schedule_of committee) ~activation scores)
  in
  Alcotest.(check bool) "recovery installs a non-empty swap table (non-vacuous)" false
    (Authority_id.Set.is_empty (Leader_schedule.bad_nodes recovered));
  Alcotest.(check (list string)) "the recovered bad set matches the reference table"
    (List.map Authority_id.to_hex (bad_ids reference))
    (List.map Authority_id.to_hex (bad_ids recovered));
  Alcotest.(check (list string)) "the recovered good set matches the reference table"
    (List.map (fun a -> Authority_id.to_hex (Authority.id a)) (Leader_schedule.good_nodes reference))
    (List.map (fun a -> Authority_id.to_hex (Authority.id a)) (Leader_schedule.good_nodes recovered))

let test_leader_schedule_from_store_empty () =
  let committee, _ = setup 4 in
  let recovered = Leader_schedule.from_store committee ~threshold:Leader_schedule.Threshold.default Committed_log.empty in
  Alcotest.(check bool) "an empty log recovers the round-robin schedule (no swaps)" true
    (Authority_id.Set.is_empty (Leader_schedule.bad_nodes recovered))

(* ---- proposer recovery: the re-propose equivocation guard ---- *)

let test_proposer_recover_reproposes () =
  let committee, sk_of = setup 4 in
  let self = id_at committee 0 in
  (* the persisted last-proposed header is for round 5; the node recovers at
     round 4 (the last committed leader round) *)
  let r3 = round_certs committee sk_of ~round:3 ~parents:(genesis_digests committee) in
  let r4 = round_certs committee sk_of ~round:4 ~parents:(List.map Certificate.digest r3) in
  let stored = a_header committee ~author:self ~round:5 ~parents:(List.map Certificate.digest r4) () in
  let p, boot =
    Proposer.recover ~config:(pconfig ()) ~committee ~authority:self
      ~genesis:(Certificate.genesis committee) ~now:(ts 0) ~recovered_round:(r 4)
      ~last_proposed:(Some stored)
  in
  Alcotest.(check bool) "recovery emits no proposal until parents arrive" true
    (List.for_all (function Proposer.Broadcast_header _ -> false | _ -> true) boot);
  (* deliver a round-4 quorum: the proposal for round 5 must re-emit the STORED
     header, not a freshly built one *)
  let _, acts = Proposer.step p ~now:(ts 1) (Proposer.Parents { certs = r4; round = r 4 }) in
  let emitted = List.find_map (function Proposer.Broadcast_header h -> Some h | _ -> None) acts in
  Alcotest.(check bool) "the recovered proposer re-emits the persisted header verbatim" true
    (match emitted with Some h -> Header.equal h stored | None -> false)

let test_proposer_recover_cold_is_create () =
  let committee, _ = setup 4 in
  let self = id_at committee 0 in
  let _, boot =
    Proposer.recover ~config:(pconfig ()) ~committee ~authority:self
      ~genesis:(Certificate.genesis committee) ~now:(ts 0) ~recovered_round:Round.genesis
      ~last_proposed:None
  in
  Alcotest.(check bool) "a never-committed, never-proposed node cold-starts like create" true
    (List.exists
       (function Proposer.Broadcast_header h -> Round.to_int (Header.round h) = 1 | _ -> false)
       boot)

(* ---- voter recovery: vote-once survives a restart ---- *)

let test_voter_recover_vote_once () =
  let committee, sk_of = setup 4 in
  let self = id_at committee 0 and peer = id_at committee 1 in
  let v =
    Voter.create ~committee ~secret_key:(sk_of self) ~self_id:self
      ~genesis:(Certificate.genesis committee)
  in
  let h1 = a_header committee ~author:peer ~round:1 ~parents:(genesis_digests committee) () in
  let dag = Dag.create ~gc_depth:50 in
  let v, d1 = Voter.vote v ~dag ~now:(ts 5) h1 in
  Alcotest.(check bool) "the node votes for the peer's header" true
    (match d1 with Voter.Vote _ -> true | _ -> false);
  (* restart: rebuild the voter from only the persisted records *)
  let recovered =
    Voter.recover ~committee ~secret_key:(sk_of self) ~self_id:self
      ~genesis:(Certificate.genesis committee) ~votes:(Voter.snapshot v)
  in
  Alcotest.(check bool) "the vote-once record survives the restart" true
    (Voter.has_voted recovered peer (r 1));
  (* an equivocating header at the certified slot is still refused after recovery *)
  let dag = fst (ok_dag (Dag.try_insert dag (certify committee sk_of h1))) in
  let h2 = a_header committee ~author:peer ~round:1 ~created_at:1 ~parents:(genesis_digests committee) () in
  let _, d2 = Voter.vote recovered ~dag ~now:(ts 5) h2 in
  Alcotest.(check bool) "a conflicting header for the certified slot is refused post-restart" true
    (match d2 with Voter.Reject Voter.Equivocating_header -> true | _ -> false);
  (* the identical header still recasts the same vote *)
  let _, d3 = Voter.vote recovered ~dag ~now:(ts 6) h1 in
  Alcotest.(check bool) "the identical header recasts after restart" true
    (match (d1, d3) with
     | Voter.Vote a, Voter.Recast b ->
         Digests.Header_digest.equal (Vote.header_digest a) (Vote.header_digest b)
     | _ -> false)

(* ---- node recovery: the whole machine ---- *)

let test_node_recover_roundtrip () =
  let committee, sk_of = setup 4 in
  let self = id_at committee 0 in
  let sub_dags_per_schedule = 3 and gc_depth = 50 in
  let node, _ =
    Node.create ~committee ~secret_key:(sk_of self) ~self_id:self ~proposer_config:(pconfig ())
      ~sub_dags_per_schedule ~gc_depth ~now:(ts 0)
  in
  (* drive an optimal rounds-1..6 DAG as gossiped certificates, recording every
     emitted sub-DAG into a committed log *)
  let certs = optimal_certs committee sk_of ~upto:6 in
  let node, log =
    List.fold_left
      (fun (node, log) c ->
        match Node.step node ~now:(ts 1) (Node.Certificate_received c) with
        | Error _ -> Alcotest.fail "an optimal DAG must not be an invariant break"
        | Ok (node, cmds) ->
            let emitted =
              List.filter_map (function Node.Emit_committed sd -> Some sd | _ -> None) cmds
            in
            (node, List.fold_left Committed_log.append log emitted))
      (node, Committed_log.empty) certs
  in
  Alcotest.(check bool) "the node committed at least one sub-DAG" true
    (Option.is_some (Node.last_committed node));
  (* recover from the snapshot and the committed log *)
  let recovered =
    match
      Node.recover ~committee ~secret_key:(sk_of self) ~self_id:self ~proposer_config:(pconfig ())
        ~sub_dags_per_schedule ~gc_depth ~now:(ts 2) ~persisted:(Node.snapshot node) ~committed:log
    with
    | Ok (n, _) -> n
    | Error _ -> Alcotest.fail "recover from a valid snapshot must not fail"
  in
  Alcotest.(check int) "the recovered node's committed round matches"
    (Round.to_int (Dag.committed_round (Node.dag node)))
    (Round.to_int (Dag.committed_round (Node.dag recovered)));
  Alcotest.(check bool) "the recovered node's last committed sub-DAG matches" true
    (Option.equal Sub_dag.equal (Node.last_committed node) (Node.last_committed recovered));
  (* the recovered node keeps committing: feed rounds 7..8 and it must not stall
     or halt, reaching the same commit height as the original fed the same certs *)
  let tail = List.filter (fun c -> Round.to_int (Certificate.round c) > 6) (optimal_certs committee sk_of ~upto:8) in
  let advance start =
    List.fold_left
      (fun node c ->
        match Node.step node ~now:(ts 3) (Node.Certificate_received c) with
        | Ok (node, _) -> node
        | Error _ -> Alcotest.fail "post-recovery step must not halt on an optimal DAG")
      start tail
  in
  let node' = advance node and recovered' = advance recovered in
  Alcotest.(check int) "post-recovery commits reach the same round as the original"
    (Round.to_int (Dag.committed_round (Node.dag node')))
    (Round.to_int (Dag.committed_round (Node.dag recovered')))

let test_node_recover_resumes_without_gossip () =
  let committee, sk_of = setup 4 in
  let self = id_at committee 0 in
  let sub_dags_per_schedule = 100 and gc_depth = 50 in
  (* a recovered DAG holding certificates through round 4 (the frontier) and a
     persisted in-flight header for round 5 that was not yet certified before the
     crash — the coordinated-restart case where no peer will re-gossip round 4 *)
  let r1 = round_certs committee sk_of ~round:1 ~parents:(genesis_digests committee) in
  let r2 = round_certs committee sk_of ~round:2 ~parents:(List.map Certificate.digest r1) in
  let r3 = round_certs committee sk_of ~round:3 ~parents:(List.map Certificate.digest r2) in
  let r4 = round_certs committee sk_of ~round:4 ~parents:(List.map Certificate.digest r3) in
  let stored = a_header committee ~author:self ~round:5 ~parents:(List.map Certificate.digest r4) () in
  let persisted =
    { Node.certificates = r1 @ r2 @ r3 @ r4; last_proposed = Some stored; votes = [] }
  in
  let cmds =
    match
      Node.recover ~committee ~secret_key:(sk_of self) ~self_id:self ~proposer_config:(pconfig ())
        ~sub_dags_per_schedule ~gc_depth ~now:(ts 0) ~persisted ~committed:Committed_log.empty
    with
    | Ok (_, cmds) -> cmds
    | Error _ -> Alcotest.fail "recover from a valid snapshot must not fail"
  in
  let proposed = List.find_map (function Node.Broadcast_header h -> Some h | _ -> None) cmds in
  Alcotest.(check bool) "the recovered node re-proposes immediately, with no fresh gossip" true
    (Option.is_some proposed);
  Alcotest.(check bool) "and re-emits the persisted in-flight header verbatim (no equivocation)" true
    (match proposed with Some h -> Header.equal h stored | None -> false)

let () =
  Alcotest.run "tn_recovery"
    [
      ( "dag",
        [
          Alcotest.test_case "recover roundtrips the certificate store" `Quick test_dag_recover_roundtrip;
          Alcotest.test_case "insert_recovered skips the parent check" `Quick
            test_insert_recovered_skips_parent_check;
          Alcotest.test_case "insert_recovered still guards equivocation" `Quick
            test_insert_recovered_still_guards_equivocation;
        ] );
      ( "bullshark",
        [
          Alcotest.test_case "of_store roundtrips commit state and keeps committing" `Quick
            test_bullshark_recover_roundtrip;
          Alcotest.test_case "of_store roundtrips after garbage collection" `Quick
            test_bullshark_recover_after_gc;
        ] );
      ( "leader_schedule",
        [
          Alcotest.test_case "from_store rebuilds a swap table" `Quick test_leader_schedule_from_store_swaps;
          Alcotest.test_case "from_store on an empty log is round-robin" `Quick
            test_leader_schedule_from_store_empty;
        ] );
      ( "proposer",
        [
          Alcotest.test_case "recover re-proposes the persisted header" `Quick test_proposer_recover_reproposes;
          Alcotest.test_case "cold recover behaves like create" `Quick test_proposer_recover_cold_is_create;
        ] );
      ( "voter",
        [ Alcotest.test_case "vote-once survives a restart" `Quick test_voter_recover_vote_once ] );
      ( "node",
        [
          Alcotest.test_case "recover roundtrips the whole node" `Quick test_node_recover_roundtrip;
          Alcotest.test_case "recover resumes proposing without gossip" `Quick
            test_node_recover_resumes_without_gossip;
        ] );
    ]
