(* Tests for the primary hot path: the Proposer, the Voter, and the Node that
   composes them with the already-tested aggregators and Bullshark commit rule.
   The Proposer cases pin the propose conditions (empty round-1 startup, propose
   on a parent quorum plus a fired timer), the generation-counter defence against
   a stale timer double-proposing, and the skipped-header digest re-queue. The
   Voter cases pin the vote-once invariant (fresh vote, idempotent recast, refusal
   to sign an equivocating header) and the parent gates. The Node cases pin
   startup, certificate formation from a vote quorum, and a commit surfacing as
   consensus output. *)

open Tn_std
open Tn_types
open Tn_vertex
open Tn_consensus

let get = function Some x -> x | None -> Alcotest.fail "expected Some"
let first = function x :: _ -> x | [] -> Alcotest.fail "expected non-empty list"
let ts n = get (Units.Timestamp.of_sec (Int64.of_int n))
let r n = get (Round.of_int n)
let dur ms = get (Units.Duration.of_ms ms)
let wid = get (Units.Worker_id.of_int 0)
let batch s = Digests.Batch_digest.of_digest (Tn_crypto.Digest.hash s)

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
  Header.make ~author
    ~round:(r round)
    ~epoch:(Committee.epoch committee)
    ~created_at:(ts created_at)
    ~payload:[] ~parents

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

let pconfig ?(threshold = 1) () =
  Proposer.config ~min_header_delay:(dur 500) ~max_header_delay:(dur 1000)
    ~header_batch_threshold:threshold ~max_batches_per_header:1000

let sched committee =
  Leader_schedule.create committee ~threshold:Leader_schedule.Threshold.default

let find_header actions =
  List.find_map (function Proposer.Broadcast_header h -> Some h | _ -> None) actions

let arm_gens actions =
  List.filter_map (function Proposer.Arm_timer { gen; _ } -> Some gen | _ -> None) actions

let min_after actions =
  List.find_map
    (function
      | Proposer.Arm_timer { kind = Proposer.Min_delay; after; _ } ->
          Some (Units.Duration.to_ms after)
      | _ -> None)
    actions

let max_after actions =
  List.find_map
    (function
      | Proposer.Arm_timer { kind = Proposer.Max_delay; after; _ } ->
          Some (Units.Duration.to_ms after)
      | _ -> None)
    actions

(* ---- proposer ---- *)

let test_proposer_empty_round1 () =
  let committee, _ = setup 4 in
  let _, actions =
    Proposer.create ~config:(pconfig ()) ~committee ~authority:(id_at committee 0)
      ~schedule:(sched committee) ~genesis:(Certificate.genesis committee) ~now:(ts 0)
  in
  match find_header actions with
  | Some h ->
      Alcotest.(check int) "startup proposes round 1" 1 (Round.to_int (Header.round h));
      Alcotest.(check bool) "the round-1 header has an empty payload" true
        (Header.payload h = []);
      Alcotest.(check bool) "and validates against the committee" true
        (Result.is_ok (Header.validate committee h))
  | None -> Alcotest.fail "expected a startup proposal"

let test_proposer_proposes_on_quorum_and_timer () =
  let committee, sk_of = setup 4 in
  (* Authority 3 leads no round below 8, so the leader fast path never fires in
     this window and the min timer is the sole early trigger — the mechanic this
     case pins. (Authority 0 leads round 2, which would collapse its min delay to
     zero and propose the moment the quorum arrived.) *)
  let self = id_at committee 3 in
  let p, create_acts =
    Proposer.create ~config:(pconfig ~threshold:100 ()) ~committee ~authority:self
      ~schedule:(sched committee) ~genesis:(Certificate.genesis committee) ~now:(ts 0)
  in
  let gen = first (arm_gens create_acts) in
  (* a round-1 quorum arrives as the parents for round 2 *)
  let r1 = round_certs committee sk_of ~round:1 ~parents:(genesis_digests committee) in
  let p, before = Proposer.step p ~now:(ts 1) (Proposer.Parents { certs = r1; round = r 1 }) in
  Alcotest.(check bool) "no proposal before the min timer, high batch threshold" true
    (Option.is_none (find_header before));
  let _, after =
    Proposer.step p ~now:(ts 2) (Proposer.Timer_fired { kind = Proposer.Min_delay; gen })
  in
  match find_header after with
  | Some h ->
      Alcotest.(check int) "the fired min timer proposes round 2" 2
        (Round.to_int (Header.round h));
      Alcotest.(check bool) "the parents are the round-1 digests" true
        (List.for_all
           (fun d -> List.exists (Digests.Header_digest.equal d) (Header.parents h))
           (List.map Certificate.digest r1))
  | None -> Alcotest.fail "expected a round-2 proposal after the min timer"

let test_proposer_stale_timer_discarded () =
  let committee, sk_of = setup 4 in
  (* A non-leader in this round window, so the generation-counter mechanic is
     tested in isolation from the leader fast path (see the case above). *)
  let self = id_at committee 3 in
  let p, create_acts =
    Proposer.create ~config:(pconfig ~threshold:100 ()) ~committee ~authority:self
      ~schedule:(sched committee) ~genesis:(Certificate.genesis committee) ~now:(ts 0)
  in
  let gen1 = first (arm_gens create_acts) in
  (* advance to round 2, which re-arms the timers under a fresh generation *)
  let r1 = round_certs committee sk_of ~round:1 ~parents:(genesis_digests committee) in
  let p, _ = Proposer.step p ~now:(ts 1) (Proposer.Parents { certs = r1; round = r 1 }) in
  let p, adv =
    Proposer.step p ~now:(ts 2) (Proposer.Timer_fired { kind = Proposer.Min_delay; gen = gen1 })
  in
  Alcotest.(check bool) "advanced to round 2" true (Option.is_some (find_header adv));
  let gen2 = first (arm_gens adv) in
  Alcotest.(check bool) "the generation advanced with the proposal" true (gen2 <> gen1);
  (* hold a fresh round-2 quorum so a non-discarded timer WOULD propose round 3;
     this is what makes the discard test non-vacuous *)
  let r2 = round_certs committee sk_of ~round:2 ~parents:(List.map Certificate.digest r1) in
  let p, held = Proposer.step p ~now:(ts 3) (Proposer.Parents { certs = r2; round = r 2 }) in
  Alcotest.(check bool) "holding the parents does not itself propose" true
    (Option.is_none (find_header held));
  (* a max timer left over from generation 1 fires: despite the held quorum it
     must be discarded, so no proposal *)
  let p, stale =
    Proposer.step p ~now:(ts 4) (Proposer.Timer_fired { kind = Proposer.Max_delay; gen = gen1 })
  in
  Alcotest.(check bool) "the stale-generation timer proposes nothing" true
    (Option.is_none (find_header stale));
  Alcotest.(check int) "the round is unchanged after the stale timer" 2
    (Round.to_int (Proposer.round p));
  (* the current-generation max timer, on the same held quorum, DOES propose:
     the discard was the generation check, not a missing parent set *)
  let _, live =
    Proposer.step p ~now:(ts 5) (Proposer.Timer_fired { kind = Proposer.Max_delay; gen = gen2 })
  in
  Alcotest.(check bool) "the current-generation timer proposes round 3" true
    (match find_header live with Some h -> Round.to_int (Header.round h) = 3 | None -> false)

(* Feed a batch and deliver the current round's parent quorum; with a batch
   threshold of one that quorum triggers the next proposal directly. Returns the
   proposer, the proposal, and the round's certificate digests (the parents for
   the next round). *)
let step_round p committee sk_of ~cur ~parents ~batch ~now =
  let p, _ = Proposer.step p ~now:(ts now) (Proposer.Our_digest { batch; worker_id = wid }) in
  let certs = round_certs committee sk_of ~round:cur ~parents in
  let p, acts = Proposer.step p ~now:(ts now) (Proposer.Parents { certs; round = r cur }) in
  (p, find_header acts, List.map Certificate.digest certs)

let test_proposer_requeues_skipped () =
  let committee, sk_of = setup 4 in
  let self = id_at committee 0 in
  let p, _ =
    Proposer.create ~config:(pconfig ~threshold:1 ()) ~committee ~authority:self
      ~schedule:(sched committee) ~genesis:(Certificate.genesis committee) ~now:(ts 0)
  in
  let ba = batch "batch-A" and bb = batch "batch-B" and bc = batch "batch-C" in
  (* round 1->2 carries batch A, 2->3 carries B, 3->4 carries C *)
  let p, _, d1 =
    step_round p committee sk_of ~cur:1 ~parents:(genesis_digests committee) ~batch:ba ~now:1
  in
  let p, _, d2 = step_round p committee sk_of ~cur:2 ~parents:d1 ~batch:bb ~now:2 in
  let p, _, _d3 = step_round p committee sk_of ~cur:3 ~parents:d2 ~batch:bc ~now:3 in
  Alcotest.(check (list int)) "headers proposed for rounds 1..4" [ 1; 2; 3; 4 ]
    (List.map Round.to_int (Proposer.proposed_rounds p));
  (* commit rounds 3 and 4; round 2 is skipped below the commit, so its batch is
     re-queued, while the committed round-3 batch is not *)
  let p, _ =
    Proposer.step p ~now:(ts 4) (Proposer.Committed_headers { committed = [ r 3; r 4 ] })
  in
  Alcotest.(check (list int)) "no proposed headers remain" []
    (List.map Round.to_int (Proposer.proposed_rounds p));
  let queued = List.map fst (Proposer.pending_digests p) in
  Alcotest.(check bool) "the skipped round-2 batch is re-queued" true
    (List.exists (Digests.Batch_digest.equal ba) queued);
  Alcotest.(check bool) "the committed round-3 batch is not re-queued" false
    (List.exists (Digests.Batch_digest.equal bb) queued)

(* The leader fast path: proposing the round before one's own leader round
   collapses the min delay to zero and halves the max, so the anticipated leader
   proposes sooner and is likelier to be committed. A non-leader keeps the full
   configured delays. Both are read off the startup proposal's armed timers. *)
let test_proposer_leader_fast_path () =
  let committee, _ = setup 4 in
  (* authority 0 leads round 2, so its round-1 proposal is on the fast path *)
  let _, la =
    Proposer.create ~config:(pconfig ()) ~committee ~authority:(id_at committee 0)
      ~schedule:(sched committee) ~genesis:(Certificate.genesis committee) ~now:(ts 0)
  in
  Alcotest.(check (option int)) "the leader's min delay collapses to zero" (Some 0)
    (min_after la);
  Alcotest.(check (option int)) "the leader's max delay is halved" (Some 500)
    (max_after la);
  (* authority 3 leads no round below 8, so it keeps the full delays *)
  let _, fa =
    Proposer.create ~config:(pconfig ()) ~committee ~authority:(id_at committee 3)
      ~schedule:(sched committee) ~genesis:(Certificate.genesis committee) ~now:(ts 0)
  in
  Alcotest.(check (option int)) "a non-leader keeps the full min delay" (Some 500)
    (min_after fa);
  Alcotest.(check (option int)) "a non-leader keeps the full max delay" (Some 1000)
    (max_after fa)

(* The readiness gate: on an even round the round's own leader certificate must
   be among the held parents before an early (pre-max-timeout) proposal fires.
   A quorum that excludes the leader leaves the gate closed, so neither the
   quorum itself nor the min timer proposes; only the max deadline overrides. *)
let test_proposer_gate_withholds_early_propose () =
  let committee, sk_of = setup 4 in
  let self = id_at committee 3 in
  let leader2 = id_at committee 0 in
  let p, boot =
    Proposer.create ~config:(pconfig ~threshold:100 ()) ~committee ~authority:self
      ~schedule:(sched committee) ~genesis:(Certificate.genesis committee) ~now:(ts 0)
  in
  let g1 = first (arm_gens boot) in
  (* advance to round 2 via a full round-1 quorum and the min timer *)
  let r1 = round_certs committee sk_of ~round:1 ~parents:(genesis_digests committee) in
  let p, _ = Proposer.step p ~now:(ts 1) (Proposer.Parents { certs = r1; round = r 1 }) in
  let p, acts2 =
    Proposer.step p ~now:(ts 2) (Proposer.Timer_fired { kind = Proposer.Min_delay; gen = g1 })
  in
  Alcotest.(check int) "advanced to round 2" 2 (Round.to_int (Proposer.round p));
  let g2 = first (arm_gens acts2) in
  (* a round-2 quorum (2f+1 = 3) that EXCLUDES the round-2 leader (authority 0) *)
  let non_leaders =
    List.filter (fun id -> not (Authority_id.equal id leader2)) (ids committee)
  in
  let r2 =
    List.map
      (fun author ->
        certify committee sk_of
          (a_header committee ~author ~round:2 ~parents:(List.map Certificate.digest r1) ()))
      non_leaders
  in
  let p, held = Proposer.step p ~now:(ts 3) (Proposer.Parents { certs = r2; round = r 2 }) in
  Alcotest.(check bool) "a quorum missing the leader does not itself propose" true
    (Option.is_none (find_header held));
  let p, on_min =
    Proposer.step p ~now:(ts 4) (Proposer.Timer_fired { kind = Proposer.Min_delay; gen = g2 })
  in
  Alcotest.(check bool) "the min timer cannot override the readiness gate" true
    (Option.is_none (find_header on_min));
  let _, on_max =
    Proposer.step p ~now:(ts 5) (Proposer.Timer_fired { kind = Proposer.Max_delay; gen = g2 })
  in
  Alcotest.(check bool) "the max deadline overrides the gate and proposes round 3" true
    (match find_header on_max with Some h -> Round.to_int (Header.round h) = 3 | None -> false)

(* A forward round jump re-arms the max timer under a fresh generation, so the
   stale timer from the last proposal is discarded rather than firing the
   max-override proposal at the old, earlier deadline. This matters precisely
   because the readiness gate withholds the min-lapse proposal when the jumped-to
   round's leader is absent from the quorum — otherwise the stale timer would
   force a proposal up to a full max delay before it should. *)
let test_proposer_forward_jump_rearms_max () =
  let committee, sk_of = setup 4 in
  let self = id_at committee 3 in
  let leader4 = id_at committee 1 in
  let p, boot =
    Proposer.create ~config:(pconfig ~threshold:100 ()) ~committee ~authority:self
      ~schedule:(sched committee) ~genesis:(Certificate.genesis committee) ~now:(ts 0)
  in
  let g_old = first (arm_gens boot) in
  (* a forward jump from round 1 to a round-4 quorum that EXCLUDES the round-4
     leader, so the readiness gate stays closed and the min lapse cannot propose *)
  let r3 = round_certs committee sk_of ~round:3 ~parents:(genesis_digests committee) in
  let non_leaders =
    List.filter (fun id -> not (Authority_id.equal id leader4)) (ids committee)
  in
  let r4 =
    List.map
      (fun author ->
        certify committee sk_of
          (a_header committee ~author ~round:4 ~parents:(List.map Certificate.digest r3) ()))
      non_leaders
  in
  let p, jump = Proposer.step p ~now:(ts 1) (Proposer.Parents { certs = r4; round = r 4 }) in
  Alcotest.(check int) "the jump advances to round 4" 4 (Round.to_int (Proposer.round p));
  Alcotest.(check bool) "the gate is closed, so the jump does not itself propose" true
    (Option.is_none (find_header jump));
  Alcotest.(check bool) "the jump re-arms the max timer" true (Option.is_some (max_after jump));
  Alcotest.(check bool) "and re-arms only the max, not the min" true
    (Option.is_none (min_after jump));
  let g_new = first (arm_gens jump) in
  Alcotest.(check bool) "under a fresh generation" true (g_new <> g_old);
  (* the stale pre-jump max timer is now discarded, not honored *)
  let p, stale =
    Proposer.step p ~now:(ts 2) (Proposer.Timer_fired { kind = Proposer.Max_delay; gen = g_old })
  in
  Alcotest.(check bool) "the pre-jump max timer no longer proposes" true
    (Option.is_none (find_header stale));
  (* the re-armed max timer fires the override proposal at the correct deadline *)
  let _, live =
    Proposer.step p ~now:(ts 3) (Proposer.Timer_fired { kind = Proposer.Max_delay; gen = g_new })
  in
  Alcotest.(check bool) "the re-armed max timer proposes round 5 via the override" true
    (match find_header live with Some h -> Round.to_int (Header.round h) = 5 | None -> false)

(* ---- voter ---- *)

let voter_of committee sk_of ~self =
  Voter.create ~committee ~secret_key:(sk_of self) ~self_id:self
    ~genesis:(Certificate.genesis committee)

let test_voter_votes_valid () =
  let committee, sk_of = setup 4 in
  let self = id_at committee 0 and peer = id_at committee 1 in
  let v = voter_of committee sk_of ~self in
  let h = a_header committee ~author:peer ~round:1 ~parents:(genesis_digests committee) () in
  let _, decision = Voter.vote v ~dag:(Dag.create ~gc_depth:50) ~now:(ts 5) h in
  match decision with
  | Voter.Vote vote ->
      Alcotest.(check bool) "the vote is ours" true (Authority_id.equal (Vote.author vote) self);
      Alcotest.(check bool) "and is on the peer's header" true
        (Digests.Header_digest.equal (Vote.header_digest vote) (Header.digest h))
  | _ -> Alcotest.fail "expected a vote on the valid header"

let test_voter_recasts_identical () =
  let committee, sk_of = setup 4 in
  let self = id_at committee 0 and peer = id_at committee 1 in
  let dag = Dag.create ~gc_depth:50 in
  let h = a_header committee ~author:peer ~round:1 ~parents:(genesis_digests committee) () in
  let v, d1 = Voter.vote (voter_of committee sk_of ~self) ~dag ~now:(ts 5) h in
  let _, d2 = Voter.vote v ~dag ~now:(ts 6) h in
  Alcotest.(check bool) "the first request is a fresh vote" true
    (match d1 with Voter.Vote _ -> true | _ -> false);
  Alcotest.(check bool) "the identical re-request recasts the same vote" true
    (match (d1, d2) with
     | Voter.Vote a, Voter.Recast b ->
         Digests.Header_digest.equal (Vote.header_digest a) (Vote.header_digest b)
     | _ -> false)

let insert_cert dag cert =
  match Dag.try_insert dag cert with
  | Ok (dag, _) -> dag
  | Error e -> Alcotest.failf "insert: %s" (Dag.error_to_string e)

let test_voter_refuses_equivocation () =
  let committee, sk_of = setup 4 in
  let self = id_at committee 0 and peer = id_at committee 1 in
  let h1 = a_header committee ~author:peer ~round:1 ~parents:(genesis_digests committee) () in
  (* a certificate for h1 exists at (peer, round 1): a real quorum signed it, so a
     conflicting round-1 header is genuine equivocation *)
  let dag = insert_cert (Dag.create ~gc_depth:50) (certify committee sk_of h1) in
  let v, _ = Voter.vote (voter_of committee sk_of ~self) ~dag ~now:(ts 5) h1 in
  let h2 = a_header committee ~author:peer ~round:1 ~created_at:1 ~parents:(genesis_digests committee) () in
  let _, d2 = Voter.vote v ~dag ~now:(ts 5) h2 in
  Alcotest.(check bool) "the two headers differ" false (Header.equal h1 h2);
  Alcotest.(check bool) "a different header for a certified slot is refused" true
    (match d2 with Voter.Reject Voter.Equivocating_header -> true | _ -> false)

let test_voter_revotes_uncertified () =
  let committee, sk_of = setup 4 in
  let self = id_at committee 0 and peer = id_at committee 1 in
  (* no certificate for the peer at round 1: the earlier vote never aggregated,
     so a restarted proposer's new round-1 header is safe to re-vote *)
  let dag = Dag.create ~gc_depth:50 in
  let h1 = a_header committee ~author:peer ~round:1 ~parents:(genesis_digests committee) () in
  let v, _ = Voter.vote (voter_of committee sk_of ~self) ~dag ~now:(ts 5) h1 in
  let h2 = a_header committee ~author:peer ~round:1 ~created_at:1 ~parents:(genesis_digests committee) () in
  let _, d2 = Voter.vote v ~dag ~now:(ts 5) h2 in
  Alcotest.(check bool) "with no certificate for the slot, the node re-votes" true
    (match d2 with
     | Voter.Vote vote ->
         Digests.Header_digest.equal (Vote.header_digest vote) (Header.digest h2)
     | _ -> false)

let test_voter_needs_parents () =
  let committee, sk_of = setup 4 in
  let self = id_at committee 0 and peer = id_at committee 1 in
  let fake = Digests.Header_digest.of_digest (Tn_crypto.Digest.hash "unknown parent") in
  let h = a_header committee ~author:peer ~round:2 ~parents:[ fake ] () in
  let _, d = Voter.vote (voter_of committee sk_of ~self) ~dag:(Dag.create ~gc_depth:50) ~now:(ts 5) h in
  Alcotest.(check bool) "an unresolved parent is requested, not an error" true
    (match d with Voter.Need_parents [ x ] -> Digests.Header_digest.equal x fake | _ -> false)

let test_voter_rejects_inquorate () =
  let committee, sk_of = setup 4 in
  let self = id_at committee 0 and peer = id_at committee 1 in
  let h = a_header committee ~author:peer ~round:1 ~parents:[ first (genesis_digests committee) ] () in
  let _, d = Voter.vote (voter_of committee sk_of ~self) ~dag:(Dag.create ~gc_depth:50) ~now:(ts 5) h in
  Alcotest.(check bool) "a single genesis parent is inquorate" true
    (match d with Voter.Reject Voter.Inquorate_parents -> true | _ -> false)

let test_voter_rejects_round_zero () =
  let committee, sk_of = setup 4 in
  let self = id_at committee 0 and peer = id_at committee 1 in
  let h = a_header committee ~author:peer ~round:0 ~parents:[] () in
  let _, d = Voter.vote (voter_of committee sk_of ~self) ~dag:(Dag.create ~gc_depth:50) ~now:(ts 5) h in
  Alcotest.(check bool) "a round-0 header is never voted on" true
    (match d with Voter.Reject Voter.Round_zero -> true | _ -> false)

(* The drift-tolerance window. With the clock at 5s and the tolerance one second,
   a header stamped 6s (exactly one second ahead) is within tolerance and voted;
   one stamped 7s (two seconds ahead) is beyond it and rejected. This pins the
   inclusive [now + tolerance] boundary and, together, the tolerance value. *)
let test_voter_drift_tolerance () =
  let committee, sk_of = setup 4 in
  let self = id_at committee 0 and peer = id_at committee 1 in
  let dag = Dag.create ~gc_depth:50 in
  let within =
    a_header committee ~author:peer ~round:1 ~created_at:6
      ~parents:(genesis_digests committee) ()
  in
  let _, d_within = Voter.vote (voter_of committee sk_of ~self) ~dag ~now:(ts 5) within in
  Alcotest.(check bool) "a header one second ahead is within tolerance and voted" true
    (match d_within with Voter.Vote _ -> true | _ -> false);
  let beyond =
    a_header committee ~author:peer ~round:1 ~created_at:7
      ~parents:(genesis_digests committee) ()
  in
  let _, d_beyond = Voter.vote (voter_of committee sk_of ~self) ~dag ~now:(ts 5) beyond in
  Alcotest.(check bool) "a header two seconds ahead is beyond tolerance and rejected" true
    (match d_beyond with Voter.Reject Voter.Future_timestamp -> true | _ -> false)

(* ---- node ---- *)

let node_create committee sk_of ~self =
  Node.create ~committee ~secret_key:(sk_of self) ~self_id:self
    ~proposer_config:(pconfig ~threshold:1 ()) ~sub_dags_per_schedule:100 ~gc_depth:50
    ~now:(ts 0)

let node_header cmds =
  List.find_map (function Node.Broadcast_header h -> Some h | _ -> None) cmds

let node_step node ~now event =
  match Node.step node ~now event with
  | Ok r -> r
  | Error _ -> Alcotest.fail "unexpected node invariant error"

let test_node_bootstraps () =
  let committee, sk_of = setup 4 in
  let _, cmds = node_create committee sk_of ~self:(id_at committee 0) in
  Alcotest.(check bool) "startup broadcasts a round-1 header" true
    (match node_header cmds with Some h -> Round.to_int (Header.round h) = 1 | None -> false);
  Alcotest.(check int) "and arms both proposer timers" 2
    (List.length (List.filter (function Node.Arm_timer _ -> true | _ -> false) cmds))

let test_node_forms_certificate () =
  let committee, sk_of = setup 4 in
  let self = id_at committee 0 in
  let node, cmds = node_create committee sk_of ~self in
  let h1 = get (node_header cmds) in
  (* self already voted implicitly; two peer votes reach the quorum of 3 *)
  let node, broadcast =
    List.fold_left
      (fun (node, seen) peer ->
        let vote = Vote.sign (sk_of peer) ~voter:peer h1 in
        let node, cmds = node_step node ~now:(ts 1) (Node.Vote_received vote) in
        (node, seen || List.exists (function Node.Broadcast_certificate _ -> true | _ -> false) cmds))
      (node, false)
      [ id_at committee 1; id_at committee 2 ]
  in
  Alcotest.(check bool) "the vote quorum forms and broadcasts a certificate" true broadcast;
  Alcotest.(check bool) "our round-1 certificate is now in the dag" true
    (Option.is_some (Dag.get (Node.dag node) (r 1) self))

let test_node_offered_unsynced_parents_no_halt () =
  let committee, sk_of = setup 4 in
  let self = id_at committee 0 and peer = id_at committee 1 in
  let node, _ = node_create committee sk_of ~self in
  (* a legitimate round-2 certificate whose round-1 parents this fresh node lacks *)
  let r1 = round_certs committee sk_of ~round:1 ~parents:(genesis_digests committee) in
  let orphan =
    first (round_certs committee sk_of ~round:2 ~parents:(List.map Certificate.digest r1))
  in
  let h3 = a_header committee ~author:peer ~round:3 ~parents:[ Certificate.digest orphan ] () in
  (* offering that certificate as a vote-request parent must NOT halt the node *)
  match Node.step node ~now:(ts 1) (Node.Vote_request { from_ = peer; header = h3; parents = [ orphan ] }) with
  | Error _ -> Alcotest.fail "an unsynced offered parent must not halt the node"
  | Ok (_, cmds) ->
      Alcotest.(check bool) "the unplaceable parent yields a missing-parents response, not a halt" true
        (List.exists (function Node.Send_missing_parents _ -> true | _ -> false) cmds)

let test_node_commits_via_bullshark () =
  let committee, sk_of = setup 4 in
  let self = id_at committee 0 in
  let node, _ = node_create committee sk_of ~self in
  (* feed an optimal rounds-1..3 DAG as gossiped certificates *)
  let all = List.concat_map snd (optimal_rounds committee sk_of ~upto:3) in
  let _, committed =
    List.fold_left
      (fun (node, acc) c ->
        let node, cmds = node_step node ~now:(ts 1) (Node.Certificate_received c) in
        (node, acc @ List.filter_map (function Node.Emit_committed sd -> Some sd | _ -> None) cmds))
      (node, []) all
  in
  Alcotest.(check bool) "at least one sub-dag is committed" true (committed <> []);
  Alcotest.(check bool) "the round-2 leader (ids0) is committed" true
    (List.exists
       (fun sd ->
         Round.to_int (Sub_dag.leader_round sd) = 2
         && Authority_id.equal (Sub_dag.leader_author sd) self)
       committed)

let () =
  Alcotest.run "tn_primary"
    [
      ( "proposer",
        [
          Alcotest.test_case "empty round-1 startup" `Quick test_proposer_empty_round1;
          Alcotest.test_case "proposes on quorum and timer" `Quick
            test_proposer_proposes_on_quorum_and_timer;
          Alcotest.test_case "stale-generation timer discarded" `Quick
            test_proposer_stale_timer_discarded;
          Alcotest.test_case "re-queues skipped headers" `Quick test_proposer_requeues_skipped;
          Alcotest.test_case "leader fast path shortens the delays" `Quick
            test_proposer_leader_fast_path;
          Alcotest.test_case "readiness gate withholds an early propose" `Quick
            test_proposer_gate_withholds_early_propose;
          Alcotest.test_case "forward jump re-arms the max timer" `Quick
            test_proposer_forward_jump_rearms_max;
        ] );
      ( "voter",
        [
          Alcotest.test_case "votes on a valid header" `Quick test_voter_votes_valid;
          Alcotest.test_case "recasts an identical request" `Quick test_voter_recasts_identical;
          Alcotest.test_case "refuses an equivocating header" `Quick
            test_voter_refuses_equivocation;
          Alcotest.test_case "re-votes an uncertified restart" `Quick
            test_voter_revotes_uncertified;
          Alcotest.test_case "requests missing parents" `Quick test_voter_needs_parents;
          Alcotest.test_case "rejects inquorate parents" `Quick test_voter_rejects_inquorate;
          Alcotest.test_case "rejects a round-0 header" `Quick test_voter_rejects_round_zero;
          Alcotest.test_case "accepts within, rejects beyond drift tolerance" `Quick
            test_voter_drift_tolerance;
        ] );
      ( "node",
        [
          Alcotest.test_case "bootstraps with a round-1 header" `Quick test_node_bootstraps;
          Alcotest.test_case "forms a certificate from votes" `Quick test_node_forms_certificate;
          Alcotest.test_case "unsynced offered parents do not halt" `Quick
            test_node_offered_unsynced_parents_no_halt;
          Alcotest.test_case "commits via bullshark" `Quick test_node_commits_via_bullshark;
        ] );
    ]
