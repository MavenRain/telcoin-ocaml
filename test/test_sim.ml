(* Tests for the deterministic simulator: an honest committee driven by the pure
   consensus core must reach consensus (every node commits), agree (all committed
   logs are prefix-consistent), never trip a DAG invariant, and replay identically
   from a seed. These are end-to-end: they exercise Proposer, Voter, the
   aggregators, and Bullshark together through the Node, as the shell interprets
   their commands into events. *)

open Tn_types
open Tn_vertex
open Tn_consensus
open Tn_sim

let get = function Some x -> x | None -> Alcotest.fail "expected Some"
let dur ms = get (Units.Duration.of_ms ms)

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

(* A completed run over an [n]-validator committee at the given seed and horizon. *)
let run ?(horizon = 20_000) ?(seed = 42L) ?batches n =
  let committee, sk_of = setup n in
  let cfg =
    Sim.config ~min_latency:(dur 5) ~max_latency:(dur 50) ~horizon:(dur horizon)
      ~max_steps:1_000_000 ~seed ?batches ()
  in
  Sim.create ~committee ~secret_key:sk_of ~proposer_config:Proposer.default_config
    ~sub_dags_per_schedule:100 ~gc_depth:50 ~config:cfg
  |> Sim.run
  |> fun sim -> (sim, committee)

let digest_log sim id =
  List.map
    (fun sd -> Digests.Sub_dag_digest.to_hex (Sub_dag.digest sd))
    (Sim.committed sim id)

let test_reaches_consensus () =
  let sim, committee = run 4 in
  Alcotest.(check bool) "no invariant-break error on the honest run" true
    (Option.is_none (Sim.error sim));
  Alcotest.(check bool) "every node commits at least one sub-DAG" true
    (List.for_all (fun id -> Sim.commit_count sim id > 0) (ids committee))

let test_all_nodes_agree () =
  let sim, _ = run 4 in
  match Sim.agreement sim with
  | Sim.Agree k -> Alcotest.(check bool) "nodes agree on a non-empty prefix" true (k > 0)
  | Sim.Diverge { index; _ } ->
      Alcotest.failf "nodes diverged at commit index %d" index

let test_leader_schedule_is_round_robin () =
  (* On an optimal DAG the committed leaders follow the id-sorted round-robin:
     round 2 -> authority 0, round 4 -> authority 1, ... wrapping by committee
     size. This pins that the shell's commits are the schedule, not noise. *)
  let sim, committee = run 4 in
  let order = ids committee in
  let self = get (match order with x :: _ -> Some x | [] -> None) in
  let committed = Sim.committed sim self in
  Alcotest.(check bool) "at least eight commits to check the wrap" true
    (List.length committed >= 8);
  List.iteri
    (fun i sd ->
      let expected = List.nth order (i mod List.length order) in
      Alcotest.(check bool)
        (Printf.sprintf "commit %d is led by the round-robin authority" i)
        true
        (Authority_id.equal (Sub_dag.leader_author sd) expected
        && Round.to_int (Sub_dag.leader_round sd) = (2 * (i + 1))))
    committed

let test_deterministic_replay () =
  let a, committee = run ~seed:7L 4 in
  let b, _ = run ~seed:7L 4 in
  let self = get (match ids committee with x :: _ -> Some x | [] -> None) in
  Alcotest.(check int) "the same seed delivers the same number of events"
    (Sim.steps a) (Sim.steps b);
  Alcotest.(check (list string)) "the same seed commits the identical log"
    (digest_log a self) (digest_log b self)

let test_larger_committee () =
  let sim, committee = run 7 in
  Alcotest.(check bool) "no invariant-break error at committee size 7" true
    (Option.is_none (Sim.error sim));
  Alcotest.(check bool) "every one of the seven nodes commits" true
    (List.for_all (fun id -> Sim.commit_count sim id > 0) (ids committee));
  match Sim.agreement sim with
  | Sim.Agree k -> Alcotest.(check bool) "the seven agree on a non-empty prefix" true (k > 0)
  | Sim.Diverge { index; _ } -> Alcotest.failf "size-7 committee diverged at index %d" index

(* The safety oracle only ever returns Agree on honest runs, so its
   fault-detecting path needs its own test: harvest real committed sub-DAGs, then
   arrange them into an identical pair, a prefix-lag, a fork, and a three-log case
   where only one node forks (which the all-pairs enumeration must still catch). *)
let test_agreement_oracle () =
  let sim, committee = run 4 in
  match ids committee with
  | a :: b :: c :: _ -> (
      match Sim.committed sim a with
      | s0 :: s1 :: s2 :: _ ->
          let agree logs = Sim.For_testing.agree_of_logs logs in
          (match agree [ (a, [ s0; s1; s2 ]); (b, [ s0; s1; s2 ]) ] with
          | Sim.Agree k -> Alcotest.(check int) "identical logs agree on the full length" 3 k
          | Sim.Diverge _ -> Alcotest.fail "identical logs must not diverge");
          (match agree [ (a, [ s0; s1; s2 ]); (b, [ s0; s1 ]) ] with
          | Sim.Agree k ->
              Alcotest.(check int) "a prefix-lag agrees on the shorter length" 2 k
          | Sim.Diverge _ -> Alcotest.fail "a prefix-lag must not be a divergence");
          (match agree [ (a, [ s0; s1; s2 ]); (b, [ s0; s2; s1 ]) ] with
          | Sim.Diverge { index; _ } ->
              Alcotest.(check int) "a fork is located at the first differing index" 1 index
          | Sim.Agree _ -> Alcotest.fail "differing logs must diverge");
          (match agree [ (a, [ s0; s1 ]); (b, [ s0; s1 ]); (c, [ s0; s2 ]) ] with
          | Sim.Diverge { index; _ } ->
              Alcotest.(check int) "a fork in only one node is still caught across all pairs" 1
                index
          | Sim.Agree _ -> Alcotest.fail "a fork in any pair must be detected")
      | _ -> Alcotest.fail "expected at least three committed sub-DAGs to arrange")
  | _ -> Alcotest.fail "expected a committee of at least three authorities"

(* Chunk-37 stage S6-pre: the pre-injection determinism golden. Pins the exact
   observable surface of the honest 4-node, seed-42, 20 s run — [Sim.steps],
   the id-first authority's commit count and its first/last committed sub-DAG
   digest — recorded while batch injection does not yet exist. The injection
   stage's hard constraint is that a default-absent plan leaves this run
   byte-identical, and these constants are what make that claim falsifiable
   rather than asserted. Recorded from the run itself and red-verified against
   the [ts_of_ms] coarsening (ms/1001), which shifts the header timestamps the
   nodes fold into their committed digests. *)
let golden_steps = 1959

let golden_commit_count = 23

let golden_first_digest =
  "93e2c79ad5434db18d88191f4ec7072f7100e6466149ea831871e53a5fba64c8"

let golden_last_digest =
  "4f6774b7da1e290e2bab3034b40559a21bbad308aa0a7a8f624eadc330d2e1ea"

let test_pre_injection_golden () =
  let sim, committee = run 4 in
  let self = get (match ids committee with x :: _ -> Some x | [] -> None) in
  let log = digest_log sim self in
  let first = match log with d :: _ -> Some d | [] -> None in
  let last = List.fold_left (fun _ d -> Some d) None log in
  Alcotest.(check (option string)) "golden: first committed digest"
    (Some golden_first_digest) first;
  Alcotest.(check (option string)) "golden: last committed digest"
    (Some golden_last_digest) last;
  Alcotest.(check int) "golden: commit count" golden_commit_count
    (Sim.commit_count sim self);
  Alcotest.(check int) "golden: delivered event count" golden_steps (Sim.steps sim)

(* ---- chunk-37 stage S6: batch injection ---- *)

(* A default injection plan: [per_authority] bodies per live authority, one
   every [period_ms]. The default transactions answer varies per authority and
   per index, so every synthesised body is pairwise distinct. *)
let plan ?(per_authority = 2) ?(period_ms = 1_000) ?(worker = 0)
    ?(transactions =
      fun id k -> [ Authority_id.to_hex id ^ "/" ^ string_of_int k ]) () =
  Sim.batch_plan ~per_authority ~period:(dur period_ms)
    ~worker_id:(get (Units.Worker_id.of_int worker))
    ~epoch:Units.Epoch.zero ~base_fee_per_gas:Units.Base_fee.min_protocol
    ~transactions ()

let first_id committee =
  get (match ids committee with x :: _ -> Some x | [] -> None)

let body_digests bodies =
  List.map (fun b -> Digests.Batch_digest.to_hex (Batch.digest b)) bodies

(* Every committed payload pair of [id], across every header of every committed
   sub-DAG, in commit order. *)
let committed_payload_pairs sim id =
  List.concat_map
    (fun sd ->
      List.concat_map Header.payload
        (Tn_std.Nonempty.to_list (Sub_dag.headers sd)))
    (Sim.committed sim id)

(* T6.1, THE HARD CONSTRAINT: a plan whose announcements all land beyond the
   horizon is scheduled but never delivered, and the run cannot tell — same
   steps, same elapsed clock, same committed digest log at the same seed. The
   injections drew no latency and no drop coin, so the latency stream never
   noticed them. *)
let test_beyond_horizon_plan_is_invisible () =
  let sim_off, committee = run 4 in
  let sim_on, _ = run ~batches:(plan ~period_ms:21_000 ()) 4 in
  let self = first_id committee in
  Alcotest.(check int) "steps agree" (Sim.steps sim_off) (Sim.steps sim_on);
  Alcotest.(check int) "elapsed agrees"
    (Units.Duration.to_ms (Sim.elapsed sim_off))
    (Units.Duration.to_ms (Sim.elapsed sim_on));
  Alcotest.(check (list string))
    "committed digest logs agree" (digest_log sim_off self)
    (digest_log sim_on self);
  Alcotest.(check int) "the bodies were still synthesised" 8
    (List.length (Sim.batch_bodies sim_on))

(* T6.2 (as patched by P8): the injection-OFF path, now running through the
   code that carries the injection machinery, still reproduces the S6-pre
   golden byte-for-byte — the pre-injection pin is what makes "absent means
   today's code path" falsifiable. Two injection-ON runs at the same seed are
   additionally checked to replay identically, bodies included. *)
let test_injection_off_matches_pre_injection_golden () =
  let sim, committee = run 4 in
  let self = first_id committee in
  let log = digest_log sim self in
  let first = match log with d :: _ -> Some d | [] -> None in
  let last = List.fold_left (fun _ d -> Some d) None log in
  Alcotest.(check int) "off: golden steps" golden_steps (Sim.steps sim);
  Alcotest.(check int) "off: golden commit count" golden_commit_count
    (Sim.commit_count sim self);
  Alcotest.(check (option string)) "off: golden first digest"
    (Some golden_first_digest) first;
  Alcotest.(check (option string)) "off: golden last digest"
    (Some golden_last_digest) last;
  Alcotest.(check int) "off: no bodies" 0 (List.length (Sim.batch_bodies sim));
  let on1, _ = run ~batches:(plan ()) 4 in
  let on2, _ = run ~batches:(plan ()) 4 in
  Alcotest.(check (list string)) "on/on: committed digest logs agree"
    (digest_log on1 self) (digest_log on2 self);
  Alcotest.(check (list string)) "on/on: synthesised bodies agree"
    (body_digests (Sim.batch_bodies on1))
    (body_digests (Sim.batch_bodies on2))

(* T6.3, the anti-H21 gate: with injection on, the traffic really lands — some
   committed header carries a non-empty payload — and every committed payload
   digest is answerable from a store built over [Sim.batch_bodies]. *)
let test_committed_payloads_resolve_from_bodies () =
  let sim, committee = run ~batches:(plan ()) 4 in
  let self = first_id committee in
  let store = Tn_driver.Batch_store.of_bodies (Sim.batch_bodies sim) in
  let pairs = committed_payload_pairs sim self in
  Alcotest.(check bool) "some committed payload is non-empty" true (pairs <> []);
  List.iter
    (fun (d, _) ->
      Alcotest.(check bool)
        ("payload digest resolves: " ^ Digests.Batch_digest.to_hex d)
        true
        (Option.is_some (Tn_driver.Batch_store.find store d)))
    pairs

(* T6.4: the committed payload's worker id and the stored body's worker id are
   the same fact — the announcement was read off the body, never off the plan.
   The plan's worker id is deliberately non-zero so a body built with a
   different one would be caught. *)
let test_payload_worker_id_matches_body () =
  let sim, committee = run ~batches:(plan ~worker:3 ()) 4 in
  let self = first_id committee in
  let store = Tn_driver.Batch_store.of_bodies (Sim.batch_bodies sim) in
  let pairs = committed_payload_pairs sim self in
  Alcotest.(check bool) "some committed payload is non-empty" true (pairs <> []);
  List.iter
    (fun (d, w) ->
      let body = get (Tn_driver.Batch_store.find store d) in
      Alcotest.(check int)
        ("worker ids agree: " ^ Digests.Batch_digest.to_hex d)
        (Units.Worker_id.to_int w)
        (Units.Worker_id.to_int (Batch.worker_id body)))
    pairs

(* T6.5: a varying transactions answer makes every synthesised body pairwise
   distinct (and the store holds them all); a constant answer collides — with
   this committee's equal execution addresses, into a single digest. The
   degeneracy is asserted explicitly so it is documented rather than latent. *)
let test_body_distinctness_and_documented_collision () =
  let sim, _ = run ~batches:(plan ()) 4 in
  let bodies = Sim.batch_bodies sim in
  Alcotest.(check int) "two bodies per live authority" 8 (List.length bodies);
  Alcotest.(check int) "varying transactions: pairwise distinct"
    (List.length bodies)
    (List.length (List.sort_uniq String.compare (body_digests bodies)));
  Alcotest.(check int) "varying transactions: the store holds them all"
    (List.length bodies)
    (Tn_driver.Batch_store.cardinal (Tn_driver.Batch_store.of_bodies bodies));
  let sim_c, _ = run ~batches:(plan ~transactions:(fun _ _ -> []) ()) 4 in
  let bodies_c = Sim.batch_bodies sim_c in
  Alcotest.(check int) "constant transactions: still one body per plan entry" 8
    (List.length bodies_c);
  Alcotest.(check bool) "constant transactions: per_authority > 1 collides" true
    (Tn_driver.Batch_store.cardinal (Tn_driver.Batch_store.of_bodies bodies_c)
    < List.length bodies_c)

(* T6.6: a crashed authority receives no injections — its plan entries are
   dropped exactly as its startup commands are — and no synthesised body is
   beneficiaried to it. The committee here carries DISTINCT execution
   addresses (unlike [setup]'s all-zero ones), so a beneficiary names its
   authority and the assertion discriminates. *)
let test_crashed_authority_gets_no_injections () =
  let sks_chars =
    List.mapi
      (fun i c -> (Tn_crypto.Secret_key.derive (Int64.of_int i), c))
      [ 'A'; 'B'; 'C'; 'D' ]
  in
  let authorities =
    List.map
      (fun (sk, c) ->
        Authority.make
          ~protocol_key:(Tn_crypto.Secret_key.public_key sk)
          ~execution_address:(get (Units.Address.of_bytes (String.make 20 c))))
      sks_chars
  in
  let committee =
    Result.fold ~ok:Fun.id
      ~error:(fun e -> Alcotest.failf "committee: %s" (Committee.error_to_string e))
      (Committee.create ~epoch:Units.Epoch.zero authorities)
  in
  let sk_of id =
    List.find_map
      (fun (sk, _) ->
        let a_id =
          Authority_id.of_public_key (Tn_crypto.Secret_key.public_key sk)
        in
        if Authority_id.equal a_id id then Some sk else None)
      sks_chars
    |> get
  in
  let crashed = first_id committee in
  let crashed_address =
    List.find_map
      (fun a ->
        if Authority_id.equal (Authority.id a) crashed then
          Some (Authority.execution_address a)
        else None)
      (Committee.authorities committee)
    |> get
  in
  let cfg =
    Sim.config ~min_latency:(dur 5) ~max_latency:(dur 50) ~horizon:(dur 20_000)
      ~max_steps:1_000_000 ~seed:42L ~crashed:[ crashed ]
      ~batches:(plan ()) ()
  in
  let sim =
    Sim.create ~committee ~secret_key:sk_of
      ~proposer_config:Proposer.default_config ~sub_dags_per_schedule:100
      ~gc_depth:50 ~config:cfg
    |> Sim.run
  in
  let bodies = Sim.batch_bodies sim in
  Alcotest.(check int) "two bodies per LIVE authority" 6 (List.length bodies);
  Alcotest.(check bool) "no body is beneficiaried to the crashed authority" true
    (List.for_all
       (fun b ->
         not (Units.Address.equal (Batch.beneficiary b) crashed_address))
       bodies)

let () =
  Alcotest.run "tn_sim"
    [
      ( "simulator",
        [
          Alcotest.test_case "an honest committee reaches consensus" `Quick
            test_reaches_consensus;
          Alcotest.test_case "all nodes agree on the committed prefix" `Quick
            test_all_nodes_agree;
          Alcotest.test_case "committed leaders follow the round-robin schedule" `Quick
            test_leader_schedule_is_round_robin;
          Alcotest.test_case "a seed replays identically" `Quick test_deterministic_replay;
          Alcotest.test_case "a larger committee also reaches consensus" `Quick
            test_larger_committee;
          Alcotest.test_case "the agreement oracle detects a real fork" `Quick
            test_agreement_oracle;
          Alcotest.test_case "the pre-injection golden pins the honest run" `Quick
            test_pre_injection_golden;
          Alcotest.test_case "a beyond-horizon batch plan is invisible" `Quick
            test_beyond_horizon_plan_is_invisible;
          Alcotest.test_case "injection off matches the pre-injection golden"
            `Quick test_injection_off_matches_pre_injection_golden;
          Alcotest.test_case "committed payloads resolve from the bodies" `Quick
            test_committed_payloads_resolve_from_bodies;
          Alcotest.test_case "committed worker ids match the stored bodies"
            `Quick test_payload_worker_id_matches_body;
          Alcotest.test_case "body distinctness and the documented collision"
            `Quick test_body_distinctness_and_documented_collision;
          Alcotest.test_case "a crashed authority gets no injections" `Quick
            test_crashed_authority_gets_no_injections;
        ] );
    ]
