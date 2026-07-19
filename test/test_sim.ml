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
let run ?(horizon = 20_000) ?(seed = 42L) n =
  let committee, sk_of = setup n in
  let cfg =
    Sim.config ~min_latency:(dur 5) ~max_latency:(dur 50) ~horizon:(dur horizon)
      ~max_steps:1_000_000 ~seed
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
        ] );
    ]
