(* Property tests (roadmap step 13): randomised, seed-driven simulator runs that
   assert the protocol invariants QuickCheck-style rather than on one fixed
   schedule. Each generated case is itself deterministic — the simulator is a pure
   function of (committee, seed, faults) — so a falsifying case is reproducible by
   re-running with its printed parameters, and the qcheck driver is pinned to a
   fixed [Random.State] so the whole suite replays identically in CI.

   Every assertion below was first checked empirically against the real simulator;
   the two non-obvious outcomes that shaped them:

   - {b Across seeds, the committed leader {e schedule} is invariant but the
     sub-DAG {e digests} are not.} A proposer parents its header on a 2f+1 quorum
     of the previous round, not on all [n] certificates, so a different network
     schedule freezes a different (but globally consistent) parent set into the
     DAG. Which authority anchors each commit index is fixed by round-robin leader
     election and does not move; the exact causal history it flattens can. So
     {!prop_causal} asserts leader-schedule prefix equality, never digest equality.
   - {b Across gc_depth at a {e fixed} seed, the committed digests are identical.}
     Same seed means the same schedule and the same DAG; garbage collection only
     prunes already-committed history from the working set, so it is a memory knob,
     not a consensus knob. {!prop_gc} asserts exact digest-prefix equality.

   The fault model exercised here is crash-stop and message loss (see {!Tn_sim} —
   honest-node-preserving, no Byzantine equivocation), so safety must hold in every
   case: no run may report an invariant-break error or a divergence. Liveness is
   only claimed where the honest survivors hold a quorum. *)

open Tn_types
open Tn_vertex
open Tn_consensus
open Tn_sim

let get = function Some x -> x | None -> Alcotest.fail "expected Some"
let dur ms = get (Units.Duration.of_ms ms)

(* A committee of [n] authorities and the secret-key lookup for its members —
   deterministic in [n], so the same [n] yields the same authorities across runs
   regardless of seed, which is what lets a cross-seed comparison use one id. *)
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
let f_of n = (n - 1) / 3

(* A completed run over an [n]-validator committee at the given seed, horizon, and
   optional faults. [gc_depth] is a knob so the GC-equivalence property can vary
   it. *)
let run ?(horizon = 15_000) ?(seed = 42L) ?(crashed = []) ?(drop_permille = 0)
    ?(gc_depth = 50) n =
  let committee, sk_of = setup n in
  let cfg =
    Sim.config ~min_latency:(dur 5) ~max_latency:(dur 50) ~horizon:(dur horizon)
      ~max_steps:5_000_000 ~seed ~crashed ~drop_permille ()
  in
  Sim.create ~committee ~secret_key:sk_of ~proposer_config:Proposer.default_config
    ~sub_dags_per_schedule:100 ~gc_depth ~config:cfg
  |> Sim.run
  |> fun sim -> (sim, committee)

(* ---- observation helpers ---- *)

(* The committed leader schedule: (leader author, leader round) per commit index,
   normalised to comparable values. *)
let schedule sim id =
  List.map
    (fun sd ->
      (Authority_id.to_hex (Sub_dag.leader_author sd), Round.to_int (Sub_dag.leader_round sd)))
    (Sim.committed sim id)

let digest_log sim id =
  List.map (fun sd -> Digests.Sub_dag_digest.to_hex (Sub_dag.digest sd)) (Sim.committed sim id)

(* Agreement over just the given (live) authorities' logs — used under crash
   faults, where {!Sim.agreement}'s whole-committee view would fold a silent
   node's empty log into a vacuous [Agree 0]. *)
let live_agreement sim live = Sim.For_testing.agree_of_logs (List.map (fun id -> (id, Sim.committed sim id)) live)

let not_diverged = function Sim.Agree _ -> true | Sim.Diverge _ -> false

let prefix_eq a b =
  let n = min (List.length a) (List.length b) in
  let take l = List.filteri (fun i _ -> i < n) l in
  take a = take b

(* Consecutive-pair predicate over a list; vacuously true for lists under two. *)
let rec pairwise ok = function
  | a :: (b :: _ as rest) -> ok a b && pairwise ok rest
  | _ -> true

(* ---- generators ---- *)

let gen_seed = QCheck.Gen.map Int64.of_int QCheck.Gen.int

let arb_n_seed =
  QCheck.make
    ~print:(fun (n, s) -> Printf.sprintf "n=%d seed=%Ld" n s)
    QCheck.Gen.(pair (int_range 4 7) gen_seed)

let arb_n_two_seeds =
  QCheck.make
    ~print:(fun (n, s1, s2) -> Printf.sprintf "n=%d seed1=%Ld seed2=%Ld" n s1 s2)
    QCheck.Gen.(triple (int_range 4 7) gen_seed gen_seed)

let arb_crash =
  QCheck.make
    ~print:(fun (n, k, s) -> Printf.sprintf "n=%d crash=%d seed=%Ld" n k s)
    QCheck.Gen.(triple (oneof_list [ 4; 7; 10 ]) (int_range 0 4) gen_seed)

let arb_drop =
  QCheck.make
    ~print:(fun (n, dp, s) -> Printf.sprintf "n=%d drop_permille=%d seed=%Ld" n dp s)
    QCheck.Gen.(triple (int_range 4 7) (int_range 0 800) gen_seed)

(* ---- properties ---- *)

let n_honest = "an honest committee is safe and live for every seed"

let prop_honest =
  QCheck.Test.make ~count:100 ~name:n_honest arb_n_seed (fun (n, seed) ->
      let sim, committee = run ~seed n in
      Option.is_none (Sim.error sim)
      && (match Sim.agreement sim with Sim.Agree k -> k >= 1 | Sim.Diverge _ -> false)
      && List.for_all (fun id -> Sim.commit_count sim id >= 1) (ids committee))

let n_monotone = "committed logs advance in round and never regress in timestamp"

let prop_monotone =
  QCheck.Test.make ~count:60 ~name:n_monotone arb_n_seed (fun (n, seed) ->
      let sim, committee = run ~seed n in
      List.for_all
        (fun id ->
          let log = Sim.committed sim id in
          pairwise
            (fun a b -> Round.to_int (Sub_dag.leader_round a) < Round.to_int (Sub_dag.leader_round b))
            log
          && pairwise
               (fun a b -> Units.Timestamp.compare (Sub_dag.commit_timestamp a) (Sub_dag.commit_timestamp b) <= 0)
               log
          && pairwise
               (fun a b -> Units.Timestamp.compare (Sub_dag.stored_timestamp a) (Sub_dag.stored_timestamp b) <= 0)
               log)
        (ids committee))

let n_causal = "the committed leader schedule is invariant to delivery timing"

let prop_causal =
  QCheck.Test.make ~count:60 ~name:n_causal arb_n_two_seeds (fun (n, s1, s2) ->
      let sim1, committee = run ~seed:s1 n in
      let sim2, _ = run ~seed:s2 n in
      let id = List.hd (ids committee) in
      not_diverged (Sim.agreement sim1)
      && not_diverged (Sim.agreement sim2)
      && Sim.commit_count sim1 id >= 1
      && Sim.commit_count sim2 id >= 1
      && prefix_eq (schedule sim1 id) (schedule sim2 id))

let n_gc = "committed output is invariant to gc_depth at a fixed seed"

let prop_gc =
  QCheck.Test.make ~count:60 ~name:n_gc arb_n_seed (fun (n, seed) ->
      let sim1, committee = run ~seed ~gc_depth:30 n in
      let sim2, _ = run ~seed ~gc_depth:90 n in
      let id = List.hd (ids committee) in
      (* Same seed => same schedule => same DAG; gc_depth only prunes committed
         history from the working set. So the committed digest logs must be
         EXACTLY equal (same length, same digests), not merely prefix-consistent —
         a strict-prefix or empty sim2 log would be a real GC-affects-consensus bug
         and must fail here. *)
      Option.is_none (Sim.error sim1)
      && Option.is_none (Sim.error sim2)
      && Sim.commit_count sim1 id >= 1
      && digest_log sim1 id = digest_log sim2 id)

let n_crash = "crash faults up to f keep safety and liveness; f+1 keeps safety"

let prop_crash =
  QCheck.Test.make ~count:60 ~name:n_crash arb_crash (fun (n, k_raw, seed) ->
      let all = ids (fst (setup n)) in
      let f = f_of n in
      (* Clamp so at most f+1 crash — enough to cross the liveness boundary while
         leaving the committee valid — and the crashed set is the first k in id
         order, the live set the rest. *)
      let k = min k_raw (f + 1) in
      let crashed = List.filteri (fun i _ -> i < k) all in
      let live = List.filteri (fun i _ -> i >= k) all in
      let sim, _ = run ~horizon:25_000 ~seed ~crashed n in
      let safety = Option.is_none (Sim.error sim) && not_diverged (live_agreement sim live) in
      let liveness =
        if k <= f then
          List.for_all (fun id -> Sim.commit_count sim id >= 1) live
          && (match live_agreement sim live with Sim.Agree m -> m >= 1 | Sim.Diverge _ -> false)
        else true
      in
      safety && liveness)

let n_drop = "message loss never breaks safety"

let prop_drop =
  QCheck.Test.make ~count:60 ~name:n_drop arb_drop (fun (n, drop_permille, seed) ->
      let sim, _ = run ~horizon:20_000 ~seed ~drop_permille n in
      Option.is_none (Sim.error sim) && not_diverged (Sim.agreement sim))

(* ---- alcotest wrapping ---- *)

(* qcheck's [check_exn] raises on a falsified or erroring property, with the
   printed counterexample carried in the exception (qcheck registers a Printexc
   printer, so alcotest reports it readably). The driver's [rand] is fixed so the
   sampled cases — and therefore the pass/fail verdict — replay identically. A
   distinct [salt] per property keeps the several properties that share a generator
   (e.g. the [n, seed] ones) from sampling byte-identical cases, widening coverage
   while staying deterministic. *)
let check ~salt t () = QCheck.Test.check_exn ~rand:(Random.State.make [| 0x7e1c0ffee; salt |]) t

let () =
  Alcotest.run "tn_properties"
    [
      ( "properties",
        [
          Alcotest.test_case n_honest `Slow (check ~salt:1 prop_honest);
          Alcotest.test_case n_monotone `Slow (check ~salt:2 prop_monotone);
          Alcotest.test_case n_causal `Slow (check ~salt:3 prop_causal);
          Alcotest.test_case n_gc `Slow (check ~salt:4 prop_gc);
          Alcotest.test_case n_crash `Slow (check ~salt:5 prop_crash);
          Alcotest.test_case n_drop `Slow (check ~salt:6 prop_drop);
        ] );
    ]
