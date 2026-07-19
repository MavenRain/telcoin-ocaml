(* Tests for the execution seam. The Noop engine folds committed consensus output
   into a hash-linked chain of consensus-chain blocks (the port of Rust's
   ConsensusHeader chain). Real committed sub-DAGs come from a short honest
   simulation, so these exercise the engine over exactly the data a running node
   feeds it, and check that the chain the simulator derives is well-formed and
   that honest nodes agree on it. *)

open Tn_types
open Tn_consensus
open Tn_sim
module Cb = Tn_execution.Consensus_block
module Noop = Tn_execution.Engine.Noop

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
    Result.fold ~ok:Fun.id
      ~error:(fun e -> Alcotest.failf "committee: %s" (Committee.error_to_string e))
      (Committee.create ~epoch:Units.Epoch.zero authorities)
  in
  let sk_of id =
    get
      (List.find_opt
         (fun sk ->
           Authority_id.equal
             (Authority_id.of_public_key (Tn_crypto.Secret_key.public_key sk))
             id)
         sks)
  in
  (committee, sk_of)

let ids committee = List.map Authority.id (Committee.authorities committee)
let node0 committee = get (List.nth_opt (ids committee) 0)

let run ?(seed = 42L) ?(horizon = 20_000) n =
  let committee, sk_of = setup n in
  let cfg =
    Sim.config ~min_latency:(dur 5) ~max_latency:(dur 50) ~horizon:(dur horizon)
      ~max_steps:1_000_000 ~seed ()
  in
  let sim =
    Sim.create ~committee ~secret_key:sk_of
      ~proposer_config:Proposer.default_config ~sub_dags_per_schedule:100
      ~gc_depth:50 ~config:cfg
    |> Sim.run
  in
  (sim, committee)

(* The genesis engine has produced nothing and sits at height zero. *)
let test_genesis_engine () =
  Alcotest.(check bool) "genesis engine has no tip" true
    (Option.is_none (Noop.tip Noop.genesis));
  Alcotest.(check int) "genesis height is zero" 0
    (Cb.Number.to_int (Noop.height Noop.genesis))

(* The first committed sub-DAG produces block number one, linked to the anchor. *)
let test_first_block () =
  let sim, committee = run 4 in
  let self = node0 committee in
  let sd = get (List.nth_opt (Sim.committed sim self) 0) in
  Result.fold
    ~ok:(fun (engine, block) ->
      Alcotest.(check int) "first block number is one" 1
        (Cb.Number.to_int (Cb.number block));
      Alcotest.(check bool) "first block links to the genesis anchor" true
        (Digests.Output_digest.equal (Cb.parent_hash block) Cb.genesis_parent);
      Alcotest.(check bool) "engine tip is the block just produced" true
        (Option.fold ~none:false ~some:(Cb.equal block) (Noop.tip engine));
      Alcotest.(check int) "engine height advanced to one" 1
        (Cb.Number.to_int (Noop.height engine)))
    ~error:Tn_execution.Nothing.absurd
    (Noop.execute Noop.genesis sd)

(* The derived chain is contiguous, one block per commit, each linking to its
   predecessor from the genesis anchor. *)
let test_chain_links () =
  let sim, committee = run 4 in
  let self = node0 committee in
  let chain = Sim.executed sim self in
  Alcotest.(check bool) "chain is non-empty" true (chain <> []);
  Alcotest.(check int) "one block per committed sub-DAG"
    (Sim.commit_count sim self) (List.length chain);
  List.iteri
    (fun i b ->
      Alcotest.(check int)
        (Printf.sprintf "block at index %d is numbered %d" i (i + 1))
        (i + 1)
        (Cb.Number.to_int (Cb.number b)))
    chain;
  let final_parent =
    List.fold_left
      (fun expected_parent b ->
        Alcotest.(check bool) "block links to its predecessor's digest" true
          (Digests.Output_digest.equal (Cb.parent_hash b) expected_parent);
        Cb.digest b)
      Cb.genesis_parent chain
  in
  ignore final_parent

(* The digest is a deterministic function of (parent, sub-DAG, number) and is
   sensitive to each. *)
let test_digest_deterministic () =
  let sim, committee = run 4 in
  let self = node0 committee in
  let log = Sim.committed sim self in
  let sd = get (List.nth_opt log 0) in
  let sd2 = get (List.nth_opt log 1) in
  let one = Cb.Number.succ Cb.Number.genesis in
  let two = Cb.Number.succ one in
  let b1 = Cb.create ~parent_hash:Cb.genesis_parent ~sub_dag:sd ~number:one in
  let b2 = Cb.create ~parent_hash:Cb.genesis_parent ~sub_dag:sd ~number:one in
  Alcotest.(check bool) "identical inputs give the same digest" true (Cb.equal b1 b2);
  (* Pin the frozen pre-image width: 32 (parent) + 32 (sub-DAG) + 8 (LE number)
     + 32 (extra) = 104 bytes. This fails loudly if a section is dropped. *)
  Alcotest.(check int) "pre-image is the frozen 104-byte layout" 104
    (String.length (Cb.preimage b1));
  let b_parent = Cb.create ~parent_hash:(Cb.digest b1) ~sub_dag:sd ~number:one in
  Alcotest.(check bool) "a different parent gives a different digest" false
    (Cb.equal b1 b_parent);
  let b_number = Cb.create ~parent_hash:Cb.genesis_parent ~sub_dag:sd ~number:two in
  Alcotest.(check bool) "a different number gives a different digest" false
    (Cb.equal b1 b_number);
  (* The sub-DAG is part of the pre-image: a distinct committed sub-DAG at the
     same parent and number must digest apart. This is what pins the
     Sub_dag.digest section of the layout. *)
  let b_subdag = Cb.create ~parent_hash:Cb.genesis_parent ~sub_dag:sd2 ~number:one in
  Alcotest.(check bool) "a different sub-DAG gives a different digest" false
    (Cb.equal b1 b_subdag)

(* Every honest node derives the same chain on the prefix they both committed —
   execution agreement follows from consensus agreement. *)
let test_execution_agreement () =
  let sim, committee = run 4 in
  let hexes id =
    List.map (fun b -> Digests.Output_digest.to_hex (Cb.digest b)) (Sim.executed sim id)
  in
  let logs = List.map hexes (ids committee) in
  let common = List.fold_left (fun m l -> min m (List.length l)) max_int logs in
  Alcotest.(check bool) "every node committed at least one block" true (common > 0);
  let prefix l = List.filteri (fun i _ -> i < common) l in
  let reference = prefix (get (List.nth_opt logs 0)) in
  List.iteri
    (fun i l ->
      Alcotest.(check (list string))
        (Printf.sprintf "node %d chain-prefix matches node 0" i)
        reference (prefix l))
    logs

(* The exposed tip is the last block of the derived chain. *)
let test_execution_tip () =
  let sim, committee = run 4 in
  let self = node0 committee in
  let chain = Sim.executed sim self in
  (* Guard against a vacuous [None = None] pass: the chain must be non-empty for
     the tip equality to have teeth. *)
  Alcotest.(check bool) "chain is non-empty" true (chain <> []);
  let last = List.nth_opt (List.rev chain) 0 in
  Alcotest.(check bool) "execution_tip is the last block of the chain" true
    (Option.equal Cb.equal (Sim.execution_tip sim self) last)

(* A node outside the committee has committed nothing, so its chain is empty. *)
let test_non_member () =
  let sim, _committee = run 4 in
  let outsider =
    Authority_id.of_public_key
      (Tn_crypto.Secret_key.public_key (Tn_crypto.Secret_key.derive 999L))
  in
  Alcotest.(check int) "a non-member has an empty chain" 0
    (List.length (Sim.executed sim outsider));
  Alcotest.(check bool) "a non-member has no tip" true
    (Option.is_none (Sim.execution_tip sim outsider))

let () =
  Alcotest.run "execution"
    [
      ( "noop engine",
        [
          Alcotest.test_case "genesis engine is empty" `Quick test_genesis_engine;
          Alcotest.test_case "first block is number one off the anchor" `Quick
            test_first_block;
          Alcotest.test_case "chain links block to block" `Quick test_chain_links;
          Alcotest.test_case "digest is deterministic and sensitive" `Quick
            test_digest_deterministic;
          Alcotest.test_case "honest nodes agree on the chain" `Quick
            test_execution_agreement;
          Alcotest.test_case "tip is the chain head" `Quick test_execution_tip;
          Alcotest.test_case "non-member chain is empty" `Quick test_non_member;
        ] );
    ]
