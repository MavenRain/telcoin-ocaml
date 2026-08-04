(* Chunk-37 stage 1: the consensus-chain fold.

   [Tn_execution.Consensus_chain] is the port of the subscriber's eager
   (last_parent, last_number) locals: one seedable accumulator that mints one
   block per committed sub-DAG, shared by [Engine.Noop] and the driver so the
   port has exactly ONE fold. Real committed sub-DAGs come from a short honest
   simulation (the same data a running node feeds the fold); the mixed
   empty/non-empty list is synthetic because the sim cannot yet commit a
   payload-carrying header. *)

open Tn_types
open Tn_vertex
open Tn_consensus
open Tn_sim
module Cb = Tn_execution.Consensus_block
module Chain = Tn_execution.Consensus_chain
module Noop = Tn_execution.Engine.Noop
module Nonempty = Tn_std.Nonempty

(* Totalise an option under a named expectation; Result.fold keeps both arms
   lazy, where Option.fold's ~none is eager. *)
let get what o =
  Result.fold ~ok:Fun.id
    ~error:(fun msg -> Alcotest.fail msg)
    (Option.to_result ~none:what o)

let nth what l n = get what (List.nth_opt l n)

(* Four validators; the fold never reads an execution address, so zero is fine. *)
let committee, sk_of =
  let sks =
    List.init 4 (fun i -> Tn_crypto.Secret_key.derive (Int64.of_int i))
  in
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
      ~error:(fun e ->
        Alcotest.failf "committee: %s" (Committee.error_to_string e))
      (Committee.create ~epoch:Units.Epoch.zero authorities)
  in
  let sk_of id =
    get "secret key"
      (List.find_opt
         (fun sk ->
           Authority_id.equal
             (Authority_id.of_public_key (Tn_crypto.Secret_key.public_key sk))
             id)
         sks)
  in
  (committee, sk_of)

let ids = List.map Authority.id (Committee.authorities committee)
let node0 = nth "node0" ids 0
let dur ms = get "duration" (Units.Duration.of_ms ms)

let run ?(seed = 42L) ?(horizon = 20_000) () =
  let cfg =
    Sim.config ~min_latency:(dur 5) ~max_latency:(dur 50)
      ~horizon:(dur horizon) ~max_steps:1_000_000 ~seed ()
  in
  Sim.create ~committee ~secret_key:sk_of
    ~proposer_config:Proposer.default_config ~sub_dags_per_schedule:100
    ~gc_depth:50 ~config:cfg
  |> Sim.run

(* The first [n] entries of the committed log, with the length guarded so a
   too-short log fails loudly instead of vacuously. *)
let committed_prefix sim n =
  let log = Sim.committed sim node0 in
  Alcotest.(check bool)
    (Printf.sprintf "the sim committed at least %d sub-DAGs" n)
    true
    (List.length log >= n);
  List.filteri (fun i _ -> i < n) log

(* Fold a sub-DAG list through the accumulator, returning the final accumulator
   and the blocks in chain order. *)
let fold_chain chain sds =
  let final, rev_blocks =
    List.fold_left
      (fun (c, acc) sd ->
        let c', b = Chain.append c sd in
        (c', b :: acc))
      (chain, []) sds
  in
  (final, List.rev rev_blocks)

let hexes = List.map (fun b -> Digests.Output_digest.to_hex (Cb.digest b))

(* Walk the chain checking every block links to its predecessor's digest,
   starting from [seed]; returns the digest the NEXT block would link to. *)
let check_links ~seed blocks =
  List.fold_left
    (fun expected b ->
      Alcotest.(check bool) "block links to its predecessor's digest" true
        (Digests.Output_digest.equal (Cb.parent_hash b) expected);
      Cb.digest b)
    seed blocks

(* T1.1: genesis then append yields parent_hash = genesis_parent and number
   one, not zero. *)
let test_genesis_append () =
  Alcotest.(check bool) "genesis accumulator has no tip" true
    (Option.is_none (Chain.tip Chain.genesis));
  Alcotest.(check bool) "genesis parent is the documented anchor" true
    (Digests.Output_digest.equal (Chain.parent Chain.genesis) Cb.genesis_parent);
  Alcotest.(check int) "genesis number is zero" 0
    (Cb.Number.to_int (Chain.number Chain.genesis));
  let sim = run () in
  let sd = nth "first committed sub-DAG" (committed_prefix sim 1) 0 in
  let chain, block = Chain.append Chain.genesis sd in
  Alcotest.(check bool) "first block links to the genesis anchor" true
    (Digests.Output_digest.equal (Cb.parent_hash block) Cb.genesis_parent);
  Alcotest.(check int) "first block number is one, not zero" 1
    (Cb.Number.to_int (Cb.number block));
  Alcotest.(check bool) "the accumulator advanced to the block's digest" true
    (Digests.Output_digest.equal (Chain.parent chain) (Cb.digest block));
  Alcotest.(check bool) "the accumulator's tip is the block just minted" true
    (Option.fold ~none:false ~some:(Cb.equal block) (Chain.tip chain))

(* T1.2: three distinct sub-DAGs give numbers 1,2,3, each block linking to the
   PREVIOUS block's digest. *)
let test_chain_links () =
  let sim = run () in
  let sds = committed_prefix sim 3 in
  let sd_hexes = List.map (fun sd -> Digests.Sub_dag_digest.to_hex (Sub_dag.digest sd)) sds in
  Alcotest.(check int) "the three sub-DAGs are pairwise distinct" 3
    (List.length (List.sort_uniq String.compare sd_hexes));
  let final, blocks = fold_chain Chain.genesis sds in
  Alcotest.(check (list int)) "numbers are 1,2,3" [ 1; 2; 3 ]
    (List.map (fun b -> Cb.Number.to_int (Cb.number b)) blocks);
  let next_parent = check_links ~seed:Cb.genesis_parent blocks in
  Alcotest.(check bool) "the accumulator's parent is the last block's digest"
    true
    (Digests.Output_digest.equal (Chain.parent final) next_parent)

(* T1.3: resume ~parent ~number seeds the fold at that tip, and a resumed chain
   digests apart from a genesis chain everywhere (H5). *)
let test_resume () =
  let sim = run () in
  let sds = committed_prefix sim 3 in
  let sd0 = nth "sd0" sds 0 in
  (* The restart tip: the chain after one genesis-anchored block. *)
  let pre, minted = Chain.append Chain.genesis sd0 in
  let d = Chain.parent pre in
  let n = Chain.number pre in
  let resumed = Chain.resume ~parent:d ~number:n in
  Alcotest.(check bool) "a resumed accumulator has no tip" true
    (Option.is_none (Chain.tip resumed));
  let _, block = Chain.append resumed sd0 in
  Alcotest.(check bool) "the resumed block links to the seeded parent" true
    (Digests.Output_digest.equal (Cb.parent_hash block) d);
  Alcotest.(check int) "the resumed block is numbered succ n"
    (Cb.Number.to_int n + 1)
    (Cb.Number.to_int (Cb.number block));
  Alcotest.(check int) "the seed number is the minted block's, i.e. one" 1
    (Cb.Number.to_int (Cb.number minted));
  (* Same sub-DAG list, different seed: every block digests apart. *)
  let _, resumed_blocks = fold_chain (Chain.resume ~parent:d ~number:n) sds in
  let _, genesis_blocks = fold_chain Chain.genesis sds in
  let genesis_hexes = hexes genesis_blocks in
  Alcotest.(check bool)
    "no resumed block digest appears anywhere in the genesis chain" true
    (List.for_all (fun h -> not (List.mem h genesis_hexes))
       (hexes resumed_blocks))

(* T1.4 (graft G2): Noop re-expressed over the fold is the SAME fold, checked
   differentially over an actual committed log, not a synthetic list. *)
let test_noop_differential () =
  let sim = run () in
  let log = Sim.committed sim node0 in
  Alcotest.(check bool) "the committed log is non-empty" true (log <> []);
  let final, noop_rev =
    List.fold_left
      (fun (eng, acc) sd ->
        Result.fold
          ~ok:(fun (eng', blocks) -> (eng', List.rev_append blocks acc))
          ~error:Tn_execution.Nothing.absurd
          (Noop.execute eng sd))
      (Noop.create (), []) log
  in
  let noop_blocks = List.rev noop_rev in
  let _, chain_blocks = fold_chain Chain.genesis log in
  Alcotest.(check int) "one block per committed sub-DAG" (List.length log)
    (List.length noop_blocks);
  Alcotest.(check (list string)) "Noop's blocks equal Consensus_chain's"
    (hexes chain_blocks) (hexes noop_blocks);
  let last = nth "last block" (List.rev noop_blocks) 0 in
  Alcotest.(check int) "Noop.height is the last block's number"
    (Cb.Number.to_int (Cb.number last))
    (Cb.Number.to_int (Noop.height final))

(* A one-certificate sub-DAG whose single header carries [payload]. *)
let synthetic_sub_dag ~author ~r ~payload =
  let certify header =
    let votes =
      List.map (fun id -> Vote.sign (sk_of id) ~voter:id header) ids
    in
    Result.fold ~ok:Fun.id
      ~error:(fun e ->
        Alcotest.failf "certify: %s" (Certificate.error_to_string e))
      (Certificate.assemble committee header votes)
  in
  let header =
    Header.make ~author ~round:(get "round" (Round.of_int r))
      ~epoch:Units.Epoch.zero
      ~created_at:(get "timestamp" (Units.Timestamp.of_sec 55L))
      ~payload
      ~parents:(List.map Certificate.digest (Certificate.genesis committee))
  in
  Sub_dag.create
    ~sequence:(Nonempty.singleton (certify header))
    ~scores:(Reputation_scores.fresh committee)
    ~previous:None

(* T1.5: EVERY committed sub-DAG consumes exactly one number — an empty output
   no less than a payload-carrying one (H1: the number is consumed at receipt,
   before anything looks at a body) — and the fold is deterministic: the same
   sub-DAG list re-folds to the same digests. *)
let test_mixed_list_numbers () =
  let batch =
    Batch.make ~transactions:[ "\x01" ] ~epoch:Units.Epoch.zero
      ~beneficiary:Units.Address.zero
      ~base_fee_per_gas:(Units.Base_fee.of_int64 7L)
      ~worker_id:Units.Worker_id.zero
  in
  let id0 = nth "id0" ids 0 in
  let id1 = nth "id1" ids 1 in
  let sds =
    [
      synthetic_sub_dag ~author:id0 ~r:1 ~payload:[];
      synthetic_sub_dag ~author:id1 ~r:2
        ~payload:[ (Batch.digest batch, Units.Worker_id.zero) ];
      synthetic_sub_dag ~author:id0 ~r:3 ~payload:[];
    ]
  in
  let sd_hexes =
    List.map (fun sd -> Digests.Sub_dag_digest.to_hex (Sub_dag.digest sd)) sds
  in
  Alcotest.(check int) "the mixed sub-DAGs are pairwise distinct" 3
    (List.length (List.sort_uniq String.compare sd_hexes));
  let _, blocks = fold_chain Chain.genesis sds in
  Alcotest.(check int) "one block per sub-DAG, empty outputs included" 3
    (List.length blocks);
  Alcotest.(check (list int))
    "numbers are dense 1,2,3 across the empty/non-empty mix" [ 1; 2; 3 ]
    (List.map (fun b -> Cb.Number.to_int (Cb.number b)) blocks);
  ignore (check_links ~seed:Cb.genesis_parent blocks);
  (* Body-independence as determinism: nothing outside the sub-DAG list feeds
     the digests, so a re-fold is byte-identical. *)
  let _, blocks2 = fold_chain Chain.genesis sds in
  Alcotest.(check (list string)) "re-folding the same list is byte-identical"
    (hexes blocks) (hexes blocks2)

let drop k l = List.filteri (fun i _ -> i >= k) l

(* T1.6 (chunk-38 stage 7 backfill, S7.6): THE ACCUMULATOR LEMMA. For a
   sub-DAG list split at any j, [resume] seeded from the genesis fold's j-th
   block and folded over the tail produces block-for-block the same blocks as
   the genesis fold of the whole list restricted to the tail. This is the
   algebraic fact [Driver.resume]'s re-mint rests on, pinned here at the
   accumulator itself so a mis-seeded resume (M47's genesis-parent seed) is
   caught one layer below the driver, where it cannot be confused with a
   wrong engine anchor. *)
let test_tail_lemma () =
  let sim = run () in
  let n = 6 in
  let sds = committed_prefix sim n in
  let _, blocks = fold_chain Chain.genesis sds in
  List.iter
    (fun j ->
      let bj = nth "the split block" blocks (j - 1) in
      let resumed = Chain.resume ~parent:(Cb.digest bj) ~number:(Cb.number bj) in
      let _, tail = fold_chain resumed (drop j sds) in
      Alcotest.(check (list string))
        (Printf.sprintf "split at %d: the resumed tail IS the whole fold's tail" j)
        (hexes (drop j blocks)) (hexes tail);
      Alcotest.(check (list int))
        (Printf.sprintf "split at %d: with the same numbers" j)
        (List.map (fun b -> Cb.Number.to_int (Cb.number b)) (drop j blocks))
        (List.map (fun b -> Cb.Number.to_int (Cb.number b)) tail))
    (List.init (n - 1) (fun i -> i + 1))

let () =
  Alcotest.run "consensus_chain"
    [
      ( "the fold",
        [
          Alcotest.test_case "genesis append is block one off the anchor" `Quick
            test_genesis_append;
          Alcotest.test_case "three appends chain-link 1,2,3" `Quick
            test_chain_links;
          Alcotest.test_case "resume seeds the tip and forks the digests" `Quick
            test_resume;
          Alcotest.test_case "Noop is the same fold, over a real log" `Quick
            test_noop_differential;
          Alcotest.test_case "an empty output still consumes a number" `Quick
            test_mixed_list_numbers;
          Alcotest.test_case "a resumed tail is the whole fold's tail" `Quick
            test_tail_lemma;
        ] );
    ]
