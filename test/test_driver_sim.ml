(* Chunk-37 stage 7: end to end - the sim's committed chain through the
   driver, and the in-sim epoch close (D9).

   This file is the ONLY place tn_sim and tn_driver meet: the test suite is
   the wiring layer, so neither library depends on the other (D1). The
   committee is four of the five testnet validator execution addresses
   (chain-configs/testnet/committee.yaml), NOT test_sim.ml's all-zero ones
   (L4-T7), so an author resolved to the wrong seat cannot pass. The sim
   runs with injection ON (one body per authority every 2 s), the driver
   folds one authority's committed log with bodies from
   [Sim.batch_bodies], and the four positive properties are non-vacuity
   (T7.1, the H21 gate), two-chain contiguity (T7.2), deterministic
   cross-authority replay plus attach provenance (T7.3) and fail-stop on
   a missing body (T7.4).

   P7 carries over: every injected transaction is a placeholder the decode
   layer drops before the block, so nothing here reads a fee credit -
   what T7.1 counts is blocks against committed payload entries. P8
   reshapes T7.3: a lookup that answers the WRONG body deterministically
   mis-resolves identically for both authorities, so agreement alone
   cannot catch it; the discriminating assertion checks every attached
   body against the INJECTION side (Sim.batch_bodies) directly, because
   any check routed back through Batch_store's own keying is true for
   every store it can build. T7.5 is D9's in-sim close: the REAL testnet
   duration (28800 s) is unreachable inside the 20 s horizon (G7, pinned
   negatively in T7.1), so the close runs under a synthetic spec
   (genesis 0, 10 s epochs), the post-handoff continuation is a
   hand-minted epoch-1 output (the sim's own remainder is epoch-0 and now
   rightly refused, H8), and the registry-world fixture proof in
   test_driver_epoch.ml stands whatever this file does (risk R1). *)

open Tn_types
open Tn_vertex
open Tn_consensus
open Tn_sim
module Bf = Block_fixtures
module Cb = Tn_execution.Consensus_block
module Nonempty = Tn_std.Nonempty
module Output = Tn_batch.Output
module Driver = Tn_driver.Driver
module Outcome = Tn_driver.Outcome
module Batch_store = Tn_driver.Batch_store
module Chain_spec = Tn_driver.Chain_spec
module Epoch_duration = Tn_driver.Chain_spec.Epoch_duration
module Address_book = Tn_driver.Address_book
module Block_number = Tn_engine.Block_number
module Executed_block = Tn_engine.Executed_block
module Block_header = Tn_evm.Block_header
module U256 = Tn_state.U256

(* Totalise an option under a named expectation; Result.fold keeps both arms
   lazy, where Option.fold's ~none is eager. *)
let get what o =
  Result.fold ~ok:Fun.id
    ~error:(fun msg -> Alcotest.fail msg)
    (Option.to_result ~none:what o)

let nth what l n = get what (List.nth_opt l n)
let last what l = nth what l (List.length l - 1)
let dur ms = get "duration" (Units.Duration.of_ms ms)
let mk_addr c = get "address" (Units.Address.of_bytes (String.make 20 c))
let take k l = List.filteri (fun i _ -> i < k) l

(* Whether [needle] occurs in [haystack], for error-string assertions. *)
let mentions needle haystack =
  let n = String.length needle in
  List.exists
    (fun start ->
      String.equal needle
        (String.of_seq (Seq.take n (Seq.drop start (String.to_seq haystack)))))
    (List.init (Stdlib.max 0 (String.length haystack - n + 1)) Fun.id)

(* Four of the five testnet validator execution addresses, verbatim from
   chain-configs/testnet/committee.yaml (as in test_driver_epoch.ml): four
   DISTINCT registered seats, so a body beneficiaried or a leader credited
   at the wrong seat is visible (L4-T7). *)
let validator_addresses =
  List.map
    (fun h -> get "validator address" (Units.Address.of_bytes (Bf.hex h)))
    [
      "0033a370616805b1fd275b7ffab83fc41d665ccb";
      "89dab9f6fdc569c1bcdbd6493f25b7040b55dc79";
      "3518b301b86ceb53b5a3dff62e55cd43ef59d024";
      "efaacf04b92298a88200aa50aa6bb7bfce587b17";
    ]

(* Two committees over the SAME validator seats and different protocol keys
   model successive registry committees, as in test_driver_epoch.ml. The
   epoch-0 one runs the sim; the epoch-1 one is T7.5's handoff argument. *)
let build_committee ~seed ~epoch =
  let sks =
    List.mapi
      (fun i _ -> Tn_crypto.Secret_key.derive (Int64.of_int (seed + i)))
      validator_addresses
  in
  let authorities =
    List.mapi
      (fun i sk ->
        Authority.make
          ~protocol_key:(Tn_crypto.Secret_key.public_key sk)
          ~execution_address:(nth "validator address" validator_addresses i))
      sks
  in
  let cmt =
    Result.fold ~ok:Fun.id
      ~error:(fun e ->
        Alcotest.failf "committee: %s" (Committee.error_to_string e))
      (Committee.create ~epoch authorities)
  in
  (cmt, sks)

let committee, sks = build_committee ~seed:0 ~epoch:Units.Epoch.zero

let committee_next, sks_next =
  build_committee ~seed:600 ~epoch:(Units.Epoch.succ Units.Epoch.zero)

let sk_of id =
  get "secret key"
    (List.find_opt
       (fun sk ->
         Authority_id.equal
           (Authority_id.of_public_key (Tn_crypto.Secret_key.public_key sk))
           id)
       sks)

(* Both epochs' authors resolve through ONE monotone book (P10). *)
let address_of =
  Address_book.find
    (Address_book.union
       (Address_book.of_committee committee)
       (Address_book.of_committee committee_next))

(* ---------- T7.5's epoch-1 continuation machinery ---------- *)

let ts n = get "timestamp" (Units.Timestamp.of_sec n)
let round n = get "round" (Round.of_int n)
let epoch1 = Units.Epoch.succ Units.Epoch.zero

let sk_next_of id =
  get "epoch-1 secret key"
    (List.find_opt
       (fun sk ->
         Authority_id.equal
           (Authority_id.of_public_key (Tn_crypto.Secret_key.public_key sk))
           id)
       sks_next)

let certify_next header =
  let ids_next = List.map Authority.id (Committee.authorities committee_next) in
  let votes =
    List.map (fun id -> Vote.sign (sk_next_of id) ~voter:id header) ids_next
  in
  Result.fold ~ok:Fun.id
    ~error:(fun e ->
      Alcotest.failf "certify: %s" (Certificate.error_to_string e))
    (Certificate.assemble committee_next header votes)

(* One single-header epoch-1 sub-DAG committed at [at]. Hand-minted because
   the sim ran entirely under the epoch-0 committee, so every output it has
   left is STALE once epoch 1 installs - exactly the InvalidPackEpoch class
   [Driver.step] refuses (H8) - and a legal continuation must be minted by
   the epoch-1 committee itself. *)
let epoch1_sub_dag ~r ~at payload =
  let header =
    Header.make
      ~author:
        (nth "epoch-1 seat"
           (List.map Authority.id (Committee.authorities committee_next))
           0)
      ~round:(round r) ~epoch:epoch1 ~created_at:(ts at) ~payload
      ~parents:(List.map Certificate.digest (Certificate.genesis committee_next))
  in
  Sub_dag.create
    ~sequence:(get "certificates" (Nonempty.of_list [ certify_next header ]))
    ~scores:(Reputation_scores.fresh committee_next)
    ~previous:None

(* A fresh epoch-1 body: the continuation must not reuse a sim body, whose
   epoch field is 0. *)
let body_next =
  Batch.make ~transactions:[ "epoch-1/0" ] ~epoch:epoch1
    ~beneficiary:(nth "validator address" validator_addresses 0)
    ~base_fee_per_gas:Units.Base_fee.min_protocol
    ~worker_id:Units.Worker_id.zero

(* Injection ON: eight bodies per authority, one every 2 s (announcements at
   2..16 s), so payload-carrying outputs exist on BOTH sides of T7.5's
   synthetic 10 s boundary. The transactions answer varies per authority and
   per index, so every body is pairwise distinct and a wrong-body lookup
   (P8's mutant class) cannot answer the right bytes by collision. *)
let plan =
  Sim.batch_plan ~per_authority:8 ~period:(dur 2_000)
    ~worker_id:Units.Worker_id.zero ~epoch:Units.Epoch.zero
    ~base_fee_per_gas:Units.Base_fee.min_protocol
    ~transactions:(fun id k -> [ Authority_id.to_hex id ^ "/" ^ string_of_int k ])
    ()

(* One deterministic run, shared by every case (the sim is immutable). *)
let sim =
  lazy
    (let cfg =
       Sim.config ~min_latency:(dur 5) ~max_latency:(dur 50)
         ~horizon:(dur 20_000) ~max_steps:1_000_000 ~seed:42L ~batches:plan ()
     in
     Sim.run
       (Sim.create ~committee ~secret_key:sk_of
          ~proposer_config:Proposer.default_config ~sub_dags_per_schedule:100
          ~gc_depth:50 ~config:cfg))

let ids = List.map Authority.id (Committee.authorities committee)
let self = nth "authority 0" ids 0
let committed_self () = Sim.committed (Lazy.force sim) self
let store () = Batch_store.of_bodies (Sim.batch_bodies (Lazy.force sim))

(* ---------- the specs the drivers cold-start from ---------- *)

let u256_int n = get "u256" (U256.of_int n)
let u256_hex s = get "word" (U256.of_hex s)

let registry_entry =
  Tn_state.Genesis_account.make ~nonce:Tn_state.Nonce.zero
    ~balance:
      (get "balance"
         (U256.of_hex
            (String.make (64 - String.length Registry_genesis.balance_hex) '0'
           ^ Registry_genesis.balance_hex)))
    ~code:(Some (Bf.hex Registry_genesis.code_hex))
    ~storage:
      (List.map
         (fun (s, v) -> (u256_hex s, u256_hex v))
         Registry_genesis.storage_hex)

let genesis_hash = Tn_keccak.digest "chunk-37 end-to-end genesis sentinel"
let basefee_address = mk_addr '\xbe'

(* Genesis at second 0, so the sim's own clock (headers commit at 0..20 s)
   is the chain's clock. The duration decides everything: 28800 s (the
   testnet default) puts the boundary far past the horizon - H25/L7-F19's
   unreachability, pinned negatively in T7.1 (G7) - while T7.5's synthetic
   10 s epoch closes in-sim. *)
let spec_of duration_s =
  Result.fold ~ok:Fun.id
    ~error:(fun e ->
      Alcotest.failf "chain spec: %s" (Chain_spec.error_to_string e))
    (Chain_spec.create ~chain_id:(u256_int 2017) ~basefee_address ~genesis_hash
       ~genesis_base_fee:(u256_int 7) ~genesis_gas_limit:30_000_000
       ~genesis_timestamp:Units.Timestamp.zero
       ~epoch_duration:(get "epoch duration" (Epoch_duration.of_secs duration_s))
       ~registry:registry_entry ~extra_alloc:[] ())

let wide_spec = lazy (spec_of 28800)

let step_ok what d sd ~bodies =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "%s: %s" what (Outcome.error_to_string e))
    (Driver.step d sd ~bodies ~address_of)

let fold_ok what d sds ~bodies =
  match Driver.fold d sds ~bodies ~address_of with
  | Outcome.Advance { driver; advances } -> (driver, advances)
  | Outcome.Sealed { driver = _; advances = _; rest } ->
      Alcotest.failf "%s: sealed with %d outputs unconsumed" what
        (List.length rest)
  | Outcome.Halted { advances = _; error } ->
      Alcotest.failf "%s: %s" what (Outcome.error_to_string error)

(* Every committed payload pair of a sub-DAG, headers in commit order. *)
let flat_payload sd =
  List.concat_map Header.payload (Nonempty.to_list (Sub_dag.headers sd))

let all_blocks advances = List.concat_map (fun a -> a.Outcome.blocks) advances

(* T7.1, the anti-H21 gate: the injected traffic EXECUTED - the total block
   count over all advances is positive and equals the flattened payload
   count over the committed headers (one block per flattened batch,
   engine.mli:25-33). G7's honest negative pin rides along: under the
   testnet duration nothing inside the 20 s horizon closes the epoch. *)
let t71 () =
  let _, advances =
    fold_ok "fold" (Driver.create (Lazy.force wide_spec) ~committee)
      (committed_self ()) ~bodies:(store ())
  in
  let blocks = all_blocks advances in
  Alcotest.(check bool) "the injected traffic executed: some block exists" true
    (List.length blocks > 0);
  Alcotest.(check int) "one execution block per flattened committed batch"
    (List.length (List.concat_map flat_payload (committed_self ())))
    (List.length blocks);
  Alcotest.(check bool)
    "G7: the 28800 s testnet duration never closes inside the horizon" true
    (List.for_all (fun a -> not a.Outcome.closes_epoch) advances)

(* T7.2: consensus numbers over the fold are 1..M with M = Sim.commit_count,
   execution numbers are 1..N contiguous, and every execution block's parent
   hash is its predecessor's hash - across output boundaries, from the
   spec's genesis anchor on. *)
let t72 () =
  let m = Sim.commit_count (Lazy.force sim) self in
  let _, advances =
    fold_ok "fold" (Driver.create (Lazy.force wide_spec) ~committee)
      (committed_self ()) ~bodies:(store ())
  in
  Alcotest.(check (list int)) "consensus numbers are 1..M contiguous"
    (List.init m (fun i -> i + 1))
    (List.map (fun a -> Cb.Number.to_int (Cb.number a.Outcome.consensus)) advances);
  let blocks = all_blocks advances in
  Alcotest.(check (list int)) "execution numbers are 1..N contiguous"
    (List.init (List.length blocks) (fun i -> i + 1))
    (List.map (fun b -> Block_number.to_int (Executed_block.number b)) blocks);
  let (_ : Tn_keccak.t) =
    List.fold_left
      (fun expected b ->
        Alcotest.(check string) "block links to its predecessor's hash"
          (Tn_keccak.to_hex expected)
          (Tn_keccak.to_hex (Block_header.parent_hash (Executed_block.header b)));
        Executed_block.hash b)
      genesis_hash blocks
  in
  ()

(* T7.3 (as reshaped by P8): two honest authorities' drivers, over the
   common prefix the agreement oracle reports, produce identical execution
   block hashes. Honest scope for that half: the fold is a PURE function of
   the committed log and the oracle certifies the two logs digest-identical,
   so it is a determinism pin (hidden state or ambient randomness in the
   driver would break it), not an independent agreement proof. The
   discriminating half checks every attached body against an index built
   directly from the INJECTION side (Sim.batch_bodies), never through
   Batch_store: comparing [Output.batch_digests] with digests re-derived
   from the attached bodies would be true for EVERY store Batch_store can
   build (add keys by Batch.digest, so digest (find s d) = d on every hit),
   while the injection-side bytes expose a lookup that answers a
   wrong-but-registered body - which mis-resolves identically for both
   authorities and leaves the agreement half green. *)
let t73 () =
  let s = Lazy.force sim in
  let a = nth "authority 0" ids 0 in
  let b = nth "authority 1" ids 1 in
  let k =
    match Sim.agreement s with
    | Sim.Agree k -> k
    | Sim.Diverge { index; _ } ->
        Alcotest.failf "honest sim diverged at commit index %d" index
  in
  Alcotest.(check bool) "the oracle reports a non-empty common prefix" true
    (k > 0);
  let drive id =
    let _, advances =
      fold_ok "fold" (Driver.create (Lazy.force wide_spec) ~committee)
        (take k (Sim.committed s id)) ~bodies:(store ())
    in
    advances
  in
  let advances_a = drive a in
  let hashes advances =
    List.map (fun blk -> Tn_keccak.to_hex (Executed_block.hash blk))
      (all_blocks advances)
  in
  let ha = hashes advances_a in
  Alcotest.(check bool) "the common prefix carries some execution block" true
    (ha <> []);
  Alcotest.(check (list string))
    "digest-identical logs replay to identical block hashes" ha
    (hashes (drive b));
  let injected = Sim.batch_bodies (Lazy.force sim) in
  let injected_body d =
    get "an injected body for a committed digest"
      (List.find_opt
         (fun b ->
           String.equal
             (Digests.Batch_digest.to_hex (Batch.digest b))
             (Digests.Batch_digest.to_hex d))
         injected)
  in
  List.iter
    (fun adv ->
      Alcotest.(check (list (list string)))
        "every attached body carries the injection-side bytes (P8)"
        (List.map
           (fun d -> Batch.transactions (injected_body d))
           (Output.batch_digests adv.Outcome.output))
        (List.map Batch.transactions
           (List.concat_map snd (Output.certified adv.Outcome.output))))
    advances_a

(* T7.4: missing bodies are fatal, not skipped - folding the same committed
   log over an EMPTY store halts at the first payload-carrying output with
   the first unresolvable digest named, and the prefix is exactly the
   leading run of empty outputs (L2-T2's silent-skip inversion, made red). *)
let t74 () =
  let committed = committed_self () in
  let leading_empty =
    fst
      (List.fold_left
         (fun (n, stopped) sd ->
           if stopped || flat_payload sd <> [] then (n, true) else (n + 1, false))
         (0, false) committed)
  in
  let first_digest =
    get "a payload-carrying output"
      (List.find_map
         (fun sd -> Option.map fst (List.nth_opt (flat_payload sd) 0))
         committed)
  in
  match
    Driver.fold (Driver.create (Lazy.force wide_spec) ~committee) committed
      ~bodies:Batch_store.empty ~address_of
  with
  | Outcome.Advance { driver = _; advances } ->
      Alcotest.failf
        "fold returned Ok with %d advances despite the empty body store"
        (List.length advances)
  | Outcome.Sealed { driver = _; advances = _; rest = _ } ->
      Alcotest.fail "fold sealed despite the empty body store"
  | Outcome.Halted { advances; error } ->
      Alcotest.(check int)
        "the prefix stops at the first payload-carrying output" leading_empty
        (List.length advances);
      Alcotest.(check bool) "the error names the first unresolvable digest"
        true
        (mentions (Digests.Batch_digest.to_hex first_digest)
           (Outcome.error_to_string error))

(* T7.5, D9's in-sim close: under the synthetic spec (genesis 0, 10 s
   epochs) some advance closes the epoch inside the 20 s horizon, the next
   boundary is the closing output's commit time + 10 (H9), the handoff to
   the epoch-1 committee succeeds, and the following outputs extend the SAME
   execution chain - the first post-handoff block builds on the closing
   block's hash at closing + 1 while the consensus chain keeps counting. *)
let t75 () =
  let bodies = store () in
  let rec to_close d = function
    | [] ->
        Alcotest.fail
          "no output closed the 10 s epoch inside the 20 s horizon (D9)"
    | sd :: rest ->
        let d', a = step_ok "pre-close step" d sd ~bodies in
        if a.Outcome.closes_epoch then (d', a, rest) else to_close d' rest
  in
  let d, closing, rest =
    to_close (Driver.create (spec_of 10) ~committee) (committed_self ())
  in
  let closing_block = last "closing block" closing.Outcome.blocks in
  let closed = Units.Timestamp.to_sec (Output.committed_at closing.Outcome.output) in
  Alcotest.(check (option int64)) "closed_at is the closing commit time"
    (Some closed)
    (Option.map Units.Timestamp.to_sec (Driver.closed_at d));
  Alcotest.(check (option int64)) "next_boundary = closed_at + 10 (H9)"
    (Some (Int64.add closed 10L))
    (Option.map Units.Timestamp.to_sec (Driver.next_boundary d));
  let d1 =
    Result.fold ~ok:Fun.id
      ~error:(fun e ->
        Alcotest.failf "handoff: %s" (Driver.handoff_error_to_string e))
      (Driver.begin_epoch d ~committee:committee_next)
  in
  match rest with
  | [] -> Alcotest.fail "no committed output left after the in-sim close"
  | stale :: _ ->
      (* The sim's own remaining outputs are epoch-0 ones: after the
         handoff they are exactly the staleness H8 refuses, so the first
         doubles as the InvalidPackEpoch probe on REAL sim data. *)
      Alcotest.(check string)
        "the sim's stale epoch-0 output is refused after the handoff (H8)"
        "output refused: leader epoch 0 does not match the installed \
         committee epoch 1"
        (Result.fold
           ~ok:(fun _ -> "ok")
           ~error:Outcome.error_to_string
           (Driver.step d1 stale ~bodies ~address_of));
      let sd_next =
        epoch1_sub_dag ~r:1 ~at:(Int64.add closed 1L)
          [ (Batch.digest body_next, Units.Worker_id.zero) ]
      in
      let _, adv =
        step_ok "hand-minted epoch-1 output" d1 sd_next
          ~bodies:
            (Batch_store.of_bodies
               (body_next :: Sim.batch_bodies (Lazy.force sim)))
      in
      Alcotest.(check int) "the consensus chain kept counting (H8)"
        (Cb.Number.to_int (Cb.number closing.Outcome.consensus) + 1)
        (Cb.Number.to_int (Cb.number adv.Outcome.consensus));
      let b1 = nth "first epoch-1 block" adv.Outcome.blocks 0 in
      Alcotest.(check string)
        "the first post-handoff block builds on the closing block's hash"
        (Tn_keccak.to_hex (Executed_block.hash closing_block))
        (Tn_keccak.to_hex (Block_header.parent_hash (Executed_block.header b1)));
      Alcotest.(check int) "and its number is closing + 1"
        (Block_number.to_int (Executed_block.number closing_block) + 1)
        (Block_number.to_int (Executed_block.number b1))

let () =
  Alcotest.run "driver sim"
    [
      ( "end to end",
        [
          Alcotest.test_case "the injected traffic executes (non-vacuity)"
            `Quick t71;
          Alcotest.test_case "both chains are contiguous through the driver"
            `Quick t72;
          Alcotest.test_case "two authorities execute the same chain" `Quick
            t73;
          Alcotest.test_case "a missing body is fatal, not skipped" `Quick t74;
          Alcotest.test_case "the synthetic 10 s epoch closes in-sim" `Quick
            t75;
        ] );
    ]
