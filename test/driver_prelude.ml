(* Chunk-38 stage 7: the ONE copy of the driver-layer test fixtures.

   The seed-42 four-authority run is the golden run the chunk-38 central
   property is stated over, and until this stage its fixtures were hand-copied
   between test_driver_sim.ml and test_driver_resume.ml (and, in part, three
   other driver test files). Two copies of the helpers the differential's two
   sides share would let the central property fail for reasons that are not
   the property - a drifted [spec_of] moves one side's genesis, a drifted
   [mk_addr] moves one side's basefee sink - so the helpers live here, once,
   and both files open this module. No .mli: it is test scaffolding, and
   test/dune's default [(modules :standard)] compiles it into every listed
   executable.

   Everything below is the verbatim shared block of the two files it was
   lifted from; the single addition is [zip], at the end. Where the two
   sources disagreed on a constant (the genesis sentinel string) exactly one
   value survives, stated at its definition. *)

open Tn_types
open Tn_vertex
open Tn_consensus
open Tn_sim
module Bf = Block_fixtures
module Cb = Tn_execution.Consensus_block
module Consensus_store = Tn_execution.Consensus_store
module Nonempty = Tn_std.Nonempty
module Output = Tn_batch.Output
module Driver = Tn_driver.Driver
module Checkpoint = Tn_driver.Checkpoint
module Subscriber = Tn_driver.Subscriber
module Outcome = Tn_driver.Outcome
module Batch_store = Tn_driver.Batch_store
module Chain_spec = Tn_driver.Chain_spec
module Epoch_duration = Tn_driver.Chain_spec.Epoch_duration
module Address_book = Tn_driver.Address_book
module Engine = Tn_engine.Engine
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
   chain-configs/testnet/committee.yaml: four DISTINCT registered seats, so a
   body beneficiaried or a leader credited at the wrong seat is visible
   (L4-T7). The distinctness is pinned by test_driver_sim.ml's migration
   tripwire, not merely asserted here in prose. *)
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
   model successive registry committees. The epoch-0 one runs the sim; the
   epoch-1 one is the handoff argument. *)
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
   the sim runs entirely under the epoch-0 committee, so every output it has
   left is STALE once epoch 1 installs - exactly the InvalidPackEpoch class
   [Driver.step] refuses (H8) - and a legal continuation must be minted by
   the epoch-1 committee itself. *)
let epoch1_sub_dag ~r ~at payload =
  let header =
    Header.make ~latest_execution_block:Tn_types.Block_num_hash.zero
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

(* Injection ON: eight bodies per authority, one every 2 s (announcements at
   2..16 s), so payload-carrying outputs exist on BOTH sides of the synthetic
   10 s boundary. The transactions answer varies per authority and per index,
   so every body is pairwise distinct and a wrong-body lookup (P8's mutant
   class) cannot answer the right bytes by collision. *)
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

(* The two source files carried different sentinel strings ("chunk-37
   end-to-end" / "chunk-38 resume"); one prelude means one sentinel, and the
   chunk-38 one survives because the resume harness is the differential this
   module exists to keep honest. Every consumer's assertion is relative to
   [genesis_hash], so the choice moves digests, not verdicts. *)
let genesis_hash = Tn_keccak.digest "chunk-38 resume genesis sentinel"
let basefee_address = mk_addr '\xbe'

(* Genesis at second 0, so the sim's own clock (headers commit at 0..20 s) is
   the chain's clock. The duration decides everything: 28800 s (the testnet
   default) puts the boundary far past the horizon, while the synthetic 10 s
   epoch closes in-sim. *)
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
let short_spec = lazy (spec_of 10)

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

(* Pairwise, or [None] if the lengths differ. A total fold, so an
   element-wise differential never indexes either side and never meets
   [List.iter2]'s length exception. Callers assert the length agreement
   separately, so "the resumed run is shorter" and "element 4 differs" stay
   two distinct red assertions. *)
let zip xs ys =
  let step state x =
    Option.bind state (fun (acc, rest) ->
        match rest with
        | [] -> None
        | y :: tl -> Some ((x, y) :: acc, tl))
  in
  Option.bind
    (List.fold_left step (Some ([], ys)) xs)
    (fun (acc, rest) ->
      match rest with [] -> Some (List.rev acc) | _ :: _ -> None)
