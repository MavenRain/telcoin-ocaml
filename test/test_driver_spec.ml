(* Chunk-37 stage 2: the driver's leaf modules.

   [Batch_store] is the batch-body seam (key derived, non-consuming, deduped);
   [Chain_spec] is the one-constructor genesis configuration whose world
   cannot lack the registry or the EIP-4788/2935 predeploys, exercised here on
   the CITED testnet scalars; [Address_book] is the [address_of] contract as a
   value. The Continuity classifier was dropped from the library (design patch
   P1) - a driver that mints its own numbers always classifies Next, so its
   other arms would be dead public surface - and T2.4 is void with it. T2.5 is
   reshaped by patch P9: the illegal duration is unrepresentable
   ([Epoch_duration.of_secs] answers [None]), not refused at [create]. *)

open Tn_types
module Bf = Block_fixtures
module Batch_store = Tn_driver.Batch_store
module Chain_spec = Tn_driver.Chain_spec
module Epoch_duration = Tn_driver.Chain_spec.Epoch_duration
module Address_book = Tn_driver.Address_book
module Anchor = Tn_engine.Anchor
module Block_number = Tn_engine.Block_number
module System_contracts = Tn_evm.System_contracts
module U256 = Tn_state.U256
module World = Tn_state.World_state

(* Totalise an option under a named expectation; Result.fold keeps both arms
   lazy, where Option.fold's ~none is eager. *)
let get what o =
  Result.fold ~ok:Fun.id
    ~error:(fun msg -> Alcotest.fail msg)
    (Option.to_result ~none:what o)

let addr c = get "address" (Units.Address.of_bytes (String.make 20 c))
let ts n = get "timestamp" (Units.Timestamp.of_sec n)
let u256_int n = get "u256" (U256.of_int n)
let fee n = Units.Base_fee.of_int64 (Int64.of_int n)
let w0 = Units.Worker_id.zero

let u256_short s =
  get "word" (U256.of_hex (String.make (64 - String.length s) '0' ^ s))

let u256_hex s = get "word" (U256.of_hex s)

let batch_t =
  Alcotest.testable
    (fun fmt b ->
      Format.pp_print_string fmt (Digests.Batch_digest.to_hex (Batch.digest b)))
    Batch.equal

let address_t =
  Alcotest.testable
    (fun fmt a ->
      Format.pp_print_string fmt (String.escaped (Units.Address.to_bytes a)))
    Units.Address.equal

(* Two bodies with distinct transaction lists, so their digests differ. The
   transaction bytes are placeholders (the engine records them as skipped);
   what the store underwrites is threading, not execution (risk R4). *)
let body_a =
  Batch.make ~transactions:[ "\x01" ] ~epoch:Units.Epoch.zero
    ~beneficiary:(addr 'a') ~base_fee_per_gas:(fee 7) ~worker_id:w0

let body_b =
  Batch.make
    ~transactions:[ "\x02"; "\x03" ]
    ~epoch:Units.Epoch.zero ~beneficiary:(addr 'b') ~base_fee_per_gas:(fee 7)
    ~worker_id:w0

(* ---------- T2.1-T2.3: the batch store ---------- *)

let test_store_roundtrip () =
  let store = Batch_store.of_bodies [ body_a ] in
  Alcotest.(check (option batch_t))
    "the added body answers by its own derived digest" (Some body_a)
    (Batch_store.find store (Batch.digest body_a));
  Alcotest.(check (option batch_t)) "an unrelated digest answers None" None
    (Batch_store.find store (Batch.digest body_b))

let test_store_rereads () =
  let store = Batch_store.of_bodies [ body_a ] in
  let digest = Batch.digest body_a in
  Alcotest.(check (option batch_t)) "first find answers the body" (Some body_a)
    (Batch_store.find store digest);
  Alcotest.(check (option batch_t))
    "second find of the same digest still answers (non-consuming)"
    (Some body_a)
    (Batch_store.find store digest)

let test_store_dedups () =
  let copy =
    Batch.make ~transactions:[ "\x01" ] ~epoch:Units.Epoch.zero
      ~beneficiary:(addr 'a') ~base_fee_per_gas:(fee 7) ~worker_id:w0
  in
  let store = Batch_store.add (Batch_store.add Batch_store.empty body_a) copy in
  Alcotest.(check int) "two adds of an equal body leave cardinal 1" 1
    (Batch_store.cardinal store);
  Alcotest.(check (option batch_t)) "and the body still answers" (Some body_a)
    (Batch_store.find store (Batch.digest body_a))

(* ---------- the cited testnet spec ---------- *)

let registry_entry =
  Tn_state.Genesis_account.make ~nonce:Tn_state.Nonce.zero
    ~balance:(u256_short Registry_genesis.balance_hex)
    ~code:(Some (Bf.hex Registry_genesis.code_hex))
    ~storage:
      (List.map
         (fun (s, v) -> (u256_hex s, u256_hex v))
         Registry_genesis.storage_hex)

let duration_28800 = get "epoch duration" (Epoch_duration.of_secs 28800)

(* chain id 2017 (chain-configs/testnet/genesis.yaml:3), base fee 0x7 (:264),
   gas limit 0x1c9c380 = 30,000,000 (:23), genesis timestamp 0x69fceea7 (:21),
   epoch duration 28800 s (tn-reth/src/test_utils.rs:836). The genesis hash is
   the caller's unverifiable claim, so any keccak stands in. *)
let testnet_spec () =
  get "chain spec"
    (Result.to_option
       (Chain_spec.create ~chain_id:(u256_int 2017)
          ~basefee_address:System_contracts.governance_safe_address
          ~genesis_hash:(Tn_keccak.digest "chunk-37 stand-in genesis hash")
          ~genesis_base_fee:(u256_int 7) ~genesis_gas_limit:30_000_000
          ~genesis_timestamp:(ts 0x69fceea7L) ~epoch_duration:duration_28800
          ~registry:registry_entry ~extra_alloc:[] ()))

(* ---------- T2.5 (as reshaped by P9): the duration guard ---------- *)

let test_duration_guard () =
  Alcotest.(check bool) "of_secs 0 is None" true
    (Option.is_none (Epoch_duration.of_secs 0));
  Alcotest.(check bool) "of_secs (-1) is None" true
    (Option.is_none (Epoch_duration.of_secs (-1)));
  Alcotest.(check (option int)) "of_secs 28800 holds 28800" (Some 28800)
    (Option.map Epoch_duration.to_secs (Epoch_duration.of_secs 28800));
  Alcotest.(check bool) "create with a positive duration is Ok" true
    (Result.is_ok
       (Chain_spec.create ~chain_id:(u256_int 2017)
          ~basefee_address:System_contracts.governance_safe_address
          ~genesis_hash:(Tn_keccak.digest "chunk-37 stand-in genesis hash")
          ~genesis_base_fee:(u256_int 7) ~genesis_gas_limit:30_000_000
          ~genesis_timestamp:(ts 0x69fceea7L) ~epoch_duration:duration_28800
          ~registry:registry_entry ~extra_alloc:[] ()))

(* ---------- T2.6: the world cannot lack the predeploys ---------- *)

let test_world_predeployed () =
  let world = Chain_spec.world (testnet_spec ()) in
  List.iter
    (fun (name, address) ->
      Alcotest.(check bool) (name ^ " holds code") true
        (System_contracts.is_deployed world address))
    [
      ("consensus registry", System_contracts.consensus_registry_address);
      ("EIP-4788 beacon roots", System_contracts.beacon_roots_address);
      ("EIP-2935 history storage", System_contracts.history_storage_address);
    ];
  List.iter
    (fun deployer ->
      Alcotest.(check int) "deployer EOA at nonce 1" 1
        (Tn_state.Nonce.to_int (World.nonce world deployer)))
    System_contracts.deployer_accounts

(* ---------- T2.7: the genesis anchor ---------- *)

let test_anchor () =
  let anchor = Chain_spec.anchor (testnet_spec ()) in
  Alcotest.(check bool) "height is Block_number.genesis" true
    (Block_number.equal (Anchor.number anchor) Block_number.genesis);
  Alcotest.(check bool) "base fee is the cited 0x7" true
    (U256.equal (Anchor.base_fee anchor) (u256_int 7));
  Alcotest.(check int) "gas limit is the cited 0x1c9c380" 30_000_000
    (Anchor.gas_limit anchor);
  Alcotest.(check bool) "a genesis anchor has no header" true
    (Option.is_none (Anchor.header anchor))

(* ---------- T2.8: epoch 0's boundary pins genesis ---------- *)

let test_first_boundary () =
  Alcotest.(check int64) "first boundary = genesis timestamp + epoch duration"
    (Int64.add 0x69fceea7L 28800L)
    (Units.Timestamp.to_sec (Chain_spec.first_boundary (testnet_spec ())))

(* ---------- P10: the address book contract ---------- *)

let authority seed address =
  Authority.make
    ~protocol_key:
      (Tn_crypto.Secret_key.public_key (Tn_crypto.Secret_key.derive seed))
    ~execution_address:address

let id_of seed =
  Authority_id.of_public_key
    (Tn_crypto.Secret_key.public_key (Tn_crypto.Secret_key.derive seed))

let committee_of entries =
  get "committee"
    (Result.to_option
       (Committee.create ~epoch:Units.Epoch.zero
          (List.map (fun (seed, a) -> authority seed a) entries)))

(* Distinct execution addresses per seat, so a book pairing an id with the
   WRONG seat's address cannot pass (no constant-valued fixture). *)
let test_book_members () =
  let cmt =
    committee_of [ (101L, addr 'a'); (102L, addr 'b'); (103L, addr 'c') ]
  in
  let book = Address_book.of_committee cmt in
  List.iter
    (fun a ->
      Alcotest.(check (option address_t)) "a member resolves to its own address"
        (Some (Authority.execution_address a))
        (Address_book.find book (Authority.id a)))
    (Committee.authorities cmt);
  Alcotest.(check (option address_t)) "a non-member resolves to None" None
    (Address_book.find book Authority_id.zero)

let test_book_union () =
  let older =
    Address_book.of_committee
      (committee_of [ (201L, addr 'x'); (202L, addr 'y') ])
  in
  let newer =
    Address_book.of_committee
      (committee_of [ (201L, addr 'X'); (203L, addr 'z') ])
  in
  let merged = Address_book.union newer older in
  Alcotest.(check (option address_t))
    "a conflicting id keeps the newer (left) address" (Some (addr 'X'))
    (Address_book.find merged (id_of 201L));
  Alcotest.(check (option address_t)) "a newer-only member survives the union"
    (Some (addr 'z'))
    (Address_book.find merged (id_of 203L));
  Alcotest.(check (option address_t)) "an older-only member survives the union"
    (Some (addr 'y'))
    (Address_book.find merged (id_of 202L))

(* ---------- chunk 42: the fork schedule, end to end through the driver ------ *)

(* [Chain_spec] is the port's genesis authority, so the chunk-42 schedule lands
   there and reaches the pre-block system calls through
   [Chain_spec.engine_config], the engine and the executor without any caller
   in between naming a fork. These two cases are the end-to-end reading of
   that: what a produced block DID, off its world, rather than which value an
   accessor answers (that half is [test_fork_dispatch]).

   One fixture serves both. Four validators, one certified sub-DAG whose single
   batch the decode layer drops, and a chain spec whose epoch boundary (28800 s
   past a genesis at second 0) sits far past the commit at second 1000, so
   nothing here closes the epoch. The produced block is then decided by the
   genesis world and the fork level alone. *)

module Driver = Tn_driver.Driver
module Outcome = Tn_driver.Outcome
module Executed_block = Tn_engine.Executed_block
module Fork_schedule = Tn_evm.Fork_schedule
module Certificate = Tn_vertex.Certificate
module Header = Tn_vertex.Header
module Vote = Tn_vertex.Vote
module Reputation_scores = Tn_consensus.Reputation_scores
module Sub_dag = Tn_consensus.Sub_dag

let fork_seeds = [ 0L; 1L; 2L; 3L ]

(* Distinct execution addresses per seat, for the same reason the address-book
   cases above use them: a fixture whose seats share an address proves less. *)
let fork_committee =
  committee_of
    [
      (0L, addr '\xa0'); (1L, addr '\xa1'); (2L, addr '\xa2'); (3L, addr '\xa3');
    ]

let fork_members = Committee.authorities fork_committee
let fork_ids = List.map Authority.id fork_members

let fork_sk_of id =
  get "secret key"
    (List.find_opt
       (fun sk ->
         Authority_id.equal
           (Authority_id.of_public_key (Tn_crypto.Secret_key.public_key sk))
           id)
       (List.map Tn_crypto.Secret_key.derive fork_seeds))

let fork_address_of id =
  List.find_map
    (fun a ->
      if Authority_id.equal (Authority.id a) id then
        Some (Authority.execution_address a)
      else None)
    fork_members

let fork_certify header =
  Result.fold ~ok:Fun.id
    ~error:(fun e ->
      Alcotest.failf "certify: %s" (Certificate.error_to_string e))
    (Certificate.assemble fork_committee header
       (List.map (fun id -> Vote.sign (fork_sk_of id) ~voter:id header) fork_ids))

(* A batch the decode layer drops, so the block is built and carries no
   transaction: what this fixture varies is the fork level, not what runs. *)
let fork_batch =
  Batch.make ~transactions:[ "\xde\xad\xbe\xef" ] ~epoch:Units.Epoch.zero
    ~beneficiary:Units.Address.zero ~base_fee_per_gas:(fee 0) ~worker_id:w0

let fork_sub_dag =
  let header =
    Header.make ~latest_execution_block:Tn_types.Block_num_hash.zero
      ~author:(get "leader id" (List.nth_opt fork_ids 0))
      ~round:(get "round" (Round.of_int 1))
      ~epoch:Units.Epoch.zero ~created_at:(ts 1_000L)
      ~payload:[ (Batch.digest fork_batch, w0) ]
      ~parents:(List.map Certificate.digest (Certificate.genesis fork_committee))
  in
  Sub_dag.create
    ~sequence:(Tn_std.Nonempty.singleton (fork_certify header))
    ~scores:(Reputation_scores.fresh fork_committee)
    ~previous:None

(* A codeless registry entry: neither case reads the registry, and storage on a
   codeless account is what [of_genesis_alloc] refuses, so it carries none. The
   two system contracts still arrive, because {!Chain_spec.create} predeploys
   them whatever the alloc says. *)
let fork_registry =
  Tn_state.Genesis_account.make ~nonce:Tn_state.Nonce.zero ~balance:U256.zero
    ~code:None ~storage:[]

let fork_spec ?fork_schedule () =
  get "chain spec"
    (Result.to_option
       (Chain_spec.create ~chain_id:(u256_int 2017)
          ~basefee_address:System_contracts.governance_safe_address
          ~genesis_hash:(Tn_keccak.digest "chunk-42 golden genesis sentinel")
          ~genesis_base_fee:(u256_int 7) ~genesis_gas_limit:30_000_000
          ~genesis_timestamp:(ts 0L) ~epoch_duration:duration_28800
          ?fork_schedule ~registry:fork_registry ~extra_alloc:[] ()))

let fork_block ?fork_schedule () =
  let _, advance =
    Result.fold ~ok:Fun.id
      ~error:(fun e -> Alcotest.failf "step: %s" (Outcome.error_to_string e))
      (Driver.step
         (Driver.create (fork_spec ?fork_schedule ()) ~committee:fork_committee)
         fork_sub_dag
         ~bodies:(Batch_store.of_bodies [ fork_batch ])
         ~address_of:fork_address_of)
  in
  Alcotest.(check int) "the output builds exactly one block" 1
    (List.length advance.Outcome.blocks);
  get "produced block" (List.nth_opt advance.Outcome.blocks 0)

(* What the two pre-block system calls left behind, which is the end-to-end
   reading of the fork level: EIP-4788 writes a PAIR of slots and EIP-2935 one,
   so a block that ran both shows [(2, 1)] and one that ran neither [(0, 0)]. *)
let fork_marks block =
  let world = Executed_block.world block in
  ( Bf.slots_set world System_contracts.beacon_roots_address,
    Bf.slots_set world System_contracts.history_storage_address )

let marks_t = Alcotest.(pair int int)
let block_hex block = Tn_keccak.to_hex (Executed_block.hash block)

(* The pinned golden. It was computed by this same fixture on the committed
   PRE-chunk-42 tree (d2da143), where no fork schedule existed, so it is a real
   before-value and not this file's own output read back:
   [telcoin-ocaml-chunk42-harness/baseline/golden/golden.ml] is the probe. Any
   chunk-42 edit that moved a byte of the default path moves this hash. *)
let fork_golden_hash =
  "0faeb53ae2bd48837fc471469d06bbe87bae3eb689ce68433b1487174074d38c"

let test_golden_byte_identity () =
  let default_block = fork_block () in
  Alcotest.(check string)
    "a spec that names no schedule reproduces the pre-chunk-42 block"
    fork_golden_hash (block_hex default_block);
  let testnet_block = fork_block ~fork_schedule:Fork_schedule.testnet () in
  Alcotest.(check string)
    "and so does the same spec handed the testnet schedule explicitly"
    fork_golden_hash (block_hex testnet_block);
  (* The hash is a digest of all 21 header fields, so agreeing on it is
     agreeing on the state root too. The marks say the two calls actually ran,
     which is the positive control the mainnet case below needs. *)
  Alcotest.check marks_t "the default block ran both pre-block calls" (2, 1)
    (fork_marks default_block);
  Alcotest.check marks_t "and so did the explicitly-testnet one" (2, 1)
    (fork_marks testnet_block)

let test_driver_mainnet_skips_4788 () =
  let mainnet_block = fork_block ~fork_schedule:Fork_schedule.mainnet () in
  Alcotest.check marks_t
    "a mainnet-scheduled driver block writes neither system contract" (0, 0)
    (fork_marks mainnet_block);
  (* Same driver, same sub-DAG, same genesis world, one argument different: the
     negative above is a gate firing and not a fixture that could never write. *)
  Alcotest.check marks_t "the same fixture under the default schedule writes"
    (2, 1)
    (fork_marks (fork_block ()));
  Alcotest.(check bool)
    "so a mainnet block is NOT the default block, byte for byte" false
    (String.equal (block_hex mainnet_block) fork_golden_hash)

(* ---------- the schedule across a resume ---------- *)

(* The review-fix cases for [Engine.resume ?fork_schedule]: before the fix,
   [Driver.resume] rebuilt the engine's config through [Config.create], so a
   mainnet (Shanghai-only) chain silently resumed on the all-at-zero default
   and built Cancun/Prague blocks. The fixtures are the fork fixtures above;
   the only new plumbing is the empty store a cold shell opens, so the resume
   replays nothing and the stepped block is decided by the schedule alone. *)

module Engine = Tn_engine.Engine
module Config = Tn_engine.Config
module Block_execution = Tn_evm.Block_execution
module Consensus_store = Tn_execution.Consensus_store
module Cb = Tn_execution.Consensus_block

let fork_fresh_store () =
  Consensus_store.create ~epoch:Units.Epoch.zero ~anchor:Cb.Number.genesis
    ~parent:Cb.genesis_parent

(* Checkpoint the COLD driver, drop it, resume from the pair. The advances
   must be empty: an output replayed here would mean the fixture is not the
   no-replay resume it claims to be. *)
let fork_resumed ?fork_schedule () =
  let spec = fork_spec ?fork_schedule () in
  let checkpoint =
    Driver.snapshot (Driver.create spec ~committee:fork_committee)
  in
  let outcome =
    Result.fold ~ok:Fun.id
      ~error:(fun e ->
        Alcotest.failf "resume: %s" (Driver.resume_error_to_string e))
      (Driver.resume spec ~committee:fork_committee ~checkpoint
         ~store:(fork_fresh_store ()) ~address_of:fork_address_of)
  in
  match outcome with
  | Outcome.Advance { driver; advances = [] } -> driver
  | Outcome.Advance { driver = _; advances = _ :: _ } ->
      Alcotest.fail "resume replayed outputs over an empty store"
  | Outcome.Sealed { driver = _; advances = _; rest = _ } ->
      Alcotest.fail "resume returned Sealed at genesis"
  | Outcome.Halted { advances = _; error } ->
      Alcotest.failf "resume halted: %s" (Outcome.error_to_string error)

(* One stepped block through a resumed driver: the same sub-DAG and batch as
   [fork_block], so the resume path is the only variable. *)
let fork_resumed_block ?fork_schedule () =
  let _, advance =
    Result.fold ~ok:Fun.id
      ~error:(fun e -> Alcotest.failf "step: %s" (Outcome.error_to_string e))
      (Driver.step
         (fork_resumed ?fork_schedule ())
         fork_sub_dag
         ~bodies:(Batch_store.of_bodies [ fork_batch ])
         ~address_of:fork_address_of)
  in
  Alcotest.(check int) "the resumed output builds exactly one block" 1
    (List.length advance.Outcome.blocks);
  get "post-resume block" (List.nth_opt advance.Outcome.blocks 0)

(* The pre-block dispositions, read off the carried token as test_engine.ml's
   T-12 reads them; every arm is named so a schedule change shows up as a
   wrong string rather than as silence. *)
let fork_root_disposition block =
  match
    Block_execution.Pre_block.consensus_root (Executed_block.pre_block block)
  with
  | Block_execution.Pre_block.Root_skipped_at_genesis -> "skipped at genesis"
  | Block_execution.Pre_block.Root_skipped_after_first_batch ->
      "skipped after the first batch"
  | Block_execution.Pre_block.Root_skipped_before_cancun ->
      "skipped before cancun"
  | Block_execution.Pre_block.Root_written _ -> "written"

let fork_hash_disposition block =
  match
    Block_execution.Pre_block.blockhashes (Executed_block.pre_block block)
  with
  | Block_execution.Pre_block.Hash_skipped_at_genesis -> "skipped at genesis"
  | Block_execution.Pre_block.Hash_skipped_before_prague ->
      "skipped before prague"
  | Block_execution.Pre_block.Hash_written _ -> "written"

let schedule_t =
  Alcotest.testable
    (fun fmt s -> Format.pp_print_string fmt (Fork_schedule.to_string s))
    Fork_schedule.equal

(* (a) A mainnet chain checkpointed and resumed stays Shanghai: the block the
   RESUMED driver builds skips both fork-gated pre-block calls, and the same
   resume path on the default schedule writes both, so the two skips are the
   schedule surviving the resume and not a fixture that could never write. *)
let test_resume_forwards_mainnet_schedule () =
  let block = fork_resumed_block ~fork_schedule:Fork_schedule.mainnet () in
  Alcotest.(check string)
    "the post-resume mainnet block skips the consensus root before cancun"
    "skipped before cancun" (fork_root_disposition block);
  Alcotest.(check string) "and skips the blockhashes write before prague"
    "skipped before prague" (fork_hash_disposition block);
  let control = fork_resumed_block () in
  Alcotest.(check string)
    "the resumed default-schedule control writes the consensus root" "written"
    (fork_root_disposition control);
  Alcotest.(check string) "and writes the blockhashes" "written"
    (fork_hash_disposition control)

(* (b) [Engine.resume] WITHOUT [?fork_schedule] still answers the testnet
   schedule: the byte-identity default, pinned. The engine it snapshots is a
   mainnet one, so the default genuinely overrides something here. *)
let test_engine_resume_default_is_testnet () =
  let spec = fork_spec ~fork_schedule:Fork_schedule.mainnet () in
  let cold = Driver.engine (Driver.create spec ~committee:fork_committee) in
  Alcotest.check schedule_t "the snapshotted engine carries mainnet"
    Fork_schedule.mainnet
    (Config.fork_schedule (Engine.config cold));
  let resumed =
    Engine.resume
      ~chain_id:(Chain_spec.chain_id spec)
      ~basefee_address:(Chain_spec.basefee_address spec)
      (Engine.snapshot cold)
  in
  Alcotest.check schedule_t
    "an Engine.resume that names no schedule defaults to testnet"
    Fork_schedule.testnet
    (Config.fork_schedule (Engine.config resumed))

let () =
  Alcotest.run "driver_spec"
    [
      ( "batch store",
        [
          Alcotest.test_case "find answers by derived digest only" `Quick
            test_store_roundtrip;
          Alcotest.test_case "the store is non-consuming" `Quick
            test_store_rereads;
          Alcotest.test_case "equal bodies dedup to one entry" `Quick
            test_store_dedups;
        ] );
      ( "chain spec",
        [
          Alcotest.test_case "an illegal epoch duration is unrepresentable"
            `Quick test_duration_guard;
          Alcotest.test_case "the world cannot lack the predeploys" `Quick
            test_world_predeployed;
          Alcotest.test_case "the genesis anchor carries the cited scalars"
            `Quick test_anchor;
          Alcotest.test_case "epoch 0's boundary pins genesis" `Quick
            test_first_boundary;
        ] );
      ( "address book",
        [
          Alcotest.test_case "members resolve, non-members are None" `Quick
            test_book_members;
          Alcotest.test_case "union is monotone and newer-biased" `Quick
            test_book_union;
        ] );
      ( "fork schedule end to end",
        [
          Alcotest.test_case "driver-mainnet-skips-4788" `Quick
            test_driver_mainnet_skips_4788;
          Alcotest.test_case "golden-byte-identity" `Quick
            test_golden_byte_identity;
          Alcotest.test_case "resume-forwards-mainnet-schedule" `Quick
            test_resume_forwards_mainnet_schedule;
          Alcotest.test_case "engine-resume-default-is-testnet" `Quick
            test_engine_resume_default_is_testnet;
        ] );
    ]
