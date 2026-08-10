(* Differential tests for the fork schedule as it is THREADED and, from later
   stages, as it is DISPATCHED on.

   The threading cases came first: the chain's [Fork_schedule.t] reaching the
   engine through [Chain_spec] and [Config], the per-block [Spec.t] the engine
   resolves from it, and the two optional-argument defaults that keep every
   pre-existing golden byte-identical. Those say which level a block CARRIES.

   The dispatch cases say what a block DOES with it, and they are differential
   by construction: one fixture is run at every level of [all_specs] and the
   figures are asserted absolutely, so a gate that fires at the wrong fork and a
   gate that never fires both fail. Each case carries its own positive control —
   the instruction that RUNS above Cancun, the floor that bites at Prague, the
   precompile that is warm at every level — because a case whose every level
   halts, or whose every level charges the same, would pass while proving
   nothing.

   The defaults are guarded by name on purpose. [Env.Block.make] answers
   [Spec.Prague] and [Config.create]/[Chain_spec.create] answer
   [Fork_schedule.testnet] because that is the chain the port modelled before a
   schedule existed; a silent change to either would move every fixture in the
   tree onto a different fork with no test saying so.

   The engine fixtures are this suite's own rather than shared, on the standing
   rule that a suite pays for the BLS committee it builds. *)

open Tn_types
open Tn_vertex
open Tn_consensus
module Cb = Tn_execution.Consensus_block
module Nonempty = Tn_std.Nonempty
module Output = Tn_batch.Output
module Anchor = Tn_engine.Anchor
module Config = Tn_engine.Config
module Engine = Tn_engine.Engine
module Executed_block = Tn_engine.Executed_block
module Chain_spec = Tn_driver.Chain_spec
module Epoch_duration = Tn_driver.Chain_spec.Epoch_duration
module Access = Tn_evm.Access
module Authorization = Tn_evm.Authorization
module Batch_position = Tn_evm.Batch_position
module Block_context = Tn_evm.Block_context
module Block_execution = Tn_evm.Block_execution
module Block_hashes = Tn_evm.Block_hashes
module Block_header = Tn_evm.Block_header
module Code = Tn_evm.Code
module Data = Tn_evm.Data
module Effects = Tn_evm.Effects
module Env = Tn_evm.Env
module Epoch_boundary = Tn_evm.Epoch_boundary
module Executor = Tn_evm.Executor
module Fork_schedule = Tn_evm.Fork_schedule
module Gas = Tn_evm.Gas
module Interpreter = Tn_evm.Interpreter
module Lifecycle = Tn_evm.Lifecycle
module Mutability = Tn_evm.Mutability
module Opcode = Tn_evm.Opcode
module Receipt = Tn_evm.Receipt
module Spec = Tn_evm.Spec
module System_call = Tn_evm.System_call
module System_contracts = Tn_evm.System_contracts
module Transaction = Tn_evm.Transaction
module Digest = Tn_crypto.Digest
module Account = Tn_state.Account
module Genesis_account = Tn_state.Genesis_account
module Nonce = Tn_state.Nonce
module U256 = Tn_state.U256
module World = Tn_state.World_state

(* ---------- totalisers, so nothing is skipped in silence ---------- *)

let get what o =
  Result.fold ~ok:Fun.id
    ~error:(fun msg -> Alcotest.fail msg)
    (Option.to_result ~none:what o)

let nth what l n = get what (List.nth_opt l n)
let mk_addr c = get "address" (Units.Address.of_bytes (String.make 20 c))
let u n = get "u256" (U256.of_int n)
let ts n = get "timestamp" (Units.Timestamp.of_sec n)
let round n = get "round" (Round.of_int n)
let w0 = Units.Worker_id.zero
let fee n = Units.Base_fee.of_int64 (Int64.of_int n)

(* A schedule [make] refused is a failed case, never a skipped assertion. *)
let with_schedule r f =
  Result.fold ~ok:f
    ~error:(fun e ->
      Alcotest.fail ("the schedule must be accepted: "
                    ^ Fork_schedule.error_to_string e))
    r

let spec_t =
  Alcotest.testable
    (fun fmt s -> Format.pp_print_string fmt (Spec.to_string s))
    (fun a b -> Int.equal (Spec.compare a b) 0)

let schedule_t =
  Alcotest.testable
    (fun fmt s -> Format.pp_print_string fmt (Fork_schedule.to_string s))
    Fork_schedule.equal

(* Every fork level through a total match, so a fourth constructor breaks this
   build rather than shortening the lists below in silence. *)
let all_specs =
  List.map
    (fun s ->
      match s with Spec.Shanghai -> s | Spec.Cancun -> s | Spec.Prague -> s)
    [ Spec.Shanghai; Spec.Cancun; Spec.Prague ]

(* ---------- block environments ---------- *)

let block_coinbase = mk_addr '\xc0'
let block_timestamp = 1_700_000_000
let block_chain_id = u 2017

let block_at ~spec =
  Env.Block.make_at_spec ~spec ~coinbase:block_coinbase
    ~timestamp:(u block_timestamp) ~number:(u 1000) ~prevrandao:U256.zero
    ~gas_limit:(u 30_000_000) ~basefee:(u 7)
    ~basefee_address:System_contracts.governance_safe_address
    ~chain_id:block_chain_id ~blob_gasprice:Env.Block.consensus_blob_gasprice
    ~hashes:Block_hashes.empty

(* The SAME block through the constructor that says nothing about forks. Every
   other field is written identically, so [Env.Block.equal] below compares the
   fork level and nothing else. *)
let block_default () =
  Env.Block.make ~coinbase:block_coinbase ~timestamp:(u block_timestamp)
    ~number:(u 1000) ~prevrandao:U256.zero ~gas_limit:(u 30_000_000)
    ~basefee:(u 7)
    ~basefee_address:System_contracts.governance_safe_address
    ~chain_id:block_chain_id ~blob_gasprice:Env.Block.consensus_blob_gasprice
    ~hashes:Block_hashes.empty

(* ---------- the committee the engine and the chain spec need ---------- *)

let member_addresses =
  [ mk_addr '\xa0'; mk_addr '\xa1'; mk_addr '\xa2'; mk_addr '\xa3' ]

let committee, sk_of =
  let sks = List.init 4 (fun i -> Tn_crypto.Secret_key.derive (Int64.of_int i)) in
  let authorities =
    List.mapi
      (fun i sk ->
        Authority.make
          ~protocol_key:(Tn_crypto.Secret_key.public_key sk)
          ~execution_address:(nth "member address" member_addresses i))
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

let members = Committee.authorities committee
let ids = List.map Authority.id members
let id0 = nth "id0" ids 0

let address_of id =
  List.find_map
    (fun a ->
      if Authority_id.equal (Authority.id a) id then
        Some (Authority.execution_address a)
      else None)
    members

let genesis_parents = List.map Certificate.digest (Certificate.genesis committee)

let certify header =
  let votes = List.map (fun id -> Vote.sign (sk_of id) ~voter:id header) ids in
  Result.fold ~ok:Fun.id
    ~error:(fun e ->
      Alcotest.failf "certify: %s" (Certificate.error_to_string e))
    (Certificate.assemble committee header votes)

(* A payload the drop layer discards, so the block is built and carries no
   transactions: this suite is about which fork a block is on, not what runs. *)
let undecodable_batch =
  Batch.make ~transactions:[ "\xde\xad\xbe\xef" ] ~epoch:Units.Epoch.zero
    ~beneficiary:Units.Address.zero ~base_fee_per_gas:(fee 0) ~worker_id:w0

let commit_at = 1_700_000_123L

let one_output =
  let header =
    Header.make ~latest_execution_block:Tn_types.Block_num_hash.zero ~author:id0
      ~round:(round 1) ~epoch:Units.Epoch.zero ~created_at:(ts commit_at)
      ~payload:[ (Batch.digest undecodable_batch, w0) ]
      ~parents:genesis_parents
  in
  let sub_dag =
    Sub_dag.create
      ~sequence:(Nonempty.singleton (certify header))
      ~scores:(Reputation_scores.fresh committee)
      ~previous:None
  in
  let consensus =
    Cb.create ~parent_hash:Cb.genesis_parent ~sub_dag
      ~number:(Cb.Number.succ Cb.Number.genesis)
  in
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "attach: %s" (Output.error_to_string e))
    (Output.attach ~consensus
       ~lookup:(fun d ->
         if Digests.Batch_digest.equal (Batch.digest undecodable_batch) d then
           Some undecodable_batch
         else None)
       ~address_of)

(* ---------- engine and chain-spec configurations ---------- *)

let genesis_hash = Tn_keccak.digest "chunk 42 fork dispatch genesis sentinel"
let ancestor_hash = Tn_keccak.digest "chunk 42 fork dispatch ancestor sentinel"
let basefee_address = mk_addr '\xbe'
let boundary_far = ts 2_000_000_000L

let anchor =
  Anchor.of_genesis ~hash:genesis_hash ~base_fee:(u 77) ~gas_limit:30_000_000

let config_default () =
  Config.create ~anchor ~ancestors:[ ancestor_hash ] ~world:World.empty
    ~chain_id:block_chain_id ~basefee_address ~epoch_boundary:boundary_far
    ~committee

let config_on fork_schedule =
  Config.create_on_schedule ~fork_schedule ~anchor
    ~ancestors:[ ancestor_hash ] ~world:World.empty ~chain_id:block_chain_id
    ~basefee_address ~epoch_boundary:boundary_far ~committee

(* A codeless registry entry: this suite never reads the registry, and storage
   on a codeless account is what [of_genesis_alloc] refuses, so it carries
   none. *)
let registry_entry =
  Genesis_account.make ~nonce:Tn_state.Nonce.zero ~balance:U256.zero ~code:None
    ~storage:[]

let duration = get "epoch duration" (Epoch_duration.of_secs 28_800)

let chain_spec_result ?fork_schedule () =
  Chain_spec.create ~chain_id:block_chain_id
    ~basefee_address:System_contracts.governance_safe_address
    ~genesis_hash ~genesis_base_fee:(u 7) ~genesis_gas_limit:30_000_000
    ~genesis_timestamp:(ts 0L) ~epoch_duration:duration ?fork_schedule
    ~registry:registry_entry ~extra_alloc:[] ()

let chain_spec ?fork_schedule () =
  Result.fold ~ok:Fun.id
    ~error:(fun e ->
      Alcotest.failf "chain spec: %s" (Chain_spec.error_to_string e))
    (chain_spec_result ?fork_schedule ())

let executed engine output =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "execute: %s" (Engine.error_to_string e))
    (Engine.execute engine output)

let one_block engine =
  let _, blocks = executed engine one_output in
  Alcotest.(check int) "the output builds exactly one block" 1
    (List.length blocks);
  nth "block" blocks 0

(* ---------- defaults guard ---------- *)

let test_env_block_default_spec_is_prague () =
  Alcotest.check spec_t "Env.Block.make answers Prague" Spec.Prague
    (Env.Block.spec (block_default ()));
  (* The explicit constructor answers whichever level it was given, so the
     default above is a default and not a constant. *)
  List.iter
    (fun s ->
      Alcotest.check spec_t
        (Printf.sprintf "make_at_spec ~spec:%s reads back" (Spec.to_string s))
        s
        (Env.Block.spec (block_at ~spec:s)))
    all_specs;
  (* The default block IS the Prague block, field for field, which is the
     byte-identity contract: no pre-existing construction site moved. *)
  Alcotest.(check bool) "the default block equals the Prague block" true
    (Env.Block.equal (block_default ()) (block_at ~spec:Spec.Prague));
  Alcotest.(check bool) "and does not equal the Shanghai one" false
    (Env.Block.equal (block_default ()) (block_at ~spec:Spec.Shanghai))

let test_config_default_schedule_is_testnet () =
  Alcotest.check schedule_t "Config.create answers the testnet schedule"
    Fork_schedule.testnet
    (Config.fork_schedule (config_default ()));
  Alcotest.check schedule_t "create_on_schedule keeps a mainnet schedule"
    Fork_schedule.mainnet
    (Config.fork_schedule (config_on Fork_schedule.mainnet));
  Alcotest.check schedule_t "and keeps a testnet one"
    Fork_schedule.testnet
    (Config.fork_schedule (config_on Fork_schedule.testnet))

let test_chain_spec_default_schedule_is_testnet () =
  Alcotest.check schedule_t "Chain_spec.create answers the testnet schedule"
    Fork_schedule.testnet
    (Chain_spec.fork_schedule (chain_spec ()));
  Alcotest.check schedule_t "and keeps a mainnet schedule it was given"
    Fork_schedule.mainnet
    (Chain_spec.fork_schedule
       (chain_spec ~fork_schedule:Fork_schedule.mainnet ()))

(* [engine_config] is the ONE conversion site, so the schedule has to survive
   it; both of its production callers name no fork at all. *)
let test_chain_spec_forwards_schedule_to_config () =
  Alcotest.check schedule_t "a mainnet spec yields a mainnet config"
    Fork_schedule.mainnet
    (Config.fork_schedule
       (Chain_spec.engine_config
          (chain_spec ~fork_schedule:Fork_schedule.mainnet ())
          ~committee));
  Alcotest.check schedule_t "a default spec yields a testnet config"
    Fork_schedule.testnet
    (Config.fork_schedule (Chain_spec.engine_config (chain_spec ()) ~committee))

let test_system_call_env_preserves_spec () =
  List.iter
    (fun s ->
      let rebuilt = System_call.system_block (block_at ~spec:s) in
      Alcotest.check spec_t
        (Printf.sprintf "a system call inside a %s block stays %s"
           (Spec.to_string s) (Spec.to_string s))
        s (Env.Block.spec rebuilt);
      (* The two documented swaps DID happen, so the assertion above is about
         the rebuilt block and not about the block it came from. *)
      Alcotest.(check bool) "gas limit swapped to the system allowance" true
        (U256.equal (Env.Block.gas_limit rebuilt) (u System_call.gas_limit));
      Alcotest.(check bool) "basefee swapped to zero" true
        (U256.equal (Env.Block.basefee rebuilt) U256.zero);
      (* And a field NOT among telcoin's swaps rode through, which is what
         makes "preserved" mean carried rather than coincidental. *)
      Alcotest.(check bool) "the blob env rode through untouched" true
        (U256.equal
           (Env.Block.blob_gasprice rebuilt)
           Env.Block.consensus_blob_gasprice))
    all_specs

(* Each disposition as one word, through a total match, so a fifth constructor
   breaks this build rather than silently widening a case. *)
let root_word pre =
  match Block_execution.Pre_block.consensus_root pre with
  | Block_execution.Pre_block.Root_skipped_after_first_batch ->
      "skipped after the first batch"
  | Block_execution.Pre_block.Root_skipped_before_cancun ->
      "skipped before cancun"
  | Block_execution.Pre_block.Root_skipped_at_genesis -> "skipped at genesis"
  | Block_execution.Pre_block.Root_written _ -> "written"

let hash_word pre =
  match Block_execution.Pre_block.blockhashes pre with
  | Block_execution.Pre_block.Hash_skipped_before_prague ->
      "skipped before prague"
  | Block_execution.Pre_block.Hash_skipped_at_genesis -> "skipped at genesis"
  | Block_execution.Pre_block.Hash_written _ -> "written"

(* ---------- engine threading ---------- *)

(* A produced block carries no fork level of its own to read back, so what it
   says about the level it ran at is what its two pre-block system calls did.
   That is the stronger reading anyway: it is the gate in [Block_execution]
   reporting which level reached it, not a field echoed alongside. The pair
   separates all three levels, because Shanghai skips both calls, Cancun writes
   the beacon root only, and Prague writes both. *)
let fork_words b =
  let pre = Executed_block.pre_block b in
  (root_word pre, hash_word pre)

let words_t = Alcotest.(pair string string)
let shanghai_words = ("skipped before cancun", "skipped before prague")
let cancun_words = ("written", "skipped before prague")
let prague_words = ("written", "written")

let test_engine_mainnet_block_spec_is_shanghai () =
  let mainnet_block = one_block (Engine.create (config_on Fork_schedule.mainnet)) in
  Alcotest.check words_t "a mainnet-scheduled block executes at Shanghai"
    shanghai_words (fork_words mainnet_block);
  let testnet_block = one_block (Engine.create (config_on Fork_schedule.testnet)) in
  Alcotest.check words_t "a testnet-scheduled block executes at Prague"
    prague_words (fork_words testnet_block);
  let default_block = one_block (Engine.create (config_default ())) in
  Alcotest.check words_t "and an engine told no schedule executes at Prague"
    prague_words (fork_words default_block);
  (* Nothing dispatches on the fork level at this stage, so the default engine
     and the explicitly-testnet one must agree byte for byte. They are the same
     schedule, so this stays true once the gates arrive. *)
  Alcotest.(check string) "the default and testnet blocks are the same block"
    (Tn_keccak.to_hex (Executed_block.hash testnet_block))
    (Tn_keccak.to_hex (Executed_block.hash default_block))

(* The engine must resolve the level from THIS block's timestamp, not from a
   constant, so the same output is run under two schedules that straddle the
   block's own second. The straddle point is read off the produced header, so
   the case cannot pass by guessing which timestamp the engine used. *)
let test_engine_block_spec_follows_block_timestamp () =
  let seconds =
    Int64.of_int
      (Block_header.timestamp
         (Executed_block.header (one_block (Engine.create (config_default ())))))
  in
  with_schedule
    (Fork_schedule.make ~shanghai:(ts 0L) ~cancun:(Some (ts seconds))
       ~prague:None)
    (fun activated_now ->
      Alcotest.check words_t
        "Cancun activating ON this block's second is active" cancun_words
        (fork_words (one_block (Engine.create (config_on activated_now)))));
  with_schedule
    (Fork_schedule.make ~shanghai:(ts 0L)
       ~cancun:(Some (ts (Int64.add seconds 1L)))
       ~prague:None)
    (fun activated_next ->
      Alcotest.check words_t "and one second later is not" shanghai_words
        (fork_words (one_block (Engine.create (config_on activated_next)))))

(* ---------- opcode activation: the five Cancun instructions ---------- *)

(* A miniature assembler. [byte] goes through a local [Buffer] rather than
   [Char.chr] so that it is total: [Buffer.add_uint8] keeps the low eight bits
   of whatever it is handed and cannot fail, and the buffer never escapes this
   function. Every value passed below is 0..255 anyway, by [Opcode.to_byte]'s
   range and by the literal operands. *)
let byte b =
  let buf = Buffer.create 1 in
  Buffer.add_uint8 buf b;
  Buffer.contents buf

let bytes_of parts = String.concat "" parts
let op o = byte (Opcode.to_byte o)
let width_of n = get "push width" (Opcode.Push_bytes.of_int n)
let push1 n = op (Opcode.Push (width_of 1)) ^ byte n
let gas_of n = get "gas" (Gas.of_int n)

(* A mutable, non-static frame in a block at [spec]. The world and the access
   set are both empty and no program below reads either, so the fork level is
   the only thing that can move an outcome. *)
let env_at ~spec =
  Env.make ~block:(block_at ~spec)
    ~tx:(Env.Tx.make ~origin:(mk_addr '\x01') ~gas_price:(u 9) ~access_list:[])
    ~call:
      (Env.Call.make ~target:(mk_addr '\x02') ~caller:(mk_addr '\x03')
         ~value:U256.zero ~data:Data.empty ~mutability:Mutability.Mutable)

(* An allowance far above anything these programs can spend, so no assertion
   below can be satisfied by an out-of-gas halt wearing another name. *)
let run_at ~spec program =
  Interpreter.run ~env:(env_at ~spec) ~code:(Code.of_string program)
    ~gas:(gas_of 1_000_000)
    ~effects:(Effects.start ~world:World.empty ~access:Access.empty)

(* An outcome as one word, so a case reads as "halts how". Total over the four
   outcomes, so a fifth breaks this build. *)
let outcome_word o =
  match o with
  | Interpreter.Stopped _ -> "stopped"
  | Interpreter.Returned _ -> "returned"
  | Interpreter.Reverted _ -> "reverted"
  | Interpreter.Failed e -> Interpreter.error_to_string e

let not_activated b = Printf.sprintf "instruction 0x%02x not activated" b
let invalid_opcode b = Printf.sprintf "invalid opcode 0x%02x" b

(* One gated instruction at every fork level: refused below Cancun, and RUNNING
   at Cancun and at Prague. The two positive halves are what stop a program that
   halted everywhere — a stack underflow, say — from satisfying the negative
   one. *)
let check_gated_at_cancun ~name ~program ~code_byte =
  Alcotest.(check string)
    (name ^ " is refused on a Shanghai block")
    (not_activated code_byte)
    (outcome_word (run_at ~spec:Spec.Shanghai program));
  Alcotest.(check string)
    (name ^ " runs on a Cancun block")
    "stopped"
    (outcome_word (run_at ~spec:Spec.Cancun program));
  Alcotest.(check string)
    (name ^ " runs on a Prague block")
    "stopped"
    (outcome_word (run_at ~spec:Spec.Prague program))

let tload_program =
  bytes_of [ push1 0x00; op Opcode.Tload; op Opcode.Pop; op Opcode.Stop ]

let tstore_program =
  bytes_of [ push1 0x07; push1 0x00; op Opcode.Tstore; op Opcode.Stop ]

let mcopy_program =
  bytes_of
    [ push1 0x00; push1 0x00; push1 0x00; op Opcode.Mcopy; op Opcode.Stop ]

let blobhash_program =
  bytes_of [ push1 0x00; op Opcode.Blobhash; op Opcode.Pop; op Opcode.Stop ]

let blobbasefee_program =
  bytes_of [ op Opcode.Blobbasefee; op Opcode.Pop; op Opcode.Stop ]

(* Five cases and not one loop: each instruction's gate must be killable on its
   own, so that a check copied to a sibling and left dead cannot hide behind the
   sibling that works. *)
let test_tload_halts_at_shanghai () =
  check_gated_at_cancun ~name:"TLOAD" ~program:tload_program
    ~code_byte:(Opcode.to_byte Opcode.Tload)

let test_tstore_halts_at_shanghai () =
  check_gated_at_cancun ~name:"TSTORE" ~program:tstore_program
    ~code_byte:(Opcode.to_byte Opcode.Tstore)

let test_mcopy_halts_at_shanghai () =
  check_gated_at_cancun ~name:"MCOPY" ~program:mcopy_program
    ~code_byte:(Opcode.to_byte Opcode.Mcopy)

let test_blobhash_halts_at_shanghai () =
  check_gated_at_cancun ~name:"BLOBHASH" ~program:blobhash_program
    ~code_byte:(Opcode.to_byte Opcode.Blobhash)

let test_blobbasefee_halts_at_shanghai () =
  check_gated_at_cancun ~name:"BLOBBASEFEE" ~program:blobbasefee_program
    ~code_byte:(Opcode.to_byte Opcode.Blobbasefee)

(* [0x0c] names no instruction at any fork, which is a different fact from
   [MCOPY] naming one that Shanghai has not reached. revm keeps them apart as
   [OpcodeNotFound] and [NotActivated], and so does this port: collapsing them
   would say a Shanghai chain does not know [0x5e] is an instruction, and it
   does. *)
let unassigned_byte = 0x0c

let test_not_activated_is_distinct () =
  Alcotest.(check bool) "0x0c decodes to no instruction at all" true
    (Option.is_none (Opcode.decode unassigned_byte));
  let gated = outcome_word (run_at ~spec:Spec.Shanghai mcopy_program) in
  let unknown =
    outcome_word
      (run_at ~spec:Spec.Shanghai
         (bytes_of [ byte unassigned_byte; op Opcode.Stop ]))
  in
  Alcotest.(check string) "a Cancun instruction below Cancun is not activated"
    (not_activated (Opcode.to_byte Opcode.Mcopy))
    gated;
  Alcotest.(check string) "an unassigned byte is an invalid opcode"
    (invalid_opcode unassigned_byte) unknown;
  Alcotest.(check bool) "and the two halts are not the same halt" false
    (String.equal gated unknown)

(* ---------- executor gates: the EIP-7623 floor and the warm set ---------- *)

let tx_sender = mk_addr '\xa1'
let tx_target = mk_addr '\xb2'
let account_of ~balance = Account.make ~nonce:Nonce.zero ~balance:(u balance)

let world_of pairs =
  List.fold_left
    (fun w (address, acct) -> World.set_account w address acct)
    World.empty pairs

(* The gas price equals the block's base fee, so the telcoin settlement split
   moves no value an assertion below could confuse with gas. *)
let call_tx ~data =
  Transaction.make ~sender:tx_sender ~nonce:Nonce.zero ~gas_limit:100_000
    ~kind:(Transaction.Call tx_target) ~value:U256.zero ~data ~access_list:[]
    ~chain_id:(Some block_chain_id)
    ~fee:(Transaction.Legacy { gas_price = u 7 })

let included receipt =
  match receipt with
  | Receipt.Success _ -> true
  | Receipt.Reverted _ | Receipt.Halted _ -> false

let gas_used_at ~spec ~world tx =
  Result.fold
    ~ok:(fun (receipt, _world) ->
      Alcotest.(check bool) "the fixture must succeed, not revert or halt" true
        (included receipt);
      Receipt.gas_used receipt)
    ~error:(fun e ->
      Alcotest.failf "unexpected rejection: %s" (Executor.error_to_string e))
    (Executor.execute world ~block:(block_at ~spec) tx)

(* A hundred nonzero calldata bytes to a codeless target: the intrinsic charge
   is 21000 + 16*100 = 22600 and the EIP-7623 floor is 21000 + 10*(4*100) =
   25000, so the floor is what the block charges where it is installed and is
   invisible where it is not. The frame runs nothing, so neither figure carries
   an execution term. *)
let floor_data = String.make 100 '\xff'
let floor_intrinsic = 22600
let floor_charge = 25000
let payer_world = world_of [ (tx_sender, account_of ~balance:10_000_000) ]

let test_floor_zero_at_cancun () =
  let used spec =
    gas_used_at ~spec ~world:payer_world (call_tx ~data:floor_data)
  in
  Alcotest.(check int) "a Shanghai block charges the intrinsic cost"
    floor_intrinsic (used Spec.Shanghai);
  Alcotest.(check int) "so does a Cancun block" floor_intrinsic
    (used Spec.Cancun);
  (* The positive control: the floor DOES bite at Prague, so the two assertions
     above are about a gate and not about a fixture too small to reach it. *)
  Alcotest.(check int) "and a Prague block charges the EIP-7623 floor"
    floor_charge (used Spec.Prague)

(* A contract that touches one precompile address and drops the answer.
   [BALANCE] is priced 100 on a warm account and 2600 on a cold one, so the
   block's warm set is legible straight off the receipt: 21000 intrinsic, then
   3 for the [PUSH1], the access, and 2 for the [POP]. *)
let balance_probe n =
  bytes_of [ push1 n; op Opcode.Balance; op Opcode.Pop; op Opcode.Stop ]

let probe_warm = 21000 + 3 + 100 + 2
let probe_cold = 21000 + 3 + 2600 + 2

let probe_used ~address spec =
  gas_used_at ~spec
    ~world:
      (world_of
         [
           (tx_sender, account_of ~balance:10_000_000);
           ( tx_target,
             Account.with_code (account_of ~balance:0) (balance_probe address) );
         ])
    (call_tx ~data:"")

let test_addr_0x0a_cold_at_shanghai () =
  Alcotest.(check int) "0x0a is COLD on a Shanghai block" probe_cold
    (probe_used ~address:0x0a Spec.Shanghai);
  Alcotest.(check int) "and warm on a Cancun block" probe_warm
    (probe_used ~address:0x0a Spec.Cancun);
  Alcotest.(check int) "and warm on a Prague block" probe_warm
    (probe_used ~address:0x0a Spec.Prague);
  (* The control: 0x09 is in the Berlin set, so it is warm at EVERY level. A
     gate that warmed nothing below Cancun would satisfy the first assertion
     and fail this one. *)
  Alcotest.(check int) "0x09 is warm on a Shanghai block too" probe_warm
    (probe_used ~address:0x09 Spec.Shanghai);
  Alcotest.(check int) "as it is on a Prague block" probe_warm
    (probe_used ~address:0x09 Spec.Prague)

(* ---------- block gates: the two pre-block system calls ---------- *)

(* The two system contracts, each seeded with a program that writes a distinct
   byte into slot 0 of its OWN storage. A call that runs is then legible off the
   world, which is a sharper oracle than the disposition alone: a gate that
   answered [Root_written] without calling would satisfy the constructor
   assertion and fail this one. *)
let slot_writer value =
  bytes_of [ push1 value; push1 0x00; op Opcode.Sstore; op Opcode.Stop ]

let beacon_mark = 0x21
let history_mark = 0x22

let system_world =
  world_of
    [
      ( System_contracts.beacon_roots_address,
        Account.with_code (account_of ~balance:0) (slot_writer beacon_mark) );
      ( System_contracts.history_storage_address,
        Account.with_code (account_of ~balance:0) (slot_writer history_mark) );
    ]

(* A first batch of a non-genesis block on an open boundary: the one shape that
   reaches every gate, so the fork level is the only thing left to decide the
   dispositions. The digests are this suite's own, arbitrary and nonzero. *)
let context_at ~spec =
  Result.fold ~ok:Fun.id
    ~error:(fun e ->
      Alcotest.failf "the context must be accepted: %s"
        (Block_context.error_to_string e))
    (Block_context.make ~block:(block_at ~spec)
       ~parent_hash:(Tn_keccak.digest "chunk-42 parent block")
       ~consensus_root:
         (Digests.Output_digest.of_digest
            (get "consensus root" (Digest.of_bytes (String.make 32 '\x40'))))
       ~nonce:
         (Units.Sequence_number.of_epoch_round
            (get "epoch" (Units.Epoch.of_int 7))
            (round 9))
       ~batch_digest:
         (Digests.Batch_digest.of_digest
            (get "batch digest" (Digest.of_bytes (String.make 32 '\x80'))))
       ~position:
         (get "position" (Batch_position.of_batch ~batch_index:0 ~worker_id:w0))
       ~boundary:Epoch_boundary.Open)

let pre_block_at ~spec =
  Result.fold ~ok:Fun.id
    ~error:(fun e ->
      Alcotest.failf "unexpected pre-block error: %s"
        (Block_execution.error_to_string e))
    (Block_execution.apply_pre_block system_world ~context:(context_at ~spec))

let mark_at pre address =
  U256.to_int (World.storage (Block_execution.Pre_block.world pre) address (u 0))

let beacon_slot pre = mark_at pre System_contracts.beacon_roots_address
let history_slot pre = mark_at pre System_contracts.history_storage_address

let check_pre_block ~spec ~root ~hash ~beacon ~history =
  let pre = pre_block_at ~spec in
  let at what = Spec.to_string spec ^ ": " ^ what in
  Alcotest.(check string) (at "the EIP-4788 disposition") root (root_word pre);
  Alcotest.(check string) (at "the EIP-2935 disposition") hash (hash_word pre);
  Alcotest.(check (option int))
    (at "the beacon-roots slot") beacon (beacon_slot pre);
  Alcotest.(check (option int))
    (at "the history-storage slot") history (history_slot pre)

let test_preblock_shanghai_writes_neither () =
  check_pre_block ~spec:Spec.Shanghai ~root:"skipped before cancun"
    ~hash:"skipped before prague" ~beacon:(Some 0) ~history:(Some 0)

let test_preblock_cancun_writes_4788_only () =
  check_pre_block ~spec:Spec.Cancun ~root:"written"
    ~hash:"skipped before prague" ~beacon:(Some beacon_mark) ~history:(Some 0)

(* The positive control for both cases above: at Prague the same context, the
   same world and the same two contracts write BOTH marks. Without it a fixture
   that could never write anything would satisfy every negative assertion. *)
let test_preblock_prague_writes_both () =
  check_pre_block ~spec:Spec.Prague ~root:"written" ~hash:"written"
    ~beacon:(Some beacon_mark) ~history:(Some history_mark)

(* ---------- transaction-type gate: EIP-7702 below Prague ---------- *)

(* An authorization needs no valid signature to make a transaction type-4: a
   entry the screen rejects is a per-entry skip inside the application loop, not
   a validity error, so the transaction is still INCLUDED at Prague and still
   refused below it. *)
let one_authorization =
  [
    Authorization.sign
      (get "authorization"
         (Authorization.make ~chain_id:block_chain_id ~address:tx_target
            ~nonce:U256.zero))
      ~y_parity:U256.zero ~r:(u 1) ~s:(u 1);
  ]

let set_code_tx ~authorizations =
  Transaction.set_code ~sender:tx_sender ~nonce:Nonce.zero ~gas_limit:100_000
    ~target:tx_target ~value:U256.zero ~data:"" ~access_list:[]
    ~chain_id:block_chain_id ~max_priority_fee_per_gas:U256.zero
    ~max_fee_per_gas:(u 7) ~authorizations

(* Included, or the name of the rejection. One word per level, so the case reads
   as a table of what each fork does with the same transaction. *)
let disposition_at ~spec tx =
  Result.fold
    ~ok:(fun (receipt, _world) ->
      if included receipt then "included" else "run but not successful")
    ~error:Executor.error_to_string
    (Executor.execute payer_world ~block:(block_at ~spec) tx)

let not_activated_type4 =
  Executor.error_to_string Executor.Eip7702_not_activated

let empty_list_rejection =
  Executor.error_to_string Executor.Empty_authorization_list

let test_type4_rejected_at_cancun () =
  let carried = set_code_tx ~authorizations:one_authorization in
  Alcotest.(check string) "a Shanghai block refuses a set-code transaction"
    not_activated_type4
    (disposition_at ~spec:Spec.Shanghai carried);
  Alcotest.(check string) "so does a Cancun block" not_activated_type4
    (disposition_at ~spec:Spec.Cancun carried);
  (* The positive control: EIP-7702 arrives at Prague, so the same transaction
     is included there. Without it a blanket refusal would pass. *)
  Alcotest.(check string) "and a Prague block includes it" "included"
    (disposition_at ~spec:Spec.Prague carried);
  (* The gate is on the transaction TYPE and sits ahead of the empty-list guard,
     which is observable in exactly one shape: the same empty-list transaction
     reports the fork below Prague and the empty list at Prague. *)
  let empty = set_code_tx ~authorizations:[] in
  Alcotest.(check string) "an empty list below Cancun reports the fork"
    not_activated_type4
    (disposition_at ~spec:Spec.Shanghai empty);
  Alcotest.(check string) "and at Cancun reports the fork too" not_activated_type4
    (disposition_at ~spec:Spec.Cancun empty);
  Alcotest.(check string) "and at Prague reports the empty list"
    empty_list_rejection
    (disposition_at ~spec:Spec.Prague empty)

(* ---------- EIP-6780: what SELFDESTRUCT destroys ---------- *)

let doomed = mk_addr '\xd0'
let heir = mk_addr '\xe1'
let doomed_balance = 1000

(* Nonempty and never executed: the interpreter runs the code passed to [run],
   so this only makes the account a contract rather than an empty entry. *)
let doomed_code = bytes_of [ push1 0x00; op Opcode.Stop ]

let push20 address =
  op (Opcode.Push (width_of 20)) ^ Units.Address.to_bytes address

(* [doomed] exists in the world BEFORE the frame starts, so it is never
   [created_here] and EIP-6780 spares it at Cancun and above. *)
let destruct_at ~spec ~beneficiary =
  Interpreter.run
    ~env:
      (Env.make ~block:(block_at ~spec)
         ~tx:
           (Env.Tx.make ~origin:(mk_addr '\x01') ~gas_price:(u 9)
              ~access_list:[])
         ~call:
           (Env.Call.make ~target:doomed ~caller:(mk_addr '\x03')
              ~value:U256.zero ~data:Data.empty ~mutability:Mutability.Mutable))
    ~code:(Code.of_string (push20 beneficiary ^ op Opcode.Selfdestruct))
    ~gas:(gas_of 1_000_000)
    ~effects:
      (Effects.start
         ~world:
           (world_of
              [
                ( doomed,
                  Account.with_code
                    (account_of ~balance:doomed_balance)
                    doomed_code );
              ])
         ~access:Access.empty)

let effects_of outcome =
  match outcome with
  | Interpreter.Stopped { effects; _ } -> effects
  | Interpreter.Returned _ ->
      Alcotest.fail "SELFDESTRUCT halts like STOP, it does not return"
  | Interpreter.Reverted _ -> Alcotest.fail "the fixture must not revert"
  | Interpreter.Failed e ->
      Alcotest.failf "unexpected halt: %s" (Interpreter.error_to_string e)

let removals ~spec ~beneficiary =
  List.length
    (Lifecycle.destroyed (Effects.lifecycle (effects_of (destruct_at ~spec ~beneficiary))))

let balance_after ~spec ~beneficiary address =
  World.balance (Effects.world (effects_of (destruct_at ~spec ~beneficiary))) address

let test_preexisting_contract_selfdestruct_at_shanghai_destroys () =
  Alcotest.(check int) "a Shanghai block records the removal" 1
    (removals ~spec:Spec.Shanghai ~beneficiary:heir);
  Alcotest.(check int) "a Cancun block records none: EIP-6780 spares it" 0
    (removals ~spec:Spec.Cancun ~beneficiary:heir);
  Alcotest.(check int) "and a Prague block records none either" 0
    (removals ~spec:Spec.Prague ~beneficiary:heir);
  (* The control: the balance moves at EVERY level, so the three figures above
     are about EIP-6780 and not about a fixture whose SELFDESTRUCT never ran. *)
  List.iter
    (fun spec ->
      Alcotest.(check bool)
        (Spec.to_string spec ^ ": the heir receives the whole balance")
        true
        (U256.equal (u doomed_balance) (balance_after ~spec ~beneficiary:heir heir)))
    all_specs;
  (* Naming ITSELF as beneficiary separates the two rules in the world rather
     than in the removal record: pre-6780 the balance is burned with the
     account, and EIP-6780 leaves an uncreated account completely alone. *)
  Alcotest.(check bool) "a Shanghai block burns the balance with the account"
    true
    (U256.is_zero (balance_after ~spec:Spec.Shanghai ~beneficiary:doomed doomed));
  Alcotest.(check bool) "a Cancun block leaves it untouched" true
    (U256.equal (u doomed_balance)
       (balance_after ~spec:Spec.Cancun ~beneficiary:doomed doomed));
  Alcotest.(check bool) "as does a Prague block" true
    (U256.equal (u doomed_balance)
       (balance_after ~spec:Spec.Prague ~beneficiary:doomed doomed))

let () =
  Alcotest.run "fork_dispatch"
    [
      ( "defaults",
        [
          Alcotest.test_case "env-block-default-spec-is-prague" `Quick
            test_env_block_default_spec_is_prague;
          Alcotest.test_case "config-default-schedule-is-testnet" `Quick
            test_config_default_schedule_is_testnet;
          Alcotest.test_case "chain-spec-default-schedule-is-testnet" `Quick
            test_chain_spec_default_schedule_is_testnet;
          Alcotest.test_case "chain-spec-forwards-schedule-to-config" `Quick
            test_chain_spec_forwards_schedule_to_config;
          Alcotest.test_case "system-call-env-preserves-spec" `Quick
            test_system_call_env_preserves_spec;
        ] );
      ( "threading",
        [
          Alcotest.test_case "engine-mainnet-block-spec-is-shanghai" `Quick
            test_engine_mainnet_block_spec_is_shanghai;
          Alcotest.test_case "engine-block-spec-follows-block-timestamp" `Quick
            test_engine_block_spec_follows_block_timestamp;
        ] );
      ( "opcode activation",
        [
          Alcotest.test_case "tload-halts-at-shanghai" `Quick
            test_tload_halts_at_shanghai;
          Alcotest.test_case "tstore-halts-at-shanghai" `Quick
            test_tstore_halts_at_shanghai;
          Alcotest.test_case "mcopy-halts-at-shanghai" `Quick
            test_mcopy_halts_at_shanghai;
          Alcotest.test_case "blobhash-halts-at-shanghai" `Quick
            test_blobhash_halts_at_shanghai;
          Alcotest.test_case "blobbasefee-halts-at-shanghai" `Quick
            test_blobbasefee_halts_at_shanghai;
          Alcotest.test_case "not-activated-is-distinct" `Quick
            test_not_activated_is_distinct;
        ] );
      ( "executor gates",
        [
          Alcotest.test_case "floor-zero-at-cancun" `Quick
            test_floor_zero_at_cancun;
          Alcotest.test_case "addr-0x0a-cold-at-shanghai" `Quick
            test_addr_0x0a_cold_at_shanghai;
          Alcotest.test_case "type4-rejected-at-cancun" `Quick
            test_type4_rejected_at_cancun;
        ] );
      ( "block gates",
        [
          Alcotest.test_case "preblock-shanghai-writes-neither" `Quick
            test_preblock_shanghai_writes_neither;
          Alcotest.test_case "preblock-cancun-writes-4788-only" `Quick
            test_preblock_cancun_writes_4788_only;
          Alcotest.test_case "preblock-prague-writes-both" `Quick
            test_preblock_prague_writes_both;
          Alcotest.test_case
            "preexisting-contract-selfdestruct-at-shanghai-destroys" `Quick
            test_preexisting_contract_selfdestruct_at_shanghai_destroys;
        ] );
    ]
