(* The chunk-30 block-execution spine: the two pinned system contracts, the
   system-call path, the pre-block EIP-4788 and EIP-2935 calls, and the
   per-transaction fold.

   INDEPENDENT ORACLES, each named where it is used:
   - the two runtime bytecodes and the three addresses are the verbatim hex of
     alloy-eips 1.8.3 (src/eip4788.rs:12-15, src/eip2935.rs:8-11), pinned as hex
     strings rather than as a digest so a reader diffs the literal against the
     crate with no decoding step;
   - the EIP-2935 slot arithmetic is pinned three ways: the hand disassembly of
     eip2935.rs:11, telcoin's engine test (crates/engine/tests/it/main.rs:100-110)
     and revm's own unit test (revm-handler-15.0.0/src/system_call.rs:295-326,
     "block with number 1 will set storage at slot 0");
   - the EIP-4788 slot pair is pinned by the disassembly of eip4788.rs:15 and by
     telcoin's engine test at main.rs:69-93;
   - the 43655-gas figure for a 2935 system call is revm's published 22143 frame
     figure (system_call.rs:302-316) plus this port's own intrinsic charge, with
     the whole derivation written out above the test.

   The fixtures, the miniature assembler and the synthetic signer live in
   block_fixtures.ml. *)

open Block_fixtures
module Bloom = Tn_evm.Bloom
module Block_execution = Tn_evm.Block_execution
module Block_gas = Tn_evm.Block_gas
module Block_roots = Tn_evm.Block_roots
module Executor = Tn_evm.Executor
module Intrinsic = Tn_evm.Intrinsic
module Receipt = Tn_evm.Receipt
module Receipt_envelope = Tn_evm.Receipt_envelope
module System_call = Tn_evm.System_call
module System_contracts = Tn_evm.System_contracts
module Trie = Tn_trie.Trie
module Pre_block = Block_execution.Pre_block

(* ------------------------------------------------------------------ *)
(* Reading spine results.                                              *)
(* ------------------------------------------------------------------ *)

let call_ok = function
  | Ok outcome -> outcome
  | Error e -> Alcotest.failf "unexpected system-call error: %s" (System_call.error_to_string e)

let pre_ok = function
  | Ok pre -> pre
  | Error e -> Alcotest.failf "unexpected pre-block error: %s" (Block_execution.error_to_string e)

let run_ok = function
  | Ok outcome -> outcome
  | Error e -> Alcotest.failf "unexpected block error: %s" (Block_execution.error_to_string e)

let block_error = function
  | Ok _ -> Alcotest.fail "expected the block to be refused"
  | Error e -> e

let root_written = function
  | Pre_block.Root_written outcome -> outcome
  | Pre_block.Root_skipped_at_genesis -> Alcotest.fail "expected Root_written, got the genesis skip"
  | Pre_block.Root_skipped_after_first_batch ->
      Alcotest.fail "expected Root_written, got the first-batch skip"

let hash_written = function
  | Pre_block.Hash_written outcome -> outcome
  | Pre_block.Hash_skipped_at_genesis -> Alcotest.fail "expected Hash_written, got the genesis skip"

let root_disposition = function
  | Pre_block.Root_written _ -> "written"
  | Pre_block.Root_skipped_at_genesis -> "skipped at genesis"
  | Pre_block.Root_skipped_after_first_batch -> "skipped after the first batch"

let hash_disposition = function
  | Pre_block.Hash_written _ -> "written"
  | Pre_block.Hash_skipped_at_genesis -> "skipped at genesis"

let refund_of = function
  | Receipt.Success { gas_refunded; _ } -> gas_refunded
  | Receipt.Reverted _ -> 0
  | Receipt.Halted _ -> 0

let receipt_is_success r =
  match r with
  | Receipt.Success _ -> true
  | Receipt.Reverted _ -> false
  | Receipt.Halted _ -> false

(* ================================================================== *)
(* 1. The pinned genesis fixture.                                      *)
(* ================================================================== *)

(* The two runtime bytecodes, verbatim from alloy-eips 1.8.3. Pinning the HEX
   rather than a keccak of it is deliberate: the hex is what the crate states,
   so this literal is diffable against the source by eye and needs no second
   hash function to be trusted. The 20-byte width of each address is the one
   rule this chunk could not lift to the type level (Units.Address.of_bytes is
   the only width-checking constructor and it is partial, so system_contracts.ml
   collapses each literal with Option.value ~default:Address.zero); that
   collapse is what the length assertions below are standing in front of. *)
let beacon_roots_code_hex =
  "3373fffffffffffffffffffffffffffffffffffffffe14604d57602036146024575f5ffd5b5f35801560495762001fff810690815414603c575f5ffd5b62001fff01545f5260205ff35b5f5ffd5b62001fff42064281555f359062001fff015500"

let history_storage_code_hex =
  "3373fffffffffffffffffffffffffffffffffffffffe14604657602036036042575f35600143038111604257611fff81430311604257611fff9006545f5260205ff35b5f5ffd5b5f35611fff60014303065500"

let test_system_contracts_are_pinned () =
  Alcotest.(check string)
    "EIP-4788 runtime bytecode" beacon_roots_code_hex
    (to_hex System_contracts.beacon_roots_code);
  Alcotest.(check string)
    "EIP-2935 runtime bytecode" history_storage_code_hex
    (to_hex System_contracts.history_storage_code);
  Alcotest.(check int) "EIP-4788 code length" 97 (String.length System_contracts.beacon_roots_code);
  Alcotest.(check int) "EIP-2935 code length" 83
    (String.length System_contracts.history_storage_code);
  Alcotest.(check string)
    "SYSTEM_ADDRESS" "fffffffffffffffffffffffffffffffffffffffe"
    (to_hex (Address.to_bytes System_contracts.system_address));
  Alcotest.(check string)
    "BEACON_ROOTS_ADDRESS" "000f3df6d732807ef1319fb7b8bb8522d0beac02"
    (to_hex (Address.to_bytes System_contracts.beacon_roots_address));
  Alcotest.(check string)
    "HISTORY_STORAGE_ADDRESS" "0000f90827f1c53a10cb7a02335b175320002935"
    (to_hex (Address.to_bytes System_contracts.history_storage_address));
  List.iter
    (fun (name, address) ->
      Alcotest.(check int) (name ^ " is 20 bytes") 20 (String.length (Address.to_bytes address));
      Alcotest.(check bool)
        (name ^ " is not the zero address")
        false
        (Address.equal address Address.zero))
    [
      ("SYSTEM_ADDRESS", System_contracts.system_address);
      ("BEACON_ROOTS_ADDRESS", System_contracts.beacon_roots_address);
      ("HISTORY_STORAGE_ADDRESS", System_contracts.history_storage_address);
    ];
  (* 8191, not 8192: ethereum/EIPs PR 9144 changed it. *)
  Alcotest.(check int) "HISTORY_SERVE_WINDOW" 8191 System_contracts.history_serve_window;
  (* The two canonical deployer EOAs telcoin's genesis pins at nonce 1. *)
  Alcotest.(check (list string))
    "deployer accounts"
    [ "0b799c86a49deeb90402691f1041aa3af2d3c875"; "3462413af4609098e1e27a490f554f260213d685" ]
    (List.map (fun a -> to_hex (Address.to_bytes a)) System_contracts.deployer_accounts);
  let world = System_contracts.predeploy World_state.empty in
  List.iter
    (fun (name, address, length) ->
      let acct = World_state.account world address in
      Alcotest.(check int) (name ^ " code length") length (Account.code_length acct);
      Alcotest.(check int) (name ^ " nonce") 0 (Nonce.to_int (Account.nonce acct));
      Alcotest.(check bool) (name ^ " balance zero") true (U256.is_zero (Account.balance acct));
      Alcotest.(check bool) (name ^ " is deployed") true (System_contracts.is_deployed world address))
    [
      ("beacon roots", System_contracts.beacon_roots_address, 97);
      ("history storage", System_contracts.history_storage_address, 83);
    ];
  List.iter
    (fun address ->
      let acct = World_state.account world address in
      Alcotest.(check int) "deployer nonce" 1 (Nonce.to_int (Account.nonce acct));
      Alcotest.(check int) "deployer code length" 0 (Account.code_length acct);
      Alcotest.(check bool) "deployer is present" true (present world address))
    System_contracts.deployer_accounts;
  Alcotest.(check bool)
    "the system address is NOT seated" false
    (present world System_contracts.system_address)

(* The genesis state root of the predeployed world. This is a REGRESSION pin
   computed by this port, not an external oracle: no alloy state-root oracle for
   a four-account world is on disk, and the trie itself is already pinned
   against alloy-trie 0.9.5 by test_block_roots.ml. What it buys is the one
   thing no other test would see: dropping either deployer EOA (nonce 1, no
   code, no balance) still leaves a world in which both contracts answer
   correctly, but changes the state root of block zero and of every block
   after it. *)
let predeployed_state_root_hex =
  "a204a6e8d2b5a9a33037d705139f6f80e9159a4c7599d1bf847b2ec3e49479b3"

let test_install_pins_the_genesis_state_root () =
  let world = System_contracts.predeploy World_state.empty in
  Alcotest.(check string)
    "predeployed genesis state root" predeployed_state_root_hex
    (to_hex (Block_roots.state_root world));
  Alcotest.(check bool)
    "differs from the empty-world root" false
    (String.equal (Block_roots.state_root world) (Block_roots.state_root World_state.empty));
  Alcotest.(check string)
    "the empty world is still the empty trie" (to_hex Trie.empty_root)
    (to_hex (Block_roots.state_root World_state.empty))

(* ================================================================== *)
(* 2. The system-call path.                                            *)
(* ================================================================== *)

(* There is no caller parameter to pass wrongly, so the only way to see which
   address the synthetic transaction is sent from is to ask a contract. *)
let test_the_caller_is_the_system_address () =
  let target = address_of 0xd4 in
  let world = with_code World_state.empty target caller_recorder in
  let outcome = call_ok (System_call.run world ~block:(block_env ()) ~contract:target ~data:"") in
  Alcotest.(check bool) "the call succeeded" true (System_call.succeeded outcome);
  Alcotest.(check string)
    "slot 0 holds SYSTEM_ADDRESS"
    (to_hex (U256.to_be_bytes (Tn_state.Address_word.to_word System_contracts.system_address)))
    (slot_hex (System_call.world outcome) target 0)

(* Half (a): only the target's account is committed, even when the frame writes
   through a sub-call. The sub-call's write is asserted to be REAL by running
   the same code through Executor.execute directly, which is the unretained
   path; without that half the assertion would hold for a fixture that simply
   never wrote anything.

   Half (b): after both pre-block calls the system address is absent, not merely
   at nonce zero. The full pipeline bumps its nonce (executor.ml:236-250) and a
   nonzero nonce makes the account non-empty under EIP-161, so committing it
   would put it in the state trie and diverge the state root. *)
let test_only_the_target_survives_the_call () =
  let callee = address_of 0xe5 in
  let target = address_of 0xd4 in
  let world =
    with_code (with_code World_state.empty callee (slot_writer ~slot:1 ~value:0x2a)) target
      (sub_caller ~callee)
  in
  let outcome = call_ok (System_call.run world ~block:(block_env ()) ~contract:target ~data:"") in
  Alcotest.(check bool) "the call succeeded" true (System_call.succeeded outcome);
  let retained = System_call.world outcome in
  Alcotest.(check int) "the sub-call's write is dropped" 0
    (get (U256.to_int (slot retained callee 1)));
  Alcotest.(check bool)
    "the callee's account is byte-identical to its pre-call value" true
    (Account.equal (World_state.account world callee) (World_state.account retained callee));
  (* The unretained path, to prove the write really happens. *)
  let tx =
    Tn_evm.Transaction.make ~sender:System_contracts.system_address ~nonce:Nonce.zero
      ~gas_limit:System_call.gas_limit
      ~kind:(Tn_evm.Transaction.Call target)
      ~value:U256.zero ~data:"" ~access_list:[] ~chain_id:None
      ~fee:(Tn_evm.Transaction.Legacy { gas_price = U256.zero })
  in
  let raw_world =
    match Executor.execute world ~block:(block_env ()) tx with
    | Ok (_, w) -> w
    | Error e -> Alcotest.failf "the unretained run was rejected: %s" (Executor.error_to_string e)
  in
  Alcotest.(check int) "the unretained world DOES carry the sub-call's write" 0x2a
    (get (U256.to_int (slot raw_world callee 1)));
  (* Half (b). *)
  let installed = System_contracts.predeploy World_state.empty in
  let pre = pre_ok (Block_execution.apply_pre_block installed ~context:(context ())) in
  let after = Pre_block.world pre in
  Alcotest.(check int) "the system address is at nonce 0" 0
    (Nonce.to_int (World_state.nonce after System_contracts.system_address));
  Alcotest.(check bool)
    "the system address is absent from the world" false
    (present after System_contracts.system_address);
  Alcotest.(check bool)
    "the coinbase is untouched" true
    (Account.equal (World_state.account installed coinbase) (World_state.account after coinbase))

(* A call into a codeless account succeeds and writes nothing. This is the
   discharge of the run-real-bytecode decision: a port that MODELLED the two
   writes with set_storage would materialize an account at the target and change
   the state root, and no assertion here would pass.

   The gas is the intrinsic charge alone, and the EIP-7623 floor binds: 32
   nonzero calldata bytes are 128 tokens, so the initial charge is
   21000 + 4*128 = 21512 while the floor is 21000 + 10*128 = 22280, and the
   executor charges the floor. The chunk's test plan predicted 21512 for this
   case, which omits the floor; the number below is what the EIP requires and
   the derivation is spelled out rather than the literal being adjusted. *)
let test_an_undeployed_target_is_a_silent_no_op () =
  let data = String.make 32 '\xab' in
  let world = world_seed [ (coinbase, account ~nonce:0 ~balance:0) ] in
  let outcome =
    call_ok
      (System_call.run world ~block:(block_env ())
         ~contract:System_contracts.beacon_roots_address ~data)
  in
  Alcotest.(check bool) "an empty target still succeeds" true (System_call.succeeded outcome);
  Alcotest.(check int) "intrinsic gas of 32 nonzero calldata bytes" 21512
    (Intrinsic.initial_gas ~kind:Intrinsic.Call ~data ~access_list:[]);
  Alcotest.(check int) "the EIP-7623 floor of the same calldata" 22280
    (Intrinsic.floor_gas ~data);
  Alcotest.(check int) "gas used is the binding floor" 22280
    (Receipt.gas_used (System_call.receipt outcome));
  Alcotest.(check bool)
    "no account is created at the target" false
    (present (System_call.world outcome) System_contracts.beacon_roots_address);
  Alcotest.(check bool)
    "the world is unchanged" true
    (World_state.equal world (System_call.world outcome));
  (* And the same through the pre-block hook, where both targets are empty. *)
  let pre = pre_ok (Block_execution.apply_pre_block world ~context:(context ())) in
  Alcotest.(check string)
    "an uninstalled world's state root survives both calls"
    (to_hex (Block_roots.state_root world))
    (to_hex (Block_roots.state_root (Pre_block.world pre)))

(* ================================================================== *)
(* 3. The two contracts' slot arithmetic, run as real bytecode.        *)
(* ================================================================== *)

(* EIP-4788 writes a PAIR of slots: ts mod 8191 <- the timestamp, and
   ts mod 8191 + 8191 <- the root. 1_700_000_000 mod 8191 = 7096, so the pair is
   (7096, 15287); both are nonzero and distinct, so neither a missing MOD nor a
   swapped SSTORE pair could pass. *)
let test_beacon_roots_slot_arithmetic () =
  let timestamp = 1_700_000_000 in
  let ring = timestamp mod System_contracts.history_serve_window in
  Alcotest.(check int) "the ring index" 7096 ring;
  let installed = System_contracts.predeploy World_state.empty in
  let ctx = context ~timestamp ~batch_index:0 ~worker_id:3 () in
  let pre = pre_ok (Block_execution.apply_pre_block installed ~context:ctx) in
  let world = Pre_block.world pre in
  let beacon = System_contracts.beacon_roots_address in
  Alcotest.(check int) "slot (ts mod 8191) holds the timestamp" timestamp
    (get (U256.to_int (slot world beacon ring)));
  Alcotest.(check string)
    "slot (ts mod 8191 + 8191) holds the consensus root"
    (to_hex (Digest.to_bytes (Digests.Output_digest.to_digest consensus_root)))
    (slot_hex world beacon (ring + System_contracts.history_serve_window));
  Alcotest.(check int) "exactly two slots were written" 2 (slots_set world beacon);
  Alcotest.(check string) "the disposition is Root_written" "written"
    (root_disposition (Pre_block.consensus_root pre));
  Alcotest.(check bool) "the 4788 call succeeded" true
    (System_call.succeeded (root_written (Pre_block.consensus_root pre)))

(* EIP-2935 is indexed by the PARENT: (current number - 1) mod 8191, valued by
   the calldata, which is the parent hash. Each case asserts BOTH the slot that
   must hold the hash and the adjacent slot that must not, because deleting the
   PUSH1 1; NUMBER; SUB from the fixture would satisfy the first half of a
   one-sided assertion. *)
let test_history_storage_is_indexed_by_the_parent () =
  let installed = System_contracts.predeploy World_state.empty in
  let history = System_contracts.history_storage_address in
  let parent_hex = to_hex (Tn_keccak.to_bytes parent_hash) in
  let run number =
    let pre = pre_ok (Block_execution.apply_pre_block installed ~context:(context ~number ())) in
    Alcotest.(check string) "the disposition is Hash_written" "written"
      (hash_disposition (Pre_block.blockhashes pre));
    Alcotest.(check bool) "the 2935 call succeeded" true
      (System_call.succeeded (hash_written (Pre_block.blockhashes pre)));
    Pre_block.world pre
  in
  (* revm's own fixture: "block with number 1 will set storage at slot 0". *)
  let w1 = run 1 in
  Alcotest.(check string) "number 1 writes slot 0" parent_hex (slot_hex w1 history 0);
  Alcotest.(check int) "number 1 writes exactly one slot" 1 (slots_set w1 history);
  let w2 = run 20_000 in
  Alcotest.(check string) "number 20000 writes slot 3617" parent_hex (slot_hex w2 history 3617);
  Alcotest.(check int) "number 20000 leaves slot 3618 zero" 0
    (get (U256.to_int (slot w2 history 3618)));
  let w3 = run 8193 in
  Alcotest.(check string) "number 8193 writes slot 1" parent_hex (slot_hex w3 history 1);
  Alcotest.(check int) "number 8193 leaves slot 2 zero" 0 (get (U256.to_int (slot w3 history 2)));
  Alcotest.(check int) "number 8193 leaves slot 8191 zero" 0
    (get (U256.to_int (slot w3 history 8191)))

(* first_batch gates 4788 and NEVER gates 2935. A port that gated both would
   write a different state root on every non-first batch of every consensus
   output. *)
let test_first_batch_gates_4788_but_never_2935 () =
  let installed = System_contracts.predeploy World_state.empty in
  let beacon = System_contracts.beacon_roots_address in
  let history = System_contracts.history_storage_address in
  let ring = 1_700_000_000 mod System_contracts.history_serve_window in
  let first = context ~batch_index:0 ~worker_id:3 () in
  let later = context ~batch_index:1 ~worker_id:3 () in
  Alcotest.(check bool) "batch 0 is the first batch" true (Block_context.first_batch first);
  Alcotest.(check bool) "batch 1 is not" false (Block_context.first_batch later);
  let pre_first = pre_ok (Block_execution.apply_pre_block installed ~context:first) in
  let pre_later = pre_ok (Block_execution.apply_pre_block installed ~context:later) in
  Alcotest.(check string) "batch 0 writes the consensus root" "written"
    (root_disposition (Pre_block.consensus_root pre_first));
  Alcotest.(check string) "batch 1 skips it, and says why" "skipped after the first batch"
    (root_disposition (Pre_block.consensus_root pre_later));
  Alcotest.(check int) "batch 0 sets both beacon slots" 2
    (slots_set (Pre_block.world pre_first) beacon);
  Alcotest.(check int) "batch 1 sets none" 0 (slots_set (Pre_block.world pre_later) beacon);
  Alcotest.(check int) "batch 1 leaves the timestamp slot zero" 0
    (get (U256.to_int (slot (Pre_block.world pre_later) beacon ring)));
  List.iter
    (fun (name, pre) ->
      Alcotest.(check string) (name ^ ": the blockhashes call runs") "written"
        (hash_disposition (Pre_block.blockhashes pre));
      Alcotest.(check int)
        (name ^ ": the history slot is set")
        1
        (slots_set (Pre_block.world pre) history))
    [ ("batch 0", pre_first); ("batch 1", pre_later) ]

(* is_first_batch is a predicate on the WORD, which is telcoin's own comparison
   (block.rs:105-107) and not an extraction. This is the port's replacement for
   the 27-line prose argument at block.rs:78-104. *)
let arb_pair =
  QCheck.make
    ~print:(fun (b, w) -> Printf.sprintf "(batch_index=%d, worker_id=%d)" b w)
    QCheck.Gen.(pair (int_range 0 1_048_575) (int_range 0 65535))

let arb_word =
  QCheck.make
    ~print:(fun n -> Printf.sprintf "word=%d" n)
    QCheck.Gen.(int_range 0 max_int)

let prop_boundary =
  QCheck.Test.make ~count:1 ~name:"the 65536 boundary" QCheck.unit (fun () ->
      Batch_position.is_first_batch (Batch_position.of_word (u 65535))
      && not (Batch_position.is_first_batch (Batch_position.of_word (u 65536))))

let prop_pack =
  QCheck.Test.make ~count:200 ~name:"pack, project, gate" arb_pair (fun (b, w) ->
      let worker_id = get (Units.Worker_id.of_int w) in
      let zero = get (Batch_position.of_batch ~batch_index:0 ~worker_id) in
      let later = get (Batch_position.of_batch ~batch_index:(1 + b) ~worker_id) in
      let any = get (Batch_position.of_batch ~batch_index:b ~worker_id) in
      Batch_position.is_first_batch zero
      && (not (Batch_position.is_first_batch later))
      && Option.equal Int.equal (Batch_position.batch_index any) (Some b)
      && Option.equal Units.Worker_id.equal (Batch_position.worker_id any) (Some worker_id))

let prop_word_round_trip =
  QCheck.Test.make ~count:200 ~name:"of_word is total and lossless" arb_word (fun n ->
      U256.equal (Batch_position.word (Batch_position.of_word (u n))) (u n))

let check_property t () =
  QCheck.Test.check_exn ~rand:(Random.State.make [| 0x30b10c; 0x5eed |]) t

(* ================================================================== *)
(* 4. Gas, on the system-call path and in the fold.                    *)
(* ================================================================== *)

(* revm's published figure for the 2935 frame is 22143
   (system_call.rs:302-316): 21 for the caller test (CALLER 2, PUSH20 3, EQ 3,
   PUSH1 3, JUMPI 10) + 1 JUMPDEST + 21 for the slot computation (PUSH0 2,
   CALLDATALOAD 3, PUSH2 3, PUSH1 3, NUMBER 2, SUB 3, MOD 5) + 22100 for the
   cold zero-to-nonzero SSTORE. Telcoin does NOT take revm's run_system_call
   fast path (evm/mod.rs:164-221 versus handler.rs:108-137), so the intrinsic
   charge is paid too: 32 nonzero calldata bytes are 128 tokens, giving
   21000 + 4*128 = 21512. The total is 43655, comfortably above the EIP-7623
   floor of 21000 + 10*128 = 22280, so the floor does not bind. *)
let test_eip2935_gas_matches_revms_fixture_plus_intrinsic () =
  let data = String.make 32 '\xab' in
  let installed = System_contracts.predeploy World_state.empty in
  let outcome =
    call_ok
      (System_call.run installed ~block:(block_env ())
         ~contract:System_contracts.history_storage_address ~data)
  in
  Alcotest.(check bool) "the call succeeded" true (System_call.succeeded outcome);
  Alcotest.(check int) "frame plus intrinsic" 43655 (Receipt.gas_used (System_call.receipt outcome));
  Alcotest.(check int) "of which the intrinsic charge" 21512
    (Intrinsic.initial_gas ~kind:Intrinsic.Call ~data ~access_list:[])

(* Block zero: the consensus root must be zero, and NEITHER call is made. The
   2935 skip is not hygiene: the contract would compute (0 - 1) mod 8191 in
   256-bit arithmetic and write (2^256 - 1) mod 8191, an absurd slot. *)
let test_genesis_gates_on_both_calls () =
  let attempt root =
    Block_context.make
      ~block:(block_env ~number:0 ())
      ~parent_hash ~consensus_root:root
      ~nonce:(sequence_number ~epoch:0 ~round:0)
      ~batch_digest
      ~position:(position_of ~batch_index:0 ~worker_id:0)
      ~boundary:Epoch_boundary.Open
  in
  Alcotest.(check string)
    "a nonzero root at block zero is refused"
    "block zero carries a nonzero consensus root"
    (Result.fold ~ok:(fun _ -> "accepted") ~error:Block_context.error_to_string
       (attempt consensus_root));
  let ctx = get_ok (attempt zero_output_digest) in
  Alcotest.(check bool) "the context is genesis" true (Block_context.is_genesis ctx);
  let installed = System_contracts.predeploy World_state.empty in
  let pre = pre_ok (Block_execution.apply_pre_block installed ~context:ctx) in
  Alcotest.(check string) "no consensus-root call" "skipped at genesis"
    (root_disposition (Pre_block.consensus_root pre));
  Alcotest.(check string) "no blockhashes call" "skipped at genesis"
    (hash_disposition (Pre_block.blockhashes pre));
  Alcotest.(check bool) "the world is untouched" true
    (World_state.equal installed (Pre_block.world pre));
  Alcotest.(check int) "no beacon slot" 0
    (slots_set (Pre_block.world pre) System_contracts.beacon_roots_address);
  Alcotest.(check int) "no history slot" 0
    (slots_set (Pre_block.world pre) System_contracts.history_storage_address)

(* ------------------------------------------------------------------ *)
(* The fold: cumulative gas, the block budget, and refusal.            *)
(* ------------------------------------------------------------------ *)

(* An independent receipts root: the cumulative values are computed here by an
   explicit running prefix over the receipt list and each envelope is encoded
   with them, rather than by Block_roots' own fold. If the two disagree the
   header's gas_used and its receipts root are committing different numbers. *)
let independent_receipts_root pairs =
  let cumulative =
    List.rev
      (snd
         (List.fold_left
            (fun (running, acc) (_, receipt) ->
              let running = running + Receipt.gas_used receipt in
              (running, running :: acc))
            (0, []) pairs))
  in
  Trie.ordered_trie_root
    (List.map2
       (fun (type_byte, receipt) cumulative_gas_used ->
         Receipt_envelope.encode_2718 ~type_byte ~cumulative_gas_used receipt)
       pairs cumulative)

(* A three-transaction block whose middle transaction earns an SSTORE-clear
   refund, so gross and net gas differ and the meter cannot be advancing by the
   gross figure. *)
let test_cumulative_gas_agrees_with_the_receipts_root () =
  let clearer = address_of 0xf6 in
  let installed = System_contracts.predeploy World_state.empty in
  let world =
    World_state.set_account installed clearer
      (Account.set_slot
         (Account.with_code
            (Account.make ~nonce:Nonce.zero ~balance:U256.zero)
            (slot_writer ~slot:1 ~value:0))
         (u 1) (u 42))
  in
  let envelopes =
    [
      legacy_envelope ~signer:1 ~gas_limit:100_000 ~value:7 ();
      legacy_envelope ~signer:2 ~gas_limit:100_000 ~kind:(Tn_evm.Transaction.Call clearer) ();
      legacy_envelope ~signer:3 ~gas_limit:100_000 ~value:11 ();
    ]
  in
  let world = fund world envelopes in
  let ctx = context () in
  let _, outcome = run_ok (Block_execution.execute world ~context:ctx envelopes) in
  let receipts = Block_execution.receipts outcome in
  Alcotest.(check int) "three receipts" 3 (List.length receipts);
  Alcotest.(check int) "three transactions" 3
    (List.length (Block_execution.transactions outcome));
  Alcotest.(check bool)
    "the middle transaction really earned a refund" true
    (refund_of (snd (List.nth receipts 1)) > 0);
  Alcotest.(check int) "the block's gas_used is the sum of the receipts'"
    (List.fold_left (fun acc (_, r) -> acc + Receipt.gas_used r) 0 receipts)
    (Block_execution.gas_used outcome);
  Alcotest.(check string)
    "the receipts root agrees with an independently threaded prefix sum"
    (to_hex (independent_receipts_root receipts))
    (to_hex (Block_roots.receipts_root receipts));
  Alcotest.(check bool)
    "and the slot really was cleared" true
    (U256.is_zero (slot (Block_execution.world outcome) clearer 1))

(* The block-available-gas check is telcoin's, and it is strictly stronger than
   the per-transaction Gas_limit_above_block the executor already applies: it
   compares against the REMAINDER. *)
let test_block_available_gas_bounds_the_fold () =
  let installed = System_contracts.predeploy World_state.empty in
  (* Exactly two 21000-gas transfers fit a 42000-gas block. *)
  let pair = [ legacy_envelope ~signer:4 ~gas_limit:21_000 (); legacy_envelope ~signer:5 ~gas_limit:21_000 () ] in
  let world = fund installed pair in
  let _, outcome =
    run_ok (Block_execution.execute world ~context:(context ~gas_limit:42_000 ()) pair)
  in
  Alcotest.(check int) "both transfers fit exactly" 42_000 (Block_execution.gas_used outcome);
  (* A spender whose frame is expensive enough that the remainder refuses the
     second transaction even though the block limit alone would admit it. *)
  let writer = address_of 0xf7 in
  let world2 =
    fund
      (with_code installed writer (slot_writer ~slot:2 ~value:0x5a))
      [ legacy_envelope ~signer:6 ~gas_limit:60_000 ~kind:(Tn_evm.Transaction.Call writer) () ]
  in
  let first = legacy_envelope ~signer:6 ~gas_limit:60_000 ~kind:(Tn_evm.Transaction.Call writer) () in
  let second = legacy_envelope ~signer:7 ~gas_limit:60_000 () in
  let world2 = fund world2 [ second ] in
  let ctx = context ~gas_limit:100_000 () in
  let _, alone = run_ok (Block_execution.execute world2 ~context:ctx [ first ]) in
  let used_1 = Block_execution.gas_used alone in
  Alcotest.(check bool) "the first transaction is expensive enough to bind" true (used_1 > 40_000);
  let e = block_error (Block_execution.execute world2 ~context:ctx [ first; second ]) in
  Alcotest.(check string)
    "the second is refused against the REMAINDER"
    (Printf.sprintf "transaction 1 wants 60000 gas but only %d remain in the block"
       (100_000 - used_1))
    (Block_execution.error_to_string e);
  (* And the two system calls, which burn 43655 + 65763 gas between them, do not
     consume any of the block's budget: a transaction whose limit is the FULL
     block gas limit is still accepted after both have run. *)
  let solo = legacy_envelope ~signer:8 ~gas_limit:100_000 () in
  let world3 = fund installed [ solo ] in
  let pre = pre_ok (Block_execution.apply_pre_block world3 ~context:ctx) in
  Alcotest.(check string) "both pre-block calls ran" "written"
    (root_disposition (Pre_block.consensus_root pre));
  Alcotest.(check string) "including the blockhashes call" "written"
    (hash_disposition (Pre_block.blockhashes pre));
  let outcome = run_ok (Block_execution.run_transactions pre ~context:ctx [ solo ]) in
  Alcotest.(check int) "the full-limit transaction was still admitted" 1
    (List.length (Block_execution.receipts outcome));
  Alcotest.(check int) "and the meter counts only it" 21_000 (Block_execution.gas_used outcome)

(* This module is the block EXECUTOR, so an invalid transaction is an error and
   not a skip. The builder's log-and-continue behaviour (tn-reth/src/lib.rs:783-800)
   belongs above it and would simply hand this function a shorter list. *)
let test_an_invalid_transaction_stops_the_block () =
  let installed = System_contracts.predeploy World_state.empty in
  let envelopes =
    [
      legacy_envelope ~signer:11 ~gas_limit:21_000 ();
      legacy_envelope ~signer:12 ~gas_limit:21_000 ();
      legacy_envelope ~signer:13 ~gas_limit:21_000 ();
    ]
  in
  let world = fund installed envelopes in
  (* The middle sender is seated at nonce 5 while its transaction says 0. *)
  let stale =
    World_state.set_account world
      (sender_of (List.nth envelopes 1))
      (account ~nonce:5 ~balance:1_000_000_000_000)
  in
  Alcotest.(check string)
    "a stale nonce stops the block at index 1"
    "transaction 1 rejected: nonce mismatch (expected 5, got 0)"
    (Block_execution.error_to_string
       (block_error (Block_execution.execute stale ~context:(context ()) envelopes)));
  (* A high-s signature is refused in recovery, before execution. *)
  let high_s =
    Tx_envelope.make
      ~payload:(Tx_envelope.payload (List.nth envelopes 1))
      ~signature:(Tx_signature.make ~parity:false ~r:curve_r ~s:U256.max_value)
  in
  let with_high_s = [ List.nth envelopes 0; high_s; List.nth envelopes 2 ] in
  Alcotest.(check string)
    "a high-s signature stops the block at index 1"
    "transaction 1: signature s exceeds secp256k1n/2 (EIP-2)"
    (Block_execution.error_to_string
       (block_error (Block_execution.execute world ~context:(context ()) with_high_s)))

(* A system call builds no receipt, so its logs are outside the header
   commitment: block.rs:957 computes the bloom from the RECEIPTS only. The
   fixture is a log-emitting contract seated at the history-storage address, so
   the 2935 call really does emit one. *)
let test_system_call_logs_never_enter_the_block_bloom () =
  let world =
    with_code World_state.empty System_contracts.history_storage_address (log_emitter ~topic:0x11)
  in
  let ctx = context () in
  let pre = pre_ok (Block_execution.apply_pre_block world ~context:ctx) in
  let emitted = Receipt.logs (System_call.receipt (hash_written (Pre_block.blockhashes pre))) in
  Alcotest.(check int) "the system call really emitted a log" 1 (List.length emitted);
  Alcotest.(check bool)
    "and that log alone would make a nonempty bloom" false
    (Bloom.equal (Bloom.of_logs emitted) Bloom.empty);
  let outcome = run_ok (Block_execution.run_transactions pre ~context:ctx []) in
  Alcotest.(check bool) "the block bloom is empty" true
    (Bloom.equal (Block_execution.logs_bloom outcome) Bloom.empty);
  Alcotest.(check string)
    "256 zero bytes"
    (String.concat "" (List.init 256 (fun _ -> "00")))
    (to_hex (Bloom.to_bytes (Block_execution.logs_bloom outcome)))

(* The converse, and the one that makes the block bloom load-bearing rather than
   decorative: a TRANSACTION's logs must reach it. Without this the whole
   computation is vacuous, because every other bloom assertion in this file is
   satisfied by the empty bloom, so replacing the fold with Bloom.empty passes.
   block.rs:957 builds the field from every receipt's logs, and a block whose
   logsBloom is 256 zero bytes when a transaction emitted a log hashes to a
   header no other client agrees with. *)
let test_transaction_logs_reach_the_block_bloom () =
  let callee = address_of 0xb2 in
  let envelopes = [ legacy_envelope ~signer:41 ~gas_limit:100_000 () ] in
  let world = with_code (fund World_state.empty envelopes) callee (log_emitter ~topic:0x5a) in
  let ctx = context () in
  let pre = pre_ok (Block_execution.apply_pre_block world ~context:ctx) in
  let outcome = run_ok (Block_execution.run_transactions pre ~context:ctx envelopes) in
  let logs = List.concat_map (fun (_, r) -> Receipt.logs r) (Block_execution.receipts outcome) in
  Alcotest.(check int) "the transaction emitted one log" 1 (List.length logs);
  Alcotest.(check bool)
    "so the block bloom is NOT empty" false
    (Bloom.equal (Block_execution.logs_bloom outcome) Bloom.empty);
  Alcotest.(check string)
    "and it is exactly the bloom of every receipt's logs"
    (to_hex (Bloom.to_bytes (Bloom.of_logs logs)))
    (to_hex (Bloom.to_bytes (Block_execution.logs_bloom outcome)))

(* Receipt and transaction ORDER, which nothing else observes. Both
   accumulators are built by pushing onto the head and reversed once at the
   end, so dropping either reversal is a one-word change no length check or
   self-comparison can see. It is not cosmetic: Block_roots.receipts_root walks
   the list building an INCLUSIVE prefix sum, so a reversed list gives the last
   transaction a cumulative_gas_used of its own gas and the first the block
   total, and keys trie slot i with the wrong receipt. The block's gas_used, an
   order-free sum, still matches, so the header hash diverges silently. *)
let test_receipt_and_transaction_order_is_execution_order () =
  (* Three distinct intrinsic-gas costs, via three distinct calldata lengths: a
     nonzero calldata byte is 16 gas, so these differ by 160 apiece. *)
  let envelopes =
    [
      legacy_envelope ~signer:51 ~gas_limit:100_000 ~data:"" ();
      legacy_envelope ~signer:52 ~gas_limit:100_000 ~data:(String.make 10 '\xab') ();
      legacy_envelope ~signer:53 ~gas_limit:100_000 ~data:(String.make 20 '\xab') ();
    ]
  in
  let world = fund World_state.empty envelopes in
  let ctx = context () in
  let pre = pre_ok (Block_execution.apply_pre_block world ~context:ctx) in
  let outcome = run_ok (Block_execution.run_transactions pre ~context:ctx envelopes) in
  (* The envelopes come back as the very ones handed in, in that order. *)
  Alcotest.(check (list string))
    "transactions are the submitted envelopes in submission order"
    (List.map (fun e -> to_hex (Tx_envelope.encode_2718 e)) envelopes)
    (List.map (fun e -> to_hex (Tx_envelope.encode_2718 e)) (Block_execution.transactions outcome));
  (* And the receipts line up with them: strictly increasing gas, because each
     transaction carries strictly more calldata than the one before. Reversing
     the list makes this strictly DECREASING. *)
  let gas = List.map (fun (_, r) -> Receipt.gas_used r) (Block_execution.receipts outcome) in
  Alcotest.(check int) "three receipts" 3 (List.length gas);
  let rec strictly_increasing = function
    | [] | [ _ ] -> true
    | a :: (b :: _ as rest) -> a < b && strictly_increasing rest
  in
  Alcotest.(check bool)
    "receipt gas is strictly increasing in submission order" true (strictly_increasing gas);
  (* The spine's own total must equal the sum over the receipts it reports, which
     is the quantity Block_roots.receipts_root re-derives as a prefix sum. *)
  Alcotest.(check int)
    "gas_used is the sum of the receipts in that order"
    (List.fold_left ( + ) 0 gas)
    (Block_execution.gas_used outcome)

(* ================================================================== *)
(* 5. The end-to-end spine.                                            *)
(* ================================================================== *)

(* One block, the real predeployed bytecode, both pre-block calls and two
   transactions. Every storage slot the disassembly predicts is asserted, and
   nothing else at either address is. This is the test that would fail if any
   one of the twelve properties System_call.run leans on stopped holding, since
   a Rejected would surface as a block error rather than as a wrong root. *)
let test_spine_end_to_end () =
  let number = 12_345 in
  let timestamp = 1_700_000_000 in
  let ring = timestamp mod System_contracts.history_serve_window in
  let recipient = address_of 0xb2 in
  let installed = System_contracts.predeploy World_state.empty in
  let envelopes =
    [
      legacy_envelope ~signer:21 ~gas_limit:50_000 ~value:1_000 ();
      legacy_envelope ~signer:22 ~gas_limit:50_000 ~value:2_500 ();
    ]
  in
  let world = fund installed envelopes in
  let ctx = context ~number ~timestamp ~batch_index:0 ~worker_id:1 () in
  let pre, outcome = run_ok (Block_execution.execute world ~context:ctx envelopes) in
  (* Both system calls ran and both succeeded. *)
  Alcotest.(check bool) "the 4788 call succeeded" true
    (System_call.succeeded (root_written (Pre_block.consensus_root pre)));
  Alcotest.(check bool) "the 2935 call succeeded" true
    (System_call.succeeded (hash_written (Pre_block.blockhashes pre)));
  let final = Block_execution.world outcome in
  let beacon = System_contracts.beacon_roots_address in
  let history = System_contracts.history_storage_address in
  (* EIP-4788: the (timestamp, root) pair. *)
  Alcotest.(check int) "beacon slot ts mod 8191 holds the timestamp" timestamp
    (get (U256.to_int (slot final beacon ring)));
  Alcotest.(check string)
    "beacon slot ts mod 8191 + 8191 holds the consensus root"
    (to_hex (Digest.to_bytes (Digests.Output_digest.to_digest consensus_root)))
    (slot_hex final beacon (ring + System_contracts.history_serve_window));
  Alcotest.(check int) "and nothing else at the beacon address" 2 (slots_set final beacon);
  (* EIP-2935: (number - 1) mod 8191 holds the PARENT hash. *)
  Alcotest.(check string)
    "history slot (number - 1) mod 8191 holds the parent hash"
    (to_hex (Tn_keccak.to_bytes parent_hash))
    (slot_hex final history ((number - 1) mod System_contracts.history_serve_window));
  Alcotest.(check int) "and nothing else at the history address" 1 (slots_set final history);
  Alcotest.(check int) "the current number's slot is untouched" 0
    (get (U256.to_int (slot final history (number mod System_contracts.history_serve_window))));
  (* The system address never lands in the trie. *)
  Alcotest.(check bool)
    "SYSTEM_ADDRESS is absent from the post-block world" false
    (present final System_contracts.system_address);
  (* The transactions really executed. *)
  Alcotest.(check int) "the recipient received both transfers" 3_500
    (get (U256.to_int (World_state.balance final recipient)));
  Alcotest.(check int) "two receipts" 2 (List.length (Block_execution.receipts outcome));
  Alcotest.(check int) "two plain transfers" 42_000 (Block_execution.gas_used outcome);
  Alcotest.(check int) "the meter's own view agrees"
    (Block_execution.gas_used outcome)
    (List.fold_left (fun acc (_, r) -> acc + Receipt.gas_used r) 0
       (Block_execution.receipts outcome));
  Alcotest.(check bool) "every receipt is a success" true
    (List.for_all (fun (_, r) -> receipt_is_success r) (Block_execution.receipts outcome))

(* Both system calls in ONE block each see SYSTEM_ADDRESS at nonce zero. That is
   what the retain buys beyond hygiene: the executor bumps the caller's nonce,
   and if the bump were committed the second call's Nonce_mismatch would reject
   it. Asserted by observing that the second call succeeds AND that the world
   between the two carries no system account. *)
let test_both_calls_see_nonce_zero () =
  let installed = System_contracts.predeploy World_state.empty in
  let block = block_env () in
  let data = String.make 32 '\x07' in
  let first =
    call_ok
      (System_call.run installed ~block ~contract:System_contracts.beacon_roots_address ~data)
  in
  let between = System_call.world first in
  Alcotest.(check int) "after the first call the system nonce is 0" 0
    (Nonce.to_int (World_state.nonce between System_contracts.system_address));
  let second =
    call_ok
      (System_call.run between ~block ~contract:System_contracts.history_storage_address ~data)
  in
  Alcotest.(check bool) "the second call succeeded" true (System_call.succeeded second);
  Alcotest.(check int) "and the system nonce is still 0" 0
    (Nonce.to_int (World_state.nonce (System_call.world second) System_contracts.system_address));
  Alcotest.(check bool)
    "the system address is absent throughout" false
    (present (System_call.world second) System_contracts.system_address)

let () =
  Alcotest.run "block-execution"
    [
      ( "system-contracts",
        [
          Alcotest.test_case "the fixture is pinned" `Quick test_system_contracts_are_pinned;
          Alcotest.test_case "predeploy pins the genesis state root" `Quick
            test_install_pins_the_genesis_state_root;
        ] );
      ( "system-call",
        [
          Alcotest.test_case "the caller is SYSTEM_ADDRESS" `Quick
            test_the_caller_is_the_system_address;
          Alcotest.test_case "only the target survives" `Quick
            test_only_the_target_survives_the_call;
          Alcotest.test_case "an undeployed target is a silent no-op" `Quick
            test_an_undeployed_target_is_a_silent_no_op;
          Alcotest.test_case "both calls see nonce zero" `Quick test_both_calls_see_nonce_zero;
          Alcotest.test_case "2935 gas is revm's frame plus intrinsic" `Quick
            test_eip2935_gas_matches_revms_fixture_plus_intrinsic;
        ] );
      ( "pre-block",
        [
          Alcotest.test_case "EIP-4788 writes the (timestamp, root) pair" `Quick
            test_beacon_roots_slot_arithmetic;
          Alcotest.test_case "EIP-2935 is indexed by the parent" `Quick
            test_history_storage_is_indexed_by_the_parent;
          Alcotest.test_case "first_batch gates 4788 but never 2935" `Quick
            test_first_batch_gates_4788_but_never_2935;
          Alcotest.test_case "genesis gates both calls" `Quick test_genesis_gates_on_both_calls;
        ] );
      ( "batch-position",
        [
          Alcotest.test_case "the 65536 boundary" `Quick (check_property prop_boundary);
          Alcotest.test_case "pack, project, gate" `Quick (check_property prop_pack);
          Alcotest.test_case "of_word round trip" `Quick (check_property prop_word_round_trip);
        ] );
      ( "fold",
        [
          Alcotest.test_case "cumulative gas agrees with the receipts root" `Quick
            test_cumulative_gas_agrees_with_the_receipts_root;
          Alcotest.test_case "the block budget bounds the fold" `Quick
            test_block_available_gas_bounds_the_fold;
          Alcotest.test_case "an invalid transaction stops the block" `Quick
            test_an_invalid_transaction_stops_the_block;
          Alcotest.test_case "system-call logs never enter the block bloom" `Quick
            test_system_call_logs_never_enter_the_block_bloom;
          Alcotest.test_case "transaction logs DO reach the block bloom" `Quick
            test_transaction_logs_reach_the_block_bloom;
          Alcotest.test_case "receipt and transaction order is execution order" `Quick
            test_receipt_and_transaction_order_is_execution_order;
        ] );
      ( "spine",
        [ Alcotest.test_case "one block, end to end" `Quick test_spine_end_to_end ] );
    ]
