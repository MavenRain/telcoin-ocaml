(* Tests for Tn_evm.Epoch_close and System_call.world_keeping_all_but_system:
   the second commit rule, the legacy pool read, the close-call ordering via
   the disposition's calldata, the mandatory-success discipline and the
   grafted env pin.

   ORACLES:
   - the two-contract commit-rule fixture distinguishes remove-SYSTEM (the
     sub-call's write persists) from retain-target (it vanishes) by
     construction, with the retain side asserted in the same test;
   - the real-fixture pool read is pinned against
     chain-configs/testnet/committee.yaml's five execution_address entries,
     an artifact INDEPENDENT of the genesis storage dump the fixture seeds;
   - the close-over-stub committee reuses the stage-4 pinned shuffle vector
     for seed 0x..01 (test_committee_shuffle.ml section C: pool arrival
     [0xa1;0xa3;0xa0;0xa2], size 3 -> [0xa3;0xa2;0xa1], hand-derived from
     the stage-1 rand golden vectors), so the only NEW steps asserted here
     are the encode-time ascending sort and the truncate-before-sort
     membership;
   - selector prefixes are hex literals, never read back from Registry_abi,
     so an encoder selector regression cannot vacuously agree. *)

open Block_fixtures
module Epoch_close = Tn_evm.Epoch_close
module Registry_abi = Tn_evm.Registry_abi
module System_call = Tn_evm.System_call
module Depth = Tn_evm.Depth
module Hash32 = Tn_evm.Hash32
module Genesis_account = Tn_state.Genesis_account
module Receipt = Tn_evm.Receipt

(* ---------- helpers ---------- *)

let call_ok = function
  | Ok outcome -> outcome
  | Error e -> Alcotest.failf "unexpected system-call error: %s" (System_call.error_to_string e)

let close_ok = function
  | Ok x -> x
  | Error e -> Alcotest.failf "unexpected epoch-close error: %s" (Epoch_close.error_to_string e)

let close_error = function
  | Ok _ -> Alcotest.fail "expected the close to be refused"
  | Error e -> e

let pool_ok = function
  | Ok pool -> pool
  | Error e -> Alcotest.failf "unexpected pool-read error: %s" (Epoch_close.error_to_string e)

let size_ok = function
  | Ok size -> size
  | Error e -> Alcotest.failf "unexpected size-read error: %s" (Epoch_close.error_to_string e)

(* The constructor name alone: the mandatory-success tests assert WHICH check
   fired, so a dropped check cannot slide to a later error and stay green. *)
let error_name = function
  | Epoch_close.Rewards_call _ -> "Rewards_call"
  | Epoch_close.Rewards_unsuccessful -> "Rewards_unsuccessful"
  | Epoch_close.Conclude_call _ -> "Conclude_call"
  | Epoch_close.Conclude_unsuccessful -> "Conclude_unsuccessful"
  | Epoch_close.Pool_read _ -> "Pool_read"
  | Epoch_close.Pool_read_unsuccessful _ -> "Pool_read_unsuccessful"
  | Epoch_close.Pool_decode _ -> "Pool_decode"
  | Epoch_close.Size_read _ -> "Size_read"
  | Epoch_close.Size_read_unsuccessful -> "Size_read_unsuccessful"
  | Epoch_close.Size_decode _ -> "Size_decode"

let seed_one =
  match Hash32.of_bytes (hex "0000000000000000000000000000000000000000000000000000000000000001") with
  | Some h -> h
  | None -> Alcotest.fail "seed fixture is not 32 bytes"

(* A 20-byte address of one repeated byte, as in test_committee_shuffle.ml. *)
let addr b =
  match Address.of_bytes (String.make 20 (Char.chr b)) with
  | Some a -> a
  | None -> Alcotest.fail "20-byte address fixture refused"

let addr_hex a = to_hex (Address.to_bytes a)
let registry = System_contracts.consensus_registry_address

(* ---------- the pinned pre-fork registry fixture, as in
   test_genesis_registry.ml ---------- *)

let u256_short s = get (U256.of_hex (String.make (64 - String.length s) '0' ^ s))
let u256_hex s = get (U256.of_hex s)

let registry_world =
  let entry =
    Genesis_account.make ~nonce:Nonce.zero
      ~balance:(u256_short Registry_genesis.balance_hex)
      ~code:(Some (hex Registry_genesis.code_hex))
      ~storage:
        (List.map (fun (s, v) -> (u256_hex s, u256_hex v)) Registry_genesis.storage_hex)
  in
  get_ok (World_state.of_genesis_alloc [ (registry, entry) ])

(* The five testnet validator execution addresses, verbatim from
   chain-configs/testnet/committee.yaml (authorities.*.execution_address), in
   the yaml's own order. That order is NOT ascending (0x89.. precedes
   0x35..), so a pool re-sort anywhere on the read path breaks the order
   assertion, and the ascending sort observed in concludeEpoch's calldata
   cannot be an accident of the input. *)
let committee_yaml_addresses =
  [
    "0033a370616805b1fd275b7ffab83fc41d665ccb";
    "89dab9f6fdc569c1bcdbd6493f25b7040b55dc79";
    "3518b301b86ceb53b5a3dff62e55cd43ef59d024";
    "efaacf04b92298a88200aa50aa6bb7bfce587b17";
    "7489025dfbaad94f2366d88a62989147d9c8b5d3";
  ]

let yaml_addrs = List.map (fun h -> get (Address.of_bytes (hex h))) committee_yaml_addresses

(* ---------- the dispatching registry stub ---------- *)

(* Hand-assembled dispatcher standing at the registry address. On EVERY call
   it first SSTOREs GASLIMIT into slot 0 and BASEFEE into slot 1 (the env
   recorder behind the env-pin test), then routes by selector:
   - each selector in [revert_selectors] REVERTs (matched first, so a revert
     selector can shadow a serving arm);
   - getValidators(uint8) (0x8cc05eda) returns [pool_blob] via CODECOPY;
   - getNextCommitteeSize() (0xeb8535c2) returns [size] as one word;
   - anything else (both write selectors) CALLs [companion], which SSTOREs
     0x2a into its own slot 1, then STOPs. The companion write is what
     separates remove-SYSTEM-commit-ALL from retain-target on the close path
     itself.
   Offsets are computed by measuring placeholder pieces of identical width,
   so the layout cannot drift from the arithmetic. *)
let dup1 = op (Opcode.Dup (get (Depth.of_int 1)))

let dispatch_stub ~revert_selectors ~pool_blob ~size ~companion =
  let env_record =
    bytes_of
      [
        op Opcode.Gaslimit; push1 0x00; op Opcode.Sstore;
        op Opcode.Basefee; push1 0x01; op Opcode.Sstore;
      ]
  in
  let selector_load =
    bytes_of [ push1 0x00; op Opcode.Calldataload; push1 0xe0; op Opcode.Shr ]
  in
  let arm dest sel =
    bytes_of [ dup1; push_bytes sel; op Opcode.Eq; push_int ~width:2 dest; op Opcode.Jumpi ]
  in
  let default = sub_caller ~callee:companion in
  let revert_code = bytes_of [ op Opcode.Jumpdest; push0; push0; op Opcode.Revert ] in
  let validators_code ~blob_off =
    bytes_of
      [
        op Opcode.Jumpdest;
        push_int ~width:2 (String.length pool_blob);
        push_int ~width:2 blob_off;
        push1 0x00; op Opcode.Codecopy;
        push_int ~width:2 (String.length pool_blob);
        push1 0x00; op Opcode.Return;
      ]
  in
  let size_code =
    bytes_of
      [
        op Opcode.Jumpdest; push1 size; push1 0x00; op Opcode.Mstore;
        push1 0x20; push1 0x00; op Opcode.Return;
      ]
  in
  let arm_len = String.length (arm 0 (hex "00000000")) in
  let arms_count = List.length revert_selectors + 2 in
  let head_len =
    String.length env_record + String.length selector_load + (arms_count * arm_len)
    + String.length default
  in
  let revert_dest = head_len in
  let validators_dest = revert_dest + String.length revert_code in
  let size_dest = validators_dest + String.length (validators_code ~blob_off:0) in
  let blob_off = size_dest + String.length size_code in
  bytes_of
    (List.concat
       [
         [ env_record; selector_load ];
         List.map (fun sel -> arm revert_dest (hex sel)) revert_selectors;
         [
           arm validators_dest (hex "8cc05eda");
           arm size_dest (hex "eb8535c2");
           default;
           revert_code;
           validators_code ~blob_off;
           size_code;
           pool_blob;
         ];
       ])

(* A strict abi-encoded ValidatorInfo[] return: 0x20 head word, length word,
   then seven inline words per element (address left-padded, epochs 0,
   status Active = 3, isRetired false, stakeVersion 0, region 0). *)
let word_of_int n = U256.to_be_bytes (u n)
let word_of_address a = String.make 12 '\000' ^ Address.to_bytes a

let pool_blob addresses =
  bytes_of
    (word_of_int 0x20 :: word_of_int (List.length addresses)
    :: List.map
         (fun a ->
           bytes_of
             [
               word_of_address a; word_of_int 0; word_of_int 0; word_of_int 3;
               word_of_int 0; word_of_int 0; word_of_int 0;
             ])
         addresses)

let companion = address_of 0xb7

(* The stage-4 C fixture: arrival [0xa1;0xa3;0xa0;0xa2] at size 3 shuffles
   under seed 0x..01 to [0xa3;0xa2;0xa1]: DESCENDING, so a dropped sort
   cannot hide; and its membership {a1,a2,a3} differs from the sorted first
   three of the pool {a0,a1,a2}, so a sort-before-truncate cannot hide
   either. *)
let stub_pool_arrival = [ addr 0xa1; addr 0xa3; addr 0xa0; addr 0xa2 ]

let stub_world ~revert_selectors =
  let stub =
    dispatch_stub ~revert_selectors ~pool_blob:(pool_blob stub_pool_arrival) ~size:3 ~companion
  in
  with_code
    (with_code World_state.empty companion (slot_writer ~slot:1 ~value:0x2a))
    registry stub

let rewards = [ (addr 0xa1, 3); (addr 0xa2, 1) ]

(* ================================================================== *)
(* 1. The second commit rule, told apart from the first.               *)
(* ================================================================== *)

(* Contract A SSTOREs its own slot 0 and CALLs contract B, which SSTOREs its
   own slot 1. Under world_keeping_all_but_system BOTH writes persist and
   the system address's account is exactly its pre-call value (absent, not
   merely nonce zero: remove semantics). Under world (retain-target) B's
   write vanishes; asserting that here is what makes the two-contract
   fixture rule-DISTINGUISHING rather than merely rule-consistent. *)
let test_commit_rule_two_contracts () =
  let callee = address_of 0xe5 in
  let target = address_of 0xd4 in
  let store_then_call =
    bytes_of [ push1 0x11; push1 0x00; op Opcode.Sstore ] ^ sub_caller ~callee
  in
  let world =
    with_code (with_code World_state.empty callee (slot_writer ~slot:1 ~value:0x2a)) target
      store_then_call
  in
  let outcome = call_ok (System_call.run world ~block:(block_env ()) ~contract:target ~data:"") in
  Alcotest.(check bool) "the call succeeded" true (System_call.succeeded outcome);
  let kept = System_call.world_keeping_all_but_system outcome in
  Alcotest.(check int) "the target's own write persists" 0x11
    (get (U256.to_int (slot kept target 0)));
  Alcotest.(check int) "the sub-call's write into B persists" 0x2a
    (get (U256.to_int (slot kept callee 1)));
  Alcotest.(check bool)
    "the system address is absent, exactly as before the call" false
    (present kept System_contracts.system_address);
  Alcotest.(check int) "so its nonce reads zero" 0
    (Nonce.to_int (World_state.nonce kept System_contracts.system_address));
  Alcotest.(check bool)
    "its account equals the pre-call account byte for byte" true
    (Account.equal
       (World_state.account world System_contracts.system_address)
       (World_state.account kept System_contracts.system_address));
  (* The contrast: the SAME outcome through the retain-target rule. *)
  let retained = System_call.world outcome in
  Alcotest.(check int) "retain-target drops the sub-call's write" 0
    (get (U256.to_int (slot retained callee 1)));
  Alcotest.(check bool)
    "retain-target leaves B byte-identical to its pre-call account" true
    (Account.equal (World_state.account world callee) (World_state.account retained callee))

(* ================================================================== *)
(* 2. The legacy pool and size reads against the REAL fixture.         *)
(* ================================================================== *)

(* One getValidators(Active) call into the pinned 28381-byte pre-fork
   bytecode, decoded strictly. The expected addresses come from
   committee.yaml, not from the storage dump; the expected ORDER is the
   contract's own return order, observed equal to the yaml order and pinned
   because it is consensus-relevant input to the shuffle. Non-commitment is
   structural: read_eligible_pool's type carries no world at all, so there
   is nothing here a committed read could even be asserted against. *)
let test_read_eligible_pool_on_the_fixture () =
  let pool = pool_ok (Epoch_close.read_eligible_pool registry_world ~block:(block_env ())) in
  Alcotest.(check (list string))
    "the five testnet validators, in the contract's return order"
    committee_yaml_addresses
    (List.map (fun v -> addr_hex (Registry_abi.Validator_info.validator_address v)) pool);
  List.iter
    (fun v ->
      Alcotest.(check bool)
        "every pre-fork pool entry reports Active" true
        (Registry_abi.Validator_status.equal Registry_abi.Validator_status.Active
           (Registry_abi.Validator_info.current_status v)))
    pool

let test_read_next_committee_size_on_the_fixture () =
  Alcotest.(check int) "getNextCommitteeSize answers 5" 5
    (size_ok (Epoch_close.read_next_committee_size registry_world ~block:(block_env ())))

(* ================================================================== *)
(* 3. close over the stub: order, sort, commit rule, env pin.          *)
(* ================================================================== *)

(* The enclosing block env is deliberately WRONG for a system call (50M gas
   limit, basefee 7): the frames must still see 30M and 0 (the recorded
   slots prove it), and the close must still run (a passed-through basefee 7
   would reject the zero-gas-price synthetic transaction outright). *)
let test_close_over_the_stub () =
  let block = block_env ~gas_limit:50_000_000 ~basefee:7 () in
  let world', d =
    close_ok
      (Epoch_close.close (stub_world ~revert_selectors:[]) ~block ~rewards ~randomness:seed_one)
  in
  (* Order, port-internally: the disposition's first calldata is the
     applyIncentives encoding of the rewards as given, the second is
     concludeEpoch; prefixes are hex literals. *)
  Alcotest.(check string) "first calldata = applyIncentives(rewards as given)"
    (to_hex (Registry_abi.apply_incentives_calldata rewards))
    (to_hex (Epoch_close.first_calldata d));
  Alcotest.(check string) "first selector is 0x0a36cdef" "0a36cdef"
    (to_hex (String.sub (Epoch_close.first_calldata d) 0 4));
  Alcotest.(check string) "second selector is 0x7b55a300" "7b55a300"
    (to_hex (String.sub (Epoch_close.second_calldata d) 0 4));
  (* The committee: shuffle [0xa3;0xa2;0xa1] (stage-4 pin), sorted ASCENDING
     at encode time. Membership excludes 0xa0, so this same assertion also
     pins truncate-before-sort. *)
  Alcotest.(check string)
    "second calldata = concludeEpoch(sort(truncate(shuffle)))"
    (to_hex (Registry_abi.conclude_epoch_calldata [ addr 0xa1; addr 0xa2; addr 0xa3 ]))
    (to_hex (Epoch_close.second_calldata d));
  Alcotest.(check bool) "applyIncentives succeeded" true
    (System_call.succeeded (Epoch_close.rewards_outcome d));
  Alcotest.(check bool) "concludeEpoch succeeded" true
    (System_call.succeeded (Epoch_close.conclude_outcome d));
  (* The env pin, recorded by the stub on the committed write path. *)
  Alcotest.(check int) "GASLIMIT inside the frame is 30M, not the block's 50M"
    30_000_000
    (get (U256.to_int (slot world' registry 0)));
  Alcotest.(check int) "BASEFEE inside the frame is 0, not the block's 7" 0
    (get (U256.to_int (slot world' registry 1)));
  (* The commit rule on the close path itself: the companion's write, made
     by a sub-call out of the registry frame, persists. *)
  Alcotest.(check int) "the companion's write persists into the close world" 0x2a
    (get (U256.to_int (slot world' companion 1)));
  Alcotest.(check bool) "the system address stays absent" false
    (present world' System_contracts.system_address)

(* A second, different enclosing env pins that the 30M/0 pair is a constant
   of the call path, not an echo of one block fixture. *)
let test_env_pin_under_another_env () =
  let block = block_env ~gas_limit:123_456_789 ~basefee:1 ~timestamp:1_800_000_000 () in
  let world', _ =
    close_ok
      (Epoch_close.close (stub_world ~revert_selectors:[]) ~block ~rewards ~randomness:seed_one)
  in
  Alcotest.(check int) "GASLIMIT still reads 30M" 30_000_000
    (get (U256.to_int (slot world' registry 0)));
  Alcotest.(check int) "BASEFEE still reads 0" 0 (get (U256.to_int (slot world' registry 1)))

(* ================================================================== *)
(* 4. Mandatory success: any reverting call is fatal, by name.         *)
(* ================================================================== *)

let test_mandatory_success () =
  let block = block_env () in
  let revert_all = bytes_of [ push0; push0; op Opcode.Revert ] in
  Alcotest.(check string) "a registry that reverts everything kills the FIRST call"
    "Rewards_unsuccessful"
    (error_name
       (close_error
          (Epoch_close.close
             (with_code World_state.empty registry revert_all)
             ~block ~rewards ~randomness:seed_one)));
  Alcotest.(check string) "a revert on concludeEpoch alone is fatal"
    "Conclude_unsuccessful"
    (error_name
       (close_error
          (Epoch_close.close
             (stub_world ~revert_selectors:[ "7b55a300" ])
             ~block ~rewards ~randomness:seed_one)));
  Alcotest.(check string) "a revert on the pool read alone is fatal"
    "Pool_read_unsuccessful"
    (error_name
       (close_error
          (Epoch_close.close
             (stub_world ~revert_selectors:[ "8cc05eda" ])
             ~block ~rewards ~randomness:seed_one)));
  Alcotest.(check string) "a revert on the size read alone is fatal"
    "Size_read_unsuccessful"
    (error_name
       (close_error
          (Epoch_close.close
             (stub_world ~revert_selectors:[ "eb8535c2" ])
             ~block ~rewards ~randomness:seed_one)))

(* ================================================================== *)
(* 5. close against the REAL pre-fork registry.                        *)
(* ================================================================== *)

(* The full close over the pinned testnet fixture: applyIncentives with one
   count per committee.yaml validator, then concludeEpoch, both against the
   live 28381-byte bytecode, both required to succeed. With pool size =
   committee size = 5 the sorted committee is the five yaml addresses in
   ascending byte order, hand-sorted below (the shuffle permutes, the sort
   canonicalises; the truncate-sensitive case lives in the stub test).
   The storage-delta and balance assertions record OBSERVED pre-fork
   contract behaviour: the close writes registry storage (so the calls
   demonstrably executed) and moves no TEL balance (pre-fork incentives
   accrue inside registry storage; the balance-moving flow is the post-fork
   contract's). *)
let test_close_on_the_fixture () =
  let world', d =
    close_ok
      (Epoch_close.close registry_world ~block:(block_env ())
         ~rewards:(List.map (fun a -> (a, 1)) yaml_addrs)
         ~randomness:seed_one)
  in
  Alcotest.(check string) "first selector is 0x0a36cdef" "0a36cdef"
    (to_hex (String.sub (Epoch_close.first_calldata d) 0 4));
  Alcotest.(check string)
    "second calldata = concludeEpoch(the five validators, ascending)"
    (to_hex
       (Registry_abi.conclude_epoch_calldata
          (List.map
             (fun h -> get (Address.of_bytes (hex h)))
             [
               "0033a370616805b1fd275b7ffab83fc41d665ccb";
               "3518b301b86ceb53b5a3dff62e55cd43ef59d024";
               "7489025dfbaad94f2366d88a62989147d9c8b5d3";
               "89dab9f6fdc569c1bcdbd6493f25b7040b55dc79";
               "efaacf04b92298a88200aa50aa6bb7bfce587b17";
             ])))
    (to_hex (Epoch_close.second_calldata d));
  Alcotest.(check bool) "applyIncentives succeeded on the real bytecode" true
    (System_call.succeeded (Epoch_close.rewards_outcome d));
  Alcotest.(check bool) "concludeEpoch succeeded on the real bytecode" true
    (System_call.succeeded (Epoch_close.conclude_outcome d));
  Alcotest.(check bool) "the close is not a silent no-op: registry storage changed"
    false
    (Tn_state.Storage.equal
       (Account.storage (World_state.account registry_world registry))
       (Account.storage (World_state.account world' registry)));
  Alcotest.(check string) "no TEL left the registry"
    (U256.to_hex (World_state.balance registry_world registry))
    (U256.to_hex (World_state.balance world' registry));
  List.iter
    (fun a ->
      Alcotest.(check bool)
        "no validator balance moved" true
        (U256.is_zero (World_state.balance world' a)))
    yaml_addrs;
  Alcotest.(check bool) "the system address stays absent" false
    (present world' System_contracts.system_address)

let () =
  Alcotest.run "epoch_close"
    [
      ( "commit rule",
        [
          Alcotest.test_case "two contracts: remove-SYSTEM vs retain-target" `Quick
            test_commit_rule_two_contracts;
        ] );
      ( "reads",
        [
          Alcotest.test_case "legacy pool read on the fixture" `Quick
            test_read_eligible_pool_on_the_fixture;
          Alcotest.test_case "next committee size on the fixture" `Quick
            test_read_next_committee_size_on_the_fixture;
        ] );
      ( "close",
        [
          Alcotest.test_case "over the stub: order, sort, commit, env pin" `Quick
            test_close_over_the_stub;
          Alcotest.test_case "env pin under another enclosing env" `Quick
            test_env_pin_under_another_env;
          Alcotest.test_case "mandatory success, by name" `Quick test_mandatory_success;
          Alcotest.test_case "the real pre-fork registry closes" `Quick
            test_close_on_the_fixture;
        ] );
    ]
