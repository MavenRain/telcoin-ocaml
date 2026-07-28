(* EIP-7702 call-path tests, chunk 33 stage 5: one-hop resolution through the
   shared {!Call_target} resolver at BOTH entry points (the interpreter's four
   call opcodes, [call_helpers.rs:165-186]; the executor's depth-0 frame,
   [handler.rs:317-332]), plus the blast-radius property that the resolver is
   the physical identity on every non-designator code.

   Gas figures are absolute hand-computed literals with the derivation in a
   comment (test_executor.ml conventions); the interpreter-level figures lean
   on the fixed opcode statics: PUSHn 3, POP 2, RETURNDATASIZE 2, STOP 0, the
   call family's 100 static base ([gas.ml:106-123]) and the 2500 cold-account
   surcharge {!Gas.account_access_cost} prices on top of it. Fixtures from
   eip7702_vectors.ml; the assembler and the block leg's synthetic signature
   machinery are Block_fixtures'. *)

module U256 = Tn_state.U256
module Nonce = Tn_state.Nonce
module Account = Tn_state.Account
module World_state = Tn_state.World_state
module Delegation = Tn_state.Delegation
module Units = Tn_types.Units
module Access = Tn_evm.Access
module Code = Tn_evm.Code
module Data = Tn_evm.Data
module Effects = Tn_evm.Effects
module Env = Tn_evm.Env
module Gas = Tn_evm.Gas
module Interpreter = Tn_evm.Interpreter
module Mutability = Tn_evm.Mutability
module Opcode = Tn_evm.Opcode
module Topic_count = Tn_evm.Topic_count
module Log = Tn_evm.Log
module Log_journal = Tn_evm.Log_journal
module Call_target = Tn_evm.Call_target
module Contract_address = Tn_evm.Contract_address
module Authorization = Tn_evm.Authorization
module Transaction = Tn_evm.Transaction
module Receipt = Tn_evm.Receipt
module Executor = Tn_evm.Executor
module Block_execution = Tn_evm.Block_execution
module Block_roots = Tn_evm.Block_roots
module Tx_payload = Tn_evm.Tx_payload
module Tx_envelope = Tn_evm.Tx_envelope
module Receipt_envelope = Tn_evm.Receipt_envelope
module Block_hashes = Tn_evm.Block_hashes
module System_contracts = Tn_evm.System_contracts
module V = Eip7702_vectors

let get o =
  Result.fold ~ok:Fun.id
    ~error:(fun () -> Alcotest.fail "expected Some")
    (Option.to_result ~none:() o)

let u n = get (U256.of_int n)
let gas_of n = get (Gas.of_int n)
let nonce_of n = get (Nonce.of_int n)

(* Block_fixtures' miniature assembler, plus the two wide pushes it lacks. *)
let op = Block_fixtures.op
let push1 = Block_fixtures.push1
let push20 address = Block_fixtures.push_bytes (Units.Address.to_bytes address)
let push32 w = Block_fixtures.push_bytes (U256.to_be_bytes w)
let bytes_of = Block_fixtures.bytes_of
let asm parts = Code.of_string (bytes_of parts)
let address_of = Block_fixtures.address_of

let word_of_address a =
  get (U256.of_be_bytes (String.make 12 '\000' ^ Units.Address.to_bytes a))

let all_gas = U256.max_value

let call ~gas ~dst ~value ~in_off ~in_len ~out_off ~out_len =
  [
    push1 out_len; push1 out_off; push1 in_len; push1 in_off; push32 value;
    push20 dst; push32 gas; op Opcode.Call;
  ]

(* The write path cannot spell a raw designator, so genesis-style delegated
   accounts are built through the same smart constructor the loop uses. *)
let designator target = Delegation.code_of_assignment (Delegation.assignment target)

let delegated ~to_ ~balance =
  Account.with_code (Account.make ~nonce:(nonce_of 1) ~balance) (designator to_)

let coded ~code balance = Account.with_code (Account.make ~nonce:(nonce_of 1) ~balance) code

(* ---------- the interpreter-level world ---------- *)

let self = address_of 0x5f
let outer_caller = address_of 0x5e
let identity = address_of 0x04

(* Plain delegate contracts. *)
let d_stop = address_of 0xe1
let d_ctx = address_of 0xd2
let probe = address_of 0xd3
let d_size = address_of 0xd4

(* Delegated EOAs, and the chain A -> B -> C. *)
let a_stop = address_of 0xa4
let a_ctx = address_of 0xa2
let a_size = address_of 0xa3
let a_chain = address_of 0xa5
let b_chain = address_of 0xb6
let c_chain = address_of 0xc7
let a_empty = address_of 0xa6
let ghost = address_of 0xe9
let a_pre = address_of 0xa7

(* Controls: an account made non-empty by its nonce alone, and a genuinely
   absent one (the new-account-cost control, exactly test_calls.ml's pair). *)
let nonce_only = address_of 0xcc
let absent = address_of 0xee

(* The context recorder: slot0 = ADDRESS, slot1 = SELFBALANCE, slot2 = 42,
   one empty LOG0, then a sub-CALL to [probe], whose own slot0 records CALLER.
   Every one of those must key on the DELEGATOR when this code runs behind a
   designator ([interpreter.input.target_address()] throughout host.rs). *)
let code_ctx_delegate =
  bytes_of
    ([ op Opcode.Address; push1 0; op Opcode.Sstore ]
    @ [ op Opcode.Selfbalance; push1 1; op Opcode.Sstore ]
    @ [ push1 42; push1 2; op Opcode.Sstore ]
    @ [ push1 0; push1 0; op (Opcode.Log Topic_count.Zero) ]
    @ call ~gas:(u 100_000) ~dst:probe ~value:U256.zero ~in_off:0 ~in_len:0
        ~out_off:0 ~out_len:0
    @ [ op Opcode.Stop ])

let code_probe = bytes_of [ op Opcode.Caller; push1 0; op Opcode.Sstore; op Opcode.Stop ]

(* CODESIZE, PUSH1 0, SSTORE: exactly 4 bytes, so the delegate's own length and
   the designator's 23 are unambiguous. *)
let code_size_delegate = bytes_of [ op Opcode.Codesize; push1 0; op Opcode.Sstore ]

let world =
  List.fold_left
    (fun w (address, account) -> World_state.set_account w address account)
    World_state.empty
    [
      (self, Account.make ~nonce:Nonce.zero ~balance:(u 1_000_000));
      (nonce_only, Account.make ~nonce:(nonce_of 3) ~balance:U256.zero);
      (d_stop, coded ~code:(bytes_of [ op Opcode.Stop ]) U256.zero);
      (d_ctx, coded ~code:code_ctx_delegate U256.zero);
      (probe, coded ~code:code_probe U256.zero);
      (d_size, coded ~code:code_size_delegate U256.zero);
      (a_stop, delegated ~to_:d_stop ~balance:U256.zero);
      (a_ctx, delegated ~to_:d_ctx ~balance:(u 777));
      (a_size, delegated ~to_:d_size ~balance:U256.zero);
      (a_chain, delegated ~to_:b_chain ~balance:U256.zero);
      (b_chain, delegated ~to_:c_chain ~balance:U256.zero);
      (c_chain, coded ~code:(bytes_of [ op Opcode.Stop ]) U256.zero);
      (a_empty, delegated ~to_:ghost ~balance:U256.zero);
      (a_pre, delegated ~to_:identity ~balance:U256.zero);
    ]

let coinbase = address_of 0xc3

let block_of ~coinbase ~basefee =
  Env.Block.make ~coinbase ~timestamp:(u 1_600_000_000) ~number:(u 1000)
    ~prevrandao:U256.zero ~gas_limit:(u 30_000_000) ~basefee:(u basefee)
    ~basefee_address:System_contracts.governance_safe_address ~chain_id:(u 1)
    ~hashes:Block_hashes.empty

let ienv =
  Env.make
    ~block:(block_of ~coinbase ~basefee:0)
    ~tx:(Env.Tx.make ~origin:outer_caller ~gas_price:U256.zero ~access_list:[])
    ~call:
      (Env.Call.make ~target:self ~caller:outer_caller ~value:U256.zero
         ~data:Data.empty ~mutability:Mutability.Mutable)

let allowance = 50_000_000
let cold_effects = Effects.start ~world ~access:Access.empty

let warm_effects addresses =
  Effects.start ~world ~access:(Access.of_transaction ~addresses ~slots:[])

let run ?(effects = cold_effects) ?(gas = allowance) parts =
  Interpreter.run ~env:ienv ~code:(asm parts) ~gas:(gas_of gas) ~effects

let effects_of = function
  | Interpreter.Stopped { effects; _ } | Interpreter.Returned { effects; _ } -> effects
  | Interpreter.Reverted _ -> Alcotest.fail "expected effects, got a top-level revert"
  | Interpreter.Failed e ->
      Alcotest.fail ("expected effects, got failure: " ^ Interpreter.error_to_string e)

let output_of = function
  | Interpreter.Returned { output; _ } -> output
  | Interpreter.Reverted { output; _ } -> output
  | Interpreter.Stopped _ -> Alcotest.fail "expected an outcome carrying output, got stop"
  | Interpreter.Failed e ->
      Alcotest.fail ("expected output, got failure: " ^ Interpreter.error_to_string e)

let remaining_of = function
  | Interpreter.Stopped { gas_left; _ }
  | Interpreter.Returned { gas_left; _ }
  | Interpreter.Reverted { gas_left; _ } ->
      Gas.remaining gas_left
  | Interpreter.Failed e ->
      Alcotest.fail ("expected a halt carrying gas, got " ^ Interpreter.error_to_string e)

let spent outcome = allowance - remaining_of outcome

let storage_of outcome address slot =
  World_state.storage (Effects.world (effects_of outcome)) address (u slot)

let balance_of outcome address =
  World_state.balance (Effects.world (effects_of outcome)) address

let check_word msg expected actual =
  Alcotest.(check bool) msg true (U256.equal expected actual)

(* ================================================================== *)
(* 1. The resolver itself: identity off the designator class.          *)
(* ================================================================== *)

let mk ~salt ~count name arb fn =
  Alcotest.test_case name `Slow (fun () ->
      QCheck.Test.check_exn
        ~rand:(Random.State.make [| 0x5eed_c; salt |])
        (QCheck.Test.make ~count ~name arb fn))

(* The corner shapes: empty code, a lone 0xEF, an ef00/ef02 21-byte tail, and
   the 23-byte ef0101 blob, which sits IN the two-byte designator class but
   fails the version check, so {!Account.delegation} answers [None] and the
   resolver must treat it as plain code (it is unreachable from any world a
   transaction runs against; see World_state's Malformed_delegation gate). *)
let special_codes =
  [
    "";
    "\xef";
    "\xef\x00" ^ String.make 21 '\x00';
    "\xef\x02" ^ String.make 21 '\x00';
    "\xef\x01\x01" ^ String.make 20 '\x11';
  ]

(* Random codes, with the astronomically unlikely well-formed designator
   remapped by a STOP prefix so the generator's support is exactly the
   non-delegated class; no index is ever read. *)
let arb_non_designator =
  QCheck.make
    ~print:(fun s -> Printf.sprintf "%d bytes: %s" (String.length s) (V.to_hex s))
    QCheck.Gen.(
      let random =
        map
          (fun s ->
            Option.fold ~none:s ~some:(fun _ -> "\x00" ^ s) (Delegation.of_code s))
          (string_size ~gen:char (int_range 0 64))
      in
      oneof_weighted [ (1, oneof_list special_codes); (9, random) ])

(* THE blast-radius property: for every account code outside the designator
   class, {!Call_target.resolve} is the identity: physically unchanged
   effects, zero surcharge, no delegate, and the code is byte-for-byte
   [Code.of_string (Account.code a)], the expression both call sites evaluated
   before Call_target existed. 1000 cases; the five corner shapes are folded
   into the generator. *)
let prop_non_delegated_identity =
  mk ~salt:7 ~count:1000 "non_delegated_call_path_is_unchanged" arb_non_designator
    (fun code_bytes ->
      let acct = Account.with_code (Account.make ~nonce:(nonce_of 1) ~balance:(u 9)) code_bytes in
      let e = Effects.start ~world ~access:Access.empty in
      let r = Call_target.resolve e acct in
      let straight = Code.of_string (Account.code acct) in
      Effects.equal (Call_target.effects r) e
      && Call_target.surcharge r = 0
      && Option.is_none (Call_target.delegate r)
      && Code.length (Call_target.code r) = Code.length straight
      && String.equal
           (Data.to_string (Code.window (Call_target.code r)))
           (Data.to_string (Code.window straight)))

(* The other half of the free identity: charging the zero surcharge is a
   no-op, so the inserted [charged (Call_target.surcharge resolved)] line
   costs the non-delegated path nothing. *)
let test_charge_zero_is_free () =
  Alcotest.(check int) "Gas.charge 0 returns the same remaining" 12345
    (Gas.remaining (get (Gas.charge 0 (gas_of 12345))))

(* ================================================================== *)
(* 2. Interpreter-level: the four call opcodes resolve one hop.        *)
(* ================================================================== *)

(* ADDRESS, SELFBALANCE, SLOAD/SSTORE, LOG and a sub-call's CALLER all key on
   the DELEGATOR; CALLER is the one system-opcode exception (it reads
   [caller_address()], [system.rs:54-64], so the sub-call made FROM the
   delegated frame reports the delegator to its callee). *)
let test_delegated_frame_context_is_the_delegator () =
  let outcome =
    run
      (call ~gas:all_gas ~dst:a_ctx ~value:U256.zero ~in_off:0 ~in_len:0 ~out_off:0
         ~out_len:0
      @ [ op Opcode.Stop ])
  in
  check_word "ADDRESS is the delegator" (word_of_address a_ctx) (storage_of outcome a_ctx 0);
  check_word "SELFBALANCE is the delegator's balance" (u 777) (storage_of outcome a_ctx 1);
  check_word "the SSTORE landed in the delegator's storage" (u 42) (storage_of outcome a_ctx 2);
  check_word "the delegate's own slot 0 is untouched" U256.zero (storage_of outcome d_ctx 0);
  check_word "the delegate's own slot 1 is untouched" U256.zero (storage_of outcome d_ctx 1);
  check_word "the delegate's own slot 2 is untouched" U256.zero (storage_of outcome d_ctx 2);
  check_word "a further callee's CALLER reads the delegator" (word_of_address a_ctx)
    (storage_of outcome probe 0);
  let logs = Log_journal.to_list (Effects.logs (effects_of outcome)) in
  Alcotest.(check int) "exactly one log" 1 (List.length logs);
  Alcotest.(check bool) "the log's address is the delegator" true
    (List.for_all (fun l -> Units.Address.equal (Log.address l) a_ctx) logs)

(* The ONE place the "23 designator bytes vs delegate code" split flips:
   CODESIZE inside the frame reads the resolved delegate's 4 bytes while
   EXTCODESIZE on the same account from outside reads the stored 23
   ([system.rs:69-74] reads the frame's bytecode; [host.rs:61-64] the
   account's). Before this chunk the two were the same value by accident. *)
let test_codesize_flips_against_extcodesize () =
  let inside =
    run
      (call ~gas:all_gas ~dst:a_size ~value:U256.zero ~in_off:0 ~in_len:0 ~out_off:0
         ~out_len:0
      @ [ op Opcode.Stop ])
  in
  check_word "CODESIZE inside the frame is the delegate's 4, never 23" (u 4)
    (storage_of inside a_size 0);
  let outside =
    run
      [
        push20 a_size; op Opcode.Extcodesize; push1 0; op Opcode.Sstore;
        push20 d_size; op Opcode.Extcodesize; push1 1; op Opcode.Sstore;
        op Opcode.Stop;
      ]
  in
  check_word "EXTCODESIZE of the delegated account is 23" (u 23) (storage_of outside self 0);
  check_word "EXTCODESIZE of the delegate is its 4" (u 4) (storage_of outside self 1)

(* +100 always, +2500 more only when the DELEGATE is cold, ON TOP of the
   target's own cold surcharge and of the opcode's 100 static base; the two
   warm sets are independent, which is what the (warm,cold)/(cold,warm) pair
   proves. Program cost: 7 pushes (21) + CALL 100 static + surcharges; the
   forwarded allowance returns in full (the delegate STOPs at once). *)
let test_call_delegation_gas_four_corners () =
  let corner ~warm =
    spent
      (run ~effects:(warm_effects warm)
         (call ~gas:all_gas ~dst:a_stop ~value:U256.zero ~in_off:0 ~in_len:0 ~out_off:0
            ~out_len:0
         @ [ op Opcode.Stop ]))
  in
  (* 21 + 100 + 0 + 100 *)
  Alcotest.(check int) "warm target, warm delegate" 221 (corner ~warm:[ a_stop; d_stop ]);
  (* 21 + 100 + 0 + 2600 *)
  Alcotest.(check int) "warm target, cold delegate" 2721 (corner ~warm:[ a_stop ]);
  (* 21 + 100 + 2500 + 100: the same total from the OTHER warm set *)
  Alcotest.(check int) "cold target, warm delegate" 2721 (corner ~warm:[ d_stop ]);
  (* 21 + 100 + 2500 + 2600 *)
  Alcotest.(check int) "cold target, cold delegate" 5221 (corner ~warm:[]);
  (* Controls: a NON-delegated callee is unchanged at 100 warm / 2600 cold. *)
  let control ~warm =
    spent
      (run ~effects:(warm_effects warm)
         (call ~gas:all_gas ~dst:d_stop ~value:U256.zero ~in_off:0 ~in_len:0 ~out_off:0
            ~out_len:0
         @ [ op Opcode.Stop ]))
  in
  Alcotest.(check int) "non-delegated warm control" 121 (control ~warm:[ d_stop ]);
  Alcotest.(check int) "non-delegated cold control" 2621 (control ~warm:[])

(* Exactly ONE hop, never a loop: calling A (-> B -> C) executes B's designator
   BYTES, which halt on 0xEF with the whole forwarded allowance consumed, no
   revert, no return data; the resolution surcharge is B's alone, charged
   once. *)
let test_two_hop_chain_halts_invalid_opcode () =
  let outcome =
    run ~effects:(warm_effects [ a_chain ])
      (call ~gas:(u 40_000) ~dst:a_chain ~value:U256.zero ~in_off:0 ~in_len:0 ~out_off:0
         ~out_len:0
      @ [ push1 0; op Opcode.Sstore; op Opcode.Returndatasize; push1 1; op Opcode.Sstore;
          op Opcode.Stop ])
  in
  check_word "the CALL pushed 0" U256.zero (storage_of outcome self 0);
  check_word "no return data" U256.zero (storage_of outcome self 1);
  (* 21 pushes + 100 static + 0 (A warm) + 2600 (one hop, B cold) + the whole
     40000 forwarded, never given back. A second hop would add C's 2600. *)
  let gas_leg =
    run ~effects:(warm_effects [ a_chain ])
      (call ~gas:(u 40_000) ~dst:a_chain ~value:U256.zero ~in_off:0 ~in_len:0 ~out_off:0
         ~out_len:0
      @ [ op Opcode.Stop ])
  in
  Alcotest.(check int) "one hop's surcharge, all forwarded gas burnt" 42721 (spent gas_leg);
  (* The same designator bytes as a TOP-LEVEL frame: the port's own halt. *)
  let top =
    Interpreter.run ~env:ienv
      ~code:(Code.of_string (designator c_chain))
      ~gas:(gas_of 30_000) ~effects:cold_effects
  in
  match top with
  | Interpreter.Failed e ->
      Alcotest.(check string) "halts Invalid_opcode 0xef" "invalid opcode 0xef"
        (Interpreter.error_to_string e)
  | Interpreter.Stopped _ -> Alcotest.fail "designator bytes must not stop cleanly"
  | Interpreter.Returned _ -> Alcotest.fail "designator bytes must not return"
  | Interpreter.Reverted _ -> Alcotest.fail "an unknown opcode is a halt, not a revert"

(* A call to a delegated account whose delegate does not exist SUCCEEDS with
   empty return data AFTER the value transfer ([frame.rs:225-229]): the value
   lands on the DELEGATOR, the forwarded gas comes back in full, and the
   charge is the 2600 cold resolution, never the 25000 new-account cost. *)
let test_empty_delegate_succeeds () =
  let program dst value =
    call ~gas:all_gas ~dst ~value ~in_off:0 ~in_len:0 ~out_off:0 ~out_len:0
    @ [ push1 0; op Opcode.Sstore; op Opcode.Returndatasize; push1 1; op Opcode.Sstore;
        op Opcode.Stop ]
  in
  let warm = [ a_empty; nonce_only; absent ] in
  let outcome = run ~effects:(warm_effects warm) (program a_empty (u 5)) in
  check_word "the CALL pushed 1" U256.one (storage_of outcome self 0);
  check_word "empty return data" U256.zero (storage_of outcome self 1);
  check_word "the 5 wei landed on the delegator" (u 5) (balance_of outcome a_empty);
  check_word "nothing landed on the absent delegate" U256.zero (balance_of outcome ghost);
  check_word "the caller paid it" (u 999_995) (balance_of outcome self);
  (* Same program against the non-empty control: the only difference is the
     cold delegate's 100 + 2500. The absent-account control differs by the
     full 25000 instead, exactly test_calls.ml's new-account pair. *)
  let spent_of dst = spent (run ~effects:(warm_effects warm) (program dst (u 5))) in
  Alcotest.(check int) "the delegated call pays 2600, not 25000" 2600
    (spent_of a_empty - spent_of nonce_only);
  Alcotest.(check int) "the genuinely empty callee pays the 25000" 25000
    (spent_of absent - spent_of nonce_only)

(* A delegated account is never [is_empty] ([call_helpers.rs:157-163] returns
   early BEFORE the delegate branch), so the 25000 and the resolution are
   mutually exclusive and [is_empty] stays keyed on the ORIGINAL account: with
   the delegate warm, a value CALL to the delegated account costs 100 more
   than the non-empty control, never 25000 more. *)
let test_call_to_delegated_charges_no_new_account () =
  let program dst =
    call ~gas:all_gas ~dst ~value:U256.one ~in_off:0 ~in_len:0 ~out_off:0 ~out_len:0
    @ [ op Opcode.Stop ]
  in
  let warm = [ a_empty; nonce_only; ghost ] in
  let spent_of dst = spent (run ~effects:(warm_effects warm) (program dst)) in
  Alcotest.(check int) "delegated: +100 resolution, no new-account cost" 100
    (spent_of a_empty - spent_of nonce_only)

(* Precompiles are keyed on [bytecode_address] = the designating account
   ([precompile_provider.rs:100-107]): an EOA delegated to IDENTITY loads
   0x04's EMPTY account code and stops, it does not echo. The resolution is
   still charged (+100, delegate warm) against the non-delegated control. *)
let test_delegated_to_precompile_does_not_run_it () =
  let program dst =
    [ push32 (get (U256.of_be_bytes ("hi" ^ String.make 30 '\000'))); push1 0;
      op Opcode.Mstore ]
    @ call ~gas:all_gas ~dst ~value:U256.zero ~in_off:0 ~in_len:2 ~out_off:0x40
        ~out_len:2
    @ [ push1 0; op Opcode.Sstore; op Opcode.Returndatasize; push1 1; op Opcode.Sstore ]
    @ [ push1 2; push1 0x40; op Opcode.Return ]
  in
  let warm = [ a_pre; nonce_only; identity ] in
  let through = run ~effects:(warm_effects warm) (program a_pre) in
  check_word "the call succeeded" U256.one (storage_of through self 0);
  check_word "but produced NO return data" U256.zero (storage_of through self 1);
  Alcotest.(check string) "the out window stayed zero" "\x00\x00" (output_of through);
  let direct = run ~effects:(warm_effects warm) (program identity) in
  check_word "calling 0x04 directly does echo" (u 2) (storage_of direct self 1);
  Alcotest.(check string) "identity output" "hi" (output_of direct);
  let spent_of dst = spent (run ~effects:(warm_effects warm) (program dst)) in
  Alcotest.(check int) "the resolution is still charged on the delegated path" 100
    (spent_of a_pre - spent_of nonce_only)

(* ================================================================== *)
(* 3. Executor-level: the depth-0 frame and the pre-warm set.          *)
(* ================================================================== *)

let addr_hex hex_pair = V.addr_of_hex (String.make 38 '0' ^ hex_pair)
let account ~nonce ~balance = Account.make ~nonce:(nonce_of nonce) ~balance:(u balance)

let world_seed pairs =
  List.fold_left
    (fun w (address, acct) -> World_state.set_account w address acct)
    World_state.empty pairs

let sender = addr_hex "f1"
let block0 = block_of ~coinbase ~basefee:0

let exec_ok world ~block tx =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "unexpected rejection: %s" (Executor.error_to_string e))
    (Executor.execute world ~block tx)

let receipt_is_success = function
  | Receipt.Success _ -> true
  | Receipt.Reverted _ -> false
  | Receipt.Halted _ -> false

let code_hex_at w address = V.to_hex (Account.code (World_state.account w address))
let nonce_at w address = Nonce.to_int (World_state.nonce w address)

let auth_key0 =
  Authorization.sign
    (get (Authorization.make ~chain_id:(u 1) ~address:V.target_11s ~nonce:U256.zero))
    ~y_parity:(u V.auth_key0_y_parity) ~r:V.auth_key0_r ~s:V.auth_key0_s

let signed_of (m : V.minted) =
  Authorization.sign
    (get (Authorization.make ~chain_id:m.V.m_chain ~address:m.V.m_address ~nonce:m.V.m_nonce))
    ~y_parity:(u m.V.m_parity) ~r:m.V.m_r ~s:m.V.m_s

let set_code_tx ~target ?(access_list = []) ~gas_limit ~authorizations () =
  Transaction.set_code ~sender ~nonce:(nonce_of 0) ~gas_limit ~target ~value:U256.zero
    ~data:"" ~access_list ~chain_id:(u 1) ~max_priority_fee_per_gas:(u 0)
    ~max_fee_per_gas:(u 0) ~authorizations

(* THE required test. A transaction delegates its own [to] target and executes
   the freshly installed delegate code in the SAME transaction: the loop runs
   in pre-execution ([pre_execution.rs:190-272]) and the top frame resolves
   from the POST-auth world, so the delegate's SSTORE lands in the DELEGATOR's
   storage. A port applying authorizations during frame setup, or resolving
   the top frame from the PRE-auth world, runs the authority's OLD empty code
   and succeeds with no effect: a silent divergence on the most common 7702
   shape there is. *)
let test_same_tx_delegate_then_execute () =
  let store42 = V.hex "602a60015500" in
  let world =
    world_seed
      [
        (sender, account ~nonce:0 ~balance:1_000_000_000);
        (V.target_11s, Account.with_code (account ~nonce:1 ~balance:0) store42);
      ]
  in
  let receipt, w =
    exec_ok world ~block:block0
      (set_code_tx ~target:V.authority_key0 ~gas_limit:100_000
         ~authorizations:[ auth_key0 ] ())
  in
  Alcotest.(check bool) "success" true (receipt_is_success receipt);
  check_word "the delegate's SSTORE landed in the AUTHORITY's storage" (u 42)
    (World_state.storage w V.authority_key0 U256.one);
  check_word "the delegate contract's own storage is untouched" U256.zero
    (World_state.storage w V.target_11s U256.one);
  Alcotest.(check string) "the designator is live on the authority" V.designator_11s_hex
    (code_hex_at w V.authority_key0);
  Alcotest.(check int) "with its nonce bump" 1 (nonce_at w V.authority_key0);
  (* intrinsic 21000 + 25000 = 46000; frame 3 + 3 + 22100 (cold SSTORE 0->42)
     = 22106; fresh authority, so no refund: net 68106. *)
  Alcotest.(check int) "hand-computed net" 68106 (Receipt.gas_used receipt)

(* Naming a delegated account in the ACCESS LIST warms only that address
   ([journal.rs:170-173] is an address-set insert, no code load); the
   AUTHORIZATION list warms authorities, never their delegate targets
   ([pre_execution.rs:234-237]). In both legs the delegate's cold 2500 is
   still paid by the first CALL; the control run that ALSO lists the delegate
   drops it. *)
let test_neither_list_warms_the_delegate () =
  (* Leg 1: access list. M calls the delegated [al_target] (-> absent
     [al_delegate]). *)
  let al_target = addr_hex "b7" in
  let al_delegate = addr_hex "b8" in
  let measuring = addr_hex "e5" in
  let measure dst =
    bytes_of
      (call ~gas:(u 60_000) ~dst ~value:U256.zero ~in_off:0 ~in_len:0 ~out_off:0
         ~out_len:0
      @ [ op Opcode.Stop ])
  in
  let world =
    world_seed
      [
        (sender, account ~nonce:0 ~balance:1_000_000_000);
        (al_target, delegated ~to_:al_delegate ~balance:U256.zero);
        (measuring, Account.with_code (account ~nonce:1 ~balance:0) (measure al_target));
      ]
  in
  let dynamic ~access_list =
    Transaction.make ~sender ~nonce:(nonce_of 0) ~gas_limit:100_000
      ~kind:(Transaction.Call measuring) ~value:U256.zero ~data:"" ~access_list
      ~chain_id:(Some (u 1))
      ~fee:(Transaction.Dynamic { max_fee = U256.zero; max_priority = None })
  in
  let listed, _ = exec_ok world ~block:block0 (dynamic ~access_list:[ (al_target, []) ]) in
  (* 21000 + 2400 (one listed address) + 21 pushes + 100 static + 0 (target
     warm via the list) + 2600 (delegate COLD: the list did not warm it). A
     port that "helpfully" pre-warmed the delegate reads 23621. *)
  Alcotest.(check int) "listing the delegator leaves the delegate cold" 26121
    (Receipt.gas_used listed);
  let both, _ =
    exec_ok world ~block:block0
      (dynamic ~access_list:[ (al_target, []); (al_delegate, []) ])
  in
  (* 21000 + 4800 + 21 + 100 + 0 + 100: the 2500 was the delegate's own. *)
  Alcotest.(check int) "listing the delegate too is what warms it" 26021
    (Receipt.gas_used both);
  (* Leg 2: authorization list. A type-4 transaction delegates key0's
     authority to 0x22*20 and then CALLs the authority: check 4 warmed the
     AUTHORITY, never its target. *)
  let measuring2 = addr_hex "e6" in
  let world2 =
    world_seed
      [
        (sender, account ~nonce:0 ~balance:1_000_000_000);
        (measuring2,
         Account.with_code (account ~nonce:1 ~balance:0) (measure V.authority_key0));
      ]
  in
  let warmed, _ =
    exec_ok world2 ~block:block0
      (set_code_tx ~target:measuring2 ~gas_limit:150_000
         ~authorizations:[ signed_of V.k0_d2_n0 ] ())
  in
  (* 21000 + 25000 + 21 + 100 + 0 (authority warm, check 4) + 2600 (its fresh
     delegate 0x22*20 COLD); the authority is fresh so nothing refunds. *)
  Alcotest.(check int) "the auth list warms the authority, not the delegate" 48721
    (Receipt.gas_used warmed);
  let control, _ =
    exec_ok world2 ~block:block0
      (set_code_tx ~target:measuring2 ~gas_limit:150_000
         ~access_list:[ (V.target_22s, []) ]
         ~authorizations:[ signed_of V.k0_d2_n0 ] ())
  in
  (* + 2400 for the listed delegate, and the CALL's 2600 becomes 100. *)
  Alcotest.(check int) "listing the delegate is what warms it" 48621
    (Receipt.gas_used control)

(* The depth-0 frame follows a DB-supplied designator with NO gas charge and
   BOTH accounts warm for free ([handler.rs:314-332]: both loads sit outside
   any gas metering), on an ordinary LEGACY transaction with no authorization
   anywhere. *)
let test_top_level_frame_resolves_free_and_prewarms_both () =
  let top_a = addr_hex "c5" in
  let top_d = addr_hex "c6" in
  let legacy ~gas_limit ~target =
    Transaction.make ~sender ~nonce:(nonce_of 0) ~gas_limit
      ~kind:(Transaction.Call target) ~value:U256.zero ~data:"" ~access_list:[]
      ~chain_id:None
      ~fee:(Transaction.Legacy { gas_price = U256.zero })
  in
  let world_with delegate_code =
    world_seed
      [
        (sender, account ~nonce:0 ~balance:1_000_000_000);
        (top_a, delegated ~to_:top_d ~balance:U256.zero);
        (top_d, Account.with_code (account ~nonce:1 ~balance:0) delegate_code);
      ]
  in
  (* (a) The delegate STOPs: gas_used is the bare 21000 intrinsic. Charging
     the resolution would read 23600. *)
  let stopped, _ =
    exec_ok (world_with (bytes_of [ op Opcode.Stop ])) ~block:block0
      (legacy ~gas_limit:30_000 ~target:top_a)
  in
  Alcotest.(check int) "resolution is FREE at depth 0" 21000 (Receipt.gas_used stopped);
  (* (b) BALANCE of the delegate, then of the designator: both warm for free,
     so each run is 21000 + 3 (PUSH20) + 100 (warm BALANCE) + 2 (POP). *)
  let balance_probe target =
    bytes_of [ push20 target; op Opcode.Balance; op Opcode.Pop; op Opcode.Stop ]
  in
  let warm_delegate, _ =
    exec_ok (world_with (balance_probe top_d)) ~block:block0
      (legacy ~gas_limit:100_000 ~target:top_a)
  in
  Alcotest.(check int) "the delegate is pre-warmed" 21105 (Receipt.gas_used warm_delegate);
  let warm_designator, _ =
    exec_ok (world_with (balance_probe top_a)) ~block:block0
      (legacy ~gas_limit:100_000 ~target:top_a)
  in
  Alcotest.(check int) "the designator is warm too" 21105 (Receipt.gas_used warm_designator);
  (* (c) The G-shape sibling: the delegate's SSTORE lands in the DESIGNATING
     account's storage, from state alone. 21000 + 6 + 22100 = 43106. *)
  let wrote, w =
    exec_ok (world_with (V.hex "602a60015500")) ~block:block0
      (legacy ~gas_limit:100_000 ~target:top_a)
  in
  Alcotest.(check int) "and pays only the frame's own gas" 43106 (Receipt.gas_used wrote);
  check_word "the write landed on the designating account" (u 42)
    (World_state.storage w top_a U256.one);
  check_word "not on the delegate" U256.zero (World_state.storage w top_d U256.one)

(* ================================================================== *)
(* 4. Block-level: a type-4 transaction through the whole spine.       *)
(* ================================================================== *)

(* The G1 shape (one authorization, existing authority) as a BLOCK: the trie
   leaf is the bare 2718 bytes and the receipt is framed with type byte 4,
   neither of which any envelope-layer test exercises end to end. The envelope
   signature is Block_fixtures' synthetic one; the sender is whatever it
   recovers, funded by {!Block_fixtures.fund}. *)
let test_block_with_type4_tx_roots () =
  let payload =
    Tx_payload.eip7702 ~chain_id:(u 1) ~nonce:(nonce_of 0)
      ~max_priority_fee_per_gas:(u 0) ~max_fee_per_gas:(u 0) ~gas_limit:46_000
      ~to_:(addr_hex "b2") ~value:U256.zero ~data:"" ~access_list:[]
      ~authorizations:[ auth_key0 ]
  in
  let envelope = Block_fixtures.sign ~signer:61 payload in
  let world =
    Block_fixtures.fund
      (World_state.set_account World_state.empty V.authority_key0
         (account ~nonce:0 ~balance:1))
      [ envelope ]
  in
  let ctx = Block_fixtures.context () in
  let _pre, outcome =
    Result.fold ~ok:Fun.id
      ~error:(fun e -> Alcotest.failf "block rejected: %s" (Block_execution.error_to_string e))
      (Block_execution.execute world ~context:ctx [ envelope ])
  in
  (match Block_execution.receipts outcome with
  | [] -> Alcotest.fail "expected one receipt"
  | _ :: _ :: _ -> Alcotest.fail "expected exactly one receipt"
  | [ (type_byte, receipt) ] ->
      Alcotest.(check int) "the receipt is framed as type 4" 4 type_byte;
      Alcotest.(check bool) "and is a success" true (receipt_is_success receipt);
      (* G1's corrected arithmetic: spent 46000, pot 12500, cap 9200 binds. *)
      Alcotest.(check int) "G1 net through the block layer" 36800
        (Receipt.gas_used receipt);
      Alcotest.(check string)
        "the receipts root commits the type-4-framed receipt"
        (V.to_hex
           (Block_roots.transactions_root
              [ Receipt_envelope.encode_2718 ~type_byte:4 ~cumulative_gas_used:36800 receipt ]))
        (V.to_hex (Block_roots.receipts_root (Block_execution.receipts outcome))));
  Alcotest.(check int) "the block's own meter agrees" 36800
    (Block_execution.gas_used outcome);
  Alcotest.(check string) "the transactions root is the trie over the bare 2718 bytes"
    (V.to_hex (Block_roots.transactions_root [ Tx_envelope.encode_2718 envelope ]))
    (V.to_hex (Block_roots.transactions_root_of (Block_execution.transactions outcome)));
  let final = Block_execution.world outcome in
  Alcotest.(check string) "the post-block world carries the designator"
    V.designator_11s_hex (code_hex_at final V.authority_key0);
  Alcotest.(check int) "and the authority's bump" 1 (nonce_at final V.authority_key0)

(* ================================================================== *)
(* 5. The negative space: what must NOT change (stage 6).              *)
(* ================================================================== *)

(* These three pass with ZERO production edits at the EXTCODE*, BALANCE,
   SELFDESTRUCT and CREATE-collision sites, and that is their point: they are
   the falsification test of storing the raw 23 designator bytes as
   [Account.code] with the hash derived. If any of them ever needs a
   production change to pass, that decision was wrong.

   The fixtures extend the shared world locally. The wide delegate sits at
   0x11..11 = {!V.target_11s} so EXTCODEHASH can be pinned against the
   EXTERNALLY computed keccak of its designator's 23 bytes
   ({!V.designator_11s_code_hash}, from cast keccak) rather than against
   anything the port derives; the revoked account is written through the same
   smart constructor the loop uses, which stores EMPTY code for the zero
   address ([Delegation.assignment] answers [Revoke]), never
   [ef0100 || 00*20]. *)

let a_wide = address_of 0xa8
let a_revoked = address_of 0xa9
let d_boom = address_of 0xd6
let a_boom = address_of 0xab
let boom_beneficiary = address_of 0xbf
let addr_zero = V.addr_of_hex (String.make 40 '0')

(* keccak256 of the empty string, revm's KECCAK_EMPTY ([primitives]). *)
let keccak_empty_hex = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"

(* EIP7702_MAGIC_HASH ([revm-bytecode] [eip7702.rs:4-6]): defined, documented
   as "used for EXTCODEHASH", and referenced NOWHERE in revm — the trap. *)
let eip7702_magic_hash_hex =
  "eadcdba66a79ab5dce91622d1d75c8cff5cff0b96944c3bf1072cd08ce018329"

(* PUSH20 beneficiary, SELFDESTRUCT: run behind a designator, it must act on
   the DELEGATOR. *)
let code_boom = bytes_of [ push20 boom_beneficiary; op Opcode.Selfdestruct ]

let world_neg =
  List.fold_left
    (fun w (address, acct) -> World_state.set_account w address acct)
    world
    [
      (V.target_11s, coded ~code:(String.make 100 '\001') U256.zero);
      (a_wide, delegated ~to_:V.target_11s ~balance:(u 654));
      ( a_revoked,
        Account.with_code
          (Account.make ~nonce:(nonce_of 1) ~balance:U256.zero)
          (designator addr_zero) );
      (d_boom, coded ~code:code_boom U256.zero);
      (a_boom, delegated ~to_:d_boom ~balance:(u 900));
    ]

let neg_cold = Effects.start ~world:world_neg ~access:Access.empty

let neg_warm addresses =
  Effects.start ~world:world_neg ~access:(Access.of_transaction ~addresses ~slots:[])

let run_neg ?(effects = neg_cold) ?(gas = allowance) parts =
  Interpreter.run ~env:ienv ~code:(asm parts) ~gas:(gas_of gas) ~effects

(* EXTCODECOPY pops the address first, then dest, source, length; pushed in
   reverse so the address ends on top. *)
let extcodecopy_32 target =
  [ push1 0x20; push1 0; push1 0; push20 target; op Opcode.Extcodecopy ]

(* EXTCODESIZE / EXTCODECOPY / EXTCODEHASH / BALANCE do NOT follow the
   designator ([host.rs:61-64], [140-142], [86-103], [22-24]): with a delegate
   holding 100 bytes of code, the delegated account still reports its own 23
   bytes, keccak of THOSE bytes, and its own balance. None of the four charges
   a delegation surcharge — the delegate at 0x11..11 is never warmed, and the
   absolute prices are test_extcode.ml's own figures, unshifted. *)
let test_extcode_family_sees_the_designator () =
  let reads =
    run_neg
      [
        push20 a_wide; op Opcode.Extcodesize; push1 0; op Opcode.Sstore;
        push20 a_wide; op Opcode.Extcodehash; push1 1; op Opcode.Sstore;
        push20 a_wide; op Opcode.Balance; push1 2; op Opcode.Sstore;
        op Opcode.Stop;
      ]
  in
  check_word "EXTCODESIZE is the designator's 23, not the delegate's 100, not 0"
    (u 23) (storage_of reads self 0);
  let hash = storage_of reads self 1 in
  check_word "EXTCODEHASH is keccak of the 23 designator bytes"
    (V.w_of_hex V.designator_11s_code_hash) hash;
  Alcotest.(check bool) "which is not KECCAK_EMPTY" false
    (U256.equal (V.w_of_hex keccak_empty_hex) hash);
  Alcotest.(check bool) "and not the dead EIP7702_MAGIC_HASH" false
    (U256.equal (V.w_of_hex eip7702_magic_hash_hex) hash);
  check_word "BALANCE is the delegator's own" (u 654) (storage_of reads self 2);
  (* The 32-byte window: ef 01 00, the address, then 9 zeroes of padding. *)
  let copied =
    output_of (run_neg (extcodecopy_32 a_wide @ [ push1 0x20; push1 0; op Opcode.Return ]))
  in
  Alcotest.(check string) "EXTCODECOPY copies the raw designator, zero-padded"
    (V.designator_11s ^ String.make 9 '\000')
    copied;
  (* The existing prices, delegate never warmed: 3 + 100 + 2500 + 2 cold,
     3 + 100 + 2 warm for the word readers; 12 + 100 + copy 3 + expansion 3 +
     2500 cold and 118 warm for the 32-byte copy — test_extcode.ml's own
     derivations. A followed designator would surface as +100 or +2600. *)
  let probe ~effects parts = spent (run_neg ~effects parts) in
  let word_reader opcode = [ push20 a_wide; op opcode; op Opcode.Pop; op Opcode.Stop ] in
  List.iter
    (fun (name, opcode) ->
      Alcotest.(check int) (name ^ " cold costs its existing 2605") 2605
        (probe ~effects:neg_cold (word_reader opcode));
      Alcotest.(check int) (name ^ " warm costs its existing 105") 105
        (probe ~effects:(neg_warm [ a_wide ]) (word_reader opcode)))
    [
      ("EXTCODESIZE", Opcode.Extcodesize); ("EXTCODEHASH", Opcode.Extcodehash);
      ("BALANCE", Opcode.Balance);
    ];
  let copy_probe = extcodecopy_32 a_wide @ [ op Opcode.Stop ] in
  Alcotest.(check int) "EXTCODECOPY cold costs its existing 2618" 2618
    (probe ~effects:neg_cold copy_probe);
  Alcotest.(check int) "EXTCODECOPY warm costs its existing 118" 118
    (probe ~effects:(neg_warm [ a_wide ]) copy_probe)

(* The same reads AFTER a zero-address revocation, which is where an
   unconditional "a designator pushes 23" would be wrong: the write path
   stored EMPTY code, so EXTCODESIZE reads 0 and EXTCODECOPY reads zeroes.
   EXTCODEHASH is KECCAK_EMPTY and NOT the EIP-1052 zero word, because the
   revocation's nonce bump defeats [is_empty]. Storing [ef0100 || 00*20]
   instead would answer 23 and the wrong hash forever. *)
let test_extcode_family_after_revocation () =
  let reads =
    run_neg
      [
        push20 a_revoked; op Opcode.Extcodesize; push1 0; op Opcode.Sstore;
        push20 a_revoked; op Opcode.Extcodehash; push1 1; op Opcode.Sstore;
        op Opcode.Stop;
      ]
  in
  check_word "EXTCODESIZE after revocation is 0" U256.zero (storage_of reads self 0);
  check_word "EXTCODEHASH after revocation is KECCAK_EMPTY"
    (V.w_of_hex keccak_empty_hex) (storage_of reads self 1);
  Alcotest.(check bool) "and NOT the EIP-1052 zero word: nonce 1 defeats is_empty"
    false
    (U256.equal U256.zero (storage_of reads self 1));
  let copied =
    output_of
      (run_neg (extcodecopy_32 a_revoked @ [ push1 0x20; push1 0; op Opcode.Return ]))
  in
  Alcotest.(check string) "EXTCODECOPY after revocation copies zeroes"
    (String.make 32 '\000') copied

(* SELFDESTRUCT run BY the delegate's code acts on the DELEGATOR and,
   post-Cancun, destroys nothing this transaction did not create
   ([journal/inner.rs:534-545]; [delegate] never marks CreatedLocal): the
   balance moves and the designator and nonce SURVIVE. And a delegated address
   is occupied — nonce 1 and 23 bytes of code — so a CREATE2 aimed at it is a
   collision ([journal/inner.rs:411-414]): delegating a counterfactual CREATE2
   address permanently bricks deployment there. *)
let test_delegated_account_survives_selfdestruct_and_bricks_create2 () =
  let boom =
    run_neg
      (call ~gas:all_gas ~dst:a_boom ~value:U256.zero ~in_off:0 ~in_len:0 ~out_off:0
         ~out_len:0
      @ [ push1 0; op Opcode.Sstore; op Opcode.Stop ])
  in
  check_word "the delegated SELFDESTRUCT frame succeeds" U256.one (storage_of boom self 0);
  check_word "the delegator's balance moved" U256.zero (balance_of boom a_boom);
  check_word "to the beneficiary" (u 900) (balance_of boom boom_beneficiary);
  let after = Effects.world (effects_of boom) in
  Alcotest.(check string) "the designator survives the SELFDESTRUCT"
    (V.to_hex (designator d_boom)) (code_hex_at after a_boom);
  Alcotest.(check int) "and so does the nonce" 1 (nonce_at after a_boom);
  (* The brick: CREATE2 with empty init code and salt 0, whose derived address
     was delegated beforehand. CREATE2 pops value, offset, len, salt — salt
     pushed first. *)
  let salt = U256.zero in
  let bricked =
    Contract_address.derive ~creator:self (Contract_address.From_salt { salt; init_code = "" })
  in
  let world_bricked =
    World_state.set_account world_neg bricked (delegated ~to_:d_stop ~balance:U256.zero)
  in
  let run_bricked ~gas parts =
    Interpreter.run ~env:ienv ~code:(asm parts) ~gas:(gas_of gas)
      ~effects:(Effects.start ~world:world_bricked ~access:Access.empty)
  in
  let create2 = [ push32 salt; push1 0; push1 0; push1 0; op Opcode.Create2 ] in
  let pushed = run_bricked ~gas:allowance (create2 @ [ push1 0; op Opcode.Sstore; op Opcode.Stop ]) in
  check_word "CREATE2 at the delegated address pushes zero" U256.zero
    (storage_of pushed self 0);
  let after2 = Effects.world (effects_of pushed) in
  Alcotest.(check string) "the designator is untouched"
    (V.to_hex (designator d_stop)) (code_hex_at after2 bricked);
  Alcotest.(check int) "its nonce is still 1" 1 (nonce_at after2 bricked);
  Alcotest.(check int) "the creator's nonce still bumped" 1 (nonce_at after2 self);
  (* The whole forward burns, exactly test_creation.ml's collision class:
     allowance 100000, pushes 12, static 32000, R = 67988, R/64 = 1062 kept,
     spend 98938. *)
  let gas_leg = run_bricked ~gas:100_000 (create2 @ [ op Opcode.Stop ]) in
  Alcotest.(check int) "a collision burns the forward" 98938 (100_000 - remaining_of gas_leg)

let () =
  Alcotest.run "eip7702 calls"
    [
      ( "resolver",
        [
          prop_non_delegated_identity;
          Alcotest.test_case "charging the zero surcharge is free" `Quick
            test_charge_zero_is_free;
        ] );
      ( "interpreter",
        [
          Alcotest.test_case "delegated_frame_context_is_the_delegator" `Quick
            test_delegated_frame_context_is_the_delegator;
          Alcotest.test_case "codesize_flips_against_extcodesize" `Quick
            test_codesize_flips_against_extcodesize;
          Alcotest.test_case "call_delegation_gas_four_corners" `Quick
            test_call_delegation_gas_four_corners;
          Alcotest.test_case "two_hop_chain_halts_invalid_opcode" `Quick
            test_two_hop_chain_halts_invalid_opcode;
          Alcotest.test_case "empty_delegate_succeeds" `Quick test_empty_delegate_succeeds;
          Alcotest.test_case "call_to_delegated_charges_no_new_account" `Quick
            test_call_to_delegated_charges_no_new_account;
          Alcotest.test_case "delegated_to_precompile_does_not_run_it" `Quick
            test_delegated_to_precompile_does_not_run_it;
        ] );
      ( "executor",
        [
          Alcotest.test_case "same_tx_delegate_then_execute_REQUIRED" `Quick
            test_same_tx_delegate_then_execute;
          Alcotest.test_case "neither_list_warms_the_delegate" `Quick
            test_neither_list_warms_the_delegate;
          Alcotest.test_case "top_level_frame_resolves_free_and_prewarms_both" `Quick
            test_top_level_frame_resolves_free_and_prewarms_both;
        ] );
      ( "block",
        [
          Alcotest.test_case "block_with_type4_tx_roots" `Quick
            test_block_with_type4_tx_roots;
        ] );
      ( "negative space",
        [
          Alcotest.test_case "extcode_family_sees_the_designator" `Quick
            test_extcode_family_sees_the_designator;
          Alcotest.test_case "extcode_family_after_revocation" `Quick
            test_extcode_family_after_revocation;
          Alcotest.test_case "delegated_account_survives_selfdestruct_and_bricks_create2"
            `Quick test_delegated_account_survives_selfdestruct_and_bricks_create2;
        ] );
    ]
