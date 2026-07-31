(* The single-transaction executor (chunk 26): the Prague mainnet transaction STF.

   test_creation.ml conventions throughout: a miniature assembler, a world seeded
   by a fold over set_account, absolute hand-computed gas asserted as literals with
   the derivation in a comment, and every outcome class asserted on the receipt and
   the resulting balances so a regression that flips a class or misprices a step
   fails here. Where a frame's gas comes from the interpreter (an SSTORE, a REVERT,
   a creation's init run) the derivation is spelled out and the literal is what the
   interpreter actually charges. *)

module U256 = Tn_state.U256
module Nonce = Tn_state.Nonce
module Units = Tn_types.Units
module Account = Tn_state.Account
module World_state = Tn_state.World_state
module Env = Tn_evm.Env
module Opcode = Tn_evm.Opcode
module Data = Tn_evm.Data
module Block_hashes = Tn_evm.Block_hashes
module Contract_address = Tn_evm.Contract_address
module Interpreter = Tn_evm.Interpreter
module Transaction = Tn_evm.Transaction
module Intrinsic = Tn_evm.Intrinsic
module Receipt = Tn_evm.Receipt
module Executor = Tn_evm.Executor

let get = function Some x -> x | None -> Alcotest.fail "expected Some"
let u n = get (U256.of_int n)
let nonce_of n = get (Nonce.of_int n)
let width_of n = get (Opcode.Push_bytes.of_int n)

(* A twenty-byte address whose last byte is [n]; distinct from the precompile
   addresses 0x01..0x0a for any [n] outside that range. *)
let address_of n =
  get
    (Units.Address.of_bytes
       (String.make (Units.Address.length - 1) '\000' ^ String.make 1 (Char.chr n)))

(* ---------- the miniature assembler ---------- *)

let byte b = String.make 1 (Char.chr b)
let op o = byte (Opcode.to_byte o)
let push1 n = op (Opcode.Push (width_of 1)) ^ byte n
let bytes_of parts = String.concat "" parts

(* ---------- world and block ---------- *)

let account ~nonce ~balance = Account.make ~nonce:(nonce_of nonce) ~balance:(u balance)

let world_seed pairs =
  List.fold_left
    (fun w (address, acct) -> World_state.set_account w address acct)
    World_state.empty pairs

let block_of ~coinbase ~basefee =
  Env.Block.make ~coinbase ~timestamp:(u 1_600_000_000) ~number:(u 1000)
    ~prevrandao:U256.zero ~gas_limit:(u 30_000_000) ~basefee:(u basefee)
    ~basefee_address:Tn_evm.System_contracts.governance_safe_address
    ~chain_id:(u 1) ~blob_gasprice:Env.Block.consensus_blob_gasprice
    ~hashes:Block_hashes.empty

(* ---------- fixed actors ---------- *)

let sender = address_of 0xa1
let target = address_of 0xb2
let coinbase = address_of 0xc3

(* ---------- reading results ---------- *)

let bal world address = get (U256.to_int (World_state.balance world address))
let nonce_int world address = Nonce.to_int (World_state.nonce world address)

let present world address =
  List.exists (fun (a, _) -> Units.Address.equal a address) (World_state.accounts world)

let exec_ok world ~block tx =
  match Executor.execute world ~block tx with
  | Ok result -> result
  | Error e -> Alcotest.failf "unexpected rejection: %s" (Executor.error_to_string e)

(* The receipt's inline records cannot escape a match, so each expectation projects
   the fields it needs into a local record with distinct names. *)
type succ = {
  su_output : string;
  su_created : Units.Address.t option;
  su_gas_used : int;
  su_gas_refunded : int;
  su_logs : Tn_evm.Log.t list;
}

type rev = { rv_output : string; rv_gas_used : int }
type hlt = { hl_reason : Receipt.halt_reason; hl_gas_used : int }

let expect_success = function
  | Receipt.Success { output; created; gas_used; gas_refunded; logs } ->
      {
        su_output = output;
        su_created = created;
        su_gas_used = gas_used;
        su_gas_refunded = gas_refunded;
        su_logs = logs;
      }
  | Receipt.Reverted _ | Receipt.Halted _ -> Alcotest.fail "expected Success"

let expect_reverted = function
  | Receipt.Reverted { output; gas_used } -> { rv_output = output; rv_gas_used = gas_used }
  | Receipt.Success _ | Receipt.Halted _ -> Alcotest.fail "expected Reverted"

let expect_halted = function
  | Receipt.Halted { reason; gas_used } -> { hl_reason = reason; hl_gas_used = gas_used }
  | Receipt.Success _ | Receipt.Reverted _ -> Alcotest.fail "expected Halted"

let check_reason ~expected reason =
  Alcotest.(check string)
    "halt reason"
    (Receipt.halt_reason_to_string expected)
    (Receipt.halt_reason_to_string reason)

(* ========================================================================== *)
(* Value-transfer calls: Legacy and EIP-1559.                                 *)
(* ========================================================================== *)

(* A plain Legacy transfer to an empty account. No calldata, so intrinsic = floor
   = 21000; the empty callee code returns all forwarded gas. Deduct is
   gas_limit * gas_price = 100000*10 = 1_000_000; the caller is reimbursed
   gas_price * (100000 - 21000) = 790_000 and the beneficiary is paid
   (10 - 3) * 21000 = 147_000, so the base fee 3 * 21000 is burned. *)
let test_legacy_value_transfer () =
  let world = world_seed [ (sender, account ~nonce:0 ~balance:1_000_000_000) ] in
  let tx =
    Transaction.make ~sender ~nonce:(nonce_of 0) ~gas_limit:100000
      ~kind:(Transaction.Call target) ~value:(u 5000) ~data:"" ~access_list:[]
      ~chain_id:(Some (u 1)) ~fee:(Transaction.Legacy { gas_price = u 10 })
  in
  let receipt, world' = exec_ok world ~block:(block_of ~coinbase ~basefee:3) tx in
  let s = expect_success receipt in
  Alcotest.(check int) "gas used" 21000 s.su_gas_used;
  Alcotest.(check int) "gas refunded" 0 s.su_gas_refunded;
  Alcotest.(check int) "logs" 0 (List.length s.su_logs);
  Alcotest.(check bool) "no created address" true (Option.is_none s.su_created);
  (* B - used*price - value = 1e9 - 210000 - 5000 *)
  Alcotest.(check int) "sender balance" 999_785_000 (bal world' sender);
  Alcotest.(check int) "recipient balance" 5000 (bal world' target);
  Alcotest.(check int) "coinbase balance" 147_000 (bal world' coinbase);
  Alcotest.(check int) "sender nonce bumped" 1 (nonce_int world' sender)

(* The same transfer as EIP-1559 with max_fee 10, priority 2, base fee 3, so the
   effective price is min(10, 3+2) = 5. Deduct is gas_limit * effective = 500_000,
   but the balance CHECK used max_fee (100000*10 + 5000), so a tx that passes the
   check is charged the lower effective price. Caller reimbursed 5*(100000-21000);
   beneficiary paid (5-3)*21000 = 42_000. *)
let test_eip1559_value_transfer () =
  let world = world_seed [ (sender, account ~nonce:0 ~balance:1_000_000_000) ] in
  let tx =
    Transaction.make ~sender ~nonce:(nonce_of 0) ~gas_limit:100000
      ~kind:(Transaction.Call target) ~value:(u 5000) ~data:"" ~access_list:[]
      ~chain_id:(Some (u 1))
      ~fee:(Transaction.Dynamic { max_fee = u 10; max_priority = Some (u 2) })
  in
  let receipt, world' = exec_ok world ~block:(block_of ~coinbase ~basefee:3) tx in
  let s = expect_success receipt in
  Alcotest.(check int) "gas used" 21000 s.su_gas_used;
  (* B - used*effective - value = 1e9 - 21000*5 - 5000 *)
  Alcotest.(check int) "sender balance" 999_890_000 (bal world' sender);
  Alcotest.(check int) "recipient balance" 5000 (bal world' target);
  Alcotest.(check int) "coinbase balance (effective-basefee)" 42_000 (bal world' coinbase)

(* The effective_gas_price formula, exercised directly across the three fee
   types. *)
let test_effective_gas_price () =
  let base_fee = u 100 in
  let legacy = Transaction.Legacy { gas_price = u 30 } in
  let al = Transaction.Access_list { gas_price = u 30 } in
  let capped = Transaction.Dynamic { max_fee = u 500; max_priority = Some (u 50) } in
  let uncapped = Transaction.Dynamic { max_fee = u 120; max_priority = Some (u 50) } in
  let no_tip = Transaction.Dynamic { max_fee = u 500; max_priority = None } in
  let mk fee =
    Transaction.make ~sender ~nonce:(nonce_of 0) ~gas_limit:21000
      ~kind:(Transaction.Call target) ~value:U256.zero ~data:"" ~access_list:[]
      ~chain_id:(Some (u 1)) ~fee
  in
  let eff fee = get (U256.to_int (Transaction.effective_gas_price (mk fee) ~base_fee)) in
  Alcotest.(check int) "legacy is gas_price" 30 (eff legacy);
  Alcotest.(check int) "2930 is gas_price" 30 (eff al);
  Alcotest.(check int) "1559 min picks base+tip" 150 (eff capped);
  Alcotest.(check int) "1559 min picks max_fee" 120 (eff uncapped);
  Alcotest.(check int) "1559 no tip is max_fee" 500 (eff no_tip)

(* ========================================================================== *)
(* Intrinsic gas and the EIP-7623 floor.                                      *)
(* ========================================================================== *)

(* The intrinsic-gas primitive on its own: 100 zero calldata bytes = 100 tokens,
   so exec intrinsic = 100*4 + 21000 = 21400 and floor = 100*10 + 21000 = 22000;
   a creation adds 32000 + 2*num_words(len). *)
let test_intrinsic_primitive () =
  let data = String.make 100 '\000' in
  Alcotest.(check int) "call intrinsic" 21400
    (Intrinsic.initial_gas ~kind:Intrinsic.Call ~data ~access_list:[] ~authorizations:[]);
  Alcotest.(check int) "floor" 22000 (Intrinsic.floor_gas ~data);
  (* one nonzero byte = 4 tokens: 4*4 + 21000 = 21016 exec, 4*10 + 21000 floor *)
  Alcotest.(check int) "one nonzero byte exec" 21016
    (Intrinsic.initial_gas ~kind:Intrinsic.Call ~data:"\x01" ~access_list:[]
       ~authorizations:[]);
  Alcotest.(check int) "one nonzero byte floor" 21040 (Intrinsic.floor_gas ~data:"\x01");
  (* create over 5 init bytes (tokens 17): 17*4 + 21000 + 32000 + 2*1 = 53070 *)
  Alcotest.(check int) "create intrinsic" 53070
    (Intrinsic.initial_gas ~kind:Intrinsic.Create
       ~data:(bytes_of [ push1 0x01; push1 0x00; op Opcode.Return ])
       ~access_list:[] ~authorizations:[])

(* A data-heavy transfer where the EIP-7623 floor binds. 100 zero bytes give
   intrinsic 21400 and floor 22000; the empty callee spends nothing beyond the
   intrinsic, so the gross spend 21400 is below the floor and the floor is charged:
   gas_used is 22000, NOT 21400. Base fee 4, so coinbase gets (10-4)*22000. *)
let test_eip7623_floor_binds () =
  let world = world_seed [ (sender, account ~nonce:0 ~balance:1_000_000_000) ] in
  let tx =
    Transaction.make ~sender ~nonce:(nonce_of 0) ~gas_limit:100000
      ~kind:(Transaction.Call target) ~value:U256.zero ~data:(String.make 100 '\000')
      ~access_list:[] ~chain_id:(Some (u 1))
      ~fee:(Transaction.Legacy { gas_price = u 10 })
  in
  let receipt, world' = exec_ok world ~block:(block_of ~coinbase ~basefee:4) tx in
  let s = expect_success receipt in
  Alcotest.(check int) "gas used is the floor" 22000 s.su_gas_used;
  (* B - used*price = 1e9 - 22000*10 *)
  Alcotest.(check int) "sender balance" 999_780_000 (bal world' sender);
  Alcotest.(check int) "coinbase balance" 132_000 (bal world' coinbase);
  Alcotest.(check bool) "fresh zero-value target not materialized" false
    (present world' target)

(* ========================================================================== *)
(* Halt and revert.                                                           *)
(* ========================================================================== *)

(* An out-of-gas halt burns the entire gas limit. The callee is a tight JUMP loop
   (JUMPDEST; PUSH1 0; JUMP) that spends forever until the allowance cannot pay the
   next instruction. A halt reverts the value transfer, keeps the nonce bump and
   the fee, forwards nothing back to the caller, and pays the beneficiary on the
   full limit: (10-3)*100000 = 700_000. *)
let test_out_of_gas_halt () =
  let loop = bytes_of [ op Opcode.Jumpdest; push1 0x00; op Opcode.Jump ] in
  let world =
    world_seed
      [
        (sender, account ~nonce:0 ~balance:1_000_000_000);
        (target, Account.with_code (account ~nonce:0 ~balance:0) loop);
      ]
  in
  let tx =
    Transaction.make ~sender ~nonce:(nonce_of 0) ~gas_limit:100000
      ~kind:(Transaction.Call target) ~value:(u 5000) ~data:"" ~access_list:[]
      ~chain_id:(Some (u 1)) ~fee:(Transaction.Legacy { gas_price = u 10 })
  in
  let receipt, world' = exec_ok world ~block:(block_of ~coinbase ~basefee:3) tx in
  let h = expect_halted receipt in
  check_reason ~expected:(Receipt.Frame_halt Interpreter.Out_of_gas) h.hl_reason;
  Alcotest.(check int) "gas used is the whole limit" 100000 h.hl_gas_used;
  (* value reverted, only the gas is gone: B - limit*price *)
  Alcotest.(check int) "sender balance" 999_000_000 (bal world' sender);
  Alcotest.(check int) "callee value reverted" 0 (bal world' target);
  Alcotest.(check int) "coinbase paid on the full limit" 700_000 (bal world' coinbase);
  Alcotest.(check int) "sender nonce persists" 1 (nonce_int world' sender)

(* A revert returns the unused gas and rolls back the value transfer, but keeps the
   nonce bump and the fee on the gas actually spent. The callee (PUSH1 0; PUSH1 0;
   REVERT) spends 6 gas beyond the intrinsic, so the gross spend is 21000 + 6 =
   21006 and gas_used is 21006 (the floor 21000 does not bind). *)
let test_revert () =
  let revert_code = bytes_of [ push1 0x00; push1 0x00; op Opcode.Revert ] in
  let world =
    world_seed
      [
        (sender, account ~nonce:0 ~balance:1_000_000_000);
        (target, Account.with_code (account ~nonce:0 ~balance:0) revert_code);
      ]
  in
  let tx =
    Transaction.make ~sender ~nonce:(nonce_of 0) ~gas_limit:100000
      ~kind:(Transaction.Call target) ~value:(u 5000) ~data:"" ~access_list:[]
      ~chain_id:(Some (u 1)) ~fee:(Transaction.Legacy { gas_price = u 10 })
  in
  let receipt, world' = exec_ok world ~block:(block_of ~coinbase ~basefee:3) tx in
  let r = expect_reverted receipt in
  Alcotest.(check int) "gas used includes the 6-gas revert" 21006 r.rv_gas_used;
  Alcotest.(check string) "empty revert output" "" r.rv_output;
  (* value reverted: B - used*price *)
  Alcotest.(check int) "sender balance" 999_789_940 (bal world' sender);
  Alcotest.(check int) "callee value reverted" 0 (bal world' target);
  Alcotest.(check int) "coinbase balance" 147_042 (bal world' coinbase);
  Alcotest.(check int) "sender nonce persists" 1 (nonce_int world' sender)

(* ========================================================================== *)
(* Contract creation.                                                          *)
(* ========================================================================== *)

let init_return_one_zero = bytes_of [ push1 0x01; push1 0x00; op Opcode.Return ]

(* A successful creation. The init code (PUSH1 1; PUSH1 0; RETURN) returns one zero
   byte, which becomes the deployed code. Intrinsic for the 5-byte init code is
   53070 (see the intrinsic test); the init run spends 9 (3+3+3 for the memory
   word), and the code deposit is 200*1 = 200, so the gross spend is
   53070 + 9 + 200 = 53279. The created address is derived from the sender's
   pre-bump nonce (0) and given nonce 1. *)
let test_create_success () =
  let world = world_seed [ (sender, account ~nonce:0 ~balance:1_000_000_000) ] in
  let tx =
    Transaction.make ~sender ~nonce:(nonce_of 0) ~gas_limit:200000
      ~kind:Transaction.Create ~value:U256.zero ~data:init_return_one_zero
      ~access_list:[] ~chain_id:(Some (u 1)) ~fee:(Transaction.Legacy { gas_price = u 10 })
  in
  let receipt, world' = exec_ok world ~block:(block_of ~coinbase ~basefee:2) tx in
  let s = expect_success receipt in
  let expected_address =
    Contract_address.derive ~creator:sender (Contract_address.From_nonce (nonce_of 0))
  in
  Alcotest.(check int) "gas used" 53279 s.su_gas_used;
  Alcotest.(check int) "gas refunded" 0 s.su_gas_refunded;
  Alcotest.(check string) "deployed code is the returned byte" "\x00" s.su_output;
  Alcotest.(check bool) "created address matches derivation" true
    (Option.fold ~none:false ~some:(Units.Address.equal expected_address) s.su_created);
  (* B - used*price - value(0) *)
  Alcotest.(check int) "sender balance" 999_467_210 (bal world' sender);
  Alcotest.(check int) "coinbase balance" 426_232 (bal world' coinbase);
  Alcotest.(check int) "sender nonce bumped in the frame" 1 (nonce_int world' sender);
  Alcotest.(check string) "created account holds the code" "\x00"
    (Account.code (World_state.account world' expected_address));
  Alcotest.(check int) "created account nonce is 1" 1
    (Nonce.to_int (Account.nonce (World_state.account world' expected_address)))

(* A creation onto an occupied address (EIP-684) halts and burns the whole gas
   limit, but the creator's nonce bump persists (a halt is a committed outcome). *)
let test_create_collision () =
  let created =
    Contract_address.derive ~creator:sender (Contract_address.From_nonce (nonce_of 0))
  in
  let world =
    world_seed
      [
        (sender, account ~nonce:0 ~balance:1_000_000_000);
        (created, account ~nonce:1 ~balance:0);
      ]
  in
  let tx =
    Transaction.make ~sender ~nonce:(nonce_of 0) ~gas_limit:200000
      ~kind:Transaction.Create ~value:U256.zero ~data:init_return_one_zero
      ~access_list:[] ~chain_id:(Some (u 1)) ~fee:(Transaction.Legacy { gas_price = u 10 })
  in
  let receipt, world' = exec_ok world ~block:(block_of ~coinbase ~basefee:2) tx in
  let h = expect_halted receipt in
  check_reason ~expected:Receipt.Create_collision h.hl_reason;
  Alcotest.(check int) "gas used is the whole limit" 200000 h.hl_gas_used;
  (* B - limit*price *)
  Alcotest.(check int) "sender balance" 998_000_000 (bal world' sender);
  Alcotest.(check int) "creator nonce bump persists on a halt" 1 (nonce_int world' sender);
  Alcotest.(check int) "collided account untouched" 1 (nonce_int world' created);
  Alcotest.(check int) "coinbase paid on the full limit" 1_600_000 (bal world' coinbase)

(* A creation whose returned code begins with the reserved 0xEF byte (EIP-3541)
   halts at deployment and burns the whole gas limit. Nothing is deployed at the
   derived address, but the creator's nonce bump persists. *)
let test_create_reserved_prefix () =
  let init_return_ef =
    bytes_of
      [ push1 0xEF; push1 0x00; op Opcode.Mstore8; push1 0x01; push1 0x00; op Opcode.Return ]
  in
  let created =
    Contract_address.derive ~creator:sender (Contract_address.From_nonce (nonce_of 0))
  in
  let world = world_seed [ (sender, account ~nonce:0 ~balance:1_000_000_000) ] in
  let tx =
    Transaction.make ~sender ~nonce:(nonce_of 0) ~gas_limit:200000
      ~kind:Transaction.Create ~value:U256.zero ~data:init_return_ef ~access_list:[]
      ~chain_id:(Some (u 1)) ~fee:(Transaction.Legacy { gas_price = u 10 })
  in
  let receipt, world' = exec_ok world ~block:(block_of ~coinbase ~basefee:2) tx in
  let h = expect_halted receipt in
  check_reason ~expected:Receipt.Create_reserved_prefix h.hl_reason;
  Alcotest.(check int) "gas used is the whole limit" 200000 h.hl_gas_used;
  Alcotest.(check int) "sender balance" 998_000_000 (bal world' sender);
  Alcotest.(check int) "creator nonce bump persists" 1 (nonce_int world' sender);
  Alcotest.(check bool) "nothing deployed at the derived address" false
    (present world' created)

(* ========================================================================== *)
(* Refund: EIP-3529 cap over a two-slot clear.                                *)
(* ========================================================================== *)

(* The callee clears two nonzero slots, each accruing a 4800 refund (9600 total)
   at a cost of 5000 each (100 entry + 2100 cold + 2800 reset). The frame spends
   10012 beyond the intrinsic (3+3 for each pair of pushes, 5000 for each SSTORE),
   so gross spend = 21000 + 10012 = 31012 and the raw refund 9600 is CAPPED to
   spent/5 = 6202. gas_used = 31012 - 6202 = 24810; gas_refunded = 6202. *)
let test_refund_cap () =
  let clear_two =
    bytes_of
      [
        push1 0x00; push1 0x01; op Opcode.Sstore;
        push1 0x00; push1 0x02; op Opcode.Sstore;
        op Opcode.Stop;
      ]
  in
  let seeded =
    Account.set_slot
      (Account.set_slot (Account.with_code (account ~nonce:0 ~balance:0) clear_two) (u 1) (u 7))
      (u 2) (u 9)
  in
  let world =
    world_seed [ (sender, account ~nonce:0 ~balance:1_000_000_000); (target, seeded) ]
  in
  let tx =
    Transaction.make ~sender ~nonce:(nonce_of 0) ~gas_limit:100000
      ~kind:(Transaction.Call target) ~value:U256.zero ~data:"" ~access_list:[]
      ~chain_id:(Some (u 1)) ~fee:(Transaction.Legacy { gas_price = u 10 })
  in
  let receipt, world' = exec_ok world ~block:(block_of ~coinbase ~basefee:3) tx in
  let s = expect_success receipt in
  Alcotest.(check int) "gas refunded is capped at spent/5" 6202 s.su_gas_refunded;
  Alcotest.(check int) "gas used is spent minus capped refund" 24810 s.su_gas_used;
  Alcotest.(check int) "slot 1 cleared" 0
    (get (U256.to_int (World_state.storage world' target (u 1))));
  Alcotest.(check int) "slot 2 cleared" 0
    (get (U256.to_int (World_state.storage world' target (u 2))));
  (* B - used*price *)
  Alcotest.(check int) "sender balance" 999_751_900 (bal world' sender);
  Alcotest.(check int) "coinbase balance" 173_670 (bal world' coinbase)

(* ========================================================================== *)
(* EIP-161 pruning: zero-reward beneficiary is not materialized.              *)
(* ========================================================================== *)

(* With gas_price == base_fee the priority fee is zero, so the beneficiary is
   credited nothing and, being absent, must stay absent (crediting zero to an
   absent account keeps it absent). The caller is still reimbursed at the full
   effective price. *)
let test_eip161_zero_reward_coinbase () =
  let world = world_seed [ (sender, account ~nonce:0 ~balance:1_000_000_000) ] in
  let tx =
    Transaction.make ~sender ~nonce:(nonce_of 0) ~gas_limit:100000
      ~kind:(Transaction.Call target) ~value:U256.zero ~data:"" ~access_list:[]
      ~chain_id:(Some (u 1)) ~fee:(Transaction.Legacy { gas_price = u 3 })
  in
  let receipt, world' = exec_ok world ~block:(block_of ~coinbase ~basefee:3) tx in
  let s = expect_success receipt in
  Alcotest.(check int) "gas used" 21000 s.su_gas_used;
  Alcotest.(check bool) "zero-reward coinbase not materialized" false
    (present world' coinbase);
  (* B - used*effective, effective = 3 *)
  Alcotest.(check int) "sender balance" 999_937_000 (bal world' sender)

(* A zero-value call leaves a fresh target absent, while a nonzero-value call to
   the same fresh target materializes it: the pruning assertion discriminates. *)
let test_eip161_zero_value_target () =
  let world = world_seed [ (sender, account ~nonce:0 ~balance:1_000_000_000) ] in
  let mk value =
    Transaction.make ~sender ~nonce:(nonce_of 0) ~gas_limit:100000
      ~kind:(Transaction.Call target) ~value ~data:"" ~access_list:[]
      ~chain_id:(Some (u 1)) ~fee:(Transaction.Legacy { gas_price = u 10 })
  in
  let _, world_zero = exec_ok world ~block:(block_of ~coinbase ~basefee:3) (mk U256.zero) in
  let _, world_one = exec_ok world ~block:(block_of ~coinbase ~basefee:3) (mk (u 1)) in
  Alcotest.(check bool) "zero-value fresh target stays absent" false
    (present world_zero target);
  Alcotest.(check bool) "nonzero-value fresh target is materialized" true
    (present world_one target);
  Alcotest.(check int) "materialized target holds the value" 1 (bal world_one target)

(* ========================================================================== *)
(* Rejection: an invalid transaction changes nothing at all.                  *)
(* ========================================================================== *)

let test_rejection_leaves_world_untouched () =
  let world = world_seed [ (sender, account ~nonce:5 ~balance:1_000_000_000) ] in
  let block = block_of ~coinbase ~basefee:3 in
  (* nonce mismatch: tx claims 0, account holds 5 *)
  let bad_nonce =
    Transaction.make ~sender ~nonce:(nonce_of 0) ~gas_limit:100000
      ~kind:(Transaction.Call target) ~value:(u 5000) ~data:"" ~access_list:[]
      ~chain_id:(Some (u 1)) ~fee:(Transaction.Legacy { gas_price = u 10 })
  in
  (match Executor.execute world ~block bad_nonce with
  | Ok _ -> Alcotest.fail "expected a nonce rejection"
  | Error (Executor.Nonce_mismatch _) -> ()
  | Error e -> Alcotest.failf "expected Nonce_mismatch, got %s" (Executor.error_to_string e));
  (* wrong chain id *)
  let bad_chain =
    Transaction.make ~sender ~nonce:(nonce_of 5) ~gas_limit:100000
      ~kind:(Transaction.Call target) ~value:(u 5000) ~data:"" ~access_list:[]
      ~chain_id:(Some (u 999)) ~fee:(Transaction.Legacy { gas_price = u 10 })
  in
  (match Executor.execute world ~block bad_chain with
  | Ok _ -> Alcotest.fail "expected a chain-id rejection"
  | Error Executor.Invalid_chain_id -> ()
  | Error e -> Alcotest.failf "expected Invalid_chain_id, got %s" (Executor.error_to_string e));
  (* a valid nonce with insufficient funds for the max fee *)
  let poor =
    Transaction.make ~sender ~nonce:(nonce_of 5) ~gas_limit:100000
      ~kind:(Transaction.Call target) ~value:(u 5000) ~data:"" ~access_list:[]
      ~chain_id:(Some (u 1))
      ~fee:(Transaction.Dynamic { max_fee = u 1_000_000_000; max_priority = Some (u 1) })
  in
  (match Executor.execute world ~block poor with
  | Ok _ -> Alcotest.fail "expected an insufficient-funds rejection"
  | Error Executor.Insufficient_funds -> ()
  | Error e -> Alcotest.failf "expected Insufficient_funds, got %s" (Executor.error_to_string e));
  (* every rejection leaves the world identical: nonce 5, full balance *)
  Alcotest.(check int) "nonce unchanged" 5 (nonce_int world sender);
  Alcotest.(check int) "balance unchanged" 1_000_000_000 (bal world sender)

(* ========================================================================== *)
(* A direct transaction to a precompile dispatches the builtin.               *)
(* ========================================================================== *)

(* revm executes a precompile at the FIRST frame too, so a transaction whose [to]
   is a precompile address runs the builtin rather than the (empty) account code.
   Target is 0x04 (IDENTITY), which echoes its input: an empty output would prove
   the empty account code ran instead. Four nonzero bytes = 16 tokens, so intrinsic
   is 21064 and floor 21160; IDENTITY spends 18, gross 21082 < floor, so the floor
   binds and gas_used = 21160. *)
let test_precompile_identity () =
  let world = world_seed [ (sender, account ~nonce:0 ~balance:1_000_000_000) ] in
  let input = "\x01\x02\x03\x04" in
  let tx =
    Transaction.make ~sender ~nonce:(nonce_of 0) ~gas_limit:100000
      ~kind:(Transaction.Call (address_of 0x04)) ~value:U256.zero ~data:input
      ~access_list:[] ~chain_id:(Some (u 1)) ~fee:(Transaction.Legacy { gas_price = u 10 })
  in
  let receipt, world' = exec_ok world ~block:(block_of ~coinbase ~basefee:3) tx in
  let s = expect_success receipt in
  Alcotest.(check string) "identity echoes its input" input s.su_output;
  Alcotest.(check bool) "no created address" true (Option.is_none s.su_created);
  Alcotest.(check int) "gas used is the floor" 21160 s.su_gas_used;
  Alcotest.(check int) "logs" 0 (List.length s.su_logs);
  (* B - used*price = 1e9 - 21160*10 ; coinbase (10-3)*21160 *)
  Alcotest.(check int) "sender balance" 999_788_400 (bal world' sender);
  Alcotest.(check int) "coinbase balance" 148_120 (bal world' coinbase)

(* ========================================================================== *)
(* More rejection variants: each is a real Prague accept-or-reject rule.       *)
(* ========================================================================== *)

let test_rejection_variants () =
  let block = block_of ~coinbase ~basefee:3 in
  (* EIP-3607: a sender that holds code is not an EOA and cannot originate a tx. *)
  let coded_world =
    world_seed
      [ (sender, Account.with_code (account ~nonce:0 ~balance:1_000_000_000) (push1 0x00)) ]
  in
  let tx3607 =
    Transaction.make ~sender ~nonce:(nonce_of 0) ~gas_limit:100000
      ~kind:(Transaction.Call target) ~value:U256.zero ~data:"" ~access_list:[]
      ~chain_id:(Some (u 1)) ~fee:(Transaction.Legacy { gas_price = u 10 })
  in
  (match Executor.execute coded_world ~block tx3607 with
  | Ok _ -> Alcotest.fail "expected an EIP-3607 rejection"
  | Error Executor.Sender_has_code -> ()
  | Error e -> Alcotest.failf "expected Sender_has_code, got %s" (Executor.error_to_string e));
  Alcotest.(check int) "3607 leaves balance untouched" 1_000_000_000 (bal coded_world sender);
  (* EIP-3860: a creation whose init code exceeds 49152 bytes is rejected. *)
  let world = world_seed [ (sender, account ~nonce:0 ~balance:1_000_000_000) ] in
  let tx3860 =
    Transaction.make ~sender ~nonce:(nonce_of 0) ~gas_limit:30_000_000
      ~kind:Transaction.Create ~value:U256.zero ~data:(String.make 49153 '\000')
      ~access_list:[] ~chain_id:(Some (u 1)) ~fee:(Transaction.Legacy { gas_price = u 10 })
  in
  (match Executor.execute world ~block tx3860 with
  | Ok _ -> Alcotest.fail "expected an EIP-3860 rejection"
  | Error Executor.Init_code_size_limit -> ()
  | Error e ->
      Alcotest.failf "expected Init_code_size_limit, got %s" (Executor.error_to_string e));
  (* EIP-7623: the calldata floor exceeds the gas limit. 1000 zero bytes give
     intrinsic 25000 and floor 31000; a gas limit of 26000 clears the intrinsic but
     not the floor, so the floor check rejects even though the intrinsic passed. *)
  let tx7623 =
    Transaction.make ~sender ~nonce:(nonce_of 0) ~gas_limit:26000
      ~kind:(Transaction.Call target) ~value:U256.zero ~data:(String.make 1000 '\000')
      ~access_list:[] ~chain_id:(Some (u 1)) ~fee:(Transaction.Legacy { gas_price = u 10 })
  in
  (match Executor.execute world ~block tx7623 with
  | Ok _ -> Alcotest.fail "expected an EIP-7623 floor rejection"
  | Error Executor.Gas_floor_above_limit -> ()
  | Error e ->
      Alcotest.failf "expected Gas_floor_above_limit, got %s" (Executor.error_to_string e));
  Alcotest.(check int) "world untouched nonce" 0 (nonce_int world sender);
  Alcotest.(check int) "world untouched balance" 1_000_000_000 (bal world sender)

(* ========================================================================== *)
(* Logs are attached on success (and, by the receipt's shape, only there).     *)
(* ========================================================================== *)

(* The callee emits one empty log: PUSH1 0 (size); PUSH1 0 (offset); LOG0 (0xa0),
   then walks off the end (a STOP). A Reverted or Halted receipt has no logs field
   at all, so "logs are dropped on a revert or a halt" holds by construction; this
   pins the positive case, that a success carries them. Gas: PUSH1 3 + PUSH1 3 +
   LOG0 375 = 381 exec over the 21000 intrinsic, and the floor does not bind. *)
let test_log_emitted_on_success () =
  let code = bytes_of [ push1 0x00; push1 0x00; byte 0xa0 ] in
  let world =
    world_seed
      [
        (sender, account ~nonce:0 ~balance:1_000_000_000);
        (target, Account.with_code (account ~nonce:0 ~balance:0) code);
      ]
  in
  let tx =
    Transaction.make ~sender ~nonce:(nonce_of 0) ~gas_limit:100000
      ~kind:(Transaction.Call target) ~value:U256.zero ~data:"" ~access_list:[]
      ~chain_id:(Some (u 1)) ~fee:(Transaction.Legacy { gas_price = u 10 })
  in
  let receipt, _ = exec_ok world ~block:(block_of ~coinbase ~basefee:3) tx in
  let s = expect_success receipt in
  Alcotest.(check int) "one log attached on success" 1 (List.length s.su_logs);
  Alcotest.(check int) "gas used" 21381 s.su_gas_used

(* ========================================================================== *)
(* An EIP-2930 access list charges its intrinsic surcharge end to end.          *)
(* ========================================================================== *)

(* A type-1 transaction with one declared address and two declared slots. The
   surcharge is 1*2400 + 2*1900 = 6200 on top of the 21000 base, so intrinsic is
   27200; the empty callee spends nothing and the floor (21000) does not bind, so
   gas_used = 27200. A legacy tx would ignore the list; this proves the typed path
   both charges it and (via effective_access_list) gates it on the fee type. *)
let test_access_list_intrinsic () =
  let world = world_seed [ (sender, account ~nonce:0 ~balance:1_000_000_000) ] in
  let tx =
    Transaction.make ~sender ~nonce:(nonce_of 0) ~gas_limit:100000
      ~kind:(Transaction.Call target) ~value:U256.zero ~data:""
      ~access_list:[ (address_of 0xd4, [ u 7; u 8 ]) ]
      ~chain_id:(Some (u 1)) ~fee:(Transaction.Access_list { gas_price = u 10 })
  in
  let receipt, _ = exec_ok world ~block:(block_of ~coinbase ~basefee:3) tx in
  let s = expect_success receipt in
  Alcotest.(check int) "gas used includes the access-list surcharge" 27200 s.su_gas_used

(* ========================================================================== *)
(* The telcoin fee split: penalty, redirected base fee, system-sender skip.   *)
(* ========================================================================== *)

let governance = Tn_evm.System_contracts.governance_safe_address

(* A plain transfer that spends 21000 of a 420_000 limit (5 percent usage), at
   basefee 0 so every wei the governance safe receives is the penalty alone.
   Penalty = (10^8 - 10^9*21000/420000)^2 * 399_000 / 10^16 = 99_750, so the
   caller is reimbursed (399_000 - 99_750)*10 and pays (21_000 + 99_750)*10 +
   5000 net. Kills the mainnet mutant (refund without the penalty: sender
   999_785_000 here instead) and the penalty-to-coinbase and penalty-burned
   mutants (governance 997_500, coinbase 210_000). The raw-byte pin on the
   governance address makes a drifted constant fail here rather than in a
   state root. *)
let test_penalty_docks_refund_and_credits_governance () =
  let world = world_seed [ (sender, account ~nonce:0 ~balance:1_000_000_000) ] in
  let tx =
    Transaction.make ~sender ~nonce:(nonce_of 0) ~gas_limit:420_000
      ~kind:(Transaction.Call target) ~value:(u 5000) ~data:"" ~access_list:[]
      ~chain_id:(Some (u 1)) ~fee:(Transaction.Legacy { gas_price = u 10 })
  in
  let receipt, world' = exec_ok world ~block:(block_of ~coinbase ~basefee:0) tx in
  let s = expect_success receipt in
  Alcotest.(check int) "gas used stays post-refund" 21000 s.su_gas_used;
  Alcotest.(check bool) "governance safe is 0x...07a0" true
    (Units.Address.equal governance
       (get (Units.Address.of_bytes (String.make 18 '\000' ^ "\x07\xa0"))));
  (* B - (used + penalty)*price - value *)
  Alcotest.(check int) "sender pays the penalty" 998_787_500 (bal world' sender);
  Alcotest.(check int) "governance receives the penalty" 997_500 (bal world' governance);
  Alcotest.(check int) "coinbase is unaffected by the penalty" 210_000
    (bal world' coinbase);
  Alcotest.(check int) "recipient" 5000 (bal world' target)

(* The Legacy-transfer vector with a nonzero base fee: the 3*21000 the mainnet
   split burned is credited to the governance safe, while the sender and the
   coinbase see figures identical to the mainnet ones (penalty 0 at this
   limit). Kills the burn-retained mutant (governance absent) and the
   basefee-to-coinbase mutant (coinbase 210_000 instead of the priority-only
   147_000). *)
let test_basefee_credited_not_burned () =
  let world = world_seed [ (sender, account ~nonce:0 ~balance:1_000_000_000) ] in
  let tx =
    Transaction.make ~sender ~nonce:(nonce_of 0) ~gas_limit:100000
      ~kind:(Transaction.Call target) ~value:(u 5000) ~data:"" ~access_list:[]
      ~chain_id:(Some (u 1)) ~fee:(Transaction.Legacy { gas_price = u 10 })
  in
  let receipt, world' = exec_ok world ~block:(block_of ~coinbase ~basefee:3) tx in
  let s = expect_success receipt in
  Alcotest.(check int) "gas used" 21000 s.su_gas_used;
  Alcotest.(check int) "sender as on mainnet" 999_785_000 (bal world' sender);
  Alcotest.(check int) "coinbase keeps only the priority fee" 147_000
    (bal world' coinbase);
  Alcotest.(check int) "governance receives basefee * gas_used" 63_000
    (bal world' governance)

(* The two-slot clearer of [test_refund_cap] at limit 400_000: gross spend
   31_012, capped refund 6_202, net 24_810. The penalty prices the PRE-refund
   31_012 (ratio 7.753 percent): (10^8 - 77_530_000)^2 * 368_988 / 10^16 =
   18_630. The caller is reimbursed (375_190 - 18_630)*10 and the governance
   safe collects 18_630*10 + 3*24_810. Kills the penalty-on-post-refund mutant,
   whose penalty over 24_810 is 54_106 (sender 999_210_840 instead). *)
let test_penalty_prices_the_prerefund_spend () =
  let clear_two =
    bytes_of
      [
        push1 0x00; push1 0x01; op Opcode.Sstore;
        push1 0x00; push1 0x02; op Opcode.Sstore;
        op Opcode.Stop;
      ]
  in
  let seeded =
    Account.set_slot
      (Account.set_slot (Account.with_code (account ~nonce:0 ~balance:0) clear_two) (u 1) (u 7))
      (u 2) (u 9)
  in
  let world =
    world_seed [ (sender, account ~nonce:0 ~balance:1_000_000_000); (target, seeded) ]
  in
  let tx =
    Transaction.make ~sender ~nonce:(nonce_of 0) ~gas_limit:400_000
      ~kind:(Transaction.Call target) ~value:U256.zero ~data:"" ~access_list:[]
      ~chain_id:(Some (u 1)) ~fee:(Transaction.Legacy { gas_price = u 10 })
  in
  let receipt, world' = exec_ok world ~block:(block_of ~coinbase ~basefee:3) tx in
  let s = expect_success receipt in
  Alcotest.(check int) "gas refunded still capped" 6202 s.su_gas_refunded;
  Alcotest.(check int) "gas used still post-refund" 24810 s.su_gas_used;
  (* B - used*price - penalty*price = B - 248_100 - 186_300 *)
  Alcotest.(check int) "sender pays the pre-refund-priced penalty" 999_565_600
    (bal world' sender);
  Alcotest.(check int) "coinbase priority fee" 173_670 (bal world' coinbase);
  Alcotest.(check int) "governance: penalty plus redirected basefee" 260_730
    (bal world' governance)

(* The same clearer at limit 250_000 straddles the regimes: the pre-refund
   ratio 31_012/250_000 is above ten percent (penalty 0) while the post-refund
   ratio 24_810/250_000 is below it (penalty 13). Identical to mainnet
   settlement except the redirected base fee; the post-refund mutant docks 13
   more gas units and shifts the sender by 130 wei. *)
let test_penalty_regime_straddle () =
  let clear_two =
    bytes_of
      [
        push1 0x00; push1 0x01; op Opcode.Sstore;
        push1 0x00; push1 0x02; op Opcode.Sstore;
        op Opcode.Stop;
      ]
  in
  let seeded =
    Account.set_slot
      (Account.set_slot (Account.with_code (account ~nonce:0 ~balance:0) clear_two) (u 1) (u 7))
      (u 2) (u 9)
  in
  let world =
    world_seed [ (sender, account ~nonce:0 ~balance:1_000_000_000); (target, seeded) ]
  in
  let tx =
    Transaction.make ~sender ~nonce:(nonce_of 0) ~gas_limit:250_000
      ~kind:(Transaction.Call target) ~value:U256.zero ~data:"" ~access_list:[]
      ~chain_id:(Some (u 1)) ~fee:(Transaction.Legacy { gas_price = u 10 })
  in
  let receipt, world' = exec_ok world ~block:(block_of ~coinbase ~basefee:3) tx in
  let s = expect_success receipt in
  Alcotest.(check int) "gas used" 24810 s.su_gas_used;
  Alcotest.(check int) "sender pays no penalty above ten percent pre-refund"
    999_751_900 (bal world' sender);
  Alcotest.(check int) "governance: redirected basefee only" 74_430
    (bal world' governance)

(* A system-sender transaction settles NOTHING ([handler.rs:85-87, 145-147]):
   no reimbursement, no coinbase reward, no governance credit. This must be a
   direct nonzero-price vector because the {!System_call} path prices
   everything at zero, where the skip is invisible. The whole 250_000 * 10
   deduction stays gone; the skip-removed mutant reimburses 2_231_380 and
   materializes both fee accounts. *)
let test_system_sender_skips_settlement () =
  let system = Tn_evm.System_contracts.system_address in
  let world = world_seed [ (system, account ~nonce:0 ~balance:1_000_000_000) ] in
  let tx =
    Transaction.make ~sender:system ~nonce:(nonce_of 0) ~gas_limit:250_000
      ~kind:(Transaction.Call target) ~value:(u 5000) ~data:"" ~access_list:[]
      ~chain_id:(Some (u 1)) ~fee:(Transaction.Legacy { gas_price = u 10 })
  in
  let receipt, world' = exec_ok world ~block:(block_of ~coinbase ~basefee:3) tx in
  let s = expect_success receipt in
  Alcotest.(check int) "gas used" 21000 s.su_gas_used;
  Alcotest.(check int) "the whole allowance stays deducted" 997_495_000
    (bal world' system);
  Alcotest.(check bool) "coinbase untouched" false (present world' coinbase);
  Alcotest.(check bool) "governance untouched" false (present world' governance);
  Alcotest.(check int) "the call itself still ran" 5000 (bal world' target);
  Alcotest.(check int) "nonce still advances" 1 (nonce_int world' system)

(* At basefee 0 with no penalty the governance safe is owed nothing and, being
   absent, must stay absent: the EIP-161 pruning claim of the .mli extended to
   the third credit. Kills an executor-level penalty that forgot its 10^16
   divisor (it would credit 790_000 * 10 here and materialize the account). *)
let test_zero_fee_block_leaves_governance_absent () =
  let world = world_seed [ (sender, account ~nonce:0 ~balance:1_000_000_000) ] in
  let tx =
    Transaction.make ~sender ~nonce:(nonce_of 0) ~gas_limit:100000
      ~kind:(Transaction.Call target) ~value:U256.zero ~data:"" ~access_list:[]
      ~chain_id:(Some (u 1)) ~fee:(Transaction.Legacy { gas_price = u 10 })
  in
  let receipt, world' = exec_ok world ~block:(block_of ~coinbase ~basefee:0) tx in
  let s = expect_success receipt in
  Alcotest.(check int) "gas used" 21000 s.su_gas_used;
  Alcotest.(check bool) "governance not materialized" false
    (present world' governance)

(* The 210_000 gate cannot bite at realistic spends: a 21_000-gas transfer
   settles identically at limits 210_000 and 210_001, because just past the
   gate the quotient still floors to zero. The gate's bite is unit-level
   ({!Gas_penalty}'s own vectors); this pins the executor-level honesty of
   that note. *)
let test_gate_boundary_is_settlement_invisible () =
  let run gas_limit =
    let world = world_seed [ (sender, account ~nonce:0 ~balance:1_000_000_000) ] in
    let tx =
      Transaction.make ~sender ~nonce:(nonce_of 0) ~gas_limit
        ~kind:(Transaction.Call target) ~value:U256.zero ~data:"" ~access_list:[]
        ~chain_id:(Some (u 1)) ~fee:(Transaction.Legacy { gas_price = u 10 })
    in
    let _, world' = exec_ok world ~block:(block_of ~coinbase ~basefee:3) tx in
    bal world' sender
  in
  Alcotest.(check int) "identical settlement across the gate" (run 210_000)
    (run 210_001)

let () =
  Alcotest.run "executor"
    [
      ( "value-transfer",
        [
          Alcotest.test_case "Legacy transfer" `Quick test_legacy_value_transfer;
          Alcotest.test_case "EIP-1559 transfer" `Quick test_eip1559_value_transfer;
          Alcotest.test_case "effective gas price" `Quick test_effective_gas_price;
        ] );
      ( "intrinsic-and-floor",
        [
          Alcotest.test_case "intrinsic primitive" `Quick test_intrinsic_primitive;
          Alcotest.test_case "EIP-7623 floor binds" `Quick test_eip7623_floor_binds;
        ] );
      ( "halt-and-revert",
        [
          Alcotest.test_case "out-of-gas halt burns the limit" `Quick test_out_of_gas_halt;
          Alcotest.test_case "revert returns gas and rolls back value" `Quick test_revert;
        ] );
      ( "creation",
        [
          Alcotest.test_case "create success deposits code" `Quick test_create_success;
          Alcotest.test_case "create collision burns the limit" `Quick test_create_collision;
          Alcotest.test_case "create 0xEF prefix rejected" `Quick test_create_reserved_prefix;
        ] );
      ( "refund",
        [ Alcotest.test_case "EIP-3529 cap over a two-slot clear" `Quick test_refund_cap ] );
      ( "telcoin-fee-split",
        [
          Alcotest.test_case "penalty docks the refund, credits governance" `Quick
            test_penalty_docks_refund_and_credits_governance;
          Alcotest.test_case "basefee credited, not burned" `Quick
            test_basefee_credited_not_burned;
          Alcotest.test_case "penalty prices the pre-refund spend" `Quick
            test_penalty_prices_the_prerefund_spend;
          Alcotest.test_case "regime straddle: pre exempt, post would not be" `Quick
            test_penalty_regime_straddle;
          Alcotest.test_case "system sender skips settlement" `Quick
            test_system_sender_skips_settlement;
          Alcotest.test_case "zero-fee block leaves governance absent" `Quick
            test_zero_fee_block_leaves_governance_absent;
          Alcotest.test_case "the 210k gate is settlement-invisible" `Quick
            test_gate_boundary_is_settlement_invisible;
        ] );
      ( "eip161-pruning",
        [
          Alcotest.test_case "zero-reward coinbase not materialized" `Quick
            test_eip161_zero_reward_coinbase;
          Alcotest.test_case "zero-value fresh target stays absent" `Quick
            test_eip161_zero_value_target;
        ] );
      ( "rejection",
        [
          Alcotest.test_case "an invalid tx changes nothing" `Quick
            test_rejection_leaves_world_untouched;
          Alcotest.test_case "EIP-3607 / EIP-3860 / EIP-7623 floor variants" `Quick
            test_rejection_variants;
        ] );
      ( "precompile",
        [
          Alcotest.test_case "a direct tx to IDENTITY runs the builtin" `Quick
            test_precompile_identity;
        ] );
      ( "logs",
        [
          Alcotest.test_case "logs are attached on success" `Quick test_log_emitted_on_success;
        ] );
      ( "access-list",
        [
          Alcotest.test_case "EIP-2930 intrinsic surcharge is charged" `Quick
            test_access_list_intrinsic;
        ] );
    ]
