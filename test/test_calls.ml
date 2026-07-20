(* The sub-frame message-call family: CALL, CALLCODE, DELEGATECALL, STATICCALL,
   the return-data readers RETURNDATASIZE and RETURNDATACOPY, and the recursive
   sub-frame seam beneath them. Faithful to revm 32.0.0 at Prague.

   Every observable a caller of a frame can see is exercised: the 1/0 the call
   pushes, the output it copies into the caller's window, the return-data buffer
   it leaves, whose storage a borrowed piece of code writes to, whose CALLER and
   CALLVALUE a delegated frame reads, the value it moves (or does not), the gas it
   forwards and hands back, and the warmings and writes that survive — or do not —
   a child that reverts. Gas figures are absolute where they are asserted, so a
   mispriced charge fails a test rather than quietly changing what a call costs.

   The four calls thread a [Call_depth.t] one deeper per frame and a
   [Return_data.t] that every call replaces; both are pinned here directly. *)

module U256 = Tn_state.U256
module Account = Tn_state.Account
module Nonce = Tn_state.Nonce
module World_state = Tn_state.World_state
module Units = Tn_types.Units
module Access = Tn_evm.Access
module Call_depth = Tn_evm.Call_depth
module Code = Tn_evm.Code
module Data = Tn_evm.Data
module Effects = Tn_evm.Effects
module Env = Tn_evm.Env
module Gas = Tn_evm.Gas
module Interpreter = Tn_evm.Interpreter
module Mutability = Tn_evm.Mutability
module Opcode = Tn_evm.Opcode
module Return_data = Tn_evm.Return_data

let get = function Some x -> x | None -> Alcotest.fail "expected Some"
let u n = get (U256.of_int n)
let gas_of n = get (Gas.of_int n)
let width_of n = get (Opcode.Push_bytes.of_int n)
let nonce_of n = get (Nonce.of_int n)

let address_of n =
  get
    (Units.Address.of_bytes
       (String.make (Units.Address.length - 1) '\000' ^ String.make 1 (Char.chr n)))

(* ---------- the miniature assembler ---------- *)

let byte b = String.make 1 (Char.chr b)
let op o = byte (Opcode.to_byte o)
let push1 n = op (Opcode.Push (width_of 1)) ^ byte n
let push20 address = op (Opcode.Push (width_of 20)) ^ Units.Address.to_bytes address
let push32 w = op (Opcode.Push (width_of 32)) ^ U256.to_be_bytes w
let asm parts = Code.of_string (String.concat "" parts)
let bytes_of parts = String.concat "" parts

(* The 1024-word gas requests everything, so the child receives the 63/64 the cap
   allows; a specific request is used only where the cap itself is under test. *)
let all_gas = U256.max_value

(* CALL and CALLCODE take seven stack words, top first: gas, address, value, then
   the input and output windows. DELEGATECALL and STATICCALL drop the value.
   Pushed in reverse so the first-popped word ends up on top. *)
let call ~gas ~dst ~value ~in_off ~in_len ~out_off ~out_len =
  [
    push1 out_len; push1 out_off; push1 in_len; push1 in_off; push32 value;
    push20 dst; push32 gas; op Opcode.Call;
  ]

let callcode ~gas ~dst ~value ~in_off ~in_len ~out_off ~out_len =
  [
    push1 out_len; push1 out_off; push1 in_len; push1 in_off; push32 value;
    push20 dst; push32 gas; op Opcode.Callcode;
  ]

let delegatecall ~gas ~dst ~in_off ~in_len ~out_off ~out_len =
  [
    push1 out_len; push1 out_off; push1 in_len; push1 in_off; push20 dst;
    push32 gas; op Opcode.Delegatecall;
  ]

let staticcall ~gas ~dst ~in_off ~in_len ~out_off ~out_len =
  [
    push1 out_len; push1 out_off; push1 in_len; push1 in_off; push20 dst;
    push32 gas; op Opcode.Staticcall;
  ]

(* RETURNDATACOPY takes [dest; source; length], dest on top. *)
let returndatacopy ~dest ~src ~len =
  [ push1 len; push1 src; push1 dest; op Opcode.Returndatacopy ]

(* Same, but the source offset is a full word, for probing the saturating clamp
   with an offset no single byte can name. *)
let returndatacopy_word ~dest ~src ~len =
  [ push1 len; push32 src; push1 dest; op Opcode.Returndatacopy ]

(* Move the top of the stack to [mem[off]] and hand back a window as output. *)
let store_at off = [ push1 off; op Opcode.Mstore ]
let return_range ~off ~len = [ push1 len; push1 off; op Opcode.Return ]

(* ---------- the accounts under test ---------- *)

let self = address_of 0x01 (* the executing account, funded, caller of sub-frames *)
let outer_caller = address_of 0xaa (* the caller of the top frame (for DELEGATECALL) *)
let outer_value = u 777 (* the top frame's apparent value (for DELEGATECALL) *)

let callee_ret = address_of 0xb1 (* returns the word 0x2a *)
let callee_store = address_of 0xb2 (* SSTOREs slot 1, then returns ADDRESS *)
let callee_ctx = address_of 0xb3 (* returns CALLER then CALLVALUE *)
let callee_revert = address_of 0xb4 (* SSTOREs slot 1, then REVERTs a word *)
let callee_gas = address_of 0xb5 (* returns the GAS reading *)
let callee_ret2 = address_of 0xb6 (* returns two bytes *)
let callee_ret4 = address_of 0xb7 (* returns four bytes *)
let callee_invalid = address_of 0xb8 (* halts on INVALID *)
let callee_nest = address_of 0xb9 (* SSTOREs slot 2, CALLs callee_revert, STOPs *)
let callee_call_store = address_of 0xba (* CALLs callee_store, STOPs *)
let callee_sstore_gas = address_of 0xbb (* SSTOREs slot 7, returns its GAS reading *)
let codeless = address_of 0xce (* no entry: empty code, stops at once *)
let absent = address_of 0xaf (* no entry: is_empty, the new-account target *)
let nonce_only = address_of 0xd1 (* a nonce alone: not is_empty, still codeless *)

let code_ret =
  bytes_of [ push1 0x2a; push1 0x00; op Opcode.Mstore; push1 0x20; push1 0x00; op Opcode.Return ]

let code_store =
  bytes_of
    [
      push1 0x2a; push1 0x01; op Opcode.Sstore; op Opcode.Address; push1 0x00;
      op Opcode.Mstore; push1 0x20; push1 0x00; op Opcode.Return;
    ]

let code_ctx =
  bytes_of
    [
      op Opcode.Caller; push1 0x00; op Opcode.Mstore; op Opcode.Callvalue;
      push1 0x20; op Opcode.Mstore; push1 0x40; push1 0x00; op Opcode.Return;
    ]

let code_revert =
  bytes_of
    [
      push1 0x2a; push1 0x01; op Opcode.Sstore; push1 0xbb; push1 0x00;
      op Opcode.Mstore; push1 0x20; push1 0x00; op Opcode.Revert;
    ]

let code_gas =
  bytes_of [ op Opcode.Gas; push1 0x00; op Opcode.Mstore; push1 0x20; push1 0x00; op Opcode.Return ]

let code_ret2 =
  bytes_of [ push1 0x00; push1 0x00; op Opcode.Mstore; push1 0x02; push1 0x00; op Opcode.Return ]

let code_ret4 =
  bytes_of [ push1 0x00; push1 0x00; op Opcode.Mstore; push1 0x04; push1 0x00; op Opcode.Return ]

let code_invalid = bytes_of [ op Opcode.Invalid ]

let code_nest =
  bytes_of
    ([ push1 0x11; push1 0x02; op Opcode.Sstore ]
    @ call ~gas:all_gas ~dst:callee_revert ~value:U256.zero ~in_off:0 ~in_len:0
        ~out_off:0 ~out_len:0
    @ [ op Opcode.Stop ])

let code_call_store =
  bytes_of
    (call ~gas:all_gas ~dst:callee_store ~value:U256.zero ~in_off:0 ~in_len:0
       ~out_off:0 ~out_len:0
    @ [ op Opcode.Stop ])

(* SSTORE the shared slot 7 to 2, then return the GAS remaining afterward. Borrowed
   by a CALLCODE so this SSTORE lands in the caller's storage, on the slot the
   caller already moved; the returned GAS is a probe of what that SSTORE cost. *)
let code_sstore_gas =
  bytes_of
    [
      push1 0x02; push1 0x07; op Opcode.Sstore; op Opcode.Gas; push1 0x00;
      op Opcode.Mstore; push1 0x20; push1 0x00; op Opcode.Return;
    ]

let coded address balance code =
  (address, Account.with_code (Account.make ~nonce:(nonce_of 1) ~balance) code)

let world =
  List.fold_left
    (fun w (address, account) -> World_state.set_account w address account)
    World_state.empty
    [
      (self, Account.make ~nonce:Nonce.zero ~balance:(u 1_000_000));
      (nonce_only, Account.make ~nonce:(nonce_of 3) ~balance:U256.zero);
      coded callee_ret U256.zero code_ret;
      coded callee_store U256.zero code_store;
      coded callee_ctx U256.zero code_ctx;
      coded callee_revert U256.zero code_revert;
      coded callee_gas U256.zero code_gas;
      coded callee_ret2 U256.zero code_ret2;
      coded callee_ret4 U256.zero code_ret4;
      coded callee_invalid U256.zero code_invalid;
      coded callee_nest U256.zero code_nest;
      coded callee_call_store U256.zero code_call_store;
      coded callee_sstore_gas U256.zero code_sstore_gas;
    ]

let base_call ~mutability =
  Env.Call.make ~target:self ~caller:outer_caller ~value:outer_value ~data:Data.empty
    ~mutability

let env_of ~mutability =
  Env.make
    ~block:
      (Env.Block.make ~coinbase:(address_of 0xc0) ~timestamp:(u 1_600_000_000)
         ~number:(u 15_500_000) ~prevrandao:U256.zero ~gas_limit:(u 25_000_000)
         ~basefee:(u 7) ~chain_id:(u 2017) ~hashes:Tn_evm.Block_hashes.empty)
    ~tx:(Env.Tx.make ~origin:(address_of 0x09) ~gas_price:(u 9) ~access_list:[])
    ~call:(base_call ~mutability)

let base_env = env_of ~mutability:Mutability.Mutable
let static_env = env_of ~mutability:Mutability.Static

let allowance = 50_000_000
let cold_effects = Effects.start ~world ~access:Access.empty

let warm_effects addresses =
  Effects.start ~world ~access:(Access.of_transaction ~addresses ~slots:[])

let run ?(env = base_env) ?(effects = cold_effects) ?(gas = allowance) parts =
  Interpreter.run ~env ~code:(asm parts) ~gas:(gas_of gas) ~effects

(* ---------- projections of an outcome ---------- *)

let output_of = function
  | Interpreter.Returned { output; _ } -> output
  | Interpreter.Reverted { output; _ } -> output
  | Interpreter.Stopped _ -> Alcotest.fail "expected an outcome carrying output, got stop"
  | Interpreter.Failed e ->
      Alcotest.fail ("expected output, got failure: " ^ Interpreter.error_to_string e)

let effects_of = function
  | Interpreter.Stopped { effects; _ } | Interpreter.Returned { effects; _ } -> effects
  | Interpreter.Reverted _ -> Alcotest.fail "expected effects, got a top-level revert"
  | Interpreter.Failed e ->
      Alcotest.fail ("expected effects, got failure: " ^ Interpreter.error_to_string e)

let remaining_of = function
  | Interpreter.Stopped { gas_left; _ }
  | Interpreter.Returned { gas_left; _ }
  | Interpreter.Reverted { gas_left; _ } ->
      Gas.remaining gas_left
  | Interpreter.Failed e ->
      Alcotest.fail ("expected a halt carrying gas, got " ^ Interpreter.error_to_string e)

let spent outcome = allowance - remaining_of outcome
let storage_at outcome address slot = World_state.storage (Effects.world (effects_of outcome)) address (u slot)
let balance_at outcome address = World_state.balance (Effects.world (effects_of outcome)) address

(* The i-th 32-byte word of an output string, as a word. *)
let word_at output i = get (U256.of_be_bytes (String.sub output (i * 32) 32))

let check_word msg expected output i =
  Alcotest.(check bool) msg true (U256.equal expected (word_at output i))

(* ---------- 1. a happy CALL returns 1 and copies its output ---------- *)

let test_call_happy_returns_1 () =
  (* CALL a callee that RETURNs the word 0x2a into [0x00, 0x20); then read the
     result, the return-data size, into memory and RETURN all three words. *)
  let outcome =
    run
      (call ~gas:all_gas ~dst:callee_ret ~value:U256.zero ~in_off:0 ~in_len:0
         ~out_off:0x00 ~out_len:0x20
      @ [ op Opcode.Returndatasize ] @ store_at 0x40
      @ store_at 0x20 (* the CALL result, still on top *)
      @ return_range ~off:0x00 ~len:0x60)
  in
  let output = output_of outcome in
  check_word "the callee's output landed at the output offset" (u 0x2a) output 0;
  check_word "CALL pushed one on success" U256.one output 1;
  check_word "RETURNDATASIZE is the 32 bytes returned" (u 32) output 2

(* ---------- 2. CALLCODE runs the code in the caller's own storage ---------- *)

let test_callcode_runs_to_code_in_self_storage () =
  (* CALLCODE borrows callee_store's code: its SSTORE must land in SELF's storage,
     and its ADDRESS must read SELF, because the storage context is the caller. *)
  let outcome =
    run
      (callcode ~gas:all_gas ~dst:callee_store ~value:U256.zero ~in_off:0 ~in_len:0
         ~out_off:0x00 ~out_len:0x20
      @ return_range ~off:0x00 ~len:0x20)
  in
  check_word "ADDRESS inside a CALLCODE is the caller itself"
    (Tn_state.Address_word.to_word self) (output_of outcome) 0;
  Alcotest.(check bool) "the SSTORE landed in the caller's storage" true
    (U256.equal (u 0x2a) (storage_at outcome self 1));
  Alcotest.(check bool) "and NOT in the borrowed account's storage" true
    (U256.is_zero (storage_at outcome callee_store 1))

(* ---------- 3. DELEGATECALL preserves CALLER and CALLVALUE, moves nothing --- *)

let test_delegatecall_preserves_caller_and_value () =
  (* The top frame was entered by outer_caller with value 777. A DELEGATECALL to
     code that reads CALLER and CALLVALUE must see exactly those — not the
     delegatecaller, not zero — and no balance may move. *)
  let outcome =
    run
      (delegatecall ~gas:all_gas ~dst:callee_ctx ~in_off:0 ~in_len:0 ~out_off:0x00
         ~out_len:0x40
      @ return_range ~off:0x00 ~len:0x40)
  in
  let output = output_of outcome in
  check_word "CALLER is inherited from the delegatecaller's own caller"
    (Tn_state.Address_word.to_word outer_caller) output 0;
  check_word "CALLVALUE is the apparent (inherited) value" outer_value output 1;
  Alcotest.(check bool) "no value moved: the caller's balance is untouched" true
    (U256.equal (u 1_000_000) (balance_at outcome self))

(* ---------- 4. STATICCALL forces static: a nested SSTORE fails ---------- *)

let test_staticcall_forces_static_nested_sstore_fails () =
  (* STATICCALL to code that SSTOREs: the child is static, so the write halts and
     the call pushes 0, leaving the callee's storage untouched. *)
  let direct =
    run
      (staticcall ~gas:all_gas ~dst:callee_store ~in_off:0 ~in_len:0 ~out_off:0x00
         ~out_len:0x20
      @ store_at 0x00 @ return_range ~off:0x00 ~len:0x20)
  in
  check_word "a static SSTORE fails, so STATICCALL pushes 0" U256.zero (output_of direct) 0;
  Alcotest.(check bool) "and the callee's storage is untouched" true
    (U256.is_zero (storage_at direct callee_store 1));
  (* Staticness is inherited through a further CALL: STATICCALL -> CALL -> SSTORE,
     where the inner CALL copies the static mutability, so the SSTORE beneath two
     frames still fails and the slot stays zero. *)
  let nested =
    run
      (staticcall ~gas:all_gas ~dst:callee_call_store ~in_off:0 ~in_len:0
         ~out_off:0x00 ~out_len:0x20
      @ [ op Opcode.Stop ])
  in
  Alcotest.(check bool) "staticness inherited through a nested CALL keeps the slot zero" true
    (U256.is_zero (storage_at nested callee_store 1))

(* ---------- 5. a value CALL from a static frame is refused; CALLCODE is not - *)

let test_value_call_from_static_frame_fails () =
  (* EIP-214: a value-bearing CALL in a static frame halts at the call site, before
     any sub-frame is entered. *)
  let outcome =
    Interpreter.run ~env:static_env
      ~code:
        (asm
           (call ~gas:all_gas ~dst:codeless ~value:U256.one ~in_off:0 ~in_len:0
              ~out_off:0 ~out_len:0
           @ [ op Opcode.Stop ]))
      ~gas:(gas_of allowance) ~effects:cold_effects
  in
  Alcotest.(check bool) "a value CALL from a static frame is CallNotAllowedInsideStatic"
    true
    (match outcome with
    | Interpreter.Failed Interpreter.Call_not_allowed_inside_static -> true
    | _ -> false);
  (* CALLCODE is exempt (its value moves only to itself), so a value CALLCODE from
     a static frame is allowed and its codeless target simply stops -> push 1. *)
  let allowed =
    Interpreter.run ~env:static_env
      ~code:
        (asm
           (callcode ~gas:all_gas ~dst:codeless ~value:U256.one ~in_off:0 ~in_len:0
              ~out_off:0 ~out_len:0
           @ store_at 0x00 @ return_range ~off:0x00 ~len:0x20))
      ~gas:(gas_of allowance) ~effects:cold_effects
  in
  check_word "a value CALLCODE from a static frame is allowed and succeeds" U256.one
    (output_of allowed) 0

(* ---------- 6. a value beyond the balance pushes 0 and refunds the stipend --- *)

let test_value_exceeds_balance_pushes_0 () =
  (* CALL with value above the caller's balance: the transfer fails, so the call
     pushes 0, the callee never runs, and no value moves. The whole forwarded gas
     (the stipend included) is handed back, while the 100 base, the 21 pushes and
     the 9000 value cost are not; the warm target makes the account access free.
     Net spend of the call = 21 + 100 + 9000 - 2300 = 6821, measured with a STOP
     that adds nothing so no observation instruction perturbs it. *)
  let call_parts =
    call ~gas:all_gas ~dst:callee_store ~value:(u 2_000_000) ~in_off:0 ~in_len:0
      ~out_off:0x00 ~out_len:0x00
  in
  let g = run ~effects:(warm_effects [ callee_store ]) (call_parts @ [ op Opcode.Stop ]) in
  Alcotest.(check int) "the full forwarded gas including the stipend is refunded" 6821
    (spent g);
  Alcotest.(check bool) "the caller's balance did not move" true
    (U256.equal (u 1_000_000) (balance_at g self));
  Alcotest.(check bool) "the callee's balance did not move" true
    (U256.is_zero (balance_at g callee_store));
  let r =
    run ~effects:(warm_effects [ callee_store ])
      (call_parts @ store_at 0x00 @ return_range ~off:0x00 ~len:0x20)
  in
  check_word "an unaffordable value CALL pushes 0" U256.zero (output_of r) 0

(* ---------- 7. the 1024-deep call-stack limit ---------- *)

let depth_of_n n =
  List.fold_left (fun d _ -> Call_depth.succ d) Call_depth.zero (List.init n (fun _ -> ()))

let one_call_program =
  asm
    (call ~gas:all_gas ~dst:codeless ~value:U256.zero ~in_off:0 ~in_len:0
       ~out_off:0 ~out_len:0
    @ store_at 0x00 @ return_range ~off:0x00 ~len:0x20)

let test_depth_1024_limit () =
  let at depth =
    Interpreter.run_subframe ~env:base_env ~code:one_call_program
      ~gas:(gas_of allowance) ~effects:cold_effects ~depth:(depth_of_n depth)
  in
  (* A frame at depth 1023 may still call: its child runs at 1024, which is within
     the limit, so the codeless callee stops and the call pushes 1. *)
  check_word "a frame at depth 1023 can still make a call" U256.one (output_of (at 1023)) 0;
  (* A frame at depth 1024 cannot: its child would run at 1025, past the limit, so
     the call is refused and pushes 0 without entering a sub-frame. *)
  check_word "a frame at depth 1024 is refused and pushes 0" U256.zero (output_of (at 1024)) 0

(* ---------- 8. RETURNDATACOPY is strict where CALLDATACOPY zero-fills -------- *)

let test_returndatacopy_strict_bounds_vs_calldatacopy () =
  (* After a call that returned four bytes, a RETURNDATACOPY whose window ends at
     five is past the buffer: an OutOfOffset halt, all gas consumed. *)
  let over_read =
    run
      (call ~gas:all_gas ~dst:callee_ret4 ~value:U256.zero ~in_off:0 ~in_len:0
         ~out_off:0 ~out_len:0
      @ returndatacopy ~dest:0x00 ~src:0x02 ~len:0x03
      @ [ op Opcode.Stop ])
  in
  Alcotest.(check bool) "a RETURNDATACOPY past the buffer halts with OutOfOffset" true
    (match over_read with
    | Interpreter.Failed Interpreter.Out_of_offset -> true
    | _ -> false);
  (* A source offset past [max_int] must not wrap to a small valid end. The
     saturating convert makes it [max_int] and the clamped [data_end] pins it at
     [max_int], well past the four-byte buffer, so a length-one read is OutOfOffset
     — not a spuriously-in-bounds [String.sub] (which would raise) and not a wrap.
     This exercises the saturating [data_end] clamp in [Return_data.read]. *)
  let saturating_over_read =
    run
      (call ~gas:all_gas ~dst:callee_ret4 ~value:U256.zero ~in_off:0 ~in_len:0
         ~out_off:0 ~out_len:0
      @ returndatacopy_word ~dest:0x00 ~src:U256.max_value ~len:0x01
      @ [ op Opcode.Stop ])
  in
  Alcotest.(check bool) "a near-max source offset saturates to OutOfOffset, never wraps" true
    (match saturating_over_read with
    | Interpreter.Failed Interpreter.Out_of_offset -> true
    | _ -> false);
  (* A zero-length copy whose source is strictly past the buffer is still refused:
     revm's [data_end = offset.saturating_add(0) > size] is checked
     UNCONDITIONALLY, before the zero-length short-circuit. Ten past a four-byte
     buffer is therefore OutOfOffset even though it would touch no memory. *)
  let zero_len_past_buffer =
    run
      (call ~gas:all_gas ~dst:callee_ret4 ~value:U256.zero ~in_off:0 ~in_len:0
         ~out_off:0 ~out_len:0
      @ returndatacopy ~dest:0x00 ~src:0x0a ~len:0x00
      @ [ op Opcode.Stop ])
  in
  Alcotest.(check bool)
    "a zero-length RETURNDATACOPY past the buffer is OutOfOffset before the len=0 short-circuit"
    true
    (match zero_len_past_buffer with
    | Interpreter.Failed Interpreter.Out_of_offset -> true
    | _ -> false);
  (* The same offset and length against CALLDATACOPY, whose source saturates and
     zero-fills, is not an error at all: the frame's (empty) calldata reads zeroes
     past its end and the program stops normally. *)
  let calldata =
    run
      ([ push1 0x03; push1 0x02; push1 0x00; op Opcode.Calldatacopy; op Opcode.Stop ])
  in
  Alcotest.(check bool) "the twin CALLDATACOPY past the end zero-fills and succeeds" true
    (match calldata with Interpreter.Stopped _ -> true | _ -> false)

(* ---------- 9. the return-data buffer is replaced on every outcome ---------- *)

let test_returndata_buffer_replaced_per_outcome () =
  (* A returning call fills the buffer; a following STOP (empty output) clears it. *)
  let after_stop =
    run
      (call ~gas:all_gas ~dst:callee_ret2 ~value:U256.zero ~in_off:0 ~in_len:0
         ~out_off:0 ~out_len:0
      @ call ~gas:all_gas ~dst:codeless ~value:U256.zero ~in_off:0 ~in_len:0
          ~out_off:0 ~out_len:0
      @ [ op Opcode.Returndatasize ] @ store_at 0x00 @ return_range ~off:0x00 ~len:0x20)
  in
  check_word "a stopping child empties the return-data buffer" U256.zero (output_of after_stop) 0;
  (* A reverting child instead fills it with its revert data, 32 bytes here. *)
  let after_revert =
    run
      (call ~gas:all_gas ~dst:callee_ret2 ~value:U256.zero ~in_off:0 ~in_len:0
         ~out_off:0 ~out_len:0
      @ call ~gas:all_gas ~dst:callee_revert ~value:U256.zero ~in_off:0 ~in_len:0
          ~out_off:0 ~out_len:0
      @ [ op Opcode.Returndatasize ] @ store_at 0x00 @ return_range ~off:0x00 ~len:0x20)
  in
  check_word "a reverting child fills the buffer with its revert data" (u 32)
    (output_of after_revert) 0

(* ---------- 10. leftover gas is refunded on success and revert, not on fail - *)

let test_leftover_gas_refunded () =
  (* A codeless callee stops at once and hands back every unit forwarded, so a
     successful CALL costs only the 21 pushes and the 100 base: 121 in all. *)
  let ok =
    run ~effects:(warm_effects [ codeless ])
      (call ~gas:all_gas ~dst:codeless ~value:U256.zero ~in_off:0 ~in_len:0
         ~out_off:0 ~out_len:0
      @ [ op Opcode.Stop ])
  in
  Alcotest.(check int) "a stopping child refunds all forwarded gas" 121 (spent ok);
  (* An INVALID callee halts exceptionally and forfeits the whole forwarded
     allowance, so the caller keeps only the 1/64 it reserved. *)
  let failed =
    run ~effects:(warm_effects [ callee_invalid ])
      (call ~gas:all_gas ~dst:callee_invalid ~value:U256.zero ~in_off:0 ~in_len:0
         ~out_off:0 ~out_len:0
      @ [ op Opcode.Stop ])
  in
  (* A forfeited call leaves the caller only the 1/64 it reserved before
     forwarding: [remaining = R/64] where [R = allowance - 121]. *)
  Alcotest.(check int) "a failing child forfeits its forwarded gas"
    ((allowance - 121) / 64)
    (remaining_of failed)

(* ---------- 11. a revert drops effects but the return data stays copyable ---- *)

let test_revert_drops_effects_returndata_copyable () =
  (* The callee SSTOREs, then REVERTs a word. The write must vanish, the call must
     push 0, and yet its revert data must remain copyable through RETURNDATACOPY. *)
  let outcome =
    run
      (call ~gas:all_gas ~dst:callee_revert ~value:U256.zero ~in_off:0 ~in_len:0
         ~out_off:0 ~out_len:0
      @ returndatacopy ~dest:0x20 ~src:0x00 ~len:0x20
      @ store_at 0x00 (* the CALL result *)
      @ return_range ~off:0x00 ~len:0x40)
  in
  let output = output_of outcome in
  check_word "a reverting CALL pushes 0" U256.zero output 0;
  check_word "yet its revert data copies out of the buffer" (u 0xbb) output 1;
  Alcotest.(check bool) "the reverted SSTORE left the storage untouched" true
    (U256.is_zero (storage_at outcome callee_revert 1))

(* ---------- 12. the EIP-150 63/64 cap ---------- *)

let test_sixty_three_over_64_cap () =
  (* With value zero and a request past what any allowance can name, the forward is
     exactly the 63/64 ceiling and nothing more. 6400/64 = 100, so 6300. *)
  let cg = Gas.call_gas ~requested:U256.max_value ~remaining:(gas_of 6400) ~value:U256.zero in
  Alcotest.(check int) "the caller is charged the 63/64 ceiling" 6300 cg.Gas.charge;
  Alcotest.(check int) "with no value, nothing is added on top" 6300
    (Gas.remaining cg.Gas.forwarded);
  Alcotest.(check int) "forwardable_gas is that ceiling" 6300 (Gas.forwardable_gas (gas_of 6400));
  (* A request below the ceiling caps the forward at the request. *)
  let capped = Gas.call_gas ~requested:(u 1000) ~remaining:(gas_of 6400) ~value:U256.zero in
  Alcotest.(check int) "a smaller request is the cap" 1000 capped.Gas.charge;
  Alcotest.(check int) "and is forwarded as-is" 1000 (Gas.remaining capped.Gas.forwarded)

(* ---------- 13. the stipend is forwarded on top of the cap ---------- *)

let test_stipend_forwarding () =
  (* A value call requesting zero gas still forwards the 2300 stipend, gifted on
     top and charged to no one. *)
  let cg = Gas.call_gas ~requested:U256.zero ~remaining:(gas_of 100_000) ~value:U256.one in
  Alcotest.(check int) "requesting zero charges the caller nothing" 0 cg.Gas.charge;
  Alcotest.(check int) "but the callee still receives the 2300 stipend" 2300
    (Gas.remaining cg.Gas.forwarded);
  (* End to end: the callee's GAS reads 2298, the 2300 it entered with less GAS's
     own 2, proving the stipend really reached the sub-frame. *)
  let outcome =
    run
      (call ~gas:U256.zero ~dst:callee_gas ~value:U256.one ~in_off:0 ~in_len:0
         ~out_off:0x00 ~out_len:0x20
      @ return_range ~off:0x00 ~len:0x20)
  in
  check_word "the sub-frame runs on the stipend" (u 2298) (output_of outcome) 0

(* ---------- 14. the target's warming survives a child revert ---------- *)

let test_warming_survives_child_revert () =
  (* A cold CALL to a callee that reverts: the child's effects are dropped, but the
     warming of the target is placed in the parent before the transfer branches, so
     the target is warm afterward even though the child reverted. *)
  let outcome =
    run
      (call ~gas:all_gas ~dst:callee_revert ~value:U256.zero ~in_off:0 ~in_len:0
         ~out_off:0 ~out_len:0
      @ [ op Opcode.Stop ])
  in
  let touched = Effects.access (effects_of outcome) in
  Alcotest.(check bool) "the reverting call still leaves its target warm" true
    (Access.mem_account touched callee_revert);
  Alcotest.(check bool) "an untouched address stays cold" false
    (Access.mem_account touched callee_ret)

(* ---------- 15. original stays transaction-scoped across a nested revert ----- *)

let test_original_transaction_scoped () =
  (* A child SSTOREs slot 2, then a grandchild SSTOREs slot 1 and reverts. The
     child's write survives; the grandchild's is dropped; and the pre-transaction
     world every SSTORE nets against (Effects.base) is unmoved by the nesting,
     because a sub-frame never re-runs Effects.start. *)
  let outcome =
    run
      (call ~gas:all_gas ~dst:callee_nest ~value:U256.zero ~in_off:0 ~in_len:0
         ~out_off:0 ~out_len:0
      @ [ op Opcode.Stop ])
  in
  Alcotest.(check bool) "the child's own write survived" true
    (U256.equal (u 0x11) (storage_at outcome callee_nest 2));
  Alcotest.(check bool) "the reverting grandchild's write was dropped" true
    (U256.is_zero (storage_at outcome callee_revert 1));
  (* [original] is transaction-scoped, and that is observable through EIP-2200 gas,
     not just through [Effects.base] (whose equality with the start world is a
     tautology a re-baselining sub-frame would still satisfy). The outer frame
     SSTOREs shared slot 7 (0 -> 1), then CALLCODEs a child that SSTOREs the SAME
     slot in the SAME storage context (1 -> 2) and returns its remaining GAS. With
     correct transaction-scoped [original] the child's write is DIRTY (original 0
     <> present 1) — the cheap ~100 branch — so its returned GAS sits high. Were a
     sub-frame to re-baseline [original] to the value it inherited, the child would
     see original 1 == present 1, take the SSTORE_RESET ~2900 branch, and its
     returned GAS would fall ~2800 lower. The threshold below clears the ~100 charge
     and only it: it is the observed dirty-branch reading (49_194_299) less 1_400,
     so the ~2800 reset gap drops the reading below it while the dirty reading clears
     it with room to spare. *)
  let gas_scoped =
    run
      ([ push1 0x01; push1 0x07; op Opcode.Sstore ]
      @ callcode ~gas:all_gas ~dst:callee_sstore_gas ~value:U256.zero ~in_off:0
          ~in_len:0 ~out_off:0x00 ~out_len:0x20
      @ return_range ~off:0x00 ~len:0x20)
  in
  let child_gas = get (U256.to_int (word_at (output_of gas_scoped) 0)) in
  Alcotest.(check bool)
    "the child's SSTORE took the cheap dirty branch: original stayed transaction-scoped"
    true
    (child_gas > 49_192_899)

(* ---------- 16. the new-account cost, only for CALL to an empty callee ------- *)

let test_new_account_cost () =
  (* A value CALL that brings an is_empty account into existence pays 25000 more
     than the same CALL to an account made non-empty by a nonce alone. Both targets
     are warm and both stop at once, so the only difference is the new-account
     charge. *)
  let value_call dst =
    run ~effects:(warm_effects [ dst ])
      (call ~gas:all_gas ~dst ~value:U256.one ~in_off:0 ~in_len:0 ~out_off:0
         ~out_len:0
      @ [ op Opcode.Stop ])
  in
  Alcotest.(check int) "CALL to an empty callee costs 25000 more than to a non-empty one"
    25000
    (spent (value_call absent) - spent (value_call nonce_only));
  (* CALLCODE never charges it, even to an empty target: the account is the
     caller's own and no account is created. *)
  let value_callcode dst =
    run ~effects:(warm_effects [ dst ])
      (callcode ~gas:all_gas ~dst ~value:U256.one ~in_off:0 ~in_len:0 ~out_off:0
         ~out_len:0
      @ [ op Opcode.Stop ])
  in
  Alcotest.(check int) "CALLCODE to an empty target charges no new-account cost" 0
    (spent (value_callcode absent) - spent (value_callcode nonce_only))

(* ---------- the property: call gas is bounded, and drive terminates ---------- *)

let mk ~salt ~count name arb fn =
  Alcotest.test_case name `Slow (fun () ->
      QCheck.Test.check_exn
        ~rand:(Random.State.make [| 0x5eed_c; salt |])
        (QCheck.Test.make ~count ~name arb fn))

let prop_call_gas =
  mk ~salt:1 ~count:3000 "call_gas: charge <= remaining, capped, stipend on top"
    (QCheck.triple
       (QCheck.int_range 0 2_000_000_000)
       (QCheck.int_range 0 4_000_000_000)
       QCheck.bool)
    (fun (rem, req, moves) ->
      let remaining = gas_of rem in
      let value = if moves then U256.one else U256.zero in
      let cg = Gas.call_gas ~requested:(u req) ~remaining ~value in
      let ceiling = Gas.forwardable_gas remaining in
      let forwarded = Gas.remaining cg.Gas.forwarded in
      cg.Gas.charge >= 0
      && cg.Gas.charge <= rem
      && cg.Gas.charge <= ceiling
      && cg.Gas.charge = Int.min ceiling req
      && forwarded >= 0
      && forwarded = cg.Gas.charge + (if moves then 2300 else 0)
      && forwarded <= cg.Gas.charge + 2300)

let random_code =
  QCheck.make ~print:(fun s -> Printf.sprintf "%d bytes" (String.length s))
    QCheck.Gen.(
      map
        (fun cs -> String.init (List.length cs) (List.nth cs))
        (list_size (int_range 0 64) (map Char.chr (int_range 0 255))))

let prop_terminates =
  mk ~salt:2 ~count:500 "run_subframe terminates on random bytecode near the depth limit"
    random_code
    (fun bytes ->
      (* Seeded one frame below the limit so any CALL bottoms out at once, and
         bounded by gas regardless: returning at all is the property. *)
      let _ =
        Interpreter.run_subframe ~env:base_env ~code:(Code.of_string bytes)
          ~gas:(gas_of 200_000) ~effects:cold_effects ~depth:(depth_of_n 1023)
      in
      true)

let () =
  Alcotest.run "tn_evm_calls"
    [
      ( "call",
        [
          Alcotest.test_case "a happy CALL returns 1" `Quick test_call_happy_returns_1;
          Alcotest.test_case "CALLCODE runs in the caller's storage" `Quick
            test_callcode_runs_to_code_in_self_storage;
          Alcotest.test_case "DELEGATECALL preserves caller and value" `Quick
            test_delegatecall_preserves_caller_and_value;
          Alcotest.test_case "STATICCALL forces static, a nested SSTORE fails" `Quick
            test_staticcall_forces_static_nested_sstore_fails;
          Alcotest.test_case "a value CALL from a static frame fails" `Quick
            test_value_call_from_static_frame_fails;
          Alcotest.test_case "value beyond balance pushes 0" `Quick
            test_value_exceeds_balance_pushes_0;
          Alcotest.test_case "the 1024 depth limit" `Quick test_depth_1024_limit;
        ] );
      ( "return data",
        [
          Alcotest.test_case "RETURNDATACOPY strict vs CALLDATACOPY zero-fill" `Quick
            test_returndatacopy_strict_bounds_vs_calldatacopy;
          Alcotest.test_case "the buffer is replaced per outcome" `Quick
            test_returndata_buffer_replaced_per_outcome;
        ] );
      ( "gas",
        [
          Alcotest.test_case "leftover gas refunded on ok/revert, not on fail" `Quick
            test_leftover_gas_refunded;
          Alcotest.test_case "the 63/64 cap" `Quick test_sixty_three_over_64_cap;
          Alcotest.test_case "the stipend forwards on top" `Quick test_stipend_forwarding;
          Alcotest.test_case "the new-account cost, CALL only, empty only" `Quick
            test_new_account_cost;
        ] );
      ( "effects",
        [
          Alcotest.test_case "revert drops effects, keeps return data" `Quick
            test_revert_drops_effects_returndata_copyable;
          Alcotest.test_case "warming survives a child revert" `Quick
            test_warming_survives_child_revert;
          Alcotest.test_case "original stays transaction-scoped" `Quick
            test_original_transaction_scoped;
        ] );
      ("properties", [ prop_call_gas; prop_terminates ]);
    ]
