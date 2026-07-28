(* EIP-7702 gas tests, chunk 33: the intrinsic side — the 25000-per-LISTED-
   entry charge ([cfg/gas_params.rs:729-731]), the EIP-7623 floor's exclusion
   of that charge ([cfg/gas_params.rs:664-666, 741-744]) and the balance
   precheck's exclusion of it ([transaction.rs:167-178]) — and, since the loop
   stage, the refund-pipeline vectors G1..G6 (cap-bound refund, floor-zeroed
   refund, revert/halt survival) plus the executor-level pricing of check 4's
   warmth.

   Gas is asserted through the receipt ([Receipt.gas_used], the NET, and the
   [gas_refunded] a success commits to), never through the nominal pot: the
   pot is pinned via [Auth_list.refund] in test_eip7702_state.ml.

   test_executor.ml conventions: absolute hand-computed gas asserted as
   literals with the derivation in a comment. Fixtures from eip7702_vectors.ml. *)

module U256 = Tn_state.U256
module Nonce = Tn_state.Nonce
module Account = Tn_state.Account
module World_state = Tn_state.World_state
module Units = Tn_types.Units
module Env = Tn_evm.Env
module Block_hashes = Tn_evm.Block_hashes
module Authorization = Tn_evm.Authorization
module Auth_list = Tn_evm.Auth_list
module Transaction = Tn_evm.Transaction
module Intrinsic = Tn_evm.Intrinsic
module Receipt = Tn_evm.Receipt
module Executor = Tn_evm.Executor
module V = Eip7702_vectors

let get o =
  Result.fold ~ok:Fun.id
    ~error:(fun () -> Alcotest.fail "expected Some")
    (Option.to_result ~none:() o)

let u n = get (U256.of_int n)
let nonce_of n = get (Nonce.of_int n)

(* A twenty-byte address whose last byte is the given hex pair; distinct from
   the precompile addresses 0x01..0x0a for any pair outside that range. *)
let address_of hex_pair = V.addr_of_hex (String.make 38 '0' ^ hex_pair)
let account ~nonce ~balance = Account.make ~nonce:(nonce_of nonce) ~balance:(u balance)

let world_seed pairs =
  List.fold_left
    (fun w (address, acct) -> World_state.set_account w address acct)
    World_state.empty pairs

let block_of ~coinbase ~basefee =
  Env.Block.make ~coinbase ~timestamp:(u 1_600_000_000) ~number:(u 1000)
    ~prevrandao:U256.zero ~gas_limit:(u 30_000_000) ~basefee:(u basefee)
    ~basefee_address:Tn_evm.System_contracts.governance_safe_address ~chain_id:(u 1)
    ~hashes:Block_hashes.empty

let sender = address_of "a1"
let target = address_of "b2"
let coinbase = address_of "c3"

let exec_ok world ~block tx =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "unexpected rejection: %s" (Executor.error_to_string e))
    (Executor.execute world ~block tx)

let check_rejects name expected result =
  Result.fold
    ~ok:(fun _ -> Alcotest.failf "%s: expected a rejection" name)
    ~error:(fun e ->
      Alcotest.(check string) name
        (Executor.error_to_string expected)
        (Executor.error_to_string e))
    result

(* An entry the loop will SKIP for its chain id (2 against a chain-1 block);
   the signature never needs to recover, so the sentinel r/s do. The intrinsic
   must charge it anyway. *)
let auth_chain2 =
  Authorization.sign
    (get (Authorization.make ~chain_id:(u 2) ~address:V.target_11s ~nonce:U256.zero))
    ~y_parity:U256.zero ~r:V.r_ones ~s:V.s_twos

(* The key-0 oracle entry (chain 1, target 0x11*20, nonce 0): it screens
   through, and once the loop lands it APPLIES against [V.authority_key0] —
   which these worlds never seed, so the authority is FRESH and earns no
   refund ([pre_execution.rs:268-271] requires a pre-existing authority).
   That choice is what keeps every gas literal below stable when the loop
   arrives: the "pot = 12500" leg needs a pre-existing authority and
   [Auth_list.refund], and belongs to the loop stage. *)
let auth_key0 =
  Authorization.sign
    (get (Authorization.make ~chain_id:(u 1) ~address:V.target_11s ~nonce:U256.zero))
    ~y_parity:(u V.auth_key0_y_parity) ~r:V.auth_key0_r ~s:V.auth_key0_s

let set_code_tx ~gas_limit ~max_fee ~authorizations =
  Transaction.set_code ~sender ~nonce:(nonce_of 0) ~gas_limit ~target ~value:U256.zero
    ~data:"" ~access_list:[] ~chain_id:(u 1) ~max_priority_fee_per_gas:(u 0)
    ~max_fee_per_gas:max_fee ~authorizations

(* [initial_gas] adds 25000 per LISTED authorization, valid or not: the list
   here is n copies of a chain-mismatched entry the loop will never apply, and
   the charge counts them all ([cfg/gas.rs:181-188] passes
   [authorization_list_len()]). [floor_gas] has no authorization parameter at
   all — its arity is the guard — so it is 21000 in every case. *)
let test_intrinsic_charges_every_listed_entry () =
  let ig n =
    Intrinsic.initial_gas ~kind:Intrinsic.Call ~data:"" ~access_list:[]
      ~authorizations:(List.init n (fun _ -> auth_chain2))
  in
  Alcotest.(check int) "no authorizations" 21000 (ig 0);
  Alcotest.(check int) "one listed entry" 46000 (ig 1);
  Alcotest.(check int) "two listed entries" 71000 (ig 2);
  Alcotest.(check int) "three listed entries" 96000 (ig 3);
  Alcotest.(check int) "the floor never sees them" 21000 (Intrinsic.floor_gas ~data:"");
  (* Executor level: two entries, ONE chain-mismatched, so a mutation that
     counts only appliable entries computes 46000 and stops rejecting at
     70999. intrinsic = 21000 + 2*25000 = 71000. *)
  let world = world_seed [ (sender, account ~nonce:0 ~balance:1_000_000_000) ] in
  let block = block_of ~coinbase ~basefee:3 in
  let entries = [ auth_chain2; auth_key0 ] in
  check_rejects "one gas short of the two-entry intrinsic"
    Executor.Intrinsic_gas_above_limit
    (Executor.execute world ~block
       (set_code_tx ~gas_limit:70999 ~max_fee:(u 10) ~authorizations:entries));
  (* At exactly 71000 the whole limit is the intrinsic: the codeless target
     frame runs on zero gas and succeeds, so spent = 71000 and — with no loop
     yet, and after it a fresh authority earning nothing — the net is 71000. *)
  let receipt, _ =
    exec_ok world ~block
      (set_code_tx ~gas_limit:71000 ~max_fee:(u 10) ~authorizations:entries)
  in
  Alcotest.(check int) "the intrinsic is the whole spend" 71000 (Receipt.gas_used receipt)

(* The EIP-7623 floor is calldata tokens alone: 10000 zero bytes are 10000
   tokens, floor = 10*10000 + 21000 = 121000 however many authorizations the
   transaction lists, while the initial gas moves by exactly 25000 per entry
   (21000 + 4*10000 = 61000 bare, 136000 with three). A floor that wrongly
   included 25000*n would read 196000 here. *)
let test_floor_excludes_auth_cost () =
  let data = String.make 10000 '\000' in
  Alcotest.(check int) "floor of 10000 zero bytes" 121000 (Intrinsic.floor_gas ~data);
  Alcotest.(check int) "initial, no entries" 61000
    (Intrinsic.initial_gas ~kind:Intrinsic.Call ~data ~access_list:[] ~authorizations:[]);
  Alcotest.(check int) "initial, three entries" 136000
    (Intrinsic.initial_gas ~kind:Intrinsic.Call ~data ~access_list:[]
       ~authorizations:[ auth_chain2; auth_chain2; auth_chain2 ])

(* The 25000-per-auth intrinsic is paid out of gas_limit, never out of an
   additional balance requirement: the precheck is
   [gas_limit * max_fee + value] with NO extra term ([transaction.rs:167-178]).
   A sender funded EXACTLY 71000 * 1 + 0 clears it with two authorizations;
   a port that added 2*25000 to the precheck would demand 121000 and reject.
   One wei under the exact product must still reject, which is what makes
   "exactly funded" a boundary rather than a headroom. *)
let test_balance_precheck_excludes_auth_cost () =
  let block = block_of ~coinbase ~basefee:1 in
  let tx =
    set_code_tx ~gas_limit:71000 ~max_fee:(u 1)
      ~authorizations:[ auth_chain2; auth_key0 ]
  in
  let exactly = world_seed [ (sender, account ~nonce:0 ~balance:71000) ] in
  let receipt, _ = exec_ok exactly ~block tx in
  Alcotest.(check int) "exactly funded, and the intrinsic is the spend" 71000
    (Receipt.gas_used receipt);
  let one_short = world_seed [ (sender, account ~nonce:0 ~balance:70999) ] in
  check_rejects "one wei short of gas_limit * max_fee" Executor.Insufficient_funds
    (Executor.execute one_short ~block tx)

(* ---------------------------------------------------------------- *)
(* The loop-era vectors (chunk 33, stage 4): G1..G6 and warmth       *)
(* ---------------------------------------------------------------- *)

(* Every gas assertion below reads the NET ([Receipt.gas_used]) or the
   receipt's own [gas_refunded], never the pot: the corrected first-regime
   arithmetic is 46000 - min(12500, 46000/5) = 36800, and the nominal 12500
   appears in NO gas_used expectation in this file — the pot is asserted
   through [Auth_list.refund] in test_eip7702_state.ml, where it belongs. *)

(* A minted vector (eip7702_vectors.ml) as a signed authorization. *)
let signed_of (m : V.minted) =
  Authorization.sign
    (get (Authorization.make ~chain_id:m.V.m_chain ~address:m.V.m_address ~nonce:m.V.m_nonce))
    ~y_parity:(u m.V.m_parity) ~r:m.V.m_r ~s:m.V.m_s

(* The full type-4 builder for vectors that need calldata, an access list or a
   seeded contract target; trailing unit so the optional arguments erase. *)
let tx4 ?(target = target) ?(data = "") ?(access_list = []) ~gas_limit ~max_fee
    ~authorizations () =
  Transaction.set_code ~sender ~nonce:(nonce_of 0) ~gas_limit ~target ~value:U256.zero
    ~data ~access_list ~chain_id:(u 1) ~max_priority_fee_per_gas:(u 0)
    ~max_fee_per_gas:max_fee ~authorizations

let success_refunded = function
  | Receipt.Success { gas_refunded; _ } -> gas_refunded
  | Receipt.Reverted _ -> Alcotest.fail "expected a success receipt"
  | Receipt.Halted _ -> Alcotest.fail "expected a success receipt"

let reverted_gas = function
  | Receipt.Reverted { gas_used; _ } -> gas_used
  | Receipt.Success _ -> Alcotest.fail "expected a revert receipt"
  | Receipt.Halted _ -> Alcotest.fail "expected a revert receipt"

let halted_gas = function
  | Receipt.Halted { gas_used; _ } -> gas_used
  | Receipt.Success _ -> Alcotest.fail "expected a halt receipt"
  | Receipt.Reverted _ -> Alcotest.fail "expected a halt receipt"

let code_hex_at w address =
  V.to_hex (Account.code (World_state.account w address))

let nonce_at w address = Nonce.to_int (World_state.nonce w address)

(* Zero-price block and transaction for the G vectors: the refund arithmetic
   is entirely in gas units, and zero prices keep every balance out of it. *)
let block0 = block_of ~coinbase ~basefee:0

let seeded extra = world_seed ((sender, account ~nonce:0 ~balance:1_000_000_000) :: extra)

(* G1 — the first regime, in the CORRECTED arithmetic. One applying entry
   against an EXISTING authority, no calldata, gas_limit = intrinsic = 21000 +
   25000 = 46000; the codeless target runs on zero gas, so spent = 46000. The
   pot is 12500 but the EIP-3529 cap is 46000/5 = 9200 and BINDS:
   net = 46000 - 9200 = 36800 (the floor, 21000, does not). A flat "25000
   charged, 12500 back" reading gives 33500 and fails by 3300. *)
let test_g1_authority_exists_cap_binds () =
  let receipt, w =
    exec_ok (seeded [ (V.authority_key0, account ~nonce:0 ~balance:1) ]) ~block:block0
      (tx4 ~gas_limit:46000 ~max_fee:(u 0) ~authorizations:[ auth_key0 ] ())
  in
  Alcotest.(check int) "net 36800, not 33500" 36800 (Receipt.gas_used receipt);
  Alcotest.(check int) "the cap is what was refunded" 9200 (success_refunded receipt);
  Alcotest.(check string) "and the delegation landed" V.designator_11s_hex
    (code_hex_at w V.authority_key0);
  Alcotest.(check int) "with its bump" 1 (nonce_at w V.authority_key0)

(* G2 — the same transaction against an ABSENT authority: no refund at all,
   net = the full 46000, and the delegation still lands, permanently
   materialising the account ([pre_execution.rs:252-265] applies regardless of
   check 7's verdict). *)
let test_g2_authority_absent_no_refund () =
  let receipt, w =
    exec_ok (seeded []) ~block:block0
      (tx4 ~gas_limit:46000 ~max_fee:(u 0) ~authorizations:[ auth_key0 ] ())
  in
  Alcotest.(check int) "the full intrinsic is the net" 46000 (Receipt.gas_used receipt);
  Alcotest.(check int) "nothing refunded" 0 (success_refunded receipt);
  Alcotest.(check string) "the authority materialised delegated" V.designator_11s_hex
    (code_hex_at w V.authority_key0);
  Alcotest.(check int) "at nonce 1" 1 (nonce_at w V.authority_key0)

(* G3 — the EIP-7623 floor OVERWRITES spent and ZEROES the whole refund in ONE
   branch ([post_execution.rs:12-20]). 10000 zero calldata bytes: intrinsic =
   21000 + 40000 + 25000 = 86000, floor = 21000 + 10*10000 = 121000 (the floor
   EXCLUDES the auth term). spent = 86000, capped refund 12500,
   86000 - 12500 = 73500 < 121000, so the charge is the floor and the refund
   is zero. The Ok itself is the REJECTION leg: a floor that wrongly included
   25000*n would be 146000 > gas_limit = 130000 and [exec_ok] would die on
   [Gas_floor_above_limit] before any receipt existed — an error-identity
   assertion, not a number drift. *)
let test_g3_eip7623_floor_zeroes_the_refund () =
  let world = seeded [ (V.authority_key0, account ~nonce:0 ~balance:1) ] in
  let tx_at gas_limit =
    tx4 ~data:(String.make 10000 '\000') ~gas_limit ~max_fee:(u 0)
      ~authorizations:[ auth_key0 ] ()
  in
  let receipt, _ = exec_ok world ~block:block0 (tx_at 130000) in
  Alcotest.(check int) "the floor is the charge" 121000 (Receipt.gas_used receipt);
  Alcotest.(check int) "and the refund is zeroed, not clamped" 0
    (success_refunded receipt);
  (* The floor's VALUE, pinned by error identity at its own boundary: at
     gas_limit = floor the transaction runs; one gas below it, the rejection
     is [Gas_floor_above_limit] — not a mispricing. A floor wrongly including
     25000*n moves this boundary to 146000 and flips BOTH legs. *)
  let at_floor, _ = exec_ok world ~block:block0 (tx_at 121000) in
  Alcotest.(check int) "at the boundary the floor is still the charge" 121000
    (Receipt.gas_used at_floor);
  check_rejects "one gas below the floor is the floor's own error"
    Executor.Gas_floor_above_limit
    (Executor.execute world ~block:block0 (tx_at 120999))

(* G4 — the refund is recorded BEFORE the /5 cap, with integer FLOOR division
   ([post_execution.rs:23-29]); an adjacent pair pins the boundary rather than
   the direction. Access lists pad spent: (a) 3 addresses + 5 slots gives
   intrinsic = 21000 + 3*2400 + 5*1900 + 25000 = 62700, cap = 12540, so the
   FULL pot 12500 pays out and net = 50200; (b) one slot fewer gives 60800,
   cap = 12160 < pot, so the cap pays and net = 48640. *)
let test_g4_cap_boundary_pair () =
  let e1 = address_of "e1" in
  let e2 = address_of "e2" in
  let e3 = address_of "e3" in
  let world = seeded [ (V.authority_key0, account ~nonce:0 ~balance:1) ] in
  let five = [ (e1, [ u 1; u 2 ]); (e2, [ u 3; u 4 ]); (e3, [ u 5 ]) ] in
  let receipt_a, _ =
    exec_ok world ~block:block0
      (tx4 ~access_list:five ~gas_limit:62700 ~max_fee:(u 0)
         ~authorizations:[ auth_key0 ] ())
  in
  Alcotest.(check int) "cap 12540 does not bind" 50200 (Receipt.gas_used receipt_a);
  Alcotest.(check int) "the pot pays in full"
    (Intrinsic.per_empty_account_cost - Auth_list.per_auth_base_cost)
    (success_refunded receipt_a);
  let four = [ (e1, [ u 1; u 2 ]); (e2, [ u 3; u 4 ]); (e3, []) ] in
  let receipt_b, _ =
    exec_ok world ~block:block0
      (tx4 ~access_list:four ~gas_limit:60800 ~max_fee:(u 0)
         ~authorizations:[ auth_key0 ] ())
  in
  Alcotest.(check int) "cap 12160 binds" 48640 (Receipt.gas_used receipt_b);
  Alcotest.(check int) "and is what was refunded" 12160 (success_refunded receipt_b)

(* G5 — the auth refund is computed in pre-execution and paid in
   post-execution ([handler.rs:150-153, 226-234]), so a REVERT neither drops
   it nor rolls the delegation back. Target code PUSH1 0, PUSH1 0, REVERT
   costs 6: spent = 46000 + 6 = 46006, the frame's own refund is discarded on
   a revert, the auth pot 12500 meets cap 46006/5 = 9201, net = 36805. A port
   folding the refund into the revert arm answers 46006; one returning the
   pre-auth world loses the designator. *)
let test_g5_refund_and_designator_survive_revert () =
  let receipt, w =
    exec_ok
      (seeded
         [
           (V.authority_key0, account ~nonce:0 ~balance:1);
           (target, Account.with_code (account ~nonce:0 ~balance:0) (V.hex "60006000fd"));
         ])
      ~block:block0
      (tx4 ~gas_limit:100000 ~max_fee:(u 0) ~authorizations:[ auth_key0 ] ())
  in
  Alcotest.(check int) "reverted, net 36805" 36805 (reverted_gas receipt);
  Alcotest.(check string) "the designator survives the revert" V.designator_11s_hex
    (code_hex_at w V.authority_key0);
  Alcotest.(check int) "so does the bump" 1 (nonce_at w V.authority_key0)

(* G6 — same through an exceptional halt (a single INVALID byte), which burns
   the whole limit: spent = 100000, cap = 20000, the pot 12500 pays in full,
   net = 87500. The delegation sits below the frame checkpoint and survives
   the halt exactly as it survived the revert. *)
let test_g6_refund_and_designator_survive_halt () =
  let receipt, w =
    exec_ok
      (seeded
         [
           (V.authority_key0, account ~nonce:0 ~balance:1);
           (target, Account.with_code (account ~nonce:0 ~balance:0) (V.hex "fe"));
         ])
      ~block:block0
      (tx4 ~gas_limit:100000 ~max_fee:(u 0) ~authorizations:[ auth_key0 ] ())
  in
  Alcotest.(check int) "halted, net 87500" 87500 (halted_gas receipt);
  Alcotest.(check string) "the designator survives the halt" V.designator_11s_hex
    (code_hex_at w V.authority_key0);
  Alcotest.(check int) "so does the bump" 1 (nonce_at w V.authority_key0)

(* Check 4's warming priced through EXTCODESIZE, the executor-level sibling of
   the state file's warmth tests. The measuring contract runs PUSH20 key0's
   authority, EXTCODESIZE, POP, STOP: 3 + (100 warm | 2600 cold) + 2, so a
   type-4 transaction with one skipped-but-screened entry answers
   46000 + 105 = 46105 and one whose entry never passed checks 1-3 answers
   46000 + 2605 = 48605. The control run carries key 2's entry over the same
   tuple shape — identical intrinsic, identical (zero) refund, key 0's
   authority never named — so the 2500 difference is check 4's warmth and
   nothing else. *)
let test_warmth_from_check4_is_priced () =
  let measuring = address_of "d4" in
  let measuring_code = V.hex ("73" ^ V.authority_key0_hex ^ "3b5000") in
  let contract_code = V.hex "6001" in
  let world =
    seeded
      [
        (measuring, Account.with_code (account ~nonce:0 ~balance:0) measuring_code);
        (V.authority_key0, Account.with_code (account ~nonce:0 ~balance:0) contract_code);
        (V.authority_key2, Account.with_code (account ~nonce:0 ~balance:0) contract_code);
      ]
  in
  let run entry =
    let receipt, _ =
      exec_ok world ~block:block0
        (tx4 ~target:measuring ~gas_limit:100000 ~max_fee:(u 0) ~authorizations:[ entry ]
           ())
    in
    Receipt.gas_used receipt
  in
  (* Skipped at check 5 (key 0 bears code), warmed at check 4 anyway. *)
  let warm5 = run auth_key0 in
  Alcotest.(check int) "skipped at 5, warm anyway" 46105 warm5;
  (* Control: key 2's entry, same shape, key 0 cold. *)
  let cold_control = run (signed_of V.k2_d1_n0) in
  Alcotest.(check int) "the control pays the cold surcharge" 48605 cold_control;
  Alcotest.(check int) "check 4's warmth is worth exactly 2500" 2500
    (cold_control - warm5);
  (* Skipped at check 2: a genuine key-0 signature over a saturated nonce
     never reaches the warming, so key 0 stays as cold as in the control. *)
  Alcotest.(check int) "skipped at 2 warms nothing" 48605 (run (signed_of V.k0_d1_sat));
  (* Skipped at check 6 (wrong nonce against a CODELESS key 0): warm again. *)
  let world_codeless =
    seeded
      [
        (measuring, Account.with_code (account ~nonce:0 ~balance:0) measuring_code);
        (V.authority_key0, account ~nonce:0 ~balance:1);
      ]
  in
  let receipt6, _ =
    exec_ok world_codeless ~block:block0
      (tx4 ~target:measuring ~gas_limit:100000 ~max_fee:(u 0)
         ~authorizations:[ signed_of V.k0_d1_n7 ] ())
  in
  Alcotest.(check int) "skipped at 6, warm anyway" 46105 (Receipt.gas_used receipt6)

let () =
  Alcotest.run "eip7702 gas"
    [
      ( "intrinsic",
        [
          Alcotest.test_case "every listed entry is charged 25000" `Quick
            test_intrinsic_charges_every_listed_entry;
          Alcotest.test_case "the 7623 floor excludes the auth cost" `Quick
            test_floor_excludes_auth_cost;
          Alcotest.test_case "the balance precheck excludes the auth cost" `Quick
            test_balance_precheck_excludes_auth_cost;
        ] );
      ( "loop refunds",
        [
          Alcotest.test_case "G1_authority_exists_cap_binds" `Quick
            test_g1_authority_exists_cap_binds;
          Alcotest.test_case "G2_authority_absent_no_refund" `Quick
            test_g2_authority_absent_no_refund;
          Alcotest.test_case "G3_eip7623_floor_zeroes_the_refund" `Quick
            test_g3_eip7623_floor_zeroes_the_refund;
          Alcotest.test_case "G4_cap_boundary_pair" `Quick test_g4_cap_boundary_pair;
          Alcotest.test_case "G5_refund_and_designator_survive_REVERT" `Quick
            test_g5_refund_and_designator_survive_revert;
          Alcotest.test_case "G6_refund_and_designator_survive_HALT" `Quick
            test_g6_refund_and_designator_survive_halt;
          Alcotest.test_case "warmth_from_check4_is_priced" `Quick
            test_warmth_from_check4_is_priced;
        ] );
    ]
