(* EIP-7702 state-level executor tests, chunk 33. This stage covers the two
   validation rules the intrinsic stage lands: the empty-authorization-list
   guard and its observable POSITION in the error order
   ([validation.rs:191-204] before [validation.rs:210-254]), and the EIP-3607
   exemption for delegated senders ([pre_execution.rs:92-102]) — the
   consensus-critical line that keeps a delegated EOA able to transact at all —
   and, since the loop stage, the loop's own state effects: the disposition
   order, the check-4 warmth asymmetry, no-dedup, live nonces, the refund
   predicate, revocation and re-delegation, and the two rollback claims.

   test_executor.ml conventions; fixtures from eip7702_vectors.ml. *)

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

let receipt_class = function
  | Receipt.Success _ -> "success"
  | Receipt.Reverted _ -> "reverted"
  | Receipt.Halted _ -> "halted"

(* Two entries every one of which the loop will SKIP or apply refund-free: one
   chain-mismatched (2 against chain 1), one whose sentinel r/s cannot recover
   a real signer — and if recovery someday answered an address, that authority
   is fresh here and earns nothing, so the gas literal survives the loop
   stage either way. *)
let auth_chain2 =
  Authorization.sign
    (get (Authorization.make ~chain_id:(u 2) ~address:V.target_11s ~nonce:U256.zero))
    ~y_parity:U256.zero ~r:V.r_ones ~s:V.s_twos

let auth_sentinel =
  Authorization.sign
    (get (Authorization.make ~chain_id:(u 1) ~address:V.target_11s ~nonce:U256.zero))
    ~y_parity:U256.zero ~r:V.r_ones ~s:V.s_twos

let set_code_tx ~gas_limit ~max_priority ~max_fee ~authorizations =
  Transaction.set_code ~sender ~nonce:(nonce_of 0) ~gas_limit ~target ~value:U256.zero
    ~data:"" ~access_list:[] ~chain_id:(u 1) ~max_priority_fee_per_gas:max_priority
    ~max_fee_per_gas:max_fee ~authorizations

(* The empty list is the ONLY authorization rule that invalidates a whole
   transaction, and its position in the error order is observable in BOTH
   directions ([validation.rs:191-204]): the two fee checks run first, so a
   fee defect wins over an empty list; the gas guards run later, so an empty
   list wins over an over-the-limit intrinsic. Leg (e) is the other half of
   the rule: a list of entirely worthless entries is NOT empty, and no
   per-entry defect ever invalidates the transaction. *)
let test_empty_authorization_list_rejects_after_fee_checks () =
  let world = world_seed [ (sender, account ~nonce:0 ~balance:1_000_000_000) ] in
  let block = block_of ~coinbase ~basefee:3 in
  (* (a) well-formed fees, empty list. *)
  check_rejects "empty list with well-formed fees" Executor.Empty_authorization_list
    (Executor.execute world ~block
       (set_code_tx ~gas_limit:100000 ~max_priority:(u 0) ~max_fee:(u 10)
          ~authorizations:[]));
  (* (b) priority above max: the fee check precedes the empty-list guard. *)
  check_rejects "priority above max wins over the empty list"
    Executor.Priority_fee_above_max_fee
    (Executor.execute world ~block
       (set_code_tx ~gas_limit:100000 ~max_priority:(u 11) ~max_fee:(u 10)
          ~authorizations:[]));
  (* (c) max fee below the base fee of 3: the second fee check also precedes. *)
  check_rejects "max fee below base fee wins over the empty list"
    Executor.Gas_price_below_base_fee
    (Executor.execute world ~block
       (set_code_tx ~gas_limit:100000 ~max_priority:(u 0) ~max_fee:(u 1)
          ~authorizations:[]));
  (* (d) gas limit 20000 is below even the bare 21000 intrinsic, but the
     empty-list guard fires first: it precedes the gas guards. *)
  check_rejects "the empty list wins over the intrinsic guard"
    Executor.Empty_authorization_list
    (Executor.execute world ~block
       (set_code_tx ~gas_limit:20000 ~max_priority:(u 0) ~max_fee:(u 10)
          ~authorizations:[]));
  (* (e) a non-empty list of worthless entries is accepted and executes
     normally: intrinsic = 21000 + 2*25000 = 71000, the codeless target frame
     succeeds, and no per-entry defect invalidates anything. *)
  let receipt, _ =
    exec_ok world ~block
      (set_code_tx ~gas_limit:100000 ~max_priority:(u 0) ~max_fee:(u 10)
         ~authorizations:[ auth_chain2; auth_sentinel ])
  in
  Alcotest.(check string) "worthless entries still execute" "success"
    (receipt_class receipt);
  Alcotest.(check int) "and are each charged in the intrinsic" 71000
    (Receipt.gas_used receipt)

(* EIP-3607 with the EIP-7702 exemption, all four classification arms
   ([pre_execution.rs:92-102]: [!is_empty && !is_eip7702]). Leg (a) is the
   consensus-critical one: under the old [code_length > 0] check a delegated
   sender is rejected, and since the only way to shed a designator is to send
   a revoking transaction, the account would be bricked FOREVER. Legs (d) and
   (e) pin the classification boundary: 0xEF alone is not the magic (two
   bytes decide), and a magic-prefixed blob of the wrong length is
   [Undecodable], which blocks — the documented conservative divergence. *)
let test_eip3607_exempts_delegated_sender () =
  let block = block_of ~coinbase ~basefee:3 in
  let legacy_tx =
    Transaction.make ~sender ~nonce:(nonce_of 0) ~gas_limit:50000
      ~kind:(Transaction.Call target) ~value:U256.zero ~data:"" ~access_list:[]
      ~chain_id:(Some (u 1)) ~fee:(Transaction.Legacy { gas_price = u 10 })
  in
  let world_with_code code =
    world_seed
      [ (sender, Account.with_code (account ~nonce:0 ~balance:1_000_000_000) code) ]
  in
  (* (a) a delegated sender (ef0100 || 0x11*20) originates a legacy tx: Ok. *)
  let receipt, _ = exec_ok (world_with_code V.designator_11s) ~block legacy_tx in
  Alcotest.(check string) "a delegated sender executes" "success" (receipt_class receipt);
  Alcotest.(check int) "at the plain-transfer price" 21000 (Receipt.gas_used receipt);
  (* (b) genuine code (PUSH1 0x01) still rejects. *)
  check_rejects "genuine code rejects" Executor.Sender_has_code
    (Executor.execute (world_with_code "\x60\x01") ~block legacy_tx);
  (* (c) a codeless sender was never in question. *)
  let receipt_c, _ =
    exec_ok (world_seed [ (sender, account ~nonce:0 ~balance:1_000_000_000) ]) ~block
      legacy_tx
  in
  Alcotest.(check string) "a codeless sender executes" "success" (receipt_class receipt_c);
  (* (d) 0xEF alone is not the magic: ef02 || 21 bytes classifies Contract. *)
  check_rejects "ef02-prefixed code rejects" Executor.Sender_has_code
    (Executor.execute (world_with_code ("\xef\x02" ^ String.make 21 '\x11')) ~block
       legacy_tx);
  (* (e) the right magic at the wrong length (22 bytes) is Undecodable, which
     blocks: the conservative direction for bytes we cannot classify. *)
  check_rejects "a malformed ef01 blob rejects" Executor.Sender_has_code
    (Executor.execute (world_with_code ("\xef\x01" ^ String.make 20 '\x11')) ~block
       legacy_tx)

(* ---------------------------------------------------------------- *)
(* The authorization loop (chunk 33, stage 4)                        *)
(* ---------------------------------------------------------------- *)

(* The key-0 oracle entry (chain 1, delegate 0x11*20, nonce 0), the one entry
   that both screens AND applies; here — unlike the tests above — the worlds
   often DO seed [V.authority_key0], because the refund predicate is exactly
   what is under test. *)
let auth_key0 =
  Authorization.sign
    (get (Authorization.make ~chain_id:(u 1) ~address:V.target_11s ~nonce:U256.zero))
    ~y_parity:(u V.auth_key0_y_parity) ~r:V.auth_key0_r ~s:V.auth_key0_s

(* An entry whose [r] is zero: recovery cannot answer, so check 3 skips it —
   the same [continue] as a bad parity or a high [s]. *)
let auth_r_zero =
  Authorization.sign
    (get (Authorization.make ~chain_id:(u 1) ~address:V.target_11s ~nonce:U256.zero))
    ~y_parity:U256.zero ~r:U256.zero ~s:V.s_twos

(* A minted vector (eip7702_vectors.ml) as a signed authorization. *)
let signed_of (m : V.minted) =
  Authorization.sign
    (get (Authorization.make ~chain_id:m.V.m_chain ~address:m.V.m_address ~nonce:m.V.m_nonce))
    ~y_parity:(u m.V.m_parity) ~r:m.V.m_r ~s:m.V.m_s

let apply_on world entries = Auth_list.apply ~world ~chain_id:(u 1) entries
let disps t = List.map Auth_list.disposition_to_string (Auth_list.dispositions t)

let warmed_hex t =
  List.map (fun a -> V.to_hex (Units.Address.to_bytes a)) (Auth_list.warmed t)

let check_disps name expected t = Alcotest.(check (list string)) name expected (disps t)

let check_warmed name expected t =
  Alcotest.(check (list string)) name expected (warmed_hex t)

let code_at w address = Account.code (World_state.account w address)
let nonce_at w address = Nonce.to_int (World_state.nonce w address)

let present w address =
  List.exists (fun (a, _) -> Units.Address.equal a address) (World_state.accounts w)

(* Genuine contract code for check-5 worlds: PUSH1 0x01, truncated on purpose —
   content is irrelevant, only the classification [Contract] is. *)
let contract_code = V.hex "6001"

let with_contract_code = Account.with_code (account ~nonce:0 ~balance:1) contract_code

(* THE order test: an entry failing two checks at once reports the EARLIER one,
   read directly off the dispositions rather than inferred from state
   ([pre_execution.rs:217-259] is one straight-line sequence of early
   [continue]s, so the first failing check is the one that names the entry). *)
let test_auth_check_order_pinned () =
  (* (a) chain mismatch (2 vs 1) AND saturated nonce: check 1 wins. *)
  let a =
    apply_on World_state.empty
      [
        Authorization.sign
          (get
             (Authorization.make ~chain_id:(u 2) ~address:V.target_11s
                ~nonce:V.nonce_u64_max))
          ~y_parity:U256.zero ~r:V.r_ones ~s:V.s_twos;
      ]
  in
  check_disps "chain mismatch wins over saturation" [ "chain_id_mismatch" ] a;
  check_warmed "and warms nothing" [] a;
  (* (b) saturated nonce AND r = 0: check 2 wins, before recovery could fail. *)
  let b =
    apply_on World_state.empty
      [
        Authorization.sign
          (get
             (Authorization.make ~chain_id:(u 1) ~address:V.target_11s
                ~nonce:V.nonce_u64_max))
          ~y_parity:U256.zero ~r:U256.zero ~s:V.s_twos;
      ]
  in
  check_disps "saturation wins over unrecoverability" [ "nonce_saturated" ] b;
  check_warmed "still nothing warmed" [] b;
  (* (c) r = 0 AND a code-bearing account in the world: check 3 wins — with no
     recovered authority there is nobody to run check 5 against. *)
  let world_coded = world_seed [ (V.authority_key0, with_contract_code) ] in
  let c = apply_on world_coded [ auth_r_zero ] in
  check_disps "unrecoverability wins over has_code" [ "unrecoverable" ] c;
  check_warmed "recovery never ran, so nothing warmed" [] c;
  (* (d) the authority holds contract code AND the auth nonce (7) is wrong:
     check 5 wins over check 6. *)
  let d = apply_on world_coded [ signed_of V.k0_d1_n7 ] in
  check_disps "has_code wins over nonce_mismatch" [ "has_code" ] d;
  (* (e) every check passes. *)
  let e =
    apply_on (world_seed [ (V.authority_key0, account ~nonce:0 ~balance:1) ]) [ auth_key0 ]
  in
  check_disps "all checks pass" [ "applied:refunded" ] e

(* Check 4 warms UNCONDITIONALLY, before checks 5 and 6
   ([pre_execution.rs:234-237] precedes [:239-250]): an entry those checks then
   skip leaves its authority warm, and neither skip bumps a nonce. *)
let test_skipped_at_5_or_6_leaves_authority_warm () =
  (* Skipped at check 5: the authority holds genuine code. *)
  let five = apply_on (world_seed [ (V.authority_key0, with_contract_code) ]) [ auth_key0 ] in
  check_disps "code blocks the entry" [ "has_code" ] five;
  check_warmed "but the authority is already warm" [ V.authority_key0_hex ] five;
  Alcotest.(check string) "the code is untouched" contract_code
    (code_at (Auth_list.world five) V.authority_key0);
  Alcotest.(check int) "and no nonce was bumped" 0
    (nonce_at (Auth_list.world five) V.authority_key0);
  (* Skipped at check 6: codeless authority at nonce 0, authorization nonce 7. *)
  let six =
    apply_on
      (world_seed [ (V.authority_key0, account ~nonce:0 ~balance:1) ])
      [ signed_of V.k0_d1_n7 ]
  in
  check_disps "the nonce blocks the entry" [ "nonce_mismatch" ] six;
  check_warmed "warm here too" [ V.authority_key0_hex ] six;
  Alcotest.(check int) "no bump on a nonce mismatch" 0
    (nonce_at (Auth_list.world six) V.authority_key0)

(* Checks 1-3 produce ZERO state effects: nothing is warmed, nothing bumped.
   [V.k0_d1_sat] is a GENUINE key-0 signature over the saturated-nonce tuple
   (the mint pipeline is pinned in eip7702_vectors.ml), so the authority that
   is NOT warmed here is provably [V.authority_key0] and not a hypothetical.
   The chain-mismatch leg carries its proof in-tree: the SAME entry applied
   under its own chain id recovers and delegates key 0's account. *)
let test_skipped_at_1_2_or_3_warms_nothing () =
  let seeded = world_seed [ (V.authority_key0, account ~nonce:0 ~balance:1) ] in
  let sat = apply_on seeded [ signed_of V.k0_d1_sat ] in
  check_disps "saturated nonce skips" [ "nonce_saturated" ] sat;
  check_warmed "and warms nothing" [] sat;
  Alcotest.(check bool) "in particular not key 0" false
    (List.exists (Units.Address.equal V.authority_key0) (Auth_list.warmed sat));
  let mism = apply_on seeded [ signed_of V.k0_chain2 ] in
  check_disps "chain 2 against chain 1 skips" [ "chain_id_mismatch" ] mism;
  check_warmed "nothing warmed" [] mism;
  (* The same chain-2 entry under a chain-2 loop recovers key 0 and applies:
     the signature was real all along, and only the chain test skipped it. *)
  let native = Auth_list.apply ~world:seeded ~chain_id:(u 2) [ signed_of V.k0_chain2 ] in
  check_disps "the same entry applies on its own chain" [ "applied:refunded" ] native;
  check_warmed "and it was key 0's signature" [ V.authority_key0_hex ] native;
  let unrec = apply_on seeded [ auth_r_zero ] in
  check_disps "r = 0 skips at recovery" [ "unrecoverable" ] unrec;
  check_warmed "with no state effect" [] unrec

(* No deduplication ([pre_execution.rs:216]): a repeated authority is
   re-checked against its ALREADY-BUMPED nonce, delegated again, bumped again —
   and the refund is decided PER ENTRY, so the two legs differ. A dedup
   implementation reports one disposition, one delegate and half the pot. *)
let test_no_dedup_repeated_authority () =
  let entries = [ auth_key0; signed_of V.k0_d2_n1 ] in
  (* Leg 1: the authority pre-exists, so BOTH entries earn the 12500. *)
  let existing =
    apply_on (world_seed [ (V.authority_key0, account ~nonce:0 ~balance:1) ]) entries
  in
  check_disps "both apply, both refunded"
    [ "applied:refunded"; "applied:refunded" ]
    existing;
  Alcotest.(check int) "two qualifying entries pot 25000" 25000 (Auth_list.refund existing);
  Alcotest.(check string) "the SECOND delegate wins" V.designator_22s_hex
    (V.to_hex (code_at (Auth_list.world existing) V.authority_key0));
  Alcotest.(check int) "two bumps" 2 (nonce_at (Auth_list.world existing) V.authority_key0);
  check_warmed "warmed once per entry"
    [ V.authority_key0_hex; V.authority_key0_hex ]
    existing;
  (* Leg 2: a FRESH authority. Entry 1 finds it absent (no refund); entry 2
     finds it at nonce 1 bearing a designator — existing, so refunded. *)
  let fresh = apply_on World_state.empty entries in
  check_disps "fresh then existing" [ "applied:fresh"; "applied:refunded" ] fresh;
  Alcotest.(check int) "only the second qualifies" 12500 (Auth_list.refund fresh);
  Alcotest.(check string) "the second delegate wins here too" V.designator_22s_hex
    (V.to_hex (code_at (Auth_list.world fresh) V.authority_key0));
  Alcotest.(check int) "two bumps from zero" 2
    (nonce_at (Auth_list.world fresh) V.authority_key0)

(* Check 6 compares the LIVE threaded nonce, not the pre-transaction one
   ([pre_execution.rs:247-250]): two entries both at nonce 0 cannot both
   apply, because the first bump moves the target. *)
let test_live_nonce_not_db_nonce () =
  let t =
    apply_on
      (world_seed [ (V.authority_key0, account ~nonce:0 ~balance:1) ])
      [ auth_key0; signed_of V.k0_d2_n0 ]
  in
  check_disps "the second nonce-0 entry misses" [ "applied:refunded"; "nonce_mismatch" ] t;
  Alcotest.(check int) "one refund only" 12500 (Auth_list.refund t);
  Alcotest.(check string) "the FIRST delegate stands" V.designator_11s_hex
    (V.to_hex (code_at (Auth_list.world t) V.authority_key0));
  Alcotest.(check int) "one bump" 1 (nonce_at (Auth_list.world t) V.authority_key0)

(* The caller's own nonce bump lands BEFORE the loop ([handler.rs:179-185],
   [pre_execution.rs:171-177]), so a self-authorizing sender signs
   tx.nonce + 1 and finishes at tx.nonce + 2; signing tx.nonce itself is the
   classic off-by-one and skips. Executor-level, because the ordering under
   test is the executor's. No receipt class is asserted on leg (a): the frame
   then CALLS the freshly delegated account, whose designator does not resolve
   until the next stage — the world claims below hold either way, which is the
   point: delegation happened in pre-execution, not in the frame. *)
let test_self_sponsored_needs_nonce_plus_one () =
  let s1 = V.sender_key1 in
  let world = world_seed [ (s1, account ~nonce:5 ~balance:1_000_000_000) ] in
  let block = block_of ~coinbase ~basefee:3 in
  let tx entry =
    Transaction.set_code ~sender:s1 ~nonce:(nonce_of 5) ~gas_limit:100000 ~target:s1
      ~value:U256.zero ~data:"" ~access_list:[] ~chain_id:(u 1)
      ~max_priority_fee_per_gas:(u 0) ~max_fee_per_gas:(u 10)
      ~authorizations:[ entry ]
  in
  (* (a) auth nonce 6 = tx.nonce + 1: applies; the account ends at 7. *)
  let _receipt_a, world_a = exec_ok world ~block (tx (signed_of V.k1_d1_n6)) in
  Alcotest.(check int) "bumped by the caller AND the loop" 7 (nonce_at world_a s1);
  Alcotest.(check string) "and delegated" V.designator_11s_hex
    (V.to_hex (code_at world_a s1));
  (* (b) auth nonce 5 = tx.nonce: by loop time the account is at 6; skip. *)
  let _receipt_b, world_b = exec_ok world ~block (tx (signed_of V.k1_d1_n5)) in
  Alcotest.(check int) "only the caller's bump" 6 (nonce_at world_b s1);
  Alcotest.(check string) "no delegation" "" (code_at world_b s1)

(* Check 7 is [not (Account.is_absent acct)], evaluated BEFORE the designator
   is installed ([pre_execution.rs:252-259]). Leg (c) is the port's documented
   divergent class (account.mli): storage-only, [is_empty] TRUE yet
   [is_absent] FALSE — a predicate written as [not is_empty] reports 0 there,
   and one evaluated after the write reports 12500 on leg (a). *)
let test_refund_predicate_absent_vs_existing_vs_storage_only () =
  let absent = apply_on World_state.empty [ auth_key0 ] in
  check_disps "absent authority: applied, unrefunded" [ "applied:fresh" ] absent;
  Alcotest.(check int) "pot 0" 0 (Auth_list.refund absent);
  let existing =
    apply_on (world_seed [ (V.authority_key0, account ~nonce:0 ~balance:1) ]) [ auth_key0 ]
  in
  check_disps "existing authority: refunded" [ "applied:refunded" ] existing;
  Alcotest.(check int) "pot 12500" 12500 (Auth_list.refund existing);
  let storage_only =
    apply_on
      (world_seed
         [ (V.authority_key0, Account.set_slot Account.empty (u 1) (u 7)) ])
      [ auth_key0 ]
  in
  check_disps "storage-only authority: refunded" [ "applied:refunded" ] storage_only;
  Alcotest.(check int) "pot 12500 on the divergent class" 12500
    (Auth_list.refund storage_only)

(* A delegation to the zero address stores EMPTY code with KECCAK_EMPTY —
   never a zero-pointing designator — and still bumps, and the bump is what
   keeps the account alive forever after ([account.rs:392-400] via
   {!Account.delegate}; nonce >= 1 alone defeats [is_empty]). EXTCODESIZE /
   EXTCODEHASH / EXTCODECOPY read exactly the code and hash asserted here, so
   an empty string and KECCAK_EMPTY are what they will report. *)
let test_zero_address_revocation () =
  let delegated =
    world_seed
      [
        ( V.authority_key0,
          Account.with_code (account ~nonce:3 ~balance:1) V.designator_11s );
      ]
  in
  let revoked = apply_on delegated [ signed_of V.k0_rev_n3 ] in
  check_disps "the revocation applies" [ "applied:refunded" ] revoked;
  let w = Auth_list.world revoked in
  Alcotest.(check int) "empty code, not a zero designator" 0
    (Account.code_length (World_state.account w V.authority_key0));
  Alcotest.(check bool) "and KECCAK_EMPTY, not the zero word" true
    (Tn_keccak.equal
       (Account.code_hash (World_state.account w V.authority_key0))
       Tn_keccak.empty);
  Alcotest.(check int) "the revocation still bumps" 4 (nonce_at w V.authority_key0);
  Alcotest.(check bool) "and the entry survives in the world" true
    (present w V.authority_key0);
  (* A revoked authority is codeless again, so a FURTHER authorization passes
     check 5 and re-delegates it. *)
  let again = apply_on w [ signed_of V.k0_d1_n4 ] in
  check_disps "re-delegation after revocation" [ "applied:refunded" ] again;
  Alcotest.(check string) "the new designator lands" V.designator_11s_hex
    (V.to_hex (code_at (Auth_list.world again) V.authority_key0));
  (* Revoking a NONEXISTENT authority still applies and leaves a permanent
     nonce-1 codeless entry behind: creation by revocation. *)
  let ex_nihilo = apply_on World_state.empty [ signed_of V.k2_rev_n0 ] in
  check_disps "revoking nobody still applies" [ "applied:fresh" ] ex_nihilo;
  Alcotest.(check int) "a nonce-1 entry appears" 1
    (nonce_at (Auth_list.world ex_nihilo) V.authority_key2);
  Alcotest.(check int) "with no code" 0
    (Account.code_length (World_state.account (Auth_list.world ex_nihilo) V.authority_key2));
  Alcotest.(check bool) "and it persists" true
    (present (Auth_list.world ex_nihilo) V.authority_key2)

(* Check 5 blocks only GENUINE contract code ([pre_execution.rs:239-245]:
   [!is_empty && !is_eip7702]): an already-delegated authority is re-delegated
   and simply overwritten, self-delegation included. A check written as
   [code_length > 0] or [code_hash <> KECCAK_EMPTY] skips both. *)
let test_redelegation_overwrites () =
  let delegated =
    world_seed
      [
        ( V.authority_key0,
          Account.with_code (account ~nonce:3 ~balance:1) V.designator_11s );
      ]
  in
  let over = apply_on delegated [ signed_of V.k0_d2_n3 ] in
  check_disps "an existing designator does not block" [ "applied:refunded" ] over;
  Alcotest.(check string) "and is overwritten" V.designator_22s_hex
    (V.to_hex (code_at (Auth_list.world over) V.authority_key0));
  Alcotest.(check int) "with the usual bump" 4
    (nonce_at (Auth_list.world over) V.authority_key0);
  let self = apply_on delegated [ signed_of V.k0_self_n3 ] in
  check_disps "self-delegation is allowed" [ "applied:refunded" ] self;
  Alcotest.(check string) "and stores the authority's own address"
    V.designator_self_key0_hex
    (V.to_hex (code_at (Auth_list.world self) V.authority_key0))

(* The loop CANNOT invalidate the transaction ([pre_execution.rs:214-266]
   constructs no error): a type-4 transaction whose every authorization is
   skipped still EXECUTES and still pays 25000 per listed entry. *)
let test_loop_never_rejects_the_transaction () =
  let world = world_seed [ (sender, account ~nonce:0 ~balance:1_000_000_000) ] in
  let block = block_of ~coinbase ~basefee:3 in
  let receipt, world_after =
    exec_ok world ~block
      (set_code_tx ~gas_limit:46000 ~max_priority:(u 0) ~max_fee:(u 10)
         ~authorizations:[ auth_r_zero ])
  in
  Alcotest.(check string) "a worthless entry still executes" "success"
    (receipt_class receipt);
  Alcotest.(check int) "at the full 21000 + 25000, no refund" 46000
    (Receipt.gas_used receipt);
  Alcotest.(check bool) "no account anywhere gained code" true
    (List.for_all
       (fun (_, acct) -> Account.code_length acct = 0)
       (World_state.accounts world_after))

(* The ONE rollback scope is whole-transaction rejection: a rejected type-4
   transaction leaves the world exactly as it was — no designator, no bumps,
   no warming. In this port the claim is structural (worlds are persistent
   values and the [Error] arm returns none), and the equality below pins it
   against a future executor that mutates in place or returns a half-applied
   world on the error path. *)
let test_rejection_undoes_everything () =
  let world = world_seed [ (sender, account ~nonce:0 ~balance:1_000_000_000) ] in
  let block = block_of ~coinbase ~basefee:3 in
  let before = world in
  check_rejects "a nonce mismatch rejects the whole transaction"
    (Executor.Nonce_mismatch { expected = nonce_of 0; actual = nonce_of 1 })
    (Executor.execute world ~block
       (Transaction.set_code ~sender ~nonce:(nonce_of 1) ~gas_limit:100000 ~target
          ~value:U256.zero ~data:"" ~access_list:[] ~chain_id:(u 1)
          ~max_priority_fee_per_gas:(u 0) ~max_fee_per_gas:(u 10)
          ~authorizations:[ auth_key0 ]));
  Alcotest.(check bool) "and the world is byte-identical" true
    (World_state.equal before world)

let () =
  Alcotest.run "eip7702 state"
    [
      ( "validation",
        [
          Alcotest.test_case "the empty list rejects, after the fee checks" `Quick
            test_empty_authorization_list_rejects_after_fee_checks;
          Alcotest.test_case "EIP-3607 exempts a delegated sender" `Quick
            test_eip3607_exempts_delegated_sender;
        ] );
      ( "loop",
        [
          Alcotest.test_case "auth_check_order_pinned" `Quick test_auth_check_order_pinned;
          Alcotest.test_case "skipped_at_5_or_6_leaves_authority_warm" `Quick
            test_skipped_at_5_or_6_leaves_authority_warm;
          Alcotest.test_case "skipped_at_1_2_or_3_warms_nothing" `Quick
            test_skipped_at_1_2_or_3_warms_nothing;
          Alcotest.test_case "no_dedup_repeated_authority" `Quick
            test_no_dedup_repeated_authority;
          Alcotest.test_case "live_nonce_not_db_nonce" `Quick test_live_nonce_not_db_nonce;
          Alcotest.test_case "self_sponsored_needs_nonce_plus_one" `Quick
            test_self_sponsored_needs_nonce_plus_one;
          Alcotest.test_case "refund_predicate_absent_vs_existing_vs_storage_only" `Quick
            test_refund_predicate_absent_vs_existing_vs_storage_only;
          Alcotest.test_case "zero_address_revocation" `Quick test_zero_address_revocation;
          Alcotest.test_case "redelegation_overwrites" `Quick test_redelegation_overwrites;
          Alcotest.test_case "loop_never_rejects_the_transaction" `Quick
            test_loop_never_rejects_the_transaction;
          Alcotest.test_case "rejection_undoes_everything" `Quick
            test_rejection_undoes_everything;
        ] );
    ]
