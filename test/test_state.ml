(* Tests for the execution-state foundation: the 256-bit word, the account, the
   world state and the value-transfer state transition. These are pure unit and
   golden-vector checks — the state core does no IO and is not yet wired into the
   running slice (that waits on batch payloads, which are networking-deferred), so
   it is exercised directly here against known byte layouts and hand-computed
   state transitions. *)

open Tn_types
module U256 = Tn_state.U256
module Nonce = Tn_state.Nonce
module Account = Tn_state.Account
module World_state = Tn_state.World_state
module Transfer = Tn_state.Transfer

let get = function Some x -> x | None -> Alcotest.fail "expected Some"
let u n = get (U256.of_int n)
let hex s = get (U256.of_hex s)
let addr c = get (Units.Address.of_bytes (String.make Units.Address.length c))

let zeros = String.make 64 '0'
let ffs = String.make 64 'f'

(* ---------- U256: the 256-bit word ---------- *)

(* The distinguished constants render to the byte layouts they must. *)
let test_u256_constants () =
  Alcotest.(check string) "zero is 64 hex zeros" zeros (U256.to_hex U256.zero);
  Alcotest.(check string) "max is 64 hex f's" ffs (U256.to_hex U256.max_value);
  Alcotest.(check string) "one is a single low bit"
    (String.sub zeros 0 63 ^ "1")
    (U256.to_hex U256.one);
  Alcotest.(check bool) "zero is zero" true (U256.is_zero U256.zero);
  Alcotest.(check bool) "one is not zero" false (U256.is_zero U256.one);
  Alcotest.(check int) "encoding is 32 bytes" 32
    (String.length (U256.to_be_bytes U256.zero))

(* Small integers land in the low bytes, big-endian, matching [to_le_bytes]'s
   mirror: 256 = 0x0100 in the two least-significant bytes. *)
let test_u256_of_int () =
  Alcotest.(check string) "of_int 0 is zero" zeros (U256.to_hex (u 0));
  Alcotest.(check string) "of_int 1 is one"
    (U256.to_hex U256.one) (U256.to_hex (u 1));
  Alcotest.(check string) "of_int 255 is 0xff"
    (String.sub zeros 0 62 ^ "ff")
    (U256.to_hex (u 255));
  Alcotest.(check string) "of_int 256 is 0x0100"
    (String.sub zeros 0 60 ^ "0100")
    (U256.to_hex (u 256));
  Alcotest.(check bool) "of_int rejects negatives" true
    (Option.is_none (U256.of_int (-1)))

(* The byte and hex codecs round-trip and reject malformed input. *)
let test_u256_codec () =
  let sample = hex "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" in
  Alcotest.(check string) "hex round-trips"
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    (U256.to_hex sample);
  Alcotest.(check bool) "be-bytes round-trips" true
    (U256.equal sample (get (U256.of_be_bytes (U256.to_be_bytes sample))));
  Alcotest.(check bool) "of_be_bytes rejects a short input" true
    (Option.is_none (U256.of_be_bytes (String.make 31 '\000')));
  Alcotest.(check bool) "of_hex rejects a short input" true
    (Option.is_none (U256.of_hex "00"));
  Alcotest.(check bool) "of_hex rejects a non-hex digit" true
    (Option.is_none (U256.of_hex (String.make 63 '0' ^ "g")))

(* Wrapping and checked addition agree below overflow and part at it. *)
let test_u256_add () =
  Alcotest.(check string) "1 + 2 = 3"
    (U256.to_hex (u 3))
    (U256.to_hex (U256.add (u 1) (u 2)));
  Alcotest.(check bool) "checked 1 + 2 = Some 3" true
    (Option.equal U256.equal (U256.checked_add (u 1) (u 2)) (Some (u 3)));
  (* 0xff + 1 crosses a byte boundary: carry propagates to 0x0100. *)
  Alcotest.(check string) "byte carry propagates"
    (U256.to_hex (u 256))
    (U256.to_hex (U256.add (u 255) U256.one));
  (* max + 1 wraps to zero; the checked form reports the overflow. *)
  Alcotest.(check string) "max + 1 wraps to zero" zeros
    (U256.to_hex (U256.add U256.max_value U256.one));
  Alcotest.(check bool) "checked max + 1 overflows" true
    (Option.is_none (U256.checked_add U256.max_value U256.one))

(* Wrapping and checked subtraction agree above underflow and part at it. *)
let test_u256_sub () =
  Alcotest.(check string) "5 - 3 = 2"
    (U256.to_hex (u 2))
    (U256.to_hex (U256.sub (u 5) (u 3)));
  Alcotest.(check bool) "checked 5 - 3 = Some 2" true
    (Option.equal U256.equal (U256.checked_sub (u 5) (u 3)) (Some (u 2)));
  (* 0 - 1 wraps to max; the checked form reports the underflow. *)
  Alcotest.(check string) "0 - 1 wraps to max" ffs
    (U256.to_hex (U256.sub U256.zero U256.one));
  Alcotest.(check bool) "checked 0 - 1 underflows" true
    (Option.is_none (U256.checked_sub U256.zero U256.one));
  (* Borrow across a byte boundary: 0x0100 - 1 = 0xff. *)
  Alcotest.(check string) "byte borrow propagates"
    (U256.to_hex (u 255))
    (U256.to_hex (U256.sub (u 256) U256.one))

(* Ordering is unsigned: a value with the top bit set is the largest, not
   negative as a signed reading would make it. *)
let test_u256_compare () =
  Alcotest.(check bool) "zero < one" true (U256.compare U256.zero U256.one < 0);
  Alcotest.(check bool) "one < max" true (U256.compare U256.one U256.max_value < 0);
  let top_bit = hex ("8" ^ String.make 63 '0') in
  Alcotest.(check bool) "top-bit value exceeds one (unsigned)" true
    (U256.compare top_bit U256.one > 0);
  Alcotest.(check int) "equal values compare equal" 0 (U256.compare (u 42) (u 42));
  (* [equal] must discriminate — guards every equal-based assertion below against
     an [equal] that degenerated to always-true. *)
  Alcotest.(check bool) "distinct values are unequal" false (U256.equal (u 1) (u 2))

(* ---------- Nonce ---------- *)

let test_nonce () =
  Alcotest.(check int) "fresh nonce is zero" 0 (Nonce.to_int Nonce.zero);
  Alcotest.(check int) "succ advances by one" 1 (Nonce.to_int (Nonce.succ Nonce.zero));
  Alcotest.(check bool) "equal nonces are equal" true
    (Nonce.equal (Nonce.succ Nonce.zero) (get (Nonce.of_int 1)));
  Alcotest.(check bool) "of_int rejects negatives" true
    (Option.is_none (Nonce.of_int (-1)));
  (* succ saturates rather than wrap to a negative nonce. *)
  let max_nonce = get (Nonce.of_int max_int) in
  Alcotest.(check bool) "succ saturates at the maximum" true
    (Nonce.equal (Nonce.succ max_nonce) max_nonce)

(* ---------- Account ---------- *)

let test_account () =
  Alcotest.(check bool) "empty is empty" true (Account.is_empty Account.empty);
  Alcotest.(check bool) "a funded account is not empty" false
    (Account.is_empty (Account.make ~nonce:Nonce.zero ~balance:(u 1)));
  Alcotest.(check bool) "a nonced account is not empty" false
    (Account.is_empty
       (Account.make ~nonce:(get (Nonce.of_int 1)) ~balance:U256.zero));
  let a = Account.make ~nonce:Nonce.zero ~balance:(u 100) in
  Alcotest.(check bool) "credit adds to the balance" true
    (U256.equal (Account.balance (get (Account.credit a (u 50)))) (u 150));
  Alcotest.(check bool) "debit subtracts from the balance" true
    (U256.equal (Account.balance (get (Account.debit a (u 40)))) (u 60));
  (* The [balance >= value] boundary: an exact-balance debit succeeds and empties
     the account (a strict-[>] regression of the guard would fail here). *)
  Alcotest.(check bool) "debit of the whole balance succeeds" true
    (U256.equal (Account.balance (get (Account.debit a (u 100)))) U256.zero);
  Alcotest.(check bool) "debit past the balance fails" true
    (Option.is_none (Account.debit a (u 101)));
  Alcotest.(check bool) "credit past 2^256 fails" true
    (Option.is_none
       (Account.credit (Account.make ~nonce:Nonce.zero ~balance:U256.max_value) (u 1)));
  Alcotest.(check int) "increment_nonce advances the nonce" 1
    (Nonce.to_int (Account.nonce (Account.increment_nonce a)))

(* ---------- World_state ---------- *)

let test_world_state () =
  let a = addr '\001' and b = addr '\002' in
  Alcotest.(check bool) "an absent account reads empty" true
    (Account.is_empty (World_state.account World_state.empty a));
  let st = World_state.of_alloc [ (a, u 100); (b, u 250) ] in
  Alcotest.(check bool) "alloc funds an address" true
    (U256.equal (World_state.balance st a) (u 100));
  Alcotest.(check int) "alloc leaves the nonce at zero" 0
    (Nonce.to_int (World_state.nonce st b));
  Alcotest.(check int) "alloc stored both accounts" 2
    (List.length (World_state.accounts st));
  (* Setting an account empty removes its entry (EIP-161 canonicalisation). *)
  let st_removed = World_state.set_account st a Account.empty in
  Alcotest.(check int) "setting empty removes the entry" 1
    (List.length (World_state.accounts st_removed));
  Alcotest.(check bool) "a zero allocation stores no entry" true
    (World_state.equal (World_state.of_alloc [ (a, U256.zero) ]) World_state.empty);
  (* accounts is in ascending address order. *)
  let keys = List.map (fun (k, _) -> Units.Address.to_bytes k) (World_state.accounts st) in
  Alcotest.(check (list string)) "accounts are in ascending address order"
    (List.sort String.compare keys) keys;
  (* A later allocation for the same address wins. *)
  let st_dup = World_state.of_alloc [ (a, u 1); (a, u 9) ] in
  Alcotest.(check bool) "a repeated alloc takes the last" true
    (U256.equal (World_state.balance st_dup a) (u 9));
  (* [equal] must discriminate on a differing balance at a shared key — guards the
     determinism check and the empty-alloc check against an always-true [equal]. *)
  Alcotest.(check bool) "a differing balance makes states unequal" false
    (World_state.equal st (World_state.of_alloc [ (a, u 100); (b, u 999) ]))

(* ---------- Transfer: the state transition ---------- *)

let ok_state = function
  | Ok st -> st
  | Error e -> Alcotest.failf "expected Ok, got %s" (Transfer.error_to_string e)

let test_transfer_happy () =
  let a = addr '\001' and b = addr '\002' in
  let st = World_state.of_alloc [ (a, u 100) ] in
  let tx = Transfer.make ~sender:a ~recipient:b ~value:(u 40) ~nonce:Nonce.zero in
  let st' = ok_state (Transfer.apply st tx) in
  Alcotest.(check bool) "sender debited" true (U256.equal (World_state.balance st' a) (u 60));
  Alcotest.(check bool) "recipient credited" true
    (U256.equal (World_state.balance st' b) (u 40));
  Alcotest.(check int) "sender nonce advanced" 1 (Nonce.to_int (World_state.nonce st' a));
  Alcotest.(check int) "recipient nonce untouched" 0 (Nonce.to_int (World_state.nonce st' b))

let test_transfer_nonce_mismatch () =
  let a = addr '\001' and b = addr '\002' in
  let st = World_state.of_alloc [ (a, u 100) ] in
  let tx = Transfer.make ~sender:a ~recipient:b ~value:(u 1) ~nonce:(get (Nonce.of_int 5)) in
  match Transfer.apply st tx with
  | Error (Transfer.Nonce_mismatch { expected; actual }) ->
      Alcotest.(check int) "expected is the account nonce" 0 (Nonce.to_int expected);
      Alcotest.(check int) "actual is the transfer nonce" 5 (Nonce.to_int actual)
  | Ok _ | Error (Transfer.Insufficient_balance _) | Error Transfer.Balance_overflow ->
      Alcotest.fail "expected Nonce_mismatch"

let test_transfer_insufficient () =
  let a = addr '\001' and b = addr '\002' in
  let st = World_state.of_alloc [ (a, u 100) ] in
  let tx = Transfer.make ~sender:a ~recipient:b ~value:(u 200) ~nonce:Nonce.zero in
  (match Transfer.apply st tx with
  | Error (Transfer.Insufficient_balance { balance; value }) ->
      Alcotest.(check bool) "reports the sender balance" true (U256.equal balance (u 100));
      Alcotest.(check bool) "reports the shortfall value" true (U256.equal value (u 200))
  | Ok _ | Error (Transfer.Nonce_mismatch _) | Error Transfer.Balance_overflow ->
      Alcotest.fail "expected Insufficient_balance");
  Alcotest.(check bool) "the balance is unchanged on failure" true
    (U256.equal (World_state.balance st a) (u 100))

(* The [balance >= value] boundary at the transfer level: spending the whole
   balance succeeds, empties the sender and still advances the nonce. *)
let test_transfer_exact_spend () =
  let a = addr '\001' and b = addr '\002' in
  let st = World_state.of_alloc [ (a, u 100) ] in
  let tx = Transfer.make ~sender:a ~recipient:b ~value:(u 100) ~nonce:Nonce.zero in
  let st' = ok_state (Transfer.apply st tx) in
  Alcotest.(check bool) "exact-spend empties the sender" true
    (U256.equal (World_state.balance st' a) U256.zero);
  Alcotest.(check bool) "exact-spend credits the whole value" true
    (U256.equal (World_state.balance st' b) (u 100));
  Alcotest.(check int) "exact-spend still advances the nonce" 1
    (Nonce.to_int (World_state.nonce st' a))

(* A self-transfer nets the balance to zero change but still advances the nonce:
   the recipient credit reads the already-debited sender account. *)
let test_transfer_self () =
  let a = addr '\001' in
  let st = World_state.of_alloc [ (a, u 100) ] in
  let tx = Transfer.make ~sender:a ~recipient:a ~value:(u 30) ~nonce:Nonce.zero in
  let st' = ok_state (Transfer.apply st tx) in
  Alcotest.(check bool) "self-transfer balance unchanged" true
    (U256.equal (World_state.balance st' a) (u 100));
  Alcotest.(check int) "self-transfer nonce advanced" 1 (Nonce.to_int (World_state.nonce st' a))

(* Crediting a recipient already holding the maximum balance overflows. At this
   pure-transfer layer the whole transfer reverts (the sender is not debited); the
   reth included-and-failed nonce advance is deferred to the gas / block-execution
   chunk (see transfer.mli). *)
let test_transfer_overflow () =
  let a = addr '\001' and b = addr '\002' in
  let st =
    World_state.set_account
      (World_state.of_alloc [ (a, u 100) ])
      b
      (Account.make ~nonce:Nonce.zero ~balance:U256.max_value)
  in
  let tx = Transfer.make ~sender:a ~recipient:b ~value:(u 1) ~nonce:Nonce.zero in
  (match Transfer.apply st tx with
  | Error Transfer.Balance_overflow -> ()
  | Ok _ | Error (Transfer.Nonce_mismatch _) | Error (Transfer.Insufficient_balance _) ->
      Alcotest.fail "expected Balance_overflow");
  Alcotest.(check bool) "sender not debited on a reverted transfer" true
    (U256.equal (World_state.balance st a) (u 100))

(* The transition is deterministic: applying the same sequence to two states
   built independently from the same genesis yields identical states — the
   execution-agreement corollary at the state level. *)
let test_transfer_determinism () =
  let a = addr '\001' and b = addr '\002' and c = addr '\003' in
  let genesis () = World_state.of_alloc [ (a, u 1000); (b, u 500) ] in
  let txs =
    [
      Transfer.make ~sender:a ~recipient:b ~value:(u 100) ~nonce:Nonce.zero;
      Transfer.make ~sender:b ~recipient:c ~value:(u 50) ~nonce:Nonce.zero;
      Transfer.make ~sender:a ~recipient:c ~value:(u 30) ~nonce:(get (Nonce.of_int 1));
    ]
  in
  let run () = List.fold_left (fun st tx -> ok_state (Transfer.apply st tx)) (genesis ()) txs in
  Alcotest.(check bool) "same txs from same genesis give the same state" true
    (World_state.equal (run ()) (run ()));
  (* And the hand-computed balances line up. *)
  let st = run () in
  Alcotest.(check bool) "a: 1000 - 100 - 30 = 870" true (U256.equal (World_state.balance st a) (u 870));
  Alcotest.(check bool) "b: 500 + 100 - 50 = 550" true (U256.equal (World_state.balance st b) (u 550));
  Alcotest.(check bool) "c: 0 + 50 + 30 = 80" true (U256.equal (World_state.balance st c) (u 80))

let () =
  Alcotest.run "state"
    [
      ( "u256",
        [
          Alcotest.test_case "constants render to their byte layout" `Quick
            test_u256_constants;
          Alcotest.test_case "of_int places bytes big-endian" `Quick test_u256_of_int;
          Alcotest.test_case "byte and hex codecs round-trip" `Quick test_u256_codec;
          Alcotest.test_case "addition wraps and checks" `Quick test_u256_add;
          Alcotest.test_case "subtraction wraps and checks" `Quick test_u256_sub;
          Alcotest.test_case "ordering is unsigned" `Quick test_u256_compare;
        ] );
      ("nonce", [ Alcotest.test_case "counts and saturates" `Quick test_nonce ]);
      ("account", [ Alcotest.test_case "balance and nonce arithmetic" `Quick test_account ]);
      ( "world state",
        [ Alcotest.test_case "canonical address-to-account map" `Quick test_world_state ] );
      ( "transfer",
        [
          Alcotest.test_case "a valid transfer moves value" `Quick test_transfer_happy;
          Alcotest.test_case "an exact-balance transfer succeeds" `Quick
            test_transfer_exact_spend;
          Alcotest.test_case "a wrong nonce is rejected" `Quick test_transfer_nonce_mismatch;
          Alcotest.test_case "an overdraw is rejected" `Quick test_transfer_insufficient;
          Alcotest.test_case "a self-transfer nets zero, bumps nonce" `Quick
            test_transfer_self;
          Alcotest.test_case "a credit overflow reverts" `Quick test_transfer_overflow;
          Alcotest.test_case "the transition is deterministic" `Quick
            test_transfer_determinism;
        ] );
    ]
