(* Tests for the block-header roots and the agreement oracle (Tn_evm.Block_roots).

   Independent oracles:
   - the empty trie root is the pinned constant EMPTY_ROOT_HASH;
   - single-account state root and single-slot storage root come from the
     alloy-trie 0.9.5 cargo oracle (state_root_unhashed / storage_root_unhashed),
     injected below;
   - the receipts root and transactions root come from alloy-trie
     ordered_trie_root_encoded over, respectively, alloy-consensus 2.1.0 receipt
     envelopes and two fixed 2718 byte strings. *)

module Block_roots = Tn_evm.Block_roots
module Transaction = Tn_evm.Transaction
module Receipt = Tn_evm.Receipt
module Receipt_envelope = Tn_evm.Receipt_envelope
module World_state = Tn_state.World_state
module Account = Tn_state.Account
module Nonce = Tn_state.Nonce
module U256 = Tn_state.U256
module Address = Tn_types.Units.Address
module Log = Tn_evm.Log

let to_hex s =
  let buf = Buffer.create (2 * String.length s) in
  String.iter (fun c -> Buffer.add_string buf (Printf.sprintf "%02x" (Char.code c))) s;
  Buffer.contents buf

let hex s =
  let digit c =
    match c with
    | '0' .. '9' -> Char.code c - Char.code '0'
    | 'a' .. 'f' -> Char.code c - Char.code 'a' + 10
    | 'A' .. 'F' -> Char.code c - Char.code 'A' + 10
    | _ -> 0
  in
  String.init
    (String.length s / 2)
    (fun i -> Char.chr ((digit (String.get s (2 * i)) lsl 4) lor digit (String.get s ((2 * i) + 1))))

let empty_root_hex = "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"

(* ---- constructors ---- *)

let addr_last b = Option.value ~default:Address.zero (Address.of_bytes (String.make 19 '\x00' ^ String.make 1 (Char.chr b)))
let nonce_of n = Option.value ~default:Nonce.zero (Nonce.of_int n)
let u256_of n = Option.value ~default:U256.zero (U256.of_int n)

let mk_tx fee =
  Transaction.make ~sender:Address.zero ~nonce:Nonce.zero ~gas_limit:21000 ~kind:Transaction.Create
    ~value:U256.zero ~data:"" ~access_list:[] ~chain_id:None ~fee

(* ---- empty roots ---- *)

let test_empty_roots () =
  Alcotest.(check string) "state_root empty = EMPTY_ROOT_HASH" empty_root_hex (to_hex (Block_roots.state_root World_state.empty));
  Alcotest.(check string) "storage_root empty account = EMPTY_ROOT_HASH" empty_root_hex (to_hex (Block_roots.storage_root Account.empty));
  Alcotest.(check string) "transactions_root [] = EMPTY_ROOT_HASH" empty_root_hex (to_hex (Block_roots.transactions_root []));
  Alcotest.(check string) "receipts_root [] = EMPTY_ROOT_HASH" empty_root_hex (to_hex (Block_roots.receipts_root []))

(* ---- type_byte from the fee sum ---- *)

let test_type_byte () =
  Alcotest.(check int) "Legacy -> 0" 0 (Block_roots.type_byte (mk_tx (Transaction.Legacy { gas_price = U256.zero })));
  Alcotest.(check int) "Access_list -> 1" 1 (Block_roots.type_byte (mk_tx (Transaction.Access_list { gas_price = U256.zero })));
  Alcotest.(check int) "Dynamic -> 2" 2 (Block_roots.type_byte (mk_tx (Transaction.Dynamic { max_fee = U256.zero; max_priority = None })))

(* ---- agree = state-root equality ---- *)

let test_agree () =
  let a = World_state.empty in
  let b = World_state.set_account World_state.empty (addr_last 1) (Account.make ~nonce:(nonce_of 1) ~balance:(u256_of 1000)) in
  Alcotest.(check bool) "empty agrees with empty" true (Block_roots.agree a a);
  Alcotest.(check bool) "empty disagrees with a one-account state" false (Block_roots.agree a b);
  Alcotest.(check bool) "a state agrees with itself" true (Block_roots.agree b b);
  (* Same alloc applied two ways agrees. *)
  let b2 = World_state.set_account World_state.empty (addr_last 1) (Account.make ~nonce:(nonce_of 1) ~balance:(u256_of 1000)) in
  Alcotest.(check bool) "identical states agree" true (Block_roots.agree b b2)

(* ---- receipts_root_of_block: length guard ---- *)

let r_success gas = Receipt.Success { output = ""; created = None; gas_used = gas; gas_refunded = 0; logs = [] }

let test_receipts_root_of_block_guard () =
  let tx = mk_tx (Transaction.Legacy { gas_price = U256.zero }) in
  Alcotest.(check bool) "length mismatch -> None" true (Option.is_none (Block_roots.receipts_root_of_block [ tx ] []));
  let same =
    Block_roots.receipts_root_of_block [ tx ] [ r_success 21000 ]
    |> Option.map to_hex
  in
  let direct = to_hex (Block_roots.receipts_root [ (0, r_success 21000) ]) in
  Alcotest.(check (option string)) "matching lengths -> Some (= receipts_root of the zip)" (Some direct) same

(* ---- single-account state root vs alloy-trie 0.9.5 state_root_unhashed ----
   addr 0x00..01, nonce 1, balance 1e18, codeless, storageless. *)
let test_state_root_single () =
  let ws =
    World_state.set_account World_state.empty (addr_last 1)
      (Account.make ~nonce:(nonce_of 1) ~balance:(u256_of 1_000_000_000_000_000_000))
  in
  Alcotest.(check string)
    "single-account state root matches alloy-trie oracle"
    "9c12f277e702a26a12a6dbc78d5ee8a5e1594e9365b0228e9f81a03853754ddd"
    (to_hex (Block_roots.state_root ws))

(* ---- single-slot storage root vs alloy-trie 0.9.5 storage_root_unhashed ----
   slot 1 -> value 1. (Cross-confirms the hand-derived spec-3.6 value f38f9f63..) *)
let test_storage_root_single () =
  let acct = Account.set_slot Account.empty U256.one U256.one in
  Alcotest.(check string)
    "single-slot storage root matches alloy-trie oracle"
    "f38f9f63c760d088d7dd04f743619b6291f63beebd8bdf530628f90e9cfa52d7"
    (to_hex (Block_roots.storage_root acct))

(* ---- receipts root: net cumulative gas, 2 receipts with a refund on the 2nd ----
   R1: net 30000 (no refund) -> cgu 30000; R2: net 40000, refund 10000 -> cgu 70000.
   The gross cumulative would be 30000 + (40000+10000) = 80000, a different root.
   Oracle: alloy-trie ordered_trie_root_encoded over the two eip2718 envelopes. *)
let r1 = Receipt.Success { output = ""; created = None; gas_used = 30000; gas_refunded = 0; logs = [] }
let r2 = Receipt.Success { output = ""; created = None; gas_used = 40000; gas_refunded = 10000; logs = [] }

let test_receipts_root_net () =
  (* Each envelope's cumulative field is the running net prefix-sum. *)
  Alcotest.(check string)
    "R1 envelope: cgu = net 30000 (0x7530)"
    ("f9010801827530b90100" ^ String.concat "" (List.init 256 (fun _ -> "00")) ^ "c0")
    (to_hex (Receipt_envelope.encode_2718 ~type_byte:0 ~cumulative_gas_used:30000 r1));
  Alcotest.(check string)
    "R2 envelope: cgu = net 70000 (0x011170)"
    ("f901090183011170b90100" ^ String.concat "" (List.init 256 (fun _ -> "00")) ^ "c0")
    (to_hex (Receipt_envelope.encode_2718 ~type_byte:0 ~cumulative_gas_used:70000 r2));
  Alcotest.(check string)
    "receipts root (net cumulative) matches alloy oracle"
    "2bdeff2aafdda66d95cdd1f120193849c608a24bc63bca4c2f60eeb90c6ff6fa"
    (to_hex (Block_roots.receipts_root [ (0, r1); (0, r2) ]));
  (* The gross root is DIFFERENT, so the net-vs-gross mutation is observable. *)
  Alcotest.(check bool)
    "net root differs from the gross root 4ae30a48.." true
    (not
       (String.equal
          (to_hex (Block_roots.receipts_root [ (0, r1); (0, r2) ]))
          "4ae30a48a2f0b45612da7dddfeabad87921c6038a8e226ed67af41dd7a477b16"))

(* ---- transactions root over 2 verbatim 2718 byte strings ----
   Opaque bytes fed to alloy-trie ordered_trie_root_encoded. *)
let test_transactions_root () =
  Alcotest.(check string)
    "transactions root over [01020304050607; aabbccddeeff]"
    "ad21374c7110850df3941b8e069d7d2e8064bc1b81945a42cbff072d400b6d3c"
    (to_hex (Block_roots.transactions_root [ hex "01020304050607"; hex "aabbccddeeff" ]))

(* ---- receipts root over a receipt WITH logs (nonzero derived bloom) ----
   Exercises encode_log + the encode_2718 -> Bloom.of_logs integration end to
   end through the trie, for both a legacy (type 0) and an EIP-1559 (type 2)
   leaf (the type-byte pass-through inside receipts_root). Oracle: alloy-trie
   ordered_trie_root_encoded over the alloy-consensus ReceiptWithBloom envelope. *)
let log_5_7 =
  Log.make ~address:(addr_last 0x11)
    ~topics:(Log.Topics.T2 (u256_of 0xdead, u256_of 0xbeef))
    ~data:(hex "0100ff")

let success_with_log =
  Receipt.Success { output = ""; created = None; gas_used = 1; gas_refunded = 0; logs = [ log_5_7 ] }

let test_receipts_root_with_logs () =
  Alcotest.(check string) "receipts root, one success-with-log receipt, legacy"
    "9ed71f037c5506479326046253f30e83a20e38e6179aa4b3927afb09ab8bb2eb"
    (to_hex (Block_roots.receipts_root [ (0, success_with_log) ]));
  Alcotest.(check string) "receipts root, one success-with-log receipt, EIP-1559 typed"
    "03af052cc17fc119f7e0388d51cb25c5becae390b8fdcbdc72804fab318cab9d"
    (to_hex (Block_roots.receipts_root [ (2, success_with_log) ]))

(* ---- multi-account state root and multi-slot storage root ----
   Exercises the Block_roots wiring of >1 account/slot (ordering after
   secure_root_of's internal keccak + sort). Oracle: alloy-trie
   state_root_unhashed / storage_root_unhashed over 2 entries. *)
let test_state_root_multi () =
  let ws =
    World_state.set_account
      (World_state.set_account World_state.empty (addr_last 1)
         (Account.make ~nonce:(nonce_of 1) ~balance:(u256_of 1_000_000_000_000_000_000)))
      (addr_last 2)
      (Account.make ~nonce:(nonce_of 5) ~balance:(u256_of 2_000_000_000_000_000_000))
  in
  Alcotest.(check string) "two-account state root matches alloy oracle"
    "81150d8b9c9f8fcb4eb37c290e25cb85b6a1fef665344486774a321d4fb303c9"
    (to_hex (Block_roots.state_root ws))

let test_storage_root_multi () =
  let acct =
    Account.set_slot (Account.set_slot Account.empty U256.one U256.one) (u256_of 2) (u256_of 2)
  in
  Alcotest.(check string) "two-slot storage root matches alloy oracle"
    "bf3e65b043d6d870557f8556faf48fd77aecfd8558e3b8087ee399b3a8d62694"
    (to_hex (Block_roots.storage_root acct))

let () =
  Alcotest.run "block_roots"
    [
      ( "roots",
        [
          Alcotest.test_case "empty roots are EMPTY_ROOT_HASH" `Quick test_empty_roots;
          Alcotest.test_case "type_byte from fee" `Quick test_type_byte;
          Alcotest.test_case "agree = state-root equality" `Quick test_agree;
          Alcotest.test_case "receipts_root_of_block length guard" `Quick test_receipts_root_of_block_guard;
        ] );
      ( "oracles",
        [
          Alcotest.test_case "single-account state root" `Quick test_state_root_single;
          Alcotest.test_case "single-slot storage root" `Quick test_storage_root_single;
          Alcotest.test_case "receipts root (net cumulative gas)" `Quick test_receipts_root_net;
          Alcotest.test_case "transactions root" `Quick test_transactions_root;
          Alcotest.test_case "state root (2 accounts)" `Quick test_state_root_multi;
          Alcotest.test_case "storage root (2 slots)" `Quick test_storage_root_multi;
          Alcotest.test_case "receipts root with logs (legacy + typed)" `Quick
            test_receipts_root_with_logs;
        ] );
    ]
