(* Tests for Tn_evm.Rewards_counter, the port of RewardsCounter
   (gas_accumulator.rs:94-174).

   The oracles: the merge-and-skip semantics of get_address_counts
   (gas_accumulator.rs:122-142; counts SUMMED on a shared execution address,
   authorities the committee cannot resolve contributing nothing, the whole
   map silently empty with no committee), the BTreeMap<Address, u32> output
   order (ascending 20-byte lexicographic order, here checked against
   addresses whose insertion order, count order and authority-id order all
   disagree with byte order), and the generate_withdrawals record shape
   (gas_accumulator.rs:144-158: index 0, validator_index 0, amount = the RAW
   leader count, never gwei). The record list is additionally cross-pinned
   through Block_roots.withdrawals_root, the root function chunk 30 certified
   against a live mainnet block, both against an independently hand-built
   record list and against an embedded root constant; the empty list must
   root to alloy's EMPTY_WITHDRAWALS, the value telcoin writes on every
   non-closing block (block.rs:976-978). *)

open Tn_types
module Rewards_counter = Tn_evm.Rewards_counter
module Withdrawal = Tn_evm.Withdrawal
module Block_roots = Tn_evm.Block_roots

(* ---------- helpers ---------- *)

let to_hex s =
  String.concat ""
    (List.map (fun c -> Printf.sprintf "%02x" (Char.code c)) (List.of_seq (String.to_seq s)))

(* A 20-byte address of one repeated byte, so byte order is legible: the
   whole ordering test reads off the single byte. *)
let addr b =
  match Units.Address.of_bytes (String.make 20 (Char.chr b)) with
  | Some a -> a
  | None -> Alcotest.fail "20-byte address fixture refused"

let addr_hex a = to_hex (Units.Address.to_bytes a)

(* Authority [i] of the fixture keyspace, at the given execution address. *)
let authority i address =
  Authority.make
    ~protocol_key:(Tn_crypto.Secret_key.public_key (Tn_crypto.Secret_key.derive (Int64.of_int i)))
    ~execution_address:address

let committee auths =
  match Committee.create ~epoch:Units.Epoch.zero auths with
  | Ok c -> c
  | Error e -> Alcotest.failf "committee build failed: %s" (Committee.error_to_string e)

let inc_n n counter id =
  List.fold_left (fun c _ -> Rewards_counter.inc_leader_count c id) counter (List.init n Fun.id)

(* address_counts rendered as (hex, count) pairs for whole-list assertions. *)
let counts_hex counter =
  List.map (fun (a, n) -> (addr_hex a, n)) (Rewards_counter.address_counts counter)

let unwrap_withdrawals = function
  | Ok ws -> ws
  | Error e -> Alcotest.failf "generate_withdrawals: %s" (Rewards_counter.error_to_string e)

let make_withdrawal ~address ~amount =
  match Withdrawal.make ~index:0 ~validator_index:0 ~address ~amount with
  | Some w -> w
  | None -> Alcotest.fail "withdrawal fixture refused"

(* EMPTY_WITHDRAWALS = the empty ordered trie root (block_roots.mli:49-54). *)
let empty_root_hex = "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"

(* ---------- the silent no-committee arm ---------- *)

let test_no_committee () =
  let a = authority 1 (addr 0x0a) in
  let counter = inc_n 3 Rewards_counter.empty (Authority.id a) in
  Alcotest.(check (list (pair string int)))
    "no committee: address_counts is silently empty" [] (counts_hex counter);
  Alcotest.(check (list string))
    "no committee: withdrawals are Ok []" []
    (List.map Withdrawal.to_string (unwrap_withdrawals (Rewards_counter.generate_withdrawals counter)))

(* ---------- merge on a shared address, skip of an absent authority ---------- *)

(* gas_accumulator.rs:127-138: two authorities share one execution address
   (counts 2 and 3, merged by SUM to 5) and a third authority with count 4 is
   not in the committee at all, so it contributes nothing; the result has
   exactly one entry. *)
let test_merge_and_skip () =
  let shared = addr 0x5c in
  let a1 = authority 1 shared and a2 = authority 2 shared in
  let outsider = authority 99 (addr 0x11) in
  let counter =
    Rewards_counter.set_committee Rewards_counter.empty (committee [ a1; a2 ])
  in
  let counter = inc_n 2 counter (Authority.id a1) in
  let counter = inc_n 3 counter (Authority.id a2) in
  let counter = inc_n 4 counter (Authority.id outsider) in
  Alcotest.(check (list (pair string int)))
    "shared address sums 2 + 3, absent authority contributes nothing"
    [ (addr_hex shared, 5) ]
    (counts_hex counter)

(* ---------- ascending 20-byte address order ---------- *)

(* The output order is BTreeMap<Address, u32>'s ascending byte order and
   nothing else: the fixture's insertion order (0xf3, 0x0a, 0x5c), count
   order (4, 1, 9) and address order (0x0a, 0x5c, 0xf3) all disagree. *)
let test_ascending_order () =
  let a1 = authority 1 (addr 0xf3) and a2 = authority 2 (addr 0x0a) and a3 = authority 3 (addr 0x5c) in
  let counter =
    Rewards_counter.set_committee Rewards_counter.empty (committee [ a1; a2; a3 ])
  in
  let counter = inc_n 4 counter (Authority.id a1) in
  let counter = inc_n 1 counter (Authority.id a2) in
  let counter = inc_n 9 counter (Authority.id a3) in
  Alcotest.(check (list (pair string int)))
    "counts in ascending address byte order"
    [ (addr_hex (addr 0x0a), 1); (addr_hex (addr 0x5c), 9); (addr_hex (addr 0xf3), 4) ]
    (counts_hex counter)

(* ---------- clear empties counts but keeps the committee ---------- *)

(* gas_accumulator.rs:109-113: clear() takes only the counts lock. An
   increment after clear must still resolve through the surviving committee
   without a second set_committee. *)
let test_clear_keeps_committee () =
  let a1 = authority 1 (addr 0x0a) and a2 = authority 2 (addr 0x5c) in
  let counter =
    Rewards_counter.set_committee Rewards_counter.empty (committee [ a1; a2 ])
  in
  let counter = inc_n 7 counter (Authority.id a1) in
  let counter = Rewards_counter.clear counter in
  Alcotest.(check (list (pair string int)))
    "after clear: no counts" [] (counts_hex counter);
  let counter = inc_n 1 counter (Authority.id a2) in
  Alcotest.(check (list (pair string int)))
    "after clear: the committee still resolves"
    [ (addr_hex (addr 0x5c), 1) ]
    (counts_hex counter)

(* ---------- withdrawal records and the certified root ---------- *)

(* generate_withdrawals (gas_accumulator.rs:144-158): one record per address
   in ascending order, index 0, validator_index 0, amount the RAW count. The
   list is cross-pinned through Block_roots.withdrawals_root (certified in
   chunk 30 against live mainnet block 0x1600000): the generated records must
   root identically to a hand-built record list, and to the embedded
   constant, which was derived once through that certified function. *)
let test_withdrawals () =
  let a1 = authority 1 (addr 0xf3) and a2 = authority 2 (addr 0x0a) and a3 = authority 3 (addr 0x5c) in
  let counter =
    Rewards_counter.set_committee Rewards_counter.empty (committee [ a1; a2; a3 ])
  in
  let counter = inc_n 4 counter (Authority.id a1) in
  let counter = inc_n 1 counter (Authority.id a2) in
  let counter = inc_n 9 counter (Authority.id a3) in
  let ws = unwrap_withdrawals (Rewards_counter.generate_withdrawals counter) in
  let expected =
    [
      make_withdrawal ~address:(addr 0x0a) ~amount:1;
      make_withdrawal ~address:(addr 0x5c) ~amount:9;
      make_withdrawal ~address:(addr 0xf3) ~amount:4;
    ]
  in
  Alcotest.(check (list string))
    "records: ascending addresses, index 0, validator_index 0, raw counts"
    (List.map Withdrawal.to_string expected)
    (List.map Withdrawal.to_string ws);
  Alcotest.(check string) "roots agree with the hand-built records"
    (to_hex (Block_roots.withdrawals_root expected))
    (to_hex (Block_roots.withdrawals_root ws));
  Alcotest.(check string) "the pinned root"
    "0d1b1dc444e61341e576b3762d6728cc18309a4438d6b255e8849fa493a53dfa"
    (to_hex (Block_roots.withdrawals_root ws));
  Alcotest.(check string) "empty counter roots to EMPTY_WITHDRAWALS" empty_root_hex
    (to_hex
       (Block_roots.withdrawals_root
          (unwrap_withdrawals
             (Rewards_counter.generate_withdrawals (Rewards_counter.clear counter)))))

(* ---------- the (unreachable) error surface ---------- *)

let test_error_rendering () =
  Alcotest.(check string) "Negative_amount renders address and amount"
    ("generate_withdrawals: negative amount -3 for 0x" ^ addr_hex (addr 0xab))
    (Rewards_counter.error_to_string
       (Rewards_counter.Negative_amount { address = addr 0xab; amount = -3 }))

let () =
  Alcotest.run "rewards_counter"
    [
      ( "address counts",
        [
          Alcotest.test_case "no committee is silently empty" `Quick test_no_committee;
          Alcotest.test_case "shared-address merge and absent-authority skip" `Quick
            test_merge_and_skip;
          Alcotest.test_case "ascending address byte order" `Quick test_ascending_order;
          Alcotest.test_case "clear keeps the committee" `Quick test_clear_keeps_committee;
        ] );
      ( "withdrawals",
        [
          Alcotest.test_case "records and certified root" `Quick test_withdrawals;
          Alcotest.test_case "error rendering" `Quick test_error_rendering;
        ] );
    ]
