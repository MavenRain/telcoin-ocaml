(* Tests for the EIP-2718 receipt leaf encoder (Tn_evm.Receipt_envelope).

   Two oracle families:

   - Hand-derived RLP for the empty-logs receipt (a Success/Reverted with no
     logs), whose bloom is provably all-zero, so the exact bytes follow from the
     RLP rules with no external tool. These pin the field order [status, cgu,
     bloom, logs], the status polarity, the presence of the 0xb90100+256B bloom
     field, and the typed-vs-legacy framing (one type byte, NO outer wrapper).

   - alloy-consensus 2.1.0 [ReceiptWithBloom::eip2718_encoded] hex for a receipt
     WITH logs (nonzero derived bloom), injected below from the independent cargo
     oracle. (Filled in once the oracle is built.) *)

module Receipt_envelope = Tn_evm.Receipt_envelope
module Receipt = Tn_evm.Receipt
module Log = Tn_evm.Log
module U256 = Tn_state.U256
module Address = Tn_types.Units.Address

let to_hex s =
  let buf = Buffer.create (2 * String.length s) in
  String.iter (fun c -> Buffer.add_string buf (Printf.sprintf "%02x" (Char.code c))) s;
  Buffer.contents buf

let zeros256 = String.concat "" (List.init 256 (fun _ -> "00"))

(* The bloom field of an empty-logs receipt: 0xb90100 then 256 zero bytes. *)
let empty_bloom_hex = "b90100" ^ zeros256

(* An empty-logs Success/Reverted receipt (bloom all-zero). [gas_refunded] and
   [output] are irrelevant to the leaf; only status and (the passed) cgu are. *)
let success_no_logs = Receipt.Success { output = ""; created = None; gas_used = 0; gas_refunded = 0; logs = [] }
let reverted = Receipt.Reverted { output = ""; gas_used = 0 }
let halted = Receipt.Halted { reason = Receipt.Create_collision; gas_used = 0 }

(* status is EIP-658: true only for Success. *)
let test_status_polarity () =
  Alcotest.(check bool) "Success -> true" true (Receipt_envelope.status success_no_logs);
  Alcotest.(check bool) "Reverted -> false" false (Receipt_envelope.status reverted);
  Alcotest.(check bool) "Halted -> false" false (Receipt_envelope.status halted)

(* Legacy empty-logs Success, cgu=1:
     inner list = [ 0x01 (status), 0x01 (cgu), b90100||256*00 (bloom), 0xc0 (logs) ]
     payload len = 1 + 1 + (3+256) + 1 = 262 = 0x0106  -> list header f9 01 06. *)
let test_legacy_empty_logs () =
  let expected = "f90106" ^ "01" ^ "01" ^ empty_bloom_hex ^ "c0" in
  Alcotest.(check string)
    "legacy Success empty-logs cgu=1" expected
    (to_hex (Receipt_envelope.encode_2718 ~type_byte:0 ~cumulative_gas_used:1 success_no_logs));
  (* Reverted flips only the status byte to 0x80 (RLP of 0). *)
  let expected_rev = "f90106" ^ "80" ^ "01" ^ empty_bloom_hex ^ "c0" in
  Alcotest.(check string)
    "legacy Reverted empty-logs cgu=1 (status 0x80)" expected_rev
    (to_hex (Receipt_envelope.encode_2718 ~type_byte:0 ~cumulative_gas_used:1 reverted))

(* Typed receipts prepend exactly one type byte to the byte-identical inner list,
   with NO outer Header{list:false} string wrapper (the network form would be
   b8<len>02f9.. ). This pins mutation 2a (adding an outer encode_bytes wrap). *)
let test_typed_prefix_no_outer_wrap () =
  let inner = "f90106" ^ "01" ^ "01" ^ empty_bloom_hex ^ "c0" in
  Alcotest.(check string)
    "EIP-2930 (type 1) prepends 0x01" ("01" ^ inner)
    (to_hex (Receipt_envelope.encode_2718 ~type_byte:1 ~cumulative_gas_used:1 success_no_logs));
  Alcotest.(check string)
    "EIP-1559 (type 2) prepends 0x02" ("02" ^ inner)
    (to_hex (Receipt_envelope.encode_2718 ~type_byte:2 ~cumulative_gas_used:1 success_no_logs))

(* ---- receipt WITH logs: exercises encode_log + the derived nonzero bloom ----
   alloy-consensus 2.1.0 ReceiptWithBloom (EIP-2718) for a Success receipt with
   one log (addr 0x00..0011, topics [0x..dead, 0x..beef], data 0x0100ff); the
   256-byte bloom is DERIVED from the log, so this pins encode_log's RLP
   ([0x94||addr, list of 0xa0||topic (fixed 32B), data]) and the encode_2718 ->
   Bloom.of_logs integration that the all-zero-bloom empty-logs vectors above
   cannot reach. A revert/halt carries no logs in this model, so the with-logs
   case is necessarily a Success. *)
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

let u256_of n = Option.value ~default:U256.zero (U256.of_int n)

let addr_last b =
  Option.value ~default:Address.zero (Address.of_bytes (String.make 19 '\x00' ^ String.make 1 (Char.chr b)))

let log_5_7 =
  Log.make ~address:(addr_last 0x11)
    ~topics:(Log.Topics.T2 (u256_of 0xdead, u256_of 0xbeef))
    ~data:(hex "0100ff")

let success_with_log =
  Receipt.Success { output = ""; created = None; gas_used = 1; gas_refunded = 0; logs = [ log_5_7 ] }

(* Full legacy EIP-2718 bytes from the alloy cargo oracle (derived bloom). *)
let success_with_log_eip2718 =
  "f901660101b9010000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000004000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000f85ff85d940000000000000000000000000000000000000011f842a0000000000000000000000000000000000000000000000000000000000000deada0000000000000000000000000000000000000000000000000000000000000beef830100ff"

let test_success_with_logs () =
  Alcotest.(check string)
    "legacy success-with-log envelope (derived nonzero bloom) matches alloy oracle"
    success_with_log_eip2718
    (to_hex (Receipt_envelope.encode_2718 ~type_byte:0 ~cumulative_gas_used:1 success_with_log));
  Alcotest.(check string)
    "typed (EIP-1559) success-with-log = 0x02 || the byte-identical legacy inner"
    ("02" ^ success_with_log_eip2718)
    (to_hex (Receipt_envelope.encode_2718 ~type_byte:2 ~cumulative_gas_used:1 success_with_log))

let () =
  Alcotest.run "receipt_envelope"
    [
      ( "framing",
        [
          Alcotest.test_case "status polarity (EIP-658)" `Quick test_status_polarity;
          Alcotest.test_case "legacy empty-logs field order + bloom field" `Quick test_legacy_empty_logs;
          Alcotest.test_case "typed prefix, no outer wrapper" `Quick test_typed_prefix_no_outer_wrap;
          Alcotest.test_case "success receipt with logs (encode_log + derived bloom)" `Quick
            test_success_with_logs;
        ] );
    ]
