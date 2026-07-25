(* Tests for the 2048-bit logs bloom (Tn_evm.Bloom).

   The oracle is the alloy-primitives 1.6.0 unit test [bloom.rs:236-272] "works":
   the address 0xef2d6d19..1106 alone sets bloom[20]=0x10, bloom[123]=0x08,
   bloom[155]=0x10 (bit indices 1884, 1059, 804), and adding the topic
   0x02c69b..e9fc sets three more bits. The bit positions were re-derived here
   independently with pycryptodome's keccak256, not from the port's own encoder:

     keccak256(address) = 3b2414235f5ca3cada49bf2690178797df9806a95cedb24368ca49da6b81589a
       -> bit 804 (byte[155]|=0x10), 1059 (byte[123]|=0x08), 1884 (byte[20]|=0x10)
     keccak256(topic)   = 33fcccd93ce1cea9fd541f6dbacca0509527dbe53937c8f2b20b8f4bc68e00ef
       -> bit 1020 (byte[128]|=0x10), 1241 (byte[100]|=0x02), 1249 (byte[99]|=0x02)

   The address-alone vector alone mutation-confirms both easy-to-get-wrong
   details: dropping the [255 -] reversal moves the bytes to 100/132/235, and
   flipping the mask polarity to [1 lsl (7 - bit mod 8)] changes byte[155] from
   0x10 to 0x08 — either breaks the expected hex. *)

module Bloom = Tn_evm.Bloom
module Log = Tn_evm.Log
module U256 = Tn_state.U256
module Address = Tn_types.Units.Address

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

let to_hex s =
  let buf = Buffer.create (2 * String.length s) in
  String.iter (fun c -> Buffer.add_string buf (Printf.sprintf "%02x" (Char.code c))) s;
  Buffer.contents buf

(* A 256-byte bloom as hex, built by a pure gather: byte [i] is the value listed
   for it, else zero. *)
let bloom_hex set_bytes =
  to_hex (String.init 256 (fun i -> Char.chr (Option.value ~default:0 (List.assoc_opt i set_bytes))))

let address_hex = "ef2d6d194084c2de36e0dabfce45d046b37d1106"
let topic_hex = "02c69be41d0b7e40352fc85be1cd65eb03d40ef8427a0ca4596b1ead9a00e9fc"
let addr_only = [ (20, 0x10); (123, 0x08); (155, 0x10) ]
let addr_and_topic = [ (20, 0x10); (99, 0x02); (100, 0x02); (123, 0x08); (128, 0x10); (155, 0x10) ]

let word_of h = Option.value ~default:U256.zero (U256.of_be_bytes (hex h))
let addr_of h = Option.value ~default:Address.zero (Address.of_bytes (hex h))

let test_empty () =
  Alcotest.(check string)
    "empty bloom is 256 zero bytes"
    (String.concat "" (List.init 256 (fun _ -> "00")))
    (to_hex (Bloom.to_bytes Bloom.empty));
  Alcotest.(check int) "and is exactly 256 bytes" 256 (String.length (Bloom.to_bytes Bloom.empty))

(* accrue takes the RAW 20-byte address and hashes it internally. *)
let test_address_alone () =
  let b = Bloom.accrue Bloom.empty (hex address_hex) in
  Alcotest.(check string)
    "address-alone bloom (spec 4.4 / alloy works)" (bloom_hex addr_only)
    (to_hex (Bloom.to_bytes b))

(* of_logs accrues the address then each topic, each hashed separately; the log
   bloom is the OR of all six bits. *)
let test_of_logs_address_and_topic () =
  let log =
    Log.make ~address:(addr_of address_hex) ~topics:(Log.Topics.T1 (word_of topic_hex))
      ~data:"\x01\x00\xff"
  in
  Alcotest.(check string)
    "address+topic bloom equals the alloy works literal" (bloom_hex addr_and_topic)
    (to_hex (Bloom.to_bytes (Bloom.of_logs [ log ])));
  (* A log with no topics contributes only the address's three bits. *)
  let log0 = Log.make ~address:(addr_of address_hex) ~topics:Log.Topics.T0 ~data:"" in
  Alcotest.(check string)
    "no-topic log bloom equals the address-alone bloom" (bloom_hex addr_only)
    (to_hex (Bloom.to_bytes (Bloom.of_logs [ log0 ])));
  (* An empty log set is the all-clear bloom. *)
  Alcotest.(check bool)
    "of_logs [] = empty" true
    (Bloom.equal (Bloom.of_logs []) Bloom.empty)

let () =
  Alcotest.run "bloom"
    [
      ( "logs-bloom",
        [
          Alcotest.test_case "empty is 256 zero bytes" `Quick test_empty;
          Alcotest.test_case "address-alone (spec 4.4)" `Quick test_address_alone;
          Alcotest.test_case "address + topic (alloy works literal)" `Quick test_of_logs_address_and_topic;
        ] );
    ]
