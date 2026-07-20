(* Contract creation and account destruction: CREATE, CREATE2, SELFDESTRUCT and
   BLOCKHASH. Faithful to revm 32.0.0 at Prague.

   The address derivations are pinned against oracles this port did not produce.
   The seven [CREATE2] cases are EIP-1014's own published vectors, reproduced
   verbatim; the [CREATE] cases were computed with an independent Keccak-256
   implementation (Python's pycryptodome) that was first shown to reproduce all
   seven of those EIP vectors, so the RLP nonce encoding is checked against a
   witness outside this tree rather than against itself. They cover the four
   shapes the nonce encoding has: zero as the empty string, a bare byte below
   [0x80], the [0x81]-prefixed byte at [0x80] and above, and a multi-byte
   integer. *)

module U256 = Tn_state.U256
module Nonce = Tn_state.Nonce
module Units = Tn_types.Units
module Contract_address = Tn_evm.Contract_address

let get = function Some x -> x | None -> Alcotest.fail "expected Some"
let nonce_of n = get (Nonce.of_int n)

(* A twenty-byte address from its hex, and a hex rendering of one, so that the
   published vectors can be written and compared exactly as they are published. *)
let unhex hex =
  String.init
    (String.length hex / 2)
    (fun i -> Char.chr (int_of_string ("0x" ^ String.sub hex (2 * i) 2)))

let address_of_hex hex = get (Units.Address.of_bytes (unhex hex))

let hex_of_address address =
  String.concat ""
    (List.map
       (fun c -> Printf.sprintf "%02x" (Char.code c))
       (List.of_seq (String.to_seq (Units.Address.to_bytes address))))

let check_address ~expected actual =
  Alcotest.(check string) "created address" (String.lowercase_ascii expected) (hex_of_address actual)

(* ---------- CREATE2: EIP-1014's published vectors ---------- *)

let create2 ~creator ~salt ~init_code =
  Contract_address.derive
    ~creator:(address_of_hex creator)
    (Contract_address.From_salt
       { salt = get (U256.of_be_bytes (unhex salt)); init_code = unhex init_code })

let eip1014_vectors =
  [
    ( "0000000000000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000000",
      "00",
      "4D1A2e2bB4F88F0250f26Ffff098B0b30B26BF38" );
    ( "deadbeef00000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000000",
      "00",
      "B928f69Bb1D91Cd65274e3c79d8986362984fDA3" );
    ( "deadbeef00000000000000000000000000000000",
      "000000000000000000000000feed000000000000000000000000000000000000",
      "00",
      "D04116cDd17beBE565EB2422F2497E06cC1C9833" );
    ( "0000000000000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000000",
      "deadbeef",
      "70f2b2914A2a4b783FaEFb75f459A580616Fcb5e" );
    ( "00000000000000000000000000000000deadbeef",
      "00000000000000000000000000000000000000000000000000000000cafebabe",
      "deadbeef",
      "60f3f640a8508fC6a86d45DF051962668E1e8AC7" );
    ( "00000000000000000000000000000000deadbeef",
      "00000000000000000000000000000000000000000000000000000000cafebabe",
      "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
      "1d8bfDC5D46DC4f61D6b6115972536eBE6A8854C" );
    ( "0000000000000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000000",
      "",
      "E33C0C7F7df4809055C3ebA6c09CFe4BaF1BD9e0" );
  ]

let test_create2_eip1014_vectors () =
  List.iter
    (fun (creator, salt, init_code, expected) ->
      check_address ~expected (create2 ~creator ~salt ~init_code))
    eip1014_vectors

(* ---------- CREATE: the RLP nonce encoding ---------- *)

let create_at ~creator ~nonce =
  Contract_address.derive
    ~creator:(address_of_hex creator)
    (Contract_address.From_nonce (nonce_of nonce))

(* Two creators against the four encoding shapes. The zero creator is included
   because it is the one whose RLP payload a mistake in the address item would
   still leave well formed. *)
let create_vectors =
  [
    ("6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0", 0, "cd234a471b72ba2f1ccf0a70fcaba648a5eecd8d");
    ("6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0", 1, "343c43a37d37dff08ae8c4a11544c718abb4fcf8");
    ("6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0", 127, "06d9a77f5e4b311bae8d559db9cdb4df94104aa0");
    ("6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0", 128, "08e190dcb7b73f5fcdabb43e102215c83659a76d");
    ("6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0", 255, "3ef7c1a519e4b4431e317d7839340e3139b03c65");
    ("6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0", 256, "3837c1ae70354f670550c746580199ac6a73cb0a");
    ("6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0", 65535, "65260eecff4edebabe134f76f1f39a91defde56c");
    ("0000000000000000000000000000000000000000", 0, "bd770416a3345f91e4b34576cb804a576fa48eb1");
    ("0000000000000000000000000000000000000000", 127, "5a1bfc20f2037f3e54d367a70957a5327130cea5");
    ("0000000000000000000000000000000000000000", 128, "c1784bd8a0ffebd60d0bc7099dcd811b57f30bc4");
    ("0000000000000000000000000000000000000000", 256, "1183a5a83c1fa113618603abc4509077ec672699");
    ("deadbeef00000000000000000000000000000000", 0, "f2048c36a5536fea3bc71d49ed59f2c65c546eea");
    ("deadbeef00000000000000000000000000000000", 128, "2297787b25b800d655071345a1d3a7951404b50c");
  ]

let test_create_nonce_vectors () =
  List.iter
    (fun (creator, nonce, expected) -> check_address ~expected (create_at ~creator ~nonce))
    create_vectors

(* The nonce is the only thing separating two creations by one account, so a
   derivation that ignored it — or that encoded every nonce the same way — would
   deploy every contract of a creator to one address. *)
let test_create_nonce_changes_address () =
  let creator = "6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0" in
  let addresses = List.map (fun nonce -> hex_of_address (create_at ~creator ~nonce)) [ 0; 1; 2; 127; 128; 129 ] in
  Alcotest.(check int)
    "six nonces, six distinct addresses" 6
    (List.length (List.sort_uniq String.compare addresses))

(* The salt and the init code are independent inputs to EIP-1014: changing
   either alone must move the address. *)
let test_create2_salt_and_code_independent () =
  let creator = "00000000000000000000000000000000deadbeef" in
  let base = create2 ~creator ~salt:(String.make 64 '0') ~init_code:"deadbeef" in
  let other_salt =
    create2 ~creator ~salt:(String.make 63 '0' ^ "1") ~init_code:"deadbeef"
  in
  let other_code = create2 ~creator ~salt:(String.make 64 '0') ~init_code:"deadbeff" in
  Alcotest.(check bool) "a different salt moves it" false (hex_of_address base = hex_of_address other_salt);
  Alcotest.(check bool) "a different init code moves it" false (hex_of_address base = hex_of_address other_code)

let () =
  Alcotest.run "creation"
    [
      ( "addresses",
        [
          Alcotest.test_case "CREATE2 against EIP-1014's vectors" `Quick
            test_create2_eip1014_vectors;
          Alcotest.test_case "CREATE against an independent keccak oracle" `Quick
            test_create_nonce_vectors;
          Alcotest.test_case "the nonce moves the address" `Quick
            test_create_nonce_changes_address;
          Alcotest.test_case "salt and init code move it independently" `Quick
            test_create2_salt_and_code_independent;
        ] );
    ]
