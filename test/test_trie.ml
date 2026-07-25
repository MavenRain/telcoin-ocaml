(* Tests for the Merkle-Patricia-Trie root builder (Tn_trie).

   A trie root is a consensus commitment: a block header's stateRoot,
   transactionsRoot and receiptsRoot are all roots over sets known in full. The
   oracle is the canonical ethereum/tests TrieTests corpus (extracted into
   [Trie_vectors]), whose roots were cross-checked, plus the alloy-trie 0.9.5
   worked examples for the hex-prefix and node encodings. The suite locks the
   seven critic gaps: the byte-string value slot (G1), the branch value slot for
   a prefix key (G2), the shared-prefix length taken from a sorted group's
   extremes (G3), the length-header boundaries (G4, in test_rlp), the
   ordered-trie index permutation (G5), a total root builder (G6), and the RLP
   canonicity errors (G7, in test_rlp). *)

module Rlp = Tn_rlp.Rlp
module Trie = Tn_trie.Trie
module Node = Tn_trie.Node
module Nibbles = Tn_trie.Nibbles
module Hex_prefix = Tn_trie.Hex_prefix
module Keccak = Tn_keccak
module U256 = Tn_state.U256

(* ---------- hex helpers (keys, values and roots are given as hex) ---------- *)

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

let empty_root_hex = "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
let keccak_empty_hex = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"

let ok_root = function Ok s -> to_hex s | Error e -> "<error:" ^ Trie.error_to_string e ^ ">"

(* ---------- wiring (spec 8.1) ---------- *)

let test_wiring () =
  Alcotest.(check string)
    "keccak256(\"\") = KECCAK256_EMPTY" keccak_empty_hex (Keccak.to_hex Keccak.empty);
  Alcotest.(check string) "empty_root = keccak256(0x80)" empty_root_hex (to_hex Trie.empty_root);
  Alcotest.(check string) "root [] = empty_root" empty_root_hex (ok_root (Trie.root []))

(* ---------- hex-prefix worked examples (spec 3.2) ---------- *)

let test_hex_prefix () =
  let abcd = Nibbles.of_int_list [ 0xa; 0xb; 0xc; 0xd ] in
  let abc = Nibbles.of_int_list [ 0xa; 0xb; 0xc ] in
  let empty = Nibbles.of_int_list [] in
  let case name path ~is_leaf expected =
    Alcotest.(check string) name expected (to_hex (Hex_prefix.encode path ~is_leaf))
  in
  case "ext even [A,B,C,D]" abcd ~is_leaf:false "00abcd";
  case "ext odd [A,B,C]" abc ~is_leaf:false "1abc";
  case "leaf even [A,B,C,D]" abcd ~is_leaf:true "20abcd";
  case "leaf odd [A,B,C]" abc ~is_leaf:true "3abc";
  case "leaf empty" empty ~is_leaf:true "20";
  case "ext empty" empty ~is_leaf:false "00"

let hp_decoded = function
  | Ok (p, is_leaf) -> (Nibbles.to_list p, is_leaf)
  | Error Hex_prefix.Empty_input -> ([ -1 ], false)

let test_hex_prefix_round_trip () =
  let roundtrip path ~is_leaf =
    Alcotest.(check (pair (list int) bool))
      "hp encode/decode round-trip"
      (Nibbles.to_list path, is_leaf)
      (hp_decoded (Hex_prefix.decode (Hex_prefix.encode path ~is_leaf)))
  in
  roundtrip (Nibbles.of_int_list [ 0xa; 0xb; 0xc; 0xd ]) ~is_leaf:true;
  roundtrip (Nibbles.of_int_list [ 0xa; 0xb; 0xc ]) ~is_leaf:false;
  roundtrip (Nibbles.unpack "\x64\x6f") ~is_leaf:true;
  roundtrip (Nibbles.of_int_list []) ~is_leaf:true;
  Alcotest.(check string)
    "decode of empty errors"
    (Hex_prefix.error_to_string Hex_prefix.Empty_input)
    (match Hex_prefix.decode "" with Ok _ -> "ok" | Error e -> Hex_prefix.error_to_string e)

(* ---------- node round-trips (spec 4.1 / 4.2) ---------- *)

let test_leaf_node () =
  let leaf = Node.Leaf { path = Nibbles.unpack "\x64\x6f"; value = "verb" } in
  Alcotest.(check string) "leaf [do]->verb (spec 4.1)" "c98320646f8476657262" (to_hex (Node.encode leaf))

(* The exact spec literal c98300646f8476657262 encodes a raw non-node child,
   which the type-safe [child_ref = private string] deliberately forbids
   constructing. So the extension is exercised with a real child, asserting its
   distinguishing feature: the first list element is the even-flag (0x00) HP
   string, versus a leaf's 0x20 (spec 4.2). *)
let test_extension_node () =
  let path = Nibbles.unpack "\x64\x6f" in
  Alcotest.(check string) "leaf HP flag 0x20" "20646f" (to_hex (Hex_prefix.encode path ~is_leaf:true));
  Alcotest.(check string)
    "ext HP flag 0x00" "00646f" (to_hex (Hex_prefix.encode path ~is_leaf:false));
  let child = Node.to_ref (Node.Leaf { path = Nibbles.of_int_list []; value = "verb" }) in
  let ext = Node.Extension { path; child } in
  let first_element = function
    | Ok (Rlp.List (Rlp.Str hp :: _)) -> to_hex hp
    | Ok (Rlp.List _) -> "<list-other>"
    | Ok (Rlp.Str _) -> "<str>"
    | Error e -> "<error:" ^ Rlp.error_to_string e ^ ">"
  in
  Alcotest.(check string)
    "extension's first element is the 0x00-flag HP string" "00646f"
    (first_element (Rlp.decode_exact (Node.encode ext)))

(* ---------- G1: value slot uses the byte-string path, not the scalar ---------- *)

let test_value_encoding () =
  let leaf v = to_hex (Node.encode (Node.Leaf { path = Nibbles.unpack "\x01"; value = v })) in
  Alcotest.(check string) "leaf value 00 stays a bare 00 (G1)" "c482200100" (leaf "\x00");
  Alcotest.(check string) "leaf value 0007 keeps the zero (G1)" "c6822001820007" (leaf "\x00\x07");
  let branch v = to_hex (Node.encode (Node.Branch { children = Array.make 16 None; value = Some v })) in
  let eighty16 = String.concat "" (List.init 16 (fun _ -> "80")) in
  Alcotest.(check string) "branch value 00 stays a bare 00 (G1)" ("d1" ^ eighty16 ^ "00") (branch "\x00");
  Alcotest.(check string)
    "branch value 0007 keeps the zero (G1)" ("d3" ^ eighty16 ^ "820007") (branch "\x00\x07")

(* ---------- child-collapse boundary (strict <32) and always-hash-root ---------- *)

let test_child_ref_boundary () =
  let big = Node.Leaf { path = Nibbles.unpack "\x01"; value = String.make 40 'x' } in
  let big_ref = (Node.to_ref big :> string) in
  Alcotest.(check int) "a >=32B node collapses to a 33-byte ref" 33 (String.length big_ref);
  Alcotest.(check string) "and the ref is 0xa0 || hash" "a0" (String.sub (to_hex big_ref) 0 2);
  let small = Node.Leaf { path = Nibbles.unpack "\x01"; value = "\x00" } in
  let small_ref = (Node.to_ref small :> string) in
  Alcotest.(check bool) "a <32B node is inlined verbatim" true (String.length small_ref < 32);
  Alcotest.(check string)
    "and the inline ref is the node's own rlp" (to_hex (Node.encode small)) (to_hex small_ref)

let test_always_hash_root () =
  (* The root is keccak256 of the root node's RLP even when that RLP is under 32
     bytes: this one-leaf trie's RLP is 5 bytes, yet its root is the hash, not the
     raw RLP (spec 5). *)
  Alcotest.(check string)
    "small root is keccak(node rlp), never the raw rlp"
    (Keccak.to_hex (Keccak.digest (hex "c482200100")))
    (ok_root (Trie.root [ ("\x01", "\x00") ]))

(* ---------- Nibbles.common_prefix_len clamps to the shorter path (G3) ---------- *)

let test_common_prefix_len () =
  let n = Nibbles.of_int_list in
  Alcotest.(check int)
    "clamps to the shorter path" 2 (Nibbles.common_prefix_len (n [ 1; 2; 3 ]) (n [ 1; 2 ]) ~from:0);
  Alcotest.(check int)
    "counts shared nibbles from 0" 3
    (Nibbles.common_prefix_len (Nibbles.unpack "\x12\x34") (Nibbles.unpack "\x12\x35") ~from:0);
  Alcotest.(check int)
    "from past the shorter length is 0" 0
    (Nibbles.common_prefix_len (n [ 1; 2 ]) (n [ 1; 2; 3 ]) ~from:5);
  Alcotest.(check int)
    "from at the exhausted length is 0" 0
    (Nibbles.common_prefix_len (n [ 1; 2 ]) (n [ 1; 2; 3 ]) ~from:2)

(* ---------- the canonical corpus ---------- *)

let run_root_cases label rootf cases =
  List.iter
    (fun (name, kvs, expected) ->
      let pairs = List.map (fun (k, v) -> (hex k, hex v)) kvs in
      Alcotest.(check string) (label ^ ": " ^ name) expected (ok_root (rootf pairs)))
    cases

(* anyorder: prefix keys (do/dog/doge, foo/food, be/bed, te/test) drive the
   branch value slot 16 (G2); hex proves values keep leading zeros (G1). *)
let test_anyorder () = run_root_cases "anyorder" Trie.root Trie_vectors.anyorder

(* trietest_reduced: branchingTests reduces to the empty root; insert-middle-leaf
   and branch-value-update are the multi-key regressions whose roots differ if the
   shared-prefix length is taken from the first two keys of a group rather than
   its sorted extremes (G3). *)
let test_trietest () = run_root_cases "trietest" Trie.root Trie_vectors.trietest_reduced

(* securetrie: keys are keccak256-hashed before insertion; values are account
   RLPs (G6 wrapper path). *)
let test_securetrie () = run_root_cases "securetrie" Trie.secure_root_of Trie_vectors.securetrie

(* ---------- ordered_trie_root (G5) + account_rlp ---------- *)

let test_ordered_root () =
  let case name items expected =
    Alcotest.(check string) ("ordered " ^ name) expected (to_hex (Trie.ordered_trie_root items))
  in
  case "[]" [] empty_root_hex;
  case "[cat]" [ "cat" ] "b423fb4e634b237f9e4fe311a0b72e299540b2407f2fe06f262cac177dd755bd";
  case "[cat,dog]" [ "cat"; "dog" ] "a2d85fc2849d6aec6107215f0e83954d4f25913d445387fc2c0ece0665219186";
  case "[0x010203]" [ hex "010203" ] "a2b827ebdbd9b2fed2315021fed07c69c3b2518f16b8e7031ea9abfd65958037";
  Alcotest.(check string)
    "ordered_rlp [cat] (Encodable variant)"
    "908502129085c0b36719165ad423378b153f91584f43ccae6da1e76ceb002742"
    (to_hex (Trie.ordered_trie_root_rlp [ "cat" ]))

let test_account_rlp () =
  let u256 n = match U256.of_int n with Some x -> x | None -> U256.zero in
  let a =
    Trie.account_rlp ~nonce:1 ~balance:(u256 0x05f446a7) ~storage_root:Trie.empty_root
      ~code_hash:(Keccak.to_bytes Keccak.empty)
  in
  (* This is exactly the a94f... account of securetrie/test1:
     [nonce=1, balance=0x05f446a7, storage_root=EMPTY_ROOT, code_hash=KECCAK_EMPTY]. *)
  Alcotest.(check string)
    "account_rlp matches the securetrie fixture account"
    ("f848018405f446a7a0" ^ empty_root_hex ^ "a0" ^ keccak_empty_hex)
    (to_hex a);
  let count = function
    | Ok (Rlp.List items) -> List.length items
    | Ok (Rlp.Str _) -> -1
    | Error _ -> -2
  in
  Alcotest.(check int) "account_rlp is a 4-element list" 4 (count (Rlp.decode_exact a));
  (* A full 32-byte balance stays a 32-byte scalar (0xa0 prefix), never trimmed;
     nonce 0 is the scalar 0x80. This pins the wide-scalar balance path. *)
  let wide =
    Trie.account_rlp ~nonce:0 ~balance:U256.max_value ~storage_root:Trie.empty_root
      ~code_hash:(Keccak.to_bytes Keccak.empty)
  in
  Alcotest.(check string)
    "account_rlp with a full 32-byte balance"
    ("f86480a0"
    ^ String.concat "" (List.init 32 (fun _ -> "ff"))
    ^ "a0" ^ empty_root_hex ^ "a0" ^ keccak_empty_hex)
    (to_hex wide)

(* ---------- (a) duplicate-key detection ---------- *)

let is_dup = function Error (Trie.Duplicate_key _) -> true | Ok _ -> false

let test_duplicate_key () =
  (* Two entries under the same key are a Duplicate_key error, not a last-writer. *)
  Alcotest.(check bool)
    "root rejects a repeated key" true
    (is_dup (Trie.root [ ("\x01\x02", "a"); ("\x01\x02", "b") ]));
  (* secure_root_of hashes keys, so two equal RAW keys collide after hashing. *)
  Alcotest.(check bool)
    "secure_root_of rejects a repeated raw key" true
    (is_dup (Trie.secure_root_of [ ("addr", "v1"); ("addr", "v2") ]));
  (* Control: distinct keys succeed, so the error is duplication, not shape. *)
  Alcotest.(check bool)
    "distinct keys are Ok" true
    (match Trie.root [ ("\x01\x02", "a"); ("\x01\x03", "b") ] with Ok _ -> true | Error _ -> false)

(* ---------- (b) state root end-to-end vs the alloy-trie 0.9.5 oracle ---------- *)

(* Cross-checked against the reth pin alloy-trie 0.9.5 [state_root_unhashed] over
   two accounts at addresses 0x00..01 (fully default) and 0x00..02 (nonce 5,
   balance 1e18). The default account pins the nonce=0/balance=0 -> 0x80 scalars. *)
let test_state_root () =
  let addr n = String.make 19 '\x00' ^ String.make 1 (Char.chr n) in
  let keccak_empty = Keccak.to_bytes Keccak.empty in
  let acct1 =
    Trie.account_rlp ~nonce:0 ~balance:U256.zero ~storage_root:Trie.empty_root
      ~code_hash:keccak_empty
  in
  let acct2 =
    Trie.account_rlp ~nonce:5
      ~balance:(match U256.of_int 1_000_000_000_000_000_000 with Some x -> x | None -> U256.zero)
      ~storage_root:Trie.empty_root ~code_hash:keccak_empty
  in
  Alcotest.(check string)
    "default account rlp pins nonce 0/balance 0 -> 0x80"
    ("f8448080a0" ^ empty_root_hex ^ "a0" ^ keccak_empty_hex)
    (to_hex acct1);
  Alcotest.(check string)
    "state root matches alloy-trie 0.9.5 oracle"
    "ce2217443ba8a430ab9035e12de17c7e9417af2bf783fbc75598f1ada377ca06"
    (ok_root (Trie.secure_root_of [ (addr 1, acct1); (addr 2, acct2) ]))

(* ---------- (c) storage root end-to-end vs the alloy-trie 0.9.5 oracle ---------- *)

(* Cross-checked against alloy-trie 0.9.5 [storage_root_unhashed] over slot 0 ->
   value 0 (RLP scalar 0x80) and slot 1 -> a full 32-byte value. The value is the
   trimmed scalar of the U256, not the raw 32 bytes. *)
let test_storage_root () =
  let slot n = String.make 31 '\x00' ^ String.make 1 (Char.chr n) in
  let scalar h =
    Rlp.encode_scalar
      (match U256.of_be_bytes (hex h) with Some x -> U256.to_be_bytes x | None -> "")
  in
  let val0 = scalar (String.make 64 '0') in
  let val1 = scalar "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210" in
  Alcotest.(check string) "zero-slot value encodes as the scalar 0x80" "80" (to_hex val0);
  Alcotest.(check string)
    "storage root matches alloy-trie 0.9.5 oracle"
    "31a782e29be953e2d774ae22e8876f56000bb8e7c32edde99af445fd7724bda3"
    (ok_root (Trie.secure_root_of [ (slot 0, val0); (slot 1, val1) ]))

(* ---------- (d) child-collapse boundary at exactly 31 and 32 bytes ---------- *)

(* The collapse rule is strictly [< 32]: a node whose own RLP is 31 bytes is
   inlined verbatim, one whose RLP is exactly 32 bytes is replaced by its 33-byte
   [0xa0 || keccak] reference. This pins the [< 32] vs [<= 32] off-by-one. The
   value length that lands the leaf on each boundary is searched for, not
   hard-coded, so the test survives an unrelated encoding tweak. *)
let test_collapse_boundary () =
  let leaf_of len = Node.Leaf { path = Nibbles.unpack "\x01"; value = String.make len 'x' } in
  let enc_len len = String.length (Node.encode (leaf_of len)) in
  let find target = List.find_opt (fun l -> enc_len l = target) (List.init 64 Fun.id) in
  match (find 31, find 32) with
  | Some l31, Some l32 ->
      let n31 = leaf_of l31 and n32 = leaf_of l32 in
      Alcotest.(check int) "the 31-byte node's rlp is 31 bytes" 31 (String.length (Node.encode n31));
      let ref31 = (Node.to_ref n31 :> string) in
      Alcotest.(check int) "a 31-byte node is inlined (ref length 31)" 31 (String.length ref31);
      Alcotest.(check string)
        "and the inline ref equals the node's own rlp" (to_hex (Node.encode n31)) (to_hex ref31);
      Alcotest.(check int) "the 32-byte node's rlp is 32 bytes" 32 (String.length (Node.encode n32));
      let ref32 = (Node.to_ref n32 :> string) in
      Alcotest.(check int) "a 32-byte node collapses to a 33-byte ref" 33 (String.length ref32);
      Alcotest.(check string)
        "and the ref is 0xa0 || keccak(rlp)"
        ("a0" ^ Keccak.to_hex (Keccak.digest (Node.encode n32)))
        (to_hex ref32)
  | Some _, None | None, Some _ | None, None ->
      Alcotest.fail "could not construct 31- and 32-byte leaf nodes"

(* ---------- (e) adjust_index_for_rlp permutation, direct unit ---------- *)

(* The three arms of alloy-trie root.rs:8-16 at the 0x7e/0x7f/0x80 boundary. A
   single-line mutation to any arm changes one of these outputs. *)
let test_adjust_index () =
  let case i len expected =
    Alcotest.(check int)
      (Printf.sprintf "adjust_index_for_rlp %d %d" i len)
      expected
      (Trie.adjust_index_for_rlp i len)
  in
  (* i > 0x7f -> i unchanged *)
  case 0x80 0x81 0x80;
  case 0xff 0x200 0xff;
  (* i = 0x7f -> 0 *)
  case 0x7f 0x80 0;
  case 0x7f 0x81 0;
  (* i + 1 = len -> 0 (including the single-item case) *)
  case 0x7e 0x7f 0;
  case 0 1 0;
  (* otherwise i + 1 *)
  case 0x7e 0x80 0x7f;
  case 0 0x200 1;
  case 5 0x200 6

let () =
  Alcotest.run "trie"
    [
      ("wiring", [ Alcotest.test_case "empty roots and keccak wiring" `Quick test_wiring ]);
      ( "hex-prefix",
        [
          Alcotest.test_case "worked examples (spec 3.2)" `Quick test_hex_prefix;
          Alcotest.test_case "encode/decode round-trip" `Quick test_hex_prefix_round_trip;
        ] );
      ( "nodes",
        [
          Alcotest.test_case "leaf round-trip (spec 4.1)" `Quick test_leaf_node;
          Alcotest.test_case "extension flag (spec 4.2)" `Quick test_extension_node;
          Alcotest.test_case "value slot uses encode_bytes (G1)" `Quick test_value_encoding;
          Alcotest.test_case "child-ref inline/hash boundary" `Quick test_child_ref_boundary;
          Alcotest.test_case "root is always hashed" `Quick test_always_hash_root;
          Alcotest.test_case "common_prefix_len clamps (G3)" `Quick test_common_prefix_len;
        ] );
      ( "corpus",
        [
          Alcotest.test_case "trieanyorder (root)" `Quick test_anyorder;
          Alcotest.test_case "trietest reduced (root)" `Quick test_trietest;
          Alcotest.test_case "securetrie (secure_root_of)" `Quick test_securetrie;
        ] );
      ( "roots",
        [
          Alcotest.test_case "ordered_trie_root (G5)" `Quick test_ordered_root;
          Alcotest.test_case "adjust_index_for_rlp permutation (G5)" `Quick test_adjust_index;
          Alcotest.test_case "account_rlp" `Quick test_account_rlp;
          Alcotest.test_case "state root vs oracle" `Quick test_state_root;
          Alcotest.test_case "storage root vs oracle" `Quick test_storage_root;
        ] );
      ( "invariants",
        [
          Alcotest.test_case "duplicate-key detection" `Quick test_duplicate_key;
          Alcotest.test_case "child-collapse 31/32 boundary" `Quick test_collapse_boundary;
        ] );
    ]
