(* Tests for the EIP-7702 wire layer: the delegation designator (its bytes, its
   classification and the write-path assignment), one authorization (its three
   signed-over fields, the 0x05 signing preimage, the six-item wire encoding
   and the three pure checks of revm's loop), and — since stage 2 — the
   type-0x04 envelope end to end: encode, decode, hash and sender recovery.

   The authorization list's state-touching half and the designator's effect on
   CALL and EXTCODE* arrive in later chunk-33 stages; where a fixture pins half
   of a rule now and half later, the comment says so rather than leaving the
   reader to wonder what the test forgot.

   The oracles are named in eip7702_vectors.ml. *)

module Delegation = Tn_state.Delegation
module Account = Tn_state.Account
module World_state = Tn_state.World_state
module Genesis_account = Tn_state.Genesis_account
module Nonce = Tn_state.Nonce
module U256 = Tn_state.U256
module Authorization = Tn_evm.Authorization
module Secp256k1 = Tn_evm.Secp256k1
module Transaction = Tn_evm.Transaction
module Tx_payload = Tn_evm.Tx_payload
module Tx_signature = Tn_evm.Tx_signature
module Tx_envelope = Tn_evm.Tx_envelope
module Tx_recovery = Tn_evm.Tx_recovery
module Block_roots = Tn_evm.Block_roots
module Executor = Tn_evm.Executor
module Receipt = Tn_evm.Receipt
module Env = Tn_evm.Env
module Block_hashes = Tn_evm.Block_hashes
module Rlp = Tn_rlp.Rlp
module Trie = Tn_trie.Trie
module Address = Tn_types.Units.Address
module V = Eip7702_vectors

let get = function Some x -> x | None -> Alcotest.fail "expected Some"
let w n = get (U256.of_int n)
let chain_one = w 1

let auth ~address ~nonce =
  get (Authorization.make ~chain_id:chain_one ~address ~nonce)

(* ---------------------------------------------------------------- *)
(* Type-0x04 builders (used from stage 2 on)                         *)
(* ---------------------------------------------------------------- *)

let b = V.hex

(* Vector 1 as a value: key 0's signed authorization over the
   (chain 1, 0x11*20, nonce 0) tuple preimage_1_to_11s pins. *)
let signed_auth_key0 =
  Authorization.sign
    (auth ~address:V.target_11s ~nonce:U256.zero)
    ~y_parity:(w V.auth_key0_y_parity) ~r:V.auth_key0_r ~s:V.auth_key0_s

(* Vector 2's payload, with the authorization list a parameter so the empty and
   multi-entry shapes reuse the sentinels. *)
let type4_payload ~authorizations =
  Tx_payload.eip7702 ~chain_id:V.type4_chain_id ~nonce:(get (Nonce.of_int V.type4_nonce))
    ~max_priority_fee_per_gas:V.type4_max_priority ~max_fee_per_gas:V.type4_max_fee
    ~gas_limit:V.type4_gas_limit ~to_:V.target_11s ~value:V.type4_value ~data:""
    ~access_list:V.type4_access_list ~authorizations

let type4_signature = Tx_signature.make ~parity:V.type4_parity ~r:V.type4_r ~s:V.type4_s

let type4_envelope =
  Tx_envelope.make ~payload:(type4_payload ~authorizations:[ signed_auth_key0 ])
    ~signature:type4_signature

(* The type-2 differential twin: the same nine shared fields and the same
   signature, so the two envelopes may differ in exactly the type byte and the
   trailing authorization list. Its encoder is pinned by the committed
   tx_vectors golden tests, which is what makes it an independent oracle for
   the type-4 field order. *)
let eip1559_twin =
  Tx_envelope.make
    ~payload:
      (Tx_payload.eip1559 ~chain_id:V.type4_chain_id
         ~nonce:(get (Nonce.of_int V.type4_nonce))
         ~max_priority_fee_per_gas:V.type4_max_priority ~max_fee_per_gas:V.type4_max_fee
         ~gas_limit:V.type4_gas_limit
         ~kind:(Transaction.Call V.target_11s)
         ~value:V.type4_value ~data:"" ~access_list:V.type4_access_list)
    ~signature:type4_signature

(* Raw-chunk builders in test_tx_envelope.ml's register, so a malformed chunk
   (a leading-zero y_parity, a 19-byte address) can be injected: encode_list
   concatenates already-encoded chunks and computes only the header. *)
let auth_chunks ~chain ~nonce ~y =
  [
    b chain;
    b ("94" ^ V.twenty_11s);
    b nonce;
    b y;
    b ("a0" ^ V.auth_key0_r_hex);
    b ("a0" ^ V.auth_key0_s_hex);
  ]

let well_formed_auth_chunks = auth_chunks ~chain:"01" ~nonce:"80" ~y:"01"

(* The thirteen chunks of a well-formed type-4 envelope: the sentinels of
   vector 2 with an EMPTY access list (c0), so the interesting chunk under test
   stands alone. *)
let t4_fields ~auth_items =
  [
    b "01";
    b "03";
    b "07";
    b "0b";
    b "830186a0";
    b ("94" ^ V.twenty_11s);
    b "0d";
    b "80";
    b "c0";
    Rlp.encode_list auth_items;
    b "80";
    b ("a0" ^ V.type4_r_hex);
    b ("a0" ^ V.type4_s_hex);
  ]

let t4_of fields = "\x04" ^ Rlp.encode_list fields
let replace i v xs = List.mapi (fun j x -> if Int.equal j i then v else x) xs

let check_reject name bytes expected =
  Alcotest.(check string)
    name
    (Tx_envelope.error_to_string expected)
    (Result.fold ~ok:(fun _ -> "Ok (accepted)") ~error:Tx_envelope.error_to_string
       (Tx_envelope.decode_2718 bytes))

let decode_ok name bytes =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "%s: %s" name (Tx_envelope.error_to_string e))
    (Tx_envelope.decode_2718 bytes)

let single_auth e =
  match Tx_payload.authorizations (Tx_envelope.payload e) with
  | [ sg ] -> sg
  | [] | _ :: _ -> Alcotest.fail "expected exactly one authorization"

(* ---------------------------------------------------------------- *)
(* 1. The designator                                                 *)
(* ---------------------------------------------------------------- *)

(* The 23 bytes are ef01 || 00 || target, they ARE the account's code, and the
   code hash is their keccak - not EIP7702_MAGIC_HASH, not KECCAK_EMPTY. *)
let test_designator_bytes_and_hash () =
  let d = get (Delegation.of_code V.designator_11s) in
  let bytes = Delegation.to_bytes d in
  Alcotest.(check int) "a designator is 23 bytes" 23 (String.length bytes);
  Alcotest.(check int) "and Delegation.length agrees" 23 Delegation.length;
  Alcotest.(check string) "the bytes are ef0100 || target" V.designator_11s_hex (V.to_hex bytes);
  Alcotest.(check string) "the magic is two bytes" "ef01" (V.to_hex Delegation.magic);
  Alcotest.(check int) "the version is zero" 0 Delegation.version;
  Alcotest.(check string)
    "bytes 3.. are exactly the target"
    (V.to_hex (Address.to_bytes V.target_11s))
    (V.to_hex (String.sub bytes 3 Address.length));
  let delegated = Account.delegate Account.empty V.target_11s in
  Alcotest.(check string)
    "a delegated account's code IS the designator" V.designator_11s_hex
    (V.to_hex (Account.code delegated));
  Alcotest.(check int) "so EXTCODESIZE reads 23" 23 (Account.code_length delegated);
  Alcotest.(check string)
    "and EXTCODEHASH reads keccak of those 23 bytes" V.designator_11s_code_hash
    (Tn_keccak.to_hex (Account.code_hash delegated));
  Alcotest.(check string)
    "which is what hashing the literal gives"
    (Tn_keccak.to_hex (Tn_keccak.digest V.designator_11s))
    (Tn_keccak.to_hex (Account.code_hash delegated));
  Alcotest.(check bool)
    "and is emphatically not KECCAK_EMPTY" false
    (Tn_keccak.equal (Account.code_hash delegated) Tn_keccak.empty)

(* Inside the magic branch revm checks LENGTH before VERSION
   ([revm-bytecode eip7702.rs:36-53]). The 22-byte bad-version blob is the only
   input that tells the two orders apart, so it is the whole test. *)
let test_designator_decode_order_length_before_version () =
  Alcotest.(check string)
    "23 bytes with version 1: the version complaint" "undecodable:unsupported_version:1"
    (V.render_code_class (Delegation.classify V.bad_version_23));
  Alcotest.(check string)
    "22 bytes with version 1: the LENGTH complaint, because length is checked first"
    "undecodable:invalid_length:22"
    (V.render_code_class (Delegation.classify V.bad_version_22));
  Alcotest.(check string)
    "60 magic-prefixed bytes are a length complaint too" "undecodable:invalid_length:60"
    (V.render_code_class (Delegation.classify (V.hex ("ef01" ^ String.make 116 'a'))));
  Alcotest.(check string)
    "and a well-formed one names its target"
    ("delegated:" ^ V.twenty_11s)
    (V.render_code_class (Delegation.classify V.designator_11s))

(* Classification keys on the first TWO bytes alone
   ([revm-bytecode bytecode.rs:101-110]). A three-byte 0xEF0100 test would read
   the bad-version blob as ordinary code, which is the mutation this catches. *)
let test_classify_is_two_byte_prefix () =
  Alcotest.(check string)
    "0xEF but not 0xEF01 is ordinary code" "contract"
    (V.render_code_class (Delegation.classify (V.hex ("ef00" ^ String.make 42 '0'))));
  Alcotest.(check string)
    "a lone 0xEF cannot even be prefixed" "contract"
    (V.render_code_class (Delegation.classify "\xef"));
  Alcotest.(check string)
    "ordinary bytecode is ordinary" "contract"
    (V.render_code_class (Delegation.classify "\x60\x01"));
  Alcotest.(check string) "no code is codeless" "codeless"
    (V.render_code_class (Delegation.classify ""));
  Alcotest.(check bool)
    "of_code collapses the undecodable blob to None" false
    (Option.is_some (Delegation.of_code V.bad_version_23));
  (* The documented divergence direction: bytes we cannot classify block a
     delegation, because they are not a designator. *)
  Alcotest.(check bool)
    "and is_contract_code calls it contract code" true
    (Delegation.is_contract_code V.bad_version_23);
  Alcotest.(check bool) "a real designator is not contract code" false
    (Delegation.is_contract_code V.designator_11s);
  Alcotest.(check bool) "nor is no code" false (Delegation.is_contract_code "");
  Alcotest.(check bool) "one byte of code is" true (Delegation.is_contract_code "\x60")

(* The write path cannot express a zero-pointing designator; the read path can,
   and must ([revm-context-interface journaled_state/account.rs:448-459] for the
   first half, [bytecode.rs:101-110] for the second). *)
let test_assignment_zero_is_revoke_but_read_path_accepts () =
  Alcotest.(check string) "the zero address assigns a revocation" "revoke"
    (V.render_assignment (Delegation.assignment Address.zero));
  Alcotest.(check int)
    "which installs ZERO bytes, not 23" 0
    (String.length (Delegation.code_of_assignment (Delegation.assignment Address.zero)));
  Alcotest.(check string)
    "a nonzero address assigns a designator"
    ("assign:" ^ V.twenty_11s)
    (V.render_assignment (Delegation.assignment V.target_11s));
  Alcotest.(check int)
    "which installs 23" 23
    (String.length (Delegation.code_of_assignment (Delegation.assignment V.target_11s)));
  (* Read path: ef0100 || 0x00*20 in a genesis allocation IS a designator, and
     it points at the codeless zero account. *)
  Alcotest.(check string)
    "but 23 bytes pointing at zero classify as delegated"
    ("delegated:" ^ String.make 40 '0')
    (V.render_code_class (Delegation.classify V.designator_zero));
  let revoked = Account.delegate (Account.delegate Account.empty V.target_11s) Address.zero in
  Alcotest.(check int) "revoking leaves no code" 0 (Account.code_length revoked);
  Alcotest.(check bool) "and restores KECCAK_EMPTY" true
    (Tn_keccak.equal (Account.code_hash revoked) Tn_keccak.empty);
  (* The bump is what keeps the revoked authority out of EIP-161's clearing. *)
  Alcotest.(check int) "while the nonce has been bumped twice" 2
    (Nonce.to_int (Account.nonce revoked));
  Alcotest.(check bool) "so the account is not empty" false (Account.is_empty revoked)

(* revm's [delegate] discards the boolean [bump_nonce] returns
   ([journaled_state/account.rs:392-400,448-459]), so a saturated nonce leaves
   the nonce alone and STILL takes the code. The live loop cannot reach this -
   check 2 rejects u64::MAX and check 6 forces equality - so only a direct unit
   test can. A port that raised here, or that skipped the code write when the
   bump failed, would diverge in an adversarial state. *)
let test_nonce_saturation_still_sets_code () =
  let saturated = Account.make ~nonce:(get (Nonce.of_int max_int)) ~balance:U256.zero in
  let delegated = Account.delegate saturated V.target_11s in
  Alcotest.(check int) "the nonce is unchanged, not bumped and not raised" max_int
    (Nonce.to_int (Account.nonce delegated));
  Alcotest.(check string) "and the code is still set" V.designator_11s_hex
    (V.to_hex (Account.code delegated));
  (* The control: an unsaturated account really does bump, so the assertion
     above is about saturation and not about delegate never bumping. *)
  let fresh = Account.delegate Account.empty V.target_11s in
  Alcotest.(check int) "an unsaturated account bumps" 1 (Nonce.to_int (Account.nonce fresh))

(* A well-formed designator is admitted at genesis and is LIVE with no
   authorization involved; a malformed 0xef01 allocation is refused at the door,
   which is what keeps [Delegation.Undecodable] unreachable from any world a
   transaction runs against.

   DEFERRED to the stage that lands the call-time resolver: that a transaction
   sent to the admitted address runs the delegate's code. This stage pins
   admission and classification only. *)
let test_genesis_designator_is_live_and_malformed_rejected () =
  let entry code storage =
    Genesis_account.make ~nonce:Nonce.zero ~balance:U256.zero ~code ~storage
  in
  let load code storage = World_state.of_genesis_alloc [ (V.target_0b, entry code storage) ] in
  let render = Result.fold ~ok:(fun _ -> "ok") ~error:V.render_alloc_error in
  Alcotest.(check string)
    "21 magic-prefixed bytes are refused, naming the address and the length"
    ("malformed_delegation:" ^ String.make 38 '0' ^ "0b:invalid_length:21")
    (render (load (Some (V.hex ("ef01" ^ String.make 38 'a'))) []));
  Alcotest.(check string) "a well-formed designator is admitted" "ok"
    (render (load (Some V.designator_11s) []));
  (* The check ORDER: the pre-existing storage refusal keeps its identity for
     its own input, so adding the delegation check did not reorder anything. *)
  Alcotest.(check string)
    "and storage on a codeless entry still reports Storage_without_code"
    ("storage_without_code:" ^ String.make 38 '0' ^ "0b")
    (render (load None [ (U256.one, U256.one) ]));
  let world = get (Result.to_option (load (Some V.designator_11s) [])) in
  let seeded = World_state.account world V.target_0b in
  Alcotest.(check string) "the admitted account classifies as delegated"
    ("delegated:" ^ V.twenty_11s)
    (V.render_code_class (Account.code_class seeded));
  Alcotest.(check string) "and names its delegate"
    V.twenty_11s
    (V.to_hex (Address.to_bytes (get (Account.delegation seeded))))

(* ---------------------------------------------------------------- *)
(* 2. The authorization                                              *)
(* ---------------------------------------------------------------- *)

(* keccak(0x05 || rlp([chain_id, address, nonce])) -- the magic is 0x05 and not
   the type byte 0x04, it sits OUTSIDE the list, the list header is present, and
   the list holds three items. Each of those four is a way to recover a
   perfectly well-formed address belonging to nobody, so each gets a leg. *)
let test_authorization_signing_preimage_literal () =
  let a = auth ~address:V.target_11s ~nonce:U256.zero in
  Alcotest.(check int) "the magic is 0x05" 5 Authorization.magic;
  Alcotest.(check string)
    "the three-item RLP is the 24 bytes after the magic"
    (String.sub V.preimage_1_to_11s_hex 2 48)
    (V.to_hex (Authorization.encode a));
  Alcotest.(check int) "so the preimage is 25 bytes" 25 (String.length V.preimage_1_to_11s);
  Alcotest.(check int) "and begins with the magic byte" Authorization.magic
    (Char.code V.preimage_1_to_11s.[0]);
  Alcotest.(check string) "signature_hash is keccak of exactly that preimage"
    (Tn_keccak.to_hex (Tn_keccak.digest V.preimage_1_to_11s))
    (V.to_hex (Authorization.signature_hash a));
  let rlp = Authorization.encode a in
  Alcotest.(check bool)
    "prefixing 0x04 instead would hash to something else" false
    (String.equal (Authorization.signature_hash a)
       (Tn_keccak.to_bytes (Tn_keccak.digest ("\x04" ^ rlp))));
  Alcotest.(check bool)
    "and so would dropping the list header" false
    (String.equal (Authorization.signature_hash a)
       (Tn_keccak.to_bytes
          (Tn_keccak.digest ("\x05" ^ String.sub rlp 1 (String.length rlp - 1)))))

(* y_parity, r and s are not in the preimage. The type system already says so -
   [signature_hash] takes a [t] and only [unsigned] produces one from a [signed]
   - so this test pins the guarantee against a refactor that widens it. *)
let test_authorization_preimage_excludes_signature () =
  let a = auth ~address:V.target_11s ~nonce:U256.zero in
  let one = Authorization.sign a ~y_parity:U256.zero ~r:V.r_ones ~s:V.s_twos in
  let other = Authorization.sign a ~y_parity:U256.one ~r:V.s_twos ~s:V.r_ones in
  Alcotest.(check string)
    "two signatures over the same tuple share a preimage hash"
    (V.to_hex (Authorization.signature_hash (Authorization.unsigned one)))
    (V.to_hex (Authorization.signature_hash (Authorization.unsigned other)));
  Alcotest.(check string) "which is the unsigned tuple's own"
    (V.to_hex (Authorization.signature_hash a))
    (V.to_hex (Authorization.signature_hash (Authorization.unsigned other)));
  Alcotest.(check int) "and is 32 bytes" 32
    (String.length (Authorization.signature_hash a))

(* alloy's hand-written encoder ([auth_list.rs:224-233]): six items with the
   parity FIRST of the three signature ones, and every scalar minimal-length, so
   a zero parity is 0x80 and never a literal 0x00. *)
let test_signed_authorization_rlp_six_items () =
  let a = auth ~address:V.target_0b ~nonce:U256.zero in
  let sg = Authorization.sign a ~y_parity:U256.zero ~r:V.r_ones ~s:V.s_twos in
  let enc = Authorization.encode_signed sg in
  Alcotest.(check string) "the six-item list, byte for byte" V.signed_six_item_hex (V.to_hex enc);
  Alcotest.(check int) "92 bytes in all" 92 (String.length enc);
  Alcotest.(check int) "the y_parity slot holds 0x80, never 0x00" 0x80
    (Char.code enc.[V.y_parity_slot]);
  (* The parity really is a wire value wider than a bool: 2 signs fine and is
     only rejected at recovery. *)
  let parity_two = Authorization.sign a ~y_parity:(w 2) ~r:V.r_ones ~s:V.s_twos in
  Alcotest.(check int) "a parity of 2 encodes as the byte 0x02" 0x02
    (Char.code (Authorization.encode_signed parity_two).[V.y_parity_slot]);
  Alcotest.(check bool) "and only then makes that one authorization a no-op" false
    (Option.is_some (Authorization.screen ~chain_id:chain_one parity_two))

(* EIP-2's bound is compared with a STRICT > ([auth_list.rs:248-256]): an s
   exactly equal to floor(n/2) is ACCEPTED. Both directions, and the shared
   primitive is pinned alongside so the two cannot drift. *)
let test_high_s_is_strict () =
  Alcotest.(check string)
    "the derived bound is alloy's SECP256K1N_HALF" V.secp256k1n_half_hex
    (U256.to_hex Authorization.secp256k1n_half);
  Alcotest.(check bool) "an s exactly at the bound is NOT high" false
    (Secp256k1.s_is_high (U256.to_be_bytes V.secp256k1n_half));
  Alcotest.(check bool) "one above it is" true
    (Secp256k1.s_is_high (U256.to_be_bytes V.secp256k1n_half_plus_one));
  let a = auth ~address:V.target_11s ~nonce:U256.zero in
  let at_bound = Authorization.sign a ~y_parity:U256.zero ~r:V.curve_valid_r ~s:V.secp256k1n_half in
  let above =
    Authorization.sign a ~y_parity:U256.zero ~r:V.curve_valid_r ~s:V.secp256k1n_half_plus_one
  in
  Alcotest.(check bool) "so an authorization at the bound screens through" true
    (Option.is_some (Authorization.screen ~chain_id:chain_one at_bound));
  Alcotest.(check bool) "and one byte-value above it is skipped" false
    (Option.is_some (Authorization.screen ~chain_id:chain_one above))

(* The authorization nonce spans the whole u64 range - wider than this port's
   [Nonce.t], which is a 63-bit int - and its saturation is a per-entry SKIP,
   never a decode error and never a transaction error. The wire legs (an
   eight-byte nonce decodes, a nine-byte one is Scalar_too_wide, a saturated
   one decodes and only then skips) landed with the stage-2 decoder, below.

   STILL DEFERRED to the stage that lands the loop: that a merely-mismatched
   nonce skips at check 6 rather than rejecting the transaction. *)
let test_auth_nonce_width_u64 () =
  let two_pow_64 = U256.two_pow 64 in
  let make nonce = Authorization.make ~chain_id:chain_one ~address:V.target_11s ~nonce in
  Alcotest.(check bool) "a nonce at 2^64 cannot be written down" false
    (Option.is_some (make two_pow_64));
  Alcotest.(check bool) "2^64 - 1 can" true
    (Option.is_some (make (U256.sub two_pow_64 U256.one)));
  Alcotest.(check bool) "and so can 2^63, which no OCaml int nonce could hold" true
    (Option.is_some (make (U256.two_pow 63)));
  let screened nonce =
    Option.is_some
      (Authorization.screen ~chain_id:chain_one
         (Authorization.sign
            (auth ~address:V.target_11s ~nonce)
            ~y_parity:U256.zero ~r:V.curve_valid_r ~s:V.secp256k1n_half))
  in
  Alcotest.(check bool) "a u64::MAX nonce is skipped before recovery ever runs" false
    (screened (U256.sub two_pow_64 U256.one));
  (* The control: the same entry one nonce lower recovers, so the skip above is
     check 2's and not the signature's. *)
  Alcotest.(check bool) "while 2^64 - 2 screens through" true
    (screened (U256.sub two_pow_64 (w 2)));
  (* The wire legs. An eight-byte nonce (2^63) DECODES — no OCaml int nonce
     could hold it, which is why the field is a word — and so does the
     saturated u64::MAX, whose skip is [screen]'s, never the decoder's. Nine
     bytes are one wider than alloy's u64 and are refused as a scalar. *)
  let of_nonce nonce =
    t4_of (t4_fields ~auth_items:[ Rlp.encode_list (auth_chunks ~chain:"01" ~nonce ~y:"01") ])
  in
  let wire_nonce nonce =
    Authorization.nonce
      (Authorization.unsigned (single_auth (decode_ok "8-byte nonce" (of_nonce nonce))))
  in
  Alcotest.(check bool) "an 8-byte wire nonce of 2^63 decodes to exactly 2^63" true
    (U256.equal (U256.two_pow 63) (wire_nonce "888000000000000000"));
  Alcotest.(check bool) "a u64::MAX wire nonce decodes" true
    (U256.equal
       (U256.sub two_pow_64 U256.one)
       (wire_nonce "88ffffffffffffffff"));
  Alcotest.(check bool) "and only then is skipped, by screen" false
    (Option.is_some
       (Authorization.screen ~chain_id:chain_one
          (single_auth (decode_ok "saturated nonce" (of_nonce "88ffffffffffffffff")))));
  check_reject "a 9-byte wire nonce is Scalar_too_wide"
    (of_nonce "890100000000000000ff")
    Tx_envelope.Scalar_too_wide

(* Vector 1, end to end: key 0's RFC-6979 signature over the exact tuple
   preimage_1_to_11s pins, produced by the pinned-crate cargo oracle. The
   port's encoder must reproduce alloy's six-item bytes, its preimage keccak
   must equal alloy's [signature_hash], and [screen] must recover exactly key
   0's address — the one line no self-referential test could pin, because it
   needs a signer to RUN. *)
let test_authorization_end_to_end_key0 () =
  Alcotest.(check string)
    "the six-item encoding is alloy's, byte for byte" V.auth_key0_signed_rlp_hex
    (V.to_hex (Authorization.encode_signed signed_auth_key0));
  Alcotest.(check string)
    "the signing hash is alloy's own keccak" V.auth_signature_hash_hex
    (V.to_hex (Authorization.signature_hash (Authorization.unsigned signed_auth_key0)));
  let scr = get (Authorization.screen ~chain_id:chain_one signed_auth_key0) in
  Alcotest.(check string)
    "and recovery answers key 0's address" V.authority_key0_hex
    (V.to_hex (Address.to_bytes (Authorization.authority scr)));
  Alcotest.(check bool) "the carried nonce is the signed one" true
    (U256.is_zero (Authorization.screened_nonce scr));
  Alcotest.(check string) "and the assignment is a designator to the target"
    ("assign:" ^ V.twenty_11s)
    (V.render_assignment (Authorization.screened_assignment scr))

(* ---------------------------------------------------------------- *)
(* 3. The type-0x04 envelope (stage 2)                               *)
(* ---------------------------------------------------------------- *)

(* Positional access without an index: the first two bytes as codes (-1 for a
   missing position, which no assertion below expects), and the tail behind the
   type byte, both by structural list matches. *)
let first_two s =
  match List.of_seq (String.to_seq s) with
  | a :: b :: _ -> (Char.code a, Char.code b)
  | [ a ] -> (Char.code a, -1)
  | [] -> (-1, -1)

let strip_first s =
  match List.of_seq (String.to_seq s) with
  | [] -> s
  | _ :: rest -> String.of_seq (List.to_seq rest)

let rec render_rlp item =
  match item with
  | Rlp.Str s -> "s:" ^ V.to_hex s
  | Rlp.List xs -> "l[" ^ String.concat ";" (List.map render_rlp xs) ^ "]"

let items_of name bytes =
  Result.fold
    ~error:(fun e -> Alcotest.failf "%s: %s" name (Rlp.error_to_string e))
    ~ok:(fun item ->
      match item with
      | Rlp.Str _ -> Alcotest.failf "%s: expected a list" name
      | Rlp.List items -> items)
    (Rlp.decode_exact bytes)

let check_accept name bytes =
  Alcotest.(check string)
    name "Ok (accepted)"
    (Result.fold ~ok:(fun _ -> "Ok (accepted)") ~error:Tx_envelope.error_to_string
       (Tx_envelope.decode_2718 bytes))

(* THE field-order test, with an independent oracle: the 1559 encoder is pinned
   by the committed tx_vectors goldens, so agreement item by item on the nine
   shared fields is evidence about the type-4 encoder alone. The sentinels are
   pairwise distinct (nonce 3, priority 7, fee 11, value 13), so a port that
   copied alloy's STRUCT order — gas_limit before the fee caps, access_list
   before input — swaps two recognisable numbers and fails on the spot. *)
let test_type4_wire_prefix_matches_1559_differentially () =
  let e4 = Tx_envelope.encode_2718 type4_envelope in
  let e2 = Tx_envelope.encode_2718 eip1559_twin in
  Alcotest.(check int) "the type byte is 0x04" 4 (fst (first_two e4));
  Alcotest.(check int) "against the twin's 0x02" 2 (fst (first_two e2));
  let items4 = items_of "type-4 body" (strip_first e4) in
  let items2 = items_of "type-2 body" (strip_first e2) in
  Alcotest.(check int) "13 items against" 13 (List.length items4);
  Alcotest.(check int) "12" 12 (List.length items2);
  let rendered4 = List.map render_rlp items4 in
  let rendered2 = List.map render_rlp items2 in
  let prefix = List.filteri (fun i _ -> i < 9) in
  let suffix = List.filteri (fun i _ -> i >= 9) in
  (* chain_id 1, nonce 3, tip 7, fee 11, gas 0x0186a0, to, value 13, empty
     input, then the access list — item 8, BEFORE the authorization list. *)
  let expected_shared =
    [
      "s:01";
      "s:03";
      "s:07";
      "s:0b";
      "s:0186a0";
      "s:" ^ V.twenty_11s;
      "s:0d";
      "s:";
      "l[l[s:" ^ Tx_vectors.to_b ^ ";l[s:" ^ String.make 62 '0' ^ "01]]]";
    ]
  in
  let expected_auth_item =
    "l[s:01;s:" ^ V.twenty_11s ^ ";s:;s:01;s:" ^ V.auth_key0_r_hex ^ ";s:"
    ^ V.auth_key0_s_hex ^ "]"
  in
  let expected_tail = [ "s:"; "s:" ^ V.type4_r_hex; "s:" ^ V.type4_s_hex ] in
  Alcotest.(check (list string))
    "items 0..8 of type 4 are the sentinels in 1559 order" expected_shared
    (prefix rendered4);
  Alcotest.(check (list string))
    "and are structurally identical to the 1559 twin's" expected_shared (prefix rendered2);
  Alcotest.(check (list string))
    "the ONE extra item is the authorization list, at position 9"
    (("l[" ^ expected_auth_item ^ "]") :: expected_tail)
    (suffix rendered4);
  Alcotest.(check (list string))
    "while the twin goes straight to the same v, r, s" expected_tail (suffix rendered2)

(* The golden vector 2 from the pinned-crate oracle, plus the round-trip
   theorem extended to type 4: decode inverts encode on the nose, the signing
   payload is 0x04 || <list header> with no outer string, and the hash is
   keccak over the BARE 2718 bytes — string-framing it changes the hash. *)
let test_type4_roundtrip_and_hash () =
  let golden = b V.type4_encoded_2718_hex in
  Alcotest.(check string)
    "encode_2718 reproduces alloy's bytes" V.type4_encoded_2718_hex
    (V.to_hex (Tx_envelope.encode_2718 type4_envelope));
  let p = Tx_envelope.payload type4_envelope in
  Alcotest.(check string)
    "the signing payload is alloy's encode_for_signing" V.type4_signing_payload_hex
    (V.to_hex (Tx_envelope.signing_payload p));
  Alcotest.(check string)
    "and its keccak is alloy's signature_hash" V.type4_signing_hash_hex
    (V.to_hex (Tx_envelope.signature_hash p));
  let type_code, header_code = first_two (Tx_envelope.signing_payload p) in
  Alcotest.(check int) "the signing payload starts with the raw 0x04" 4 type_code;
  Alcotest.(check bool) "followed directly by a LIST header, no outer string" true
    (header_code >= 0xc0);
  Alcotest.(check string) "the tx hash is alloy's" V.type4_tx_hash_hex
    (V.to_hex (Tx_envelope.hash type4_envelope));
  Alcotest.(check string) "which is keccak of the bare 2718 bytes" V.type4_tx_hash_hex
    (V.to_hex (Tx_envelope.hash_of_2718 golden));
  Alcotest.(check bool) "and NOT of the string-framed network form" false
    (String.equal
       (Tx_envelope.hash type4_envelope)
       (Tx_envelope.hash_of_2718 (Rlp.encode_bytes golden)));
  Alcotest.(check string)
    "decode inverts encode on the golden bytes" V.type4_encoded_2718_hex
    (V.to_hex (Tx_envelope.encode_2718 (decode_ok "golden" golden)));
  Result.fold
    ~error:(fun e -> Alcotest.failf "recover: %s" (Tx_recovery.error_to_string e))
    ~ok:(fun t ->
      Alcotest.(check string)
        "and recovery answers key 1's address" V.sender_key1_hex
        (V.to_hex (Address.to_bytes (Transaction.sender t)));
      Alcotest.(check int) "carrying the one authorization" 1
        (List.length (Transaction.authorizations t)))
    (Tx_recovery.recover (decode_ok "golden" golden));
  (* The round trip over constructed envelopes with 0..3 authorizations,
     including a zero parity (whose y_parity item must be 0x80, the RLP scalar
     zero, never a literal 0x00) and a parity of 2 (legal on the wire). *)
  let parity0 =
    Authorization.sign (auth ~address:V.target_0b ~nonce:U256.zero) ~y_parity:U256.zero
      ~r:V.r_ones ~s:V.s_twos
  in
  let parity2 =
    Authorization.sign (auth ~address:V.target_11s ~nonce:U256.one) ~y_parity:(w 2)
      ~r:V.r_ones ~s:V.s_twos
  in
  List.iter
    (fun (label, auths) ->
      let e =
        Tx_envelope.make ~payload:(type4_payload ~authorizations:auths)
          ~signature:type4_signature
      in
      let enc = Tx_envelope.encode_2718 e in
      Alcotest.(check string)
        ("round trip: " ^ label) (V.to_hex enc)
        (V.to_hex (Tx_envelope.encode_2718 (decode_ok label enc))))
    [
      ("no authorizations", []);
      ("one", [ signed_auth_key0 ]);
      ("parity 0 and parity 2", [ parity0; parity2 ]);
      ("three", [ signed_auth_key0; parity0; parity2 ]);
    ]

(* Both are DECODE successes, handled later and elsewhere: the empty list is
   validation's rejection ([revm-handler validation.rs:199-203], the executor
   stage of this chunk), and a parity of 2 no-ops its ONE authorization at
   recovery ([auth_list.rs:135-141]). Under [read_parity] the parity-2 case
   would be [Invalid_bool] and would kill the whole transaction — the
   divergence this test exists to prevent. *)
let test_type4_decode_accepts_empty_list_and_parity_two () =
  let empty =
    Tx_envelope.encode_2718
      (Tx_envelope.make ~payload:(type4_payload ~authorizations:[])
         ~signature:type4_signature)
  in
  let e = decode_ok "empty authorization list" empty in
  Alcotest.(check int) "an empty authorization list decodes to zero entries" 0
    (List.length (Tx_payload.authorizations (Tx_envelope.payload e)));
  Alcotest.(check string) "and round-trips" (V.to_hex empty)
    (V.to_hex (Tx_envelope.encode_2718 e));
  let of_y y =
    t4_of (t4_fields ~auth_items:[ Rlp.encode_list (auth_chunks ~chain:"01" ~nonce:"80" ~y) ])
  in
  let sg = single_auth (decode_ok "parity 2" (of_y "02")) in
  Alcotest.(check bool) "a y_parity of 2 decodes with its value intact" true
    (U256.equal (w 2) (Authorization.y_parity sg));
  Alcotest.(check bool) "its signature narrows to None" false
    (Option.is_some (Authorization.signature sg));
  Alcotest.(check bool) "and screen skips that one entry" false
    (Option.is_some (Authorization.screen ~chain_id:chain_one sg));
  check_accept "a zero y_parity (0x80) decodes" (of_y "80");
  check_reject "a literal 0x00 y_parity is a leading zero" (of_y "00")
    Tx_envelope.Leading_zero_scalar;
  check_reject "a two-byte y_parity is over-wide" (of_y "820101")
    Tx_envelope.Scalar_too_wide

(* A set-code CREATE is a decode error, never a create reading: [to] is a bare
   address ([eip7702.rs:58]), read with [read_fixed] and not [read_kind], so
   the empty string that means "create" one type down is a width complaint
   here. *)
let test_type4_to_is_mandatory_address () =
  let base = t4_fields ~auth_items:[ Rlp.encode_list well_formed_auth_chunks ] in
  check_accept "the base thirteen-chunk vector decodes" (t4_of base);
  check_reject "an empty-string to (the 'create' spelling) is a width error"
    (t4_of (replace 5 (b "80") base))
    (Tx_envelope.Fixed_width { expected = 20; got = 0 });
  check_reject "a 19-byte to is the same width error"
    (t4_of (replace 5 (b ("93" ^ String.make 38 '1')) base))
    (Tx_envelope.Fixed_width { expected = 20; got = 19 })

(* The two deliberate framing narrowings apply to type 4 verbatim, the
   authorization layer inherits the list/string discipline, and the decoder
   widened by EXACTLY one type byte: the pre-existing Unknown_type_byte
   assertions for 0x03, 0x05 and 0x7f in test_tx_envelope.ml pass UNEDITED, and
   0x03/0x05 are re-checked here against a REAL type-4 body. *)
let test_type4_framing_narrowings_inherited () =
  let golden = b V.type4_encoded_2718_hex in
  let bare = strip_first golden in
  check_accept "the canonical golden decodes" golden;
  check_reject "0x00 || rlp(type-4 body) is the zero-tagged framing" ("\x00" ^ bare)
    Tx_envelope.Zero_type_byte;
  check_reject "the string-framed network form is refused" (Rlp.encode_bytes golden)
    Tx_envelope.Outer_string;
  check_reject "type byte 0x03 (EIP-4844) still has no reader" ("\x03" ^ bare)
    (Tx_envelope.Unknown_type_byte 3);
  check_reject "and 0x05 is still unassigned" ("\x05" ^ bare)
    (Tx_envelope.Unknown_type_byte 5);
  let base = t4_fields ~auth_items:[ Rlp.encode_list well_formed_auth_chunks ] in
  check_reject "an authorization list that is a byte string"
    (t4_of (replace 9 (b "81ff") base))
    Tx_envelope.Unexpected_string;
  check_reject "a byte string among the authorizations"
    (t4_of (replace 9 (Rlp.encode_list [ b "81ff" ]) base))
    Tx_envelope.Unexpected_string;
  check_reject "a seven-item authorization tuple"
    (t4_of
       (replace 9
          (Rlp.encode_list [ Rlp.encode_list (well_formed_auth_chunks @ [ b "80" ]) ])
          base))
    (Tx_envelope.Field_count { expected = 6; got = 7 })

(* The authorization chain_id is a full U256 ([auth_list.rs:47]) compared over
   all 256 bits, and zero means "any chain". A low-64-bit comparison would make
   2^64 + 2017 truncate to 2017 and wrongly apply; truncating a wide value to
   zero would make it valid on every chain.

   DEFERRED to the stage that lands the loop: the [dispositions] identity
   (Chain_id_mismatch) and that a mismatched entry warms nothing. This stage
   pins the wire width and screen's verdicts. *)
let test_auth_chain_id_is_u256_and_zero_is_any_chain () =
  let of_chain chain =
    t4_of (t4_fields ~auth_items:[ Rlp.encode_list (auth_chunks ~chain ~nonce:"80" ~y:"01") ])
  in
  (* 2^64 + 2017: a nine-byte scalar, transaction-fatal one layer down. *)
  let sg = single_auth (decode_ok "9-byte auth chain id" (of_chain "890100000000000007e1")) in
  Alcotest.(check bool) "a 9-byte auth chain_id decodes with its value intact" true
    (U256.equal
       (U256.add (U256.two_pow 64) (w 2017))
       (Authorization.chain_id (Authorization.unsigned sg)));
  Alcotest.(check bool) "and is a MISMATCH against 2017, not a truncated match" false
    (Option.is_some (Authorization.screen ~chain_id:(w 2017) sg));
  check_reject "while a 33-byte chain_id is wider than a U256"
    (of_chain ("a1" ^ "01" ^ String.make 64 '0'))
    Tx_envelope.Scalar_too_wide;
  let entry chain_id =
    Authorization.sign
      (get (Authorization.make ~chain_id ~address:V.target_11s ~nonce:U256.zero))
      ~y_parity:U256.zero ~r:V.curve_valid_r ~s:V.secp256k1n_half
  in
  Alcotest.(check bool) "chain_id zero screens through on chain 1" true
    (Option.is_some (Authorization.screen ~chain_id:chain_one (entry U256.zero)));
  Alcotest.(check bool) "and on chain 2017: zero means any chain" true
    (Option.is_some (Authorization.screen ~chain_id:(w 2017) (entry U256.zero)));
  Alcotest.(check bool) "an exact 2017 matches 2017" true
    (Option.is_some (Authorization.screen ~chain_id:(w 2017) (entry (w 2017))));
  Alcotest.(check bool) "and mismatches chain 1" false
    (Option.is_some (Authorization.screen ~chain_id:chain_one (entry (w 2017))))

(* [Block_roots.type_byte] answers 4 for a [Set_code] transaction, so the
   transactions-trie leaf for a type-4 transaction is 0x04 || rlp(...) and the
   receipts-trie leaf gets the same tag. A wrong byte is a wrong root for every
   block containing a 7702 transaction. *)
let test_transactions_trie_type_byte_is_4 () =
  Result.fold
    ~error:(fun e -> Alcotest.failf "recover: %s" (Tx_recovery.error_to_string e))
    ~ok:(fun t ->
      Alcotest.(check int) "type_byte of a recovered type-4 transaction" 4
        (Block_roots.type_byte t))
    (Tx_recovery.recover type4_envelope);
  let direct =
    Transaction.set_code ~sender:V.sender_key1 ~nonce:Nonce.zero ~gas_limit:100_000
      ~target:V.target_11s ~value:U256.zero ~data:"" ~access_list:[] ~chain_id:chain_one
      ~max_priority_fee_per_gas:V.type4_max_priority ~max_fee_per_gas:V.type4_max_fee
      ~authorizations:[ signed_auth_key0 ]
  in
  Alcotest.(check int) "and of a directly built one" 4 (Block_roots.type_byte direct);
  let golden = b V.type4_encoded_2718_hex in
  Alcotest.(check string)
    "the one-transaction trie root is over the bare 2718 leaf"
    (V.to_hex (Trie.ordered_trie_root [ golden ]))
    (V.to_hex (Block_roots.transactions_root_of [ type4_envelope ]));
  let retagged = "\x02" ^ strip_first golden in
  Alcotest.(check bool) "and differs from the same body tagged 0x02" false
    (String.equal (Trie.ordered_trie_root [ golden ]) (Trie.ordered_trie_root [ retagged ]))

(* JUDGE ADDITION. The one residual illegal state in [Transaction.t] — [make
   ~kind:Create] with a [Set_code] fee — is unobservable: [kind] derives [Call
   target] from the fee arm itself, execution runs the call path, and no
   creation surcharge is charged. Pinned differentially against the type-2
   twin, so the assertion survives the later stages: the only admissible gas
   growth for the type-4 side is the per-authorization intrinsic (25000 for the
   one listed entry here), always strictly below the 32000 creation
   surcharge. *)
let test_set_code_create_is_unobservable () =
  let kind_render k =
    match k with
    | Transaction.Call a -> "call:" ^ V.to_hex (Address.to_bytes a)
    | Transaction.Create -> "create"
  in
  let fee =
    Transaction.Set_code
      {
        max_fee = V.type4_max_fee;
        max_priority = V.type4_max_priority;
        target = V.target_11s;
        authorizations = [ signed_auth_key0 ];
      }
  in
  let sender = V.sender_key1 in
  let tx_of kind fee =
    Transaction.make ~sender ~nonce:Nonce.zero ~gas_limit:100_000 ~kind ~value:(w 13)
      ~data:"" ~access_list:[] ~chain_id:(Some chain_one) ~fee
  in
  Alcotest.(check string)
    "make ~kind:Create with a Set_code fee reads back as the call"
    ("call:" ^ V.twenty_11s)
    (kind_render (Transaction.kind (tx_of Transaction.Create fee)));
  let via_smart =
    Transaction.set_code ~sender ~nonce:Nonce.zero ~gas_limit:100_000
      ~target:V.target_11s ~value:(w 13) ~data:"" ~access_list:[] ~chain_id:chain_one
      ~max_priority_fee_per_gas:V.type4_max_priority ~max_fee_per_gas:V.type4_max_fee
      ~authorizations:[ signed_auth_key0 ]
  in
  Alcotest.(check string)
    "as does the smart constructor, which cannot even spell Create"
    ("call:" ^ V.twenty_11s)
    (kind_render (Transaction.kind via_smart));
  (* Execution: the Create-built and Call-built transactions are one
     transaction. *)
  let world =
    World_state.set_account World_state.empty sender
      (Account.make ~nonce:Nonce.zero ~balance:(w 100_000_000))
  in
  let block =
    Env.Block.make
      ~coinbase:(V.addr_of_hex (String.make 38 '0' ^ "cc"))
      ~timestamp:(w 1_600_000_000) ~number:(w 1000) ~prevrandao:U256.zero
      ~gas_limit:(w 30_000_000) ~basefee:U256.zero
      ~basefee_address:Tn_evm.System_contracts.governance_safe_address
      ~chain_id:chain_one ~hashes:Block_hashes.empty
  in
  let run tx =
    Result.fold
      ~error:(fun e ->
        Alcotest.failf "unexpected rejection: %s" (Executor.error_to_string e))
      ~ok:Fun.id
      (Executor.execute world ~block tx)
  in
  let parts r =
    match r with
    | Receipt.Success { output; created; gas_used; gas_refunded; logs = _ } ->
        (output, created, gas_used, gas_refunded)
    | Receipt.Reverted _ | Receipt.Halted _ -> Alcotest.fail "expected Success"
  in
  let rc, wc = run (tx_of Transaction.Create fee) in
  let rl, wl = run (tx_of (Transaction.Call V.target_11s) fee) in
  let oc, cc, gc, fc = parts rc in
  let ol, cl, gl, fl = parts rl in
  Alcotest.(check bool) "no created address either way" true
    (Option.is_none cc && Option.is_none cl);
  Alcotest.(check int) "identical gas_used" gl gc;
  Alcotest.(check int) "identical refund" fl fc;
  Alcotest.(check string) "identical output" ol oc;
  Alcotest.(check bool) "and identical post-states, to the state root" true
    (Block_roots.agree wc wl);
  (* The differential leg: against the type-2 twin the type-4 execution may
     grow only by the authorization intrinsic, never by the 32000 creation
     surcharge. At this stage the difference is 0; the executor stage makes it
     25000 for the one listed entry. *)
  let dyn =
    tx_of (Transaction.Call V.target_11s)
      (Transaction.Dynamic
         { max_fee = V.type4_max_fee; max_priority = Some V.type4_max_priority })
  in
  let _, cd, gd, _ = parts (fst (run dyn)) in
  Alcotest.(check bool) "the dynamic twin creates nothing either" true (Option.is_none cd);
  Alcotest.(check bool) "no 32000 creation surcharge, differentially" true
    (gc - gd >= 0 && gc - gd < 32000)

let () =
  Alcotest.run "eip7702 wire"
    [
      ( "designator",
        [
          Alcotest.test_case "the 23 bytes and their keccak" `Quick
            test_designator_bytes_and_hash;
          Alcotest.test_case "length is checked before version" `Quick
            test_designator_decode_order_length_before_version;
          Alcotest.test_case "classification is a two-byte prefix" `Quick
            test_classify_is_two_byte_prefix;
          Alcotest.test_case "zero assigns a revocation, but the read path accepts one"
            `Quick test_assignment_zero_is_revoke_but_read_path_accepts;
          Alcotest.test_case "a saturated nonce still takes the code" `Quick
            test_nonce_saturation_still_sets_code;
          Alcotest.test_case "a genesis designator is live, a malformed one refused" `Quick
            test_genesis_designator_is_live_and_malformed_rejected;
        ] );
      ( "authorization",
        [
          Alcotest.test_case "the 0x05 signing preimage, byte for byte" `Quick
            test_authorization_signing_preimage_literal;
          Alcotest.test_case "the preimage excludes the signature" `Quick
            test_authorization_preimage_excludes_signature;
          Alcotest.test_case "the signed encoding is six items, parity first" `Quick
            test_signed_authorization_rlp_six_items;
          Alcotest.test_case "the low-s bound is strict" `Quick test_high_s_is_strict;
          Alcotest.test_case "the nonce is a full u64 and saturation is a skip" `Quick
            test_auth_nonce_width_u64;
          Alcotest.test_case "the key-0 vector: sign, encode, recover, end to end" `Quick
            test_authorization_end_to_end_key0;
          Alcotest.test_case "the chain id is a u256 and zero means any chain" `Quick
            test_auth_chain_id_is_u256_and_zero_is_any_chain;
        ] );
      ( "type-0x04 envelope",
        [
          Alcotest.test_case "the wire prefix matches 1559, differentially" `Quick
            test_type4_wire_prefix_matches_1559_differentially;
          Alcotest.test_case "round trip, signing payload and hash" `Quick
            test_type4_roundtrip_and_hash;
          Alcotest.test_case "an empty list and a parity of 2 both decode" `Quick
            test_type4_decode_accepts_empty_list_and_parity_two;
          Alcotest.test_case "to is a mandatory address" `Quick
            test_type4_to_is_mandatory_address;
          Alcotest.test_case "the framing narrowings are inherited" `Quick
            test_type4_framing_narrowings_inherited;
          Alcotest.test_case "the transactions-trie type byte is 4" `Quick
            test_transactions_trie_type_byte_is_4;
          Alcotest.test_case "a set-code create is unobservable" `Quick
            test_set_code_create_is_unobservable;
        ] );
    ]
