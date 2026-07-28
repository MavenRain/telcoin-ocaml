(* Shared EIP-7702 fixtures and renderers, as tx_vectors.ml is shared by the
   transaction tests and trie_vectors.ml by the trie tests.

   Every byte string here is written out in hex with its hand-assembly in the
   comment above it, so a later reader can re-derive it with a pencil and
   without a build. The two hashes are the only values that need an oracle:

     - the designator hash is `cast keccak 0xef01001111111111111111111111111111111111111111`
       (foundry), an implementation of Keccak-256 entirely independent of
       digestif;
     - the signing-preimage hash is not pinned as a literal at all. The test
       hashes {!preimage_1_to_11s} with Tn_keccak and compares against
       Authorization.signature_hash, and Tn_keccak is itself pinned to published
       vectors in test_keccak.ml, so the composition is oracle-grounded even
       though no external EIP-7702 vector exists.

   The hex helpers come from Tx_vectors rather than being written twice. *)

module U256 = Tn_state.U256
module Delegation = Tn_state.Delegation
module World_state = Tn_state.World_state
module Address = Tn_types.Units.Address

let to_hex = Tx_vectors.to_hex
let hex = Tx_vectors.hex
let w_of_hex = Tx_vectors.w_of_hex
let addr_of_hex = Tx_vectors.addr

(* ---------------------------------------------------------------- *)
(* Addresses                                                         *)
(* ---------------------------------------------------------------- *)

let twenty_11s = String.make 40 '1'
let target_11s = addr_of_hex twenty_11s

(* 0x000...00b: nineteen zero bytes then 0x0b. Chosen for the six-item RLP
   vector because a fixed 20-byte string keeps its leading zeros, which is the
   difference between the address item and the scalar items around it. *)
let target_0b = addr_of_hex (String.make 38 '0' ^ "0b")

(* ---------------------------------------------------------------- *)
(* The designator                                                    *)
(* ---------------------------------------------------------------- *)

(* ef01 (magic) || 00 (version) || 20 address bytes = 23 bytes
   [revm-bytecode eip7702.rs:8-20,55-65]. *)
let designator_11s_hex = "ef0100" ^ twenty_11s
let designator_11s = hex designator_11s_hex

(* keccak256 of the 23 bytes above, from foundry's `cast keccak`. This is the
   code hash a delegated account reports: revm hashes the ORIGINAL byte slice,
   which for the Eip7702 variant is the raw designator
   ([bytecode.rs:61-67,170-181]). It is emphatically NOT EIP7702_MAGIC_HASH,
   which is defined at [eip7702.rs:4-6] and referenced nowhere. *)
let designator_11s_code_hash = "dfe7c7677e3d245aaff2e3e94db902f5fb37475eb611959c71ee641508dcf49a"

(* Twenty-three bytes, right magic, version byte 0x01: an Unsupported_version,
   because the length check passed first. *)
let bad_version_23_hex = "ef0101" ^ twenty_11s
let bad_version_23 = hex bad_version_23_hex

(* Twenty-two bytes, right magic, version byte 0x01: an Invalid_length, NOT an
   Unsupported_version. [eip7702.rs:36-53] checks length first, and this pair is
   the only input that tells the two orders apart. *)
let bad_version_22 = hex ("ef0101" ^ String.make 38 '1')

(* ef0100 || 0x00*20: a designator pointing at the zero address. The WRITE path
   cannot produce this (Delegation.assignment answers Revoke), but the READ path
   must accept it, because 23 such bytes in a genesis allocation are a
   designator to revm like any other. *)
let designator_zero_hex = "ef0100" ^ String.make 40 '0'
let designator_zero = hex designator_zero_hex

(* ---------------------------------------------------------------- *)
(* The authorization signing preimage                                *)
(* ---------------------------------------------------------------- *)

(* keccak(MAGIC || rlp([chain_id, address, nonce])) for chain_id = 1,
   address = 0x11*20, nonce = 0 -- alloy-eip7702 [auth_list.rs:83-93], with
   MAGIC = 0x05 from [constants.rs:14].

   Hand-assembly, twenty-five bytes:
     05                          the magic, a bare byte OUTSIDE the list
     d7                          list header, 0xc0 + 23 payload bytes
     01                          chain_id 1: a scalar below 0x80 is its own byte
     94 <20 bytes 0x11>          address: 0x80 + 20, then the fixed 20 bytes
     80                          nonce 0: the empty string, i.e. 0x80
   payload = 1 + 21 + 1 = 23, and 23 < 56, so the header is the short form. *)
let preimage_1_to_11s_hex = "05d70194" ^ twenty_11s ^ "80"
let preimage_1_to_11s = hex preimage_1_to_11s_hex

(* ---------------------------------------------------------------- *)
(* The six-item signed encoding                                      *)
(* ---------------------------------------------------------------- *)

let thirty_two_01s = String.concat "" (List.init 32 (fun _ -> "01"))
let thirty_two_02s = String.concat "" (List.init 32 (fun _ -> "02"))
let r_ones = w_of_hex thirty_two_01s
let s_twos = w_of_hex thirty_two_02s

(* alloy's hand-written encoder, [auth_list.rs:224-233], for chain_id = 1,
   address = 0x00..0b, nonce = 0, y_parity = 0, r = 0x01 repeated 32 times,
   s = 0x02 repeated 32 times.

   Hand-assembly, ninety-two bytes:
     f8 5a                       long-form list header: 0xf7 + 1, then 90
     01                          chain_id 1
     94 <20 bytes>               address, leading zeros preserved
     80                          nonce 0
     80                          y_parity 0 -- a SCALAR, so 0x80 and never 0x00
     a0 <32 bytes 0x01>          r: 0x80 + 32, then the bytes
     a0 <32 bytes 0x02>          s
   payload = 1 + 21 + 1 + 1 + 33 + 33 = 90 = 0x5a, and 90 >= 56, so the header
   takes the long form. *)
let signed_six_item_hex =
  "f85a" ^ "01" ^ "94"
  ^ (String.make 38 '0' ^ "0b")
  ^ "80" ^ "80" ^ "a0" ^ thirty_two_01s ^ "a0" ^ thirty_two_02s

(* Index of the y_parity byte in the encoding above: 2 header + 1 chain_id
   + 21 address + 1 nonce. Named so the assertion that it is 0x80 reads as a
   claim about the field rather than about a magic offset. *)
let y_parity_slot = 25

(* ---------------------------------------------------------------- *)
(* Curve constants                                                   *)
(* ---------------------------------------------------------------- *)

(* SECP256K1N_HALF = floor(n / 2), alloy-eip7702 [constants.rs:30-31]. The
   crate writes it in decimal as
   57896044618658097711785492504343953926418782139537452191302581570759080747168;
   this is the same integer in hex, and it is the INDEPENDENT pin for
   Authorization.secp256k1n_half, which is derived from Secp256k1 rather than
   written down. *)
let secp256k1n_half_hex = "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0"
let secp256k1n_half = w_of_hex secp256k1n_half_hex
let secp256k1n_half_plus_one = U256.add secp256k1n_half U256.one

(* An r taken from tx_vectors.ml:100, i.e. from a signature alloy really
   produced, so it is the x-coordinate of a real curve point and recovery
   against it succeeds. Reused here only for its curve-validity: the authority
   it recovers is nobody in particular, which is exactly what the low-s boundary
   test needs. *)
let curve_valid_r = w_of_hex "28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276"

(* ---------------------------------------------------------------- *)
(* Oracle-derived end-to-end crypto vectors (chunk 33, stage 2)      *)
(* ---------------------------------------------------------------- *)

(* Generated by an out-of-tree cargo oracle pinned to telcoin-network's own
   lock — alloy-consensus 1.8.3 / alloy-eip7702 0.6.3 / alloy-primitives 1.5.7
   / alloy-rlp 0.3.13, signing via alloy-signer-local 1.8.3 — the same
   arrangement that produced tx_vectors.ml. Do not edit the hexes by hand.

   The keys are anvil's documented dev keys 0 and 1
   (ac0974be..f2ff80 and 59c6995e..78690d), so anyone can regenerate every
   line below, and the signatures are RFC-6979 deterministic ECDSA, so a
   regeneration reproduces them byte for byte. Key 0 plays the AUTHORITY (it
   signs the authorization), key 1 the type-4 SENDER (it signs the envelope);
   the two roles are deliberately different keys so a test that confuses the
   two recovery paths cannot pass by accident. *)

(* sender(key0) and sender(key1), as alloy derives them from the pubkeys. *)
let authority_key0_hex = "f39fd6e51aad88f6f4ce6ab8827279cfffb92266"
let authority_key0 = addr_of_hex authority_key0_hex
let sender_key1_hex = "70997970c51812dc3a010c7d01b50e0d17dc79c8"
let sender_key1 = addr_of_hex sender_key1_hex

(* -- vector 1: the authorization, end to end ---------------------------
   The tuple is exactly {!preimage_1_to_11s}'s: chain_id 1, address 0x11*20,
   nonce 0. The oracle's [Authorization::signature_hash] over it — pinned here
   so the port's preimage AND its keccak are both checked against alloy rather
   than only against each other. *)
let auth_signature_hash_hex =
  "d35655e0048045ff05a91979004fc1afa8325086bbab53c2498ecfcfe431d99f"

(* Key 0's RFC-6979 signature over that hash, and the authority
   [recover_authority] answers. The parity is ONE, so the y_parity item in the
   six-item encoding below is the byte 0x01, not 0x80 — the complementary case
   to signed_six_item_hex's zero. *)
let auth_key0_y_parity = 1
let auth_key0_r_hex = "ae3ce0f5deec815c0978f060a4444485f277c3f47b1a465ce368e34e426f49ee"
let auth_key0_r = w_of_hex auth_key0_r_hex
let auth_key0_s_hex = "3e9f8631a03543dba183dd8255fa32062b616acc76f5dd8a59987cd47cf8468c"
let auth_key0_s = w_of_hex auth_key0_s_hex

(* The oracle's six-item [SignedAuthorization] RLP: f8 5a (90 payload bytes),
   chain_id 1, the 20 target bytes, nonce 0 (0x80), y_parity 1 (0x01), then r
   and s at full width. *)
let auth_key0_signed_rlp_hex =
  "f85a" ^ "01" ^ "94" ^ twenty_11s ^ "80" ^ "01" ^ "a0" ^ auth_key0_r_hex ^ "a0"
  ^ auth_key0_s_hex

(* -- vector 2: the signed type-0x04 envelope ---------------------------
   Sentinel fields chosen so a struct-order port swaps two recognisable
   numbers: chain_id 1, nonce 3, max_priority_fee_per_gas 7, max_fee_per_gas
   11, gas_limit 100000, to = 0x11*20, value 13, empty calldata, ONE
   access-list entry (address 0x00..ff, one storage key 0x01) so the list's
   position — item 8, BEFORE the authorization list — is recognisable, and the
   single authorization above as item 9.

   The signing payload is 0x04 || rlp_list(<10 fields>), 186 bytes: 04, f8 b7
   (0xb7 = 183 payload), 01, 03, 07, 0b, 83 0186a0, 94 <20 bytes 0x11>, 0d,
   80, then the access list f8 38 [f7 [94 <20>, e1 [a0 <32>]]] and the
   authorization list f8 5c [<the 92 bytes above>]. *)
let type4_signing_payload_hex =
  "04f8b70103070b830186a094" ^ twenty_11s ^ "0d80"
  ^ "f838f79400000000000000000000000000000000000000ffe1a0"
  ^ "0000000000000000000000000000000000000000000000000000000000000001" ^ "f85c"
  ^ auth_key0_signed_rlp_hex

let type4_signing_hash_hex =
  "8360a4075ffd7612c52a7574086aa9366d5c77b1199d83090f764bc5e5ccd5c8"

(* Key 1's signature over that hash. Parity FALSE, so the envelope's y_parity
   item is 0x80 — the RLP bool false — and never a literal 0x00. *)
let type4_parity = false
let type4_r_hex = "02bdf5dc50a6039ba91c088f4e9861f60e558ba9cd6f598764501c6c50a6eab7"
let type4_r = w_of_hex type4_r_hex
let type4_s_hex = "47fd89d5b7c715a5c4de40d21330f41cbcea7d1f71bf518dadb32055bd20e4d8"
let type4_s = w_of_hex type4_s_hex

(* The consensus bytes: ONE thirteen-item list — the ten body fields, then
   y_parity (0x80), r, s in the SAME list — behind the raw 0x04, 253 bytes in
   all. The header grows from b7 to fa (183 + 67 signature-tail bytes = 250). *)
let type4_encoded_2718_hex =
  "04f8fa0103070b830186a094" ^ twenty_11s ^ "0d80"
  ^ "f838f79400000000000000000000000000000000000000ffe1a0"
  ^ "0000000000000000000000000000000000000000000000000000000000000001" ^ "f85c"
  ^ auth_key0_signed_rlp_hex ^ "80" ^ "a0" ^ type4_r_hex ^ "a0" ^ type4_s_hex

(* keccak256 of the BARE bytes above ([rlp.rs:104-108]); the oracle also
   asserts hash == keccak(encoded_2718) itself, so this literal is alloy's own
   composition and not this port's. *)
let type4_tx_hash_hex = "e25c94bfe5006a6a3f4adf654c6b57b788d658165bd901416ff54602f241cb88"

(* Vector 3 — a delegation designator with its keccak — is {!designator_11s}
   / {!designator_11s_code_hash} above (stage 1, via foundry). The oracle
   recomputed the same digest through alloy-primitives' keccak256, so the two
   independent implementations agree on it. *)

(* The sentinel fields of vector 2 as OCaml values, for building the payload
   and its type-2 differential twin in the tests. *)
let type4_chain_id = w_of_hex "01"
let type4_nonce = 3
let type4_max_priority = w_of_hex "07"
let type4_max_fee = w_of_hex "0b"
let type4_gas_limit = 100_000
let type4_value = w_of_hex "0d"
let type4_access_list = [ (addr_of_hex Tx_vectors.to_b, [ w_of_hex "01" ]) ]

(* ---------------------------------------------------------------- *)
(* Minted authorization signatures (chunk 33, stage 4)               *)
(* ---------------------------------------------------------------- *)

(* The loop-stage vectors need one KEY signing MANY tuples (consecutive nonces
   for the no-dedup pair, a self-sponsored authorization, revocations), which
   the single stage-2 oracle entry cannot provide and the tree cannot mint (it
   has recovery, not signing). These were signed out-of-tree with foundry's
   `cast wallet sign --no-hash` (cast 0.3.0 — alloy's signer underneath, the
   same stack as the stage-2 oracle) over `cast keccak` of the hand-assembled
   preimage 0x05 || rlp([chain_id, address, nonce]), with the anvil dev keys
   0/1/2. The pipeline is pinned in both directions: run over vector 1's tuple
   (chain 1, 0x11*20, nonce 0) it reproduces {!auth_signature_hash_hex} and
   {!auth_key0_r}/{!auth_key0_s}/parity 1 byte for byte (RFC-6979 signing is
   deterministic, so this is an equality, not a spot check), and every entry
   below is re-verified in-tree each run, because the tests recover its
   authority through Secp256k1 and assert the loop applied it at the expected
   ADDRESS — a signature minted wrong recovers somebody else and fails loudly.

   Key 0 is {!authority_key0} (f39f..2266), key 1 {!sender_key1} (7099..79c8),
   key 2 the third anvil address below. Preimages follow the hand-assembly
   rules of {!preimage_1_to_11s_hex}; the only new shape is the saturated
   nonce, whose item is [88 ffffffffffffffff] (eight meaningful bytes), making
   the payload 31 bytes and the list header 0xdf. *)

let twenty_22s = String.make 40 '2'
let target_22s = addr_of_hex twenty_22s
let designator_22s_hex = "ef0100" ^ twenty_22s
let designator_22s = hex designator_22s_hex

(* ef0100 || key0's own address: what a self-delegation by key 0 stores. *)
let designator_self_key0_hex = "ef0100" ^ authority_key0_hex
let designator_self_key0 = hex designator_self_key0_hex
let zero_address = addr_of_hex (String.make 40 '0')

(* anvil dev key 2's address, the control authority for the warm/cold
   differencing runs. *)
let authority_key2_hex = "3c44cdddb6a900fa2b585dd299e03d12fa4293bc"
let authority_key2 = addr_of_hex authority_key2_hex

(* The unsigned tuple and its signature, ready for [Authorization.make]/[sign]
   in the tests; a record so each vector is one literal below. *)
type minted = {
  m_chain : U256.t;
  m_address : Address.t;
  m_nonce : U256.t;
  m_parity : int;
  m_r : U256.t;
  m_s : U256.t;
}

(* u64::MAX, check 2's saturation constant, as a 256-bit word. *)
let nonce_u64_max = U256.sub (U256.two_pow 64) U256.one

(* key 0 over (1, 0x22*20, 1): the second no-dedup entry, consecutive after
   vector 1's nonce 0. *)
let k0_d2_n1 =
  {
    m_chain = U256.one;
    m_address = target_22s;
    m_nonce = w_of_hex "01";
    m_parity = 0;
    m_r = w_of_hex "76ccf28c9fcd883d5837ae3c98cc9a6b9ffef1083c1d7a9f2de27a48b2723bc2";
    m_s = w_of_hex "6635a0f7ed436d386f49e75ba5c284fb09b1e314ef71aee4732bca927fb9a8c3";
  }

(* key 0 over (1, 0x22*20, 0): the live-nonce probe — same nonce as vector 1,
   different delegate. *)
let k0_d2_n0 =
  {
    m_chain = U256.one;
    m_address = target_22s;
    m_nonce = U256.zero;
    m_parity = 0;
    m_r = w_of_hex "bfa71d3b2c96bd4f573ee8e2b0da387999eb521b8c09f68499f4ed528cbeeb40";
    m_s = w_of_hex "171bb6415a3ff1207ddf5314aa05ffc168bd82f3abd0c8a7c91ef22ff58c4698";
  }

(* key 0 over (1, 0x11*20, 7): a deliberately wrong nonce, for the check-5/6
   order pin and the warm-after-nonce-mismatch leg. *)
let k0_d1_n7 =
  {
    m_chain = U256.one;
    m_address = target_11s;
    m_nonce = w_of_hex "07";
    m_parity = 1;
    m_r = w_of_hex "b2b8c828d3c87930f8ae86b9e1d786acf85adfd142c947c6754d6349ac2660ad";
    m_s = w_of_hex "42a9bfd688aca81525339878103523601dc37f541eb20c04d1a62c96af9fc808";
  }

(* key 0 over (1, 0x11*20, u64::MAX): a GENUINE signature on a saturated-nonce
   tuple, so the authority check 2 refuses to recover is provably key 0's —
   the warms-nothing assertion names a real address, not a hypothetical. *)
let k0_d1_sat =
  {
    m_chain = U256.one;
    m_address = target_11s;
    m_nonce = nonce_u64_max;
    m_parity = 0;
    m_r = w_of_hex "2b5cc6b94c848dd2a95961d4d95674ab88744afd36686bc639d1bf36fef27c11";
    m_s = w_of_hex "09501951e8577aa310e80549f2561816003c8bfb0c110ea1a67e1f7be2a27769";
  }

(* key 0 over (2, 0x11*20, 0): genuinely signed but chain-mismatched against a
   chain-1 block. *)
let k0_chain2 =
  {
    m_chain = w_of_hex "02";
    m_address = target_11s;
    m_nonce = U256.zero;
    m_parity = 0;
    m_r = w_of_hex "0c43380f4481d09f904d656f8a542b7a139d64166d56fe0d98f5980a5c9df66e";
    m_s = w_of_hex "53d3db003421c1b0af3f0d230c6485685f6f3175273c426c794903ea11f27b8c";
  }

(* key 0 over (1, zero address, 3): the revocation, against an authority whose
   live nonce is 3. *)
let k0_rev_n3 =
  {
    m_chain = U256.one;
    m_address = zero_address;
    m_nonce = w_of_hex "03";
    m_parity = 0;
    m_r = w_of_hex "b088c3d04c74f6b1c595a34350e68c5e61127fd48e4a86c9e9672ad1d26c90f7";
    m_s = w_of_hex "15c639554bfffb93c6478622f5f4c18db1902e6918983e48119d038aa0ff73d7";
  }

(* key 0 over (1, 0x11*20, 4): the re-delegation AFTER the revocation above
   bumped the authority to 4. *)
let k0_d1_n4 =
  {
    m_chain = U256.one;
    m_address = target_11s;
    m_nonce = w_of_hex "04";
    m_parity = 1;
    m_r = w_of_hex "4eb7625a1864c4a3c18771ed32e58132c96ce0c470ae8c4a6a1aa53d6777c135";
    m_s = w_of_hex "238008cab64c29cfd0295b52d99221bf2bdd3c054f9165776963172c0001a8d3";
  }

(* key 0 over (1, 0x22*20, 3): overwrites an existing delegation at nonce 3. *)
let k0_d2_n3 =
  {
    m_chain = U256.one;
    m_address = target_22s;
    m_nonce = w_of_hex "03";
    m_parity = 0;
    m_r = w_of_hex "acc8ef68f6e5f10f9e5a4d7c9cc1522ea6d02682c8dd1fa5cace2f6686488ebe";
    m_s = w_of_hex "6f25b5a466f524bc380f8647a2f4bacdea5d0914a689abc3eca7fa1786f5d9a5";
  }

(* key 0 over (1, key 0's own address, 3): the self-delegation. *)
let k0_self_n3 =
  {
    m_chain = U256.one;
    m_address = authority_key0;
    m_nonce = w_of_hex "03";
    m_parity = 0;
    m_r = w_of_hex "062ebf3f12f8a50475f9b0c89dc0a215638b6dc1146178f842c06d10fa7e4003";
    m_s = w_of_hex "5fd0d9710b702e7749c02c646201910ea0418998b0e0fe2052238e9dde0b207b";
  }

(* key 1 over (1, 0x11*20, 6): the self-sponsored authorization — key 1 is the
   tx SENDER at account nonce 5, so tx.nonce + 1 = 6 is the nonce that
   applies. *)
let k1_d1_n6 =
  {
    m_chain = U256.one;
    m_address = target_11s;
    m_nonce = w_of_hex "06";
    m_parity = 1;
    m_r = w_of_hex "714a79c939607000aa9f2071d4a55b5080d7caa164d8bb80eab67e880b3f986a";
    m_s = w_of_hex "25c5a22589c58946469450c660a1eddfce38c3a78cdbab02c5415ef8bbb9aa90";
  }

(* key 1 over (1, 0x11*20, 5): the off-by-one — tx.nonce itself, which the
   caller's own bump has already left behind. *)
let k1_d1_n5 =
  {
    m_chain = U256.one;
    m_address = target_11s;
    m_nonce = w_of_hex "05";
    m_parity = 0;
    m_r = w_of_hex "f73c5633114716111c73d5f433f829ca9cbffeff56c97e4578edcb2fe3714a02";
    m_s = w_of_hex "58a677725b16b99b58381ef8f24a4830007954a1964eda5c4b65056961d4f5bc";
  }

(* key 2 over (1, 0x11*20, 0): the control entry for the warm/cold
   differencing pair — same tuple SHAPE as vector 1, different authority, so a
   run carrying it leaves key 0's authority cold at identical intrinsic. *)
let k2_d1_n0 =
  {
    m_chain = U256.one;
    m_address = target_11s;
    m_nonce = U256.zero;
    m_parity = 1;
    m_r = w_of_hex "9a30330780ac8b2a067a406f221213526b969210b9d0933e5f1842e68fcb7c38";
    m_s = w_of_hex "15c5f2c499ba82cb14aae6b67ce298d3f473ab6619a992add012355603f951fc";
  }

(* key 2 over (1, zero address, 0): a revocation aimed at an authority that
   does not exist — it must still apply, and leave a nonce-1 codeless entry. *)
let k2_rev_n0 =
  {
    m_chain = U256.one;
    m_address = zero_address;
    m_nonce = U256.zero;
    m_parity = 0;
    m_r = w_of_hex "0d3f7bd3c18884476f1da19e9d81e453220ec96504aa2b236a6eee8446ad0d07";
    m_s = w_of_hex "122f285f016d600528d673b72ec6e2ef7710418ab3aaf57ac877d5226973bf6c";
  }

(* ---------------------------------------------------------------- *)
(* Renderers: exhaustive, so a new constructor breaks them           *)
(* ---------------------------------------------------------------- *)

let render_decode_error e =
  match e with
  | Delegation.Invalid_length n -> Printf.sprintf "invalid_length:%d" n
  | Delegation.Unsupported_version v -> Printf.sprintf "unsupported_version:%d" v

let render_code_class c =
  match c with
  | Delegation.Codeless -> "codeless"
  | Delegation.Contract -> "contract"
  | Delegation.Delegated d -> "delegated:" ^ to_hex (Address.to_bytes (Delegation.target d))
  | Delegation.Undecodable e -> "undecodable:" ^ render_decode_error e

let render_assignment a =
  match a with
  | Delegation.Assign d -> "assign:" ^ to_hex (Address.to_bytes (Delegation.target d))
  | Delegation.Revoke -> "revoke"

let render_alloc_error e =
  match e with
  | World_state.Storage_without_code a ->
      "storage_without_code:" ^ to_hex (Address.to_bytes a)
  | World_state.Malformed_delegation (a, d) ->
      "malformed_delegation:" ^ to_hex (Address.to_bytes a) ^ ":" ^ render_decode_error d
