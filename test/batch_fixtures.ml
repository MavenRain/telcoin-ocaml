(* Oracle-SIGNED fixtures for chunk 34 (the port has no secp256k1 signer).
   Shared by the chunk's test executables; not listed in test/dune's
   (names ...), dune links it into every test binary.

   THE ORACLE, with exact provenance: every row below was emitted on
   2026-07-28 by the scratchpad `exhibit-check` crate's `mint_fixtures`
   binary, [patch.crates-io]-pinned to the vendored telcoin-network @
   5dbb764e Cargo.lock crates (/Users/oobi/Documents/telcoin-vendor:
   alloy-consensus 1.8.3, alloy-eips 1.8.3, alloy-primitives 1.5.7,
   alloy-rlp 0.3.13). Only the SIGNATURES come from k256 0.13.4 (RFC 6979,
   low-s enforced); every encoded_2718 byte comes from the vendored pinned
   alloy encoders, and the tx hash is keccak256 of those bytes. The signing
   key is the well-known anvil dev key 0
   (ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80),
   address f39fd6e51aad88f6f4ce6ab8827279cfffb92266. Validity is
   independently re-proven in-tree on every run: the tests recover each
   fixture's signer through the port's own Secp256k1 and assert this exact
   address, so a fixture minted wrong recovers somebody else and fails
   loudly.

   The minting source (condensed; alloy tx constructors elided where they
   only fill the fields named in each row's comment):

     const KEY_HEX: &str = "ac09..ff80";           // anvil dev key 0
     const N_HEX: &str = "ffff..fffe baaedce6af48a03b bfd25e8cd0364141";
     fn sign_hash(sk: &SigningKey, hash: B256) -> Option<Signature> {
         let (sig, recid) = sk.sign_prehash_recoverable(hash.as_slice()).ok()?;
         let (sig, recid) = sig.normalize_s()
             .and_then(|low| RecoveryId::from_byte(recid.to_byte() ^ 1)
                 .map(|flip| (low, flip)))
             .unwrap_or((sig, recid));
         Some(Signature::new(
             U256::from_be_slice(&sig.r().to_bytes()),
             U256::from_be_slice(&sig.s().to_bytes()),
             recid.is_y_odd()))
     }
     // per fixture: sig = sign_hash(sk, tx.signature_hash());
     //              env = Envelope::<variant>(tx.into_signed(sig));
     //              row = hex(env.encoded_2718()) | signer | keccak256(enc)
     // F8 high-s twin of F1: Signature::new(r, n - s, !parity).

   Common fields unless a row says otherwise: chain_id 2017 (0x7e1),
   gas_price 7 (legacy) / max_fee 7 + priority 1 (typed), to = the zero
   address, value 0, empty calldata, empty access list.

   F7 (a valid signed EIP-7702) is NOT minted here: chunk 33's oracle vector
   already provides one in range (fee caps 7/11, gas 100_000), see
   eip7702_vectors.ml type4_encoded_2718_hex / type4_tx_hash_hex /
   sender_key1_hex. *)

(* Every fixture's signer: anvil dev key 0's address. *)
let signer = "f39fd6e51aad88f6f4ce6ab8827279cfffb92266"

(* F1: signed legacy, nonce 0, gas 21000. v = 82 0fe6 (chain 2017,
   parity 1). *)
let f1_encoded =
  "f86180078252089400000000000000000000000000000000000000008080820fe6a0a158855fd2c264458b2d8a2ff5dc54df5d9bec488945e6d9a658fd7a4b74af97a03abad40a9137f16ea89e014e8c1f6dd6631e714549b89ead6ce6c7f4e5ca66a7"

let f1_tx_hash = "350db073662ad14a47fe64c527665a79f46e85f8ef782a3bb1a54f8173eca94e"

(* F2: signed legacy, nonce 2^62 (88 4000000000000000), gas 21000: the
   exhibit-26 class with a REAL signature, for the stage-3 accept run. *)
let f2_encoded =
  "f869884000000000000000078252089400000000000000000000000000000000000000008080820fe5a0300ba9c6c803a3a922733568e57239b43fdf991499a0f2574f1d3d06affe05f1a021265c3438629304c5138edd0a5737132515df4410085087686dcb3dd5b32249"

let f2_tx_hash = "06bf78d703b62a848b120f20280ded3e49aa27fe0a34699b244abc8236caf1e8"

(* F3: signed legacy, gas 21000, calldata 0x22-padded so encoded_2718 is
   EXACTLY 1000 bytes (b9 0382 = 898 calldata bytes; f9 03e5 = 997 payload
   + 3 header), for the stage-3 byte-size boundary. *)
let f3_encoded =
  "f903e5800782520894000000000000000000000000000000000000000080b90382"
  ^ String.concat "" (List.init 898 (fun _i -> "22"))
  ^ "820fe5a09f7959db566e4c4795ff67945268eee53a22976366428848c7a09c203dc3a61aa033fe07f4cfab02b5a6141d794b5b6499ec31270b355b0a327eb941fc3b030bfb"

let f3_tx_hash = "ec831a05626b06ae105161e34ec7efc3a3087423da23218246cbbb9198c2c702"

(* F4a/F4b: signed 1559, gas 15_000_000 (83 e4e1c0) and 15_000_001
   (83 e4e1c1), for the stage-3 gas-cap boundary (2 x F4a = the cap
   exactly; F4a + F4b = one over). *)
let f4a_encoded =
  "02f8658207e180010783e4e1c09400000000000000000000000000000000000000008080c001a039aa5d34e4999663236f70c93a0f32dfaedc5a9f19dd4a8a862425d5789ce773a04bf24d461aaf73612a73ddfbda40d8c28fefb513204d64788617eb1d69140478"

let f4a_tx_hash = "d0c2d9af70271afc1cf990510fee679070cb0cd50deb9e1cedad02a600c18cfb"

let f4b_encoded =
  "02f8658207e180010783e4e1c19400000000000000000000000000000000000000008080c001a0d8fcd54970f1fd3cad9e589da65c295ea85fa5501d724fb583190ad83af3c3aba048a2c5a456e7eef4498329f4ceb73eb90389ae846ade1faee41de9e0c970e963"

let f4b_tx_hash = "934d262b7078df907ebd5e60c9ed8a6e23354c120a3339706b29514a5b1c8bf6"

(* F5: signed legacy, gas 2^63 (88 8000000000000000): the full-u64 gas
   class whose sum must overflow-detect, not wrap, in stage 3. *)
let f5_encoded =
  "f86780078880000000000000009400000000000000000000000000000000000000008080820fe5a01ba3610d48b14e04f517cc183677eeba87d4c83add6364a53d28b3c7d95bd1e3a0450e7cd7d2ebe31c5bf04004729cd26d116511fad152f55d58d4738de102bca2"

let f5_tx_hash = "bd42307d2df9f98bdf972cad061ad27aeeefe9f6dfa481c4614370958e241067"

(* F6: signed EIP-4844: 11 unsigned fields (chain 2017, nonce 0, priority 1,
   fee 7, gas 21000, to = 20 bytes of 0x23, value 0, empty data, empty
   access list, max_fee_per_blob_gas 1, ONE versioned hash 01 then 31 bytes
   of 0x11) plus the signature tail: the 14-item list behind 0x03. Its
   in-tree recovery pins the signing preimage keccak(0x03 || rlp(11)). *)
let f6_encoded =
  "03f8878207e18001078252089423232323232323232323232323232323232323238080c001e1a0011111111111111111111111111111111111111111111111111111111111111180a040f865081c97ebfcaaa000601451d8716ad05a7aee27c6c87d99a919b1c6a01ba010cdddb0589bef25841386bb5096d612ad4eb2118b986a47b023e9d33e703cd6"

let f6_tx_hash = "d68e0d5c0c1c070a71e4ec1a3db725dba524564617a36f33f9ccf0a0c2218274"

(* F8: the high-s twin of F1: same r, s' = n - s, parity flipped (v drops
   to 82 0fe5). It DECODES; the EIP-2 strict low-s gate must reject it at
   recovery, exactly where reth's checked try_into_recovered does. *)
let f8_encoded =
  "f86180078252089400000000000000000000000000000000000000008080820fe5a0a158855fd2c264458b2d8a2ff5dc54df5d9bec488945e6d9a658fd7a4b74af97a0c5452bf56ec80e915761feb173e0922857906ba16590018e52eb9697ea6bda9a"

let f8_tx_hash = "d7ef27b316a132ccd6d9bf7434e10464001c3500bbe87a0f58e962ef5d635c7e"
