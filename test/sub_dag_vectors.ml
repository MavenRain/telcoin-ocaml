(* Golden vectors for the chunk-41 [Tn_consensus.Sub_dag] wire codec, digest
   pre-image and keccak randomness, from the same Rust oracle run as
   header_vectors.ml (telcoin-network @
   5dbb764ee0f4d2fb89d3e57bc010ecde7445220d; bcs 0.1.6, blake3 1.8.3,
   alloy-primitives 1.5.7). Pure string constants, linked into every test
   binary, copyable into test/crypto_blst/.

   TWO ENCODINGS, NOT ONE. Rust's [CommittedSubDagInner] (primary/output.rs:
   295-310) has four fields, and the digest is NOT the serialized struct:

   - the CODEC (output.rs:321-339 delegating to the inner derive) writes the
     header sequence, the BCS [ReputationScores], the u64 commit timestamp and
     then the randomness LENGTH-PREFIXED, because [randomness: B256] goes
     through alloy's [serialize_bytes] and bcs always prefixes that: 0x20 then
     32 bytes;
   - the DIGEST pre-image (output.rs:457-471) writes each header's certificate
     digest BARE in sequence order, the BCS scores, the u64 stored timestamp,
     and then the SAME randomness BARE.

   The same 32 bytes are 33 on the wire and 32 in the pre-image. That
   asymmetry is Rust's, and it is the single easiest thing in this chunk to
   get wrong, so both columns are pinned here.

   Row by row: SD1 is one default header, empty non-final scores, a stored
   timestamp of zero and zero randomness — the sub-DAG of Rust's default
   [ConsensusHeader]. SD2 varies everything at once: three headers in sequence
   order, two authorities with different scores, the final flag set, a
   non-zero timestamp and a real keccak randomness. SD3 is SD2 with the flag
   cleared and the timestamp zeroed, which isolates those two fields so
   dropping either shows as its own digest.

   SD_RAND1 pins the randomness rule itself: [keccak256] of the leader's
   aggregate signature bytes. SD_RAND2 pins the missing-signature branch,
   [keccak256(BlsSignature::default().to_bytes())], together with the two
   values it must NOT equal — [keccak256("")], the empty-string fallback this
   port used before the fix, and the blake3 of the same signature bytes, which
   is what a port that routed keccak through the {!Tn_crypto} seam would
   produce. SD_NEG is SD2's pre-image under the old "tn:subdag" domain tag.

   The pre-image and digest columns are live only where the seam is real
   BLAKE3 (test/crypto_blst): a sub-DAG pre-image is made of HEADER DIGESTS,
   so it moves with the seam. The codec and randomness columns do not: header
   ENCODINGS and keccak are seam-independent, and are asserted in the default
   executables. *)

let sd1_preimage =
  "2f4670d858c9dfd845e42f72eaf457bd8f5ddf9f6fb75e7eea800b6d5a635a46000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

let sd1_digest =
  "ea58633ecd15b531e95e2705c9634939d16a40484dab4bc791c2741229f61f2c"

let sd2_preimage =
  "a75812cdd73f2b0bac33e6715788dbc2acb04fe4eb6cd5121bff9358e8d13dd07d617882e34f1bc8de548a0a3c58c21793b19a5e5456424866e65cc221c0dc96a45d8bf80d6c11ba02e62d7820a67b882472b7099486c421c79e8dee968b155e0201010101010101010101010101010101010101010101010101010101010101010500000000000000020202020202020202020202020202020202020202020202020202020202020209000000000000000101f15365000000004047e6f5296df0630e6d1021aa7bc4c8cbb651c76e1d8f6ac28b7483d693f4dd"

let sd2_digest =
  "6bdb67ba2ee002bca7851fe4ebcb58764638ef2fad3b24053fcc12e55c8f1180"

let sd3_preimage =
  "a75812cdd73f2b0bac33e6715788dbc2acb04fe4eb6cd5121bff9358e8d13dd07d617882e34f1bc8de548a0a3c58c21793b19a5e5456424866e65cc221c0dc96a45d8bf80d6c11ba02e62d7820a67b882472b7099486c421c79e8dee968b155e0201010101010101010101010101010101010101010101010101010101010101010500000000000000020202020202020202020202020202020202020202020202020202020202020209000000000000000000000000000000004047e6f5296df0630e6d1021aa7bc4c8cbb651c76e1d8f6ac28b7483d693f4dd"

let sd3_digest =
  "60594d4ab1fc1f00ba884af3d3d1e65e79c72bc30c735b09d1376a2ab5e8dd77"

let sd_codec1 =
  "010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000"

let sd_codec2 =
  "03010101010101010101010101010101010101010101010101010101010101010101000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000101010101010101010101010101010101010101010101010101010101010101010000000700000000f15365000000000220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000020bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb03000220111111111111111111111111111111111111111111111111111111111111111120222222222222222222222222222222222222222222222222222222222222222200000000000000002000000000000000000000000000000000000000000000000000000000000000000101010101010101010101010101010101010101010101010101010101010101010000000700000000f15365000000000220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000020bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb030002201111111111111111111111111111111111111111111111111111111111111111202222222222222222222222222222222222222222222222222222222222222222080706050403020120cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0201010101010101010101010101010101010101010101010101010101010101010500000000000000020202020202020202020202020202020202020202020202020202020202020209000000000000000101f1536500000000204047e6f5296df0630e6d1021aa7bc4c8cbb651c76e1d8f6ac28b7483d693f4dd"

let sd_rand1_agg_sig =
  "abababababababababababababababababababababababababababababababababababababababababababababababab"

let sd_rand1_keccak256 =
  "4047e6f5296df0630e6d1021aa7bc4c8cbb651c76e1d8f6ac28b7483d693f4dd"

let sd_rand2 =
  "08624652859a6e98ffc1608e2af0147ca4e86e1ce27672d8d3f3c9d4ffd6ef7e"

let sd_rand2_not_keccak256_empty =
  "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"

let sd_rand2_not_blake3_default_sig =
  "476c361415fc7aadab46f0b51c2293a963c62b102dc8bca649a3e563f5c7851d"

let sd_neg_domain_tag =
  "tn:subdag"

let sd_neg_digest =
  "d1d0b4e70bebb1be789797977185750d2e0e036839fc2dc9a9684b288ac5e8f0"

let bls_default_signature =
  "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

let bls_default_signature_keccak256 =
  "08624652859a6e98ffc1608e2af0147ca4e86e1ce27672d8d3f3c9d4ffd6ef7e"
