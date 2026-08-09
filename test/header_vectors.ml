(* Golden vectors for the chunk-41 [Tn_vertex.Header] BCS pre-image and
   digest, shared the way batch_vectors.ml is: not listed in test/dune's
   (names ...), so dune links it into every test binary, and pure string
   constants, so it drags in no library and can be copied into
   test/crypto_blst/ by a dune rule.

   THE ORACLE. Every row below was emitted on 2026-07-28 by a Rust oracle
   built against telcoin-network @ 5dbb764ee0f4d2fb89d3e57bc010ecde7445220d,
   pinned by that tree's Cargo.lock to bcs 0.1.6, blake3 1.8.3,
   alloy-primitives 1.5.7. The oracle declares HeaderInner verbatim from
   crates/types/src/primary/header.rs:13-39 and prints
   hex(bcs::to_bytes(inner)) and hex(blake3(bcs::to_bytes(inner))), the digest
   formula of header.rs:349-356. Its POSITIVE_CONTROL reproduced the frozen
   Batch rows V1 and V5 byte for byte, so the harness that produced these rows
   is the same one that produced the already-trusted batch column.

   The seven fields, in BCS order, and the byte class of each:
   - 1 author: AuthorityIdentifier, serde array, BARE 32 bytes;
   - 2 round: u32 LE; 3 epoch: u32 LE; 4 created_at: u64 LE;
   - 5 payload: IndexMap with #[serde(with = "indexmap::map::serde_seq")], so
     ULEB128 count then per entry a LENGTH-PREFIXED key (0x20 then 32 bytes)
     and a u16 worker id, in INSERTION order, not sorted;
   - 6 parents: BTreeSet<HeaderDigest>, ULEB128 count then LENGTH-PREFIXED
     32-byte digests in ascending byte order;
   - 7 latest_execution_block: BlockNumHash, u64 number then a
     LENGTH-PREFIXED 32-byte hash, 41 bytes in all;
   - the cached digest field is #[serde(skip)] (header.rs:37) and contributes
     nothing.

   What the set proves, row by row: H1 is Header::default() and feeds the
   genesis anchor; H2 varies author and round; H3 varies epoch, created_at and
   payload from empty to one; H4 varies payload length, worker id (0 vs 3, so
   a dropped id shows) and parents from empty to two; H5 varies BOTH sub-fields
   of field 7, so neither a dead number nor a dead hash can hide; H6 is H4 with
   the parents presented descending and must produce H4's bytes exactly, which
   is what pins the BTreeSet canonicalisation.

   The two NEG rows are the pre-fix encodings, kept so a regression is caught
   by a row rather than by a review: H_NEG_A is H4 with the payload keys and
   parents written BARE, H_NEG_B is H5 without field 7 at all. Both must differ
   from the row they shadow, and this port must REFUSE to decode either.

   The digest column is live only where the Tn_crypto seam is real BLAKE3,
   which is test/crypto_blst; under the default (stub) executables the seam is
   BLAKE2s, so the pre-image column carries the wire evidence there. *)

let h1_bcs =
  "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000"

let h1_digest =
  "2f4670d858c9dfd845e42f72eaf457bd8f5ddf9f6fb75e7eea800b6d5a635a46"

let h2_bcs =
  "01010101010101010101010101010101010101010101010101010101010101010100000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000"

let h2_digest =
  "a75812cdd73f2b0bac33e6715788dbc2acb04fe4eb6cd5121bff9358e8d13dd0"

let h3_bcs =
  "0101010101010101010101010101010101010101010101010101010101010101010000000700000000f15365000000000120aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000000000000000200000000000000000000000000000000000000000000000000000000000000000"

let h3_digest =
  "cdf5b673a52c58269bf6203c62a2ff151db86b9f9e9c91c4a1d2db7eb601a99d"

let h4_bcs =
  "0101010101010101010101010101010101010101010101010101010101010101010000000700000000f15365000000000220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000020bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0300022011111111111111111111111111111111111111111111111111111111111111112022222222222222222222222222222222222222222222222222222222222222220000000000000000200000000000000000000000000000000000000000000000000000000000000000"

let h4_digest =
  "7d617882e34f1bc8de548a0a3c58c21793b19a5e5456424866e65cc221c0dc96"

let h5_bcs =
  "0101010101010101010101010101010101010101010101010101010101010101010000000700000000f15365000000000220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000020bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb030002201111111111111111111111111111111111111111111111111111111111111111202222222222222222222222222222222222222222222222222222222222222222080706050403020120cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

let h5_digest =
  "a45d8bf80d6c11ba02e62d7820a67b882472b7099486c421c79e8dee968b155e"

let h6_bcs =
  "0101010101010101010101010101010101010101010101010101010101010101010000000700000000f15365000000000220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000020bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0300022011111111111111111111111111111111111111111111111111111111111111112022222222222222222222222222222222222222222222222222222222222222220000000000000000200000000000000000000000000000000000000000000000000000000000000000"

let h6_digest =
  "7d617882e34f1bc8de548a0a3c58c21793b19a5e5456424866e65cc221c0dc96"

let h_neg_a_bcs =
  "0101010101010101010101010101010101010101010101010101010101010101010000000700000000f153650000000002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb030002111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222220000000000000000200000000000000000000000000000000000000000000000000000000000000000"

let h_neg_a_digest =
  "02f1d1266b79e06c94849f22798ad974f412ae4a880d2291b4b89b228dfa658a"

let h_neg_b_bcs =
  "0101010101010101010101010101010101010101010101010101010101010101010000000700000000f15365000000000220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000020bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb030002201111111111111111111111111111111111111111111111111111111111111111202222222222222222222222222222222222222222222222222222222222222222"

let h_neg_b_digest =
  "9d822ca42f07dc4c7cdbabf70d4ebb302e781cc090d7d262b5ef1c87a3297979"

(* H_DUP and H_TS are the two review rows, added on 2026-08-09 by the same
   oracle binary (its POSITIVE_CONTROL still reproduces the frozen Batch rows,
   and every row above re-printed byte-identically). Both are ATTACKER wires,
   values a well-behaved proposer never writes, so each pins what this port
   does with bytes it did not produce.

   H_DUP is H4's wire with the second payload key rewritten to the first, so
   the sequence carries the key aa.. twice, with worker ids 0 then 3. Rust
   reads that field into an IndexMap through
   [#[serde(with = "indexmap::map::serde_seq")]] (primary/header.rs:22-24) and
   [IndexMap::insert] on a key already present keeps the key in its FIRST
   position and takes the LAST value, so Rust decodes ONE entry, aa.. -> 3, and
   digests the collapsed header: the oracle prints
   H_DUP_decoded_entries = 1 and H_DUP_wire_equals_reencoded = false. A port
   that kept the repeat would digest the same wire differently. *)
let h_dup_wire_bcs =
  "0101010101010101010101010101010101010101010101010101010101010101010000000700000000f15365000000000220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0300022011111111111111111111111111111111111111111111111111111111111111112022222222222222222222222222222222222222222222222222222222222222220000000000000000200000000000000000000000000000000000000000000000000000000000000000"

(* The bytes Rust re-emits for that wire: one payload entry, aa.. -> 3. *)
let h_dup_bcs =
  "0101010101010101010101010101010101010101010101010101010101010101010000000700000000f15365000000000120aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0300022011111111111111111111111111111111111111111111111111111111111111112022222222222222222222222222222222222222222222222222222222222222220000000000000000200000000000000000000000000000000000000000000000000000000000000000"

let h_dup_digest =
  "fe7d8d30475ae604ed4822e3cf183c2456a7765bded98a13bed3c548bdf726d2"

(* H_TS is H3 with created_at = u64::MAX. Rust's [TimestampSec] is a plain u64
   with no decode validation (primary/header.rs:21), so Rust accepts the row and
   digests it as it stands; the digest below is what Rust computes. This port's
   {!Tn_types.Units.Timestamp} stops at 2^63 - 1, so {!Tn_vertex.Header.codec}
   REFUSES the row. Refusing is the only choice that cannot fork a digest: a
   substituted default would make the port hash a header the writer never
   wrote. The digest column is therefore documentation of the divergence, not a
   value this port can reach. *)
let h_ts_bcs =
  "01010101010101010101010101010101010101010101010101010101010101010100000007000000ffffffffffffffff0120aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000000000000000200000000000000000000000000000000000000000000000000000000000000000"

let h_ts_digest =
  "459f3fffd6c879a442d584563a01f3fcfc2bcf5481ba9cd126e9c7cd6a27d105"

let mut_control_author =
  "0101010101010101010101010101010101010101010101010101010101010102"

let mut_control_digest =
  "e719ed81a64c1e7077fcb7035cb519bf8446710a9e0f3b7d15a8970427725bfe"
