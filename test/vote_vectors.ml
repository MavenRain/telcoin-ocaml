(* Golden vectors for the chunk-41 [Tn_vertex.Vote] signing message and the
   [Tn_vertex.Certificate] digest identity, from the same Rust oracle run as
   header_vectors.ml (telcoin-network @
   5dbb764ee0f4d2fb89d3e57bc010ecde7445220d; bcs 0.1.6, blake3 1.8.3). Pure
   string constants (except {!vo_neg_length}, a plain int), linked into every
   test binary.

   VOTE. Rust's vote pre-image (primary/vote.rs:36-39,56-58) is
   [bcs(IntentMessage { intent, value: Digest<32> })]: three intent bytes
   [02 00 01] (scope=consensus, version=0, app=telcoin, intent.rs:60-62,
   108-110) then the digest through [serialize_bytes], which BCS always
   length-prefixes: [0x20] then 32 bytes, 36 in total. [Vote.digest()] is not
   an independent hash, it is [self.header_digest.into()] (vote.rs:133-138), a
   type relabel over the same 32 bytes.

   VO1..VO3 are that 36-byte message for H1, H4, H5's digests. VO_DIGEST
   restates the relabel: a signed vote's [header_digest] field is bit-for-bit
   the header's own digest, for H4. VO_NEG is the 35-byte message this port
   produced before the fix, the RAW digest with no length prefix; it must
   differ from VO2 and its length is pinned at 35 so a regression cannot
   silently produce 36 bytes by some other wrong route.

   CERTIFICATE. Rust's certificate digest (certificate.rs:473-478) is
   [self.header.digest()], no independent hash and no codec in this chunk's
   scope (field 6 is a raw [BlsSignature], outside the crypto seam). C1..C3
   are the oracle's OWN two columns agreeing with each other: the certificate
   digest it printed for a certificate over H1/H4/H5 is byte-identical to the
   header digest it printed for that same header in header_vectors.ml. That
   agreement is itself the evidence for "no independent hash" on the Rust
   side. C_NEG restates it as an inequality: a certificate over H4 must NOT
   match H5's digest, so the identity check cannot pass on a constant. *)

let vo1_digest =
  "2f4670d858c9dfd845e42f72eaf457bd8f5ddf9f6fb75e7eea800b6d5a635a46"

let vo1_signing_message =
  "020001202f4670d858c9dfd845e42f72eaf457bd8f5ddf9f6fb75e7eea800b6d5a635a46"

let vo2_digest =
  "7d617882e34f1bc8de548a0a3c58c21793b19a5e5456424866e65cc221c0dc96"

let vo2_signing_message =
  "020001207d617882e34f1bc8de548a0a3c58c21793b19a5e5456424866e65cc221c0dc96"

let vo3_digest =
  "a45d8bf80d6c11ba02e62d7820a67b882472b7099486c421c79e8dee968b155e"

let vo3_signing_message =
  "02000120a45d8bf80d6c11ba02e62d7820a67b882472b7099486c421c79e8dee968b155e"

let vo_digest_header_digest =
  "7d617882e34f1bc8de548a0a3c58c21793b19a5e5456424866e65cc221c0dc96"

let vo_neg_message =
  "0200017d617882e34f1bc8de548a0a3c58c21793b19a5e5456424866e65cc221c0dc96"

let c1_certificate_digest =
  "2f4670d858c9dfd845e42f72eaf457bd8f5ddf9f6fb75e7eea800b6d5a635a46"

let c2_certificate_digest =
  "7d617882e34f1bc8de548a0a3c58c21793b19a5e5456424866e65cc221c0dc96"

let c3_certificate_digest =
  "a45d8bf80d6c11ba02e62d7820a67b882472b7099486c421c79e8dee968b155e"

let c_neg_over_h4_digest =
  "7d617882e34f1bc8de548a0a3c58c21793b19a5e5456424866e65cc221c0dc96"

let c_neg_compared_to_h5_digest =
  "a45d8bf80d6c11ba02e62d7820a67b882472b7099486c421c79e8dee968b155e"

let vo_neg_length = 35
