(* Golden vectors for the chunk-41 [Tn_types.Batch.Sealed] wire codec, from the
   same Rust oracle run as header_vectors.ml (telcoin-network @
   5dbb764ee0f4d2fb89d3e57bc010ecde7445220d; bcs 0.1.6, blake3 1.8.3,
   alloy-primitives 1.5.7). Pure string constants, linked into every test
   binary, copyable into test/crypto_blst/.

   Rust SealedBatch { batch: Batch, digest: BlockHash } (sealed_batch.rs:17-31)
   derives its codec, and a BCS struct is bare field concatenation in
   declaration order, so the wire is bcs(Batch) then the digest. The digest is
   a FixedBytes<32>, whose alloy serde routes through serialize_bytes, so bcs
   LENGTH-PREFIXES it: 0x20 then 32 bytes, never a bare 32. There is no
   framing and no compression around it.

   SB1, SB2 and SB3 are the sealed forms of batch vectors V1, V4 and V7
   (shortest, a varied epoch, and the largest), so the batch leg of each row is
   a pre-image this repo already froze in batch_vectors.ml. SB_NEG is SB1 with
   the 0x20 prefix byte removed: one byte short, every following byte shifted,
   so it must fail to decode and must differ from SB1.

   Rust's SealedBatch::new does NOT check the digest against the batch
   (sealed_batch.rs:25-31), so these rows pin bytes, not honesty; a wrong claim
   is a validator rejection. *)

let sb1_batch_preimage =
  "000000000014000000000000000000000000000000000000000007000000000000000000"

let sb1_digest =
  "ef244b2105b5e2899e1b7d0cbe01b7c22cd4dc1378c7b006522d45ba5818741b"

let sb1_wire =
  "00000000001400000000000000000000000000000000000000000700000000000000000020ef244b2105b5e2899e1b7d0cbe01b7c22cd4dc1378c7b006522d45ba5818741b"

let sb2_batch_preimage =
  "000700000014000000000000000000000000000000000000000007000000000000000000"

let sb2_digest =
  "8d16fdf8fd7bf78202c8343d879f7d39f64e17479ec3d96047693020544ac82f"

let sb2_wire =
  "000700000014000000000000000000000000000000000000000007000000000000000000208d16fdf8fd7bf78202c8343d879f7d39f64e17479ec3d96047693020544ac82f"

let sb3_batch_preimage =
  "018001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f0000000014000000000000000000000000000000000000000007000000000000000000"

let sb3_digest =
  "58a32c5d92611fbde5c2e9e4cf19ae574805d09e7e3eedf5b51dab080f6a6bb4"

let sb3_wire =
  "018001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f00000000140000000000000000000000000000000000000000070000000000000000002058a32c5d92611fbde5c2e9e4cf19ae574805d09e7e3eedf5b51dab080f6a6bb4"

let sb_neg_wire =
  "000000000014000000000000000000000000000000000000000007000000000000000000ef244b2105b5e2899e1b7d0cbe01b7c22cd4dc1378c7b006522d45ba5818741b"
