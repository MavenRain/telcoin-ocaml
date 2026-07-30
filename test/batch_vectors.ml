(* Golden vectors for the chunk-34 [Tn_types.Batch] BCS digest preimage,
   shared by the chunk's test executables the way block_vectors.ml and
   eip7702_vectors.ml are shared. Not listed in test/dune's (names ...):
   dune links it into every test binary.

   THE ORACLE, named with its exact provenance the way block_vectors.ml
   names its RPC endpoint. Every preimage and digest row below was emitted
   on 2026-07-28 by a real Rust oracle pinned to the exact Cargo.lock
   versions of telcoin-network @ 5dbb764e: bcs = 0.1.6 (Cargo.lock:1701),
   blake3 = 1.8.3 (Cargo.lock:1809), alloy-primitives = 1.5.7
   (Cargo.lock:447). The oracle declares the Batch struct verbatim from
   crates/types/src/worker/sealed_batch.rs:62-89 (including #[serde(skip)]
   on received_at) and prints hex(bcs::to_bytes(batch)) and
   hex(blake3(bcs::to_bytes(batch))), the digest formula of
   sealed_batch.rs:116-124 with encode = bcs::to_bytes
   (crates/types/src/codec.rs:69-71).

   Byte layout the rows pin (all integers little-endian, bcs 0.1.6):
   - transactions (Vec<Vec<u8>>): ULEB128 outer count, then per tx a
     ULEB128 length + the raw EIP-2718 bytes;
   - epoch: u32, 4 bytes;
   - beneficiary: ULEB128 length 0x14 + 20 raw bytes (alloy Address
     serializes via serialize_bytes, so bcs length-prefixes it; 21 bytes
     total, NOT a bare 20);
   - base_fee_per_gas: u64, 8 bytes; worker_id: u16, 2 bytes;
   - received_at: ZERO bytes (#[serde(skip)], sealed_batch.rs:86-88).

   Invariants the set proves: V6 = V5 byte-for-byte (the serde-skip proof);
   V7 begins 01 80 01 (tx length 128 as the two-byte ULEB128 80 01); every
   row carries the beneficiary as 0x14 + 20 bytes; V1 doubles as
   Batch::default(), pinning MIN_PROTOCOL_BASE_FEE = 7.

   The blake3 column is INERT: the port's stub crypto seam hashes
   domain ^ preimage with BLAKE2s, so nothing can assert against these
   hexes yet. The assertions activate when tn_crypto_blst lands (it must
   hash the BARE preimage with real BLAKE3 and drop the domain tag for
   Batch_digest byte-compat). *)

(* V1-default: txs [], epoch 0, beneficiary 0x00..00, base fee 7, worker 0.
   Hand-check: 00 (empty tx vec) + 00000000 (epoch) + 14 + 20x00
   (beneficiary) + 0700000000000000 (base fee) + 0000 (worker) = 36 bytes. *)
let v1_preimage =
  "000000000014000000000000000000000000000000000000000007000000000000000000"

let v1_blake3 =
  "ef244b2105b5e2899e1b7d0cbe01b7c22cd4dc1378c7b006522d45ba5818741b"

(* V2-one-tx: one 4-byte tx de ad be ef, all other fields as V1. *)
let v2_tx = "\xde\xad\xbe\xef"

let v2_preimage =
  "0104deadbeef0000000014000000000000000000000000000000000000000007000000000000000000"

let v2_blake3 =
  "dd4fe52d89be646b6b54e3d05304038941e024f4dfac301aab3f3dbec5f18784"

(* V3-two-tx: txs [01] and [02 03], all other fields as V1. *)
let v3_txs = [ "\x01"; "\x02\x03" ]

let v3_preimage =
  "0201010202030000000014000000000000000000000000000000000000000007000000000000000000"

let v3_blake3 =
  "c150f65920e116c3182b192ed34cc6081c32e1b86ce74b8b77c4c1fdc5682b88"

(* V4-epoch7: as V1 with epoch 7. *)
let v4_epoch = 7

let v4_preimage =
  "000700000014000000000000000000000000000000000000000007000000000000000000"

let v4_blake3 =
  "8d16fdf8fd7bf78202c8343d879f7d39f64e17479ec3d96047693020544ac82f"

(* V5-full: every field away from its default: txs [aa bb] and [cc],
   epoch 7, beneficiary 0x23 x 20, base fee 1_000_000_007 (07 ca 9a 3b LE),
   worker 3. *)
let v5_txs = [ "\xaa\xbb"; "\xcc" ]
let v5_epoch = 7
let v5_beneficiary = String.make 20 '\x23'
let v5_base_fee = 1_000_000_007L
let v5_worker_id = 3

let v5_preimage =
  "0202aabb01cc0700000014232323232323232323232323232323232323232307ca9a3b000000000300"

let v5_blake3 =
  "24edef8012b3fe1860f84bea8e077610d9067daf2a17460105b3ea649a647777"

(* V6-skip-proof: V5 with received_at = Some 123. The oracle emits the SAME
   preimage and digest as V5: #[serde(skip)] received_at contributes zero
   bytes. *)
let v6_received_at_sec = 123L
let v6_preimage = v5_preimage
let v6_blake3 = v5_blake3

(* V7-uleb128-128: one 128-byte tx with bytes 00..7f, all other fields as
   V1. The preimage begins 01 80 01: one tx, length 128 as the two-byte
   canonical ULEB128 80 01. *)
let v7_tx =
  "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
   \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\
   \x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\
   \x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\
   \x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\
   \x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\
   \x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\
   \x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"

let v7_preimage =
  "018001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f0000000014000000000000000000000000000000000000000007000000000000000000"

let v7_blake3 =
  "58a32c5d92611fbde5c2e9e4cf19ae574805d09e7e3eedf5b51dab080f6a6bb4"
