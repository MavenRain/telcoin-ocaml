(** The Ethereum address of a secp256k1 public key.

    [keccak256(key)] truncated to its low 20 bytes, taken over the {b 64}-byte
    uncompressed key with its SEC1 [0x04] tag already stripped. This is the last
    step of two otherwise unrelated paths — the [ECRECOVER] precompile
    ({!Precompile}) and transaction sender recovery ({!Tx_recovery}) — so it
    lives once, here, rather than twice (alloy-consensus 1.8.3
    [src/crypto.rs:349-356] and alloy-primitives 1.5.7
    [src/bits/address.rs:495-515], which agree byte for byte).

    alloy's [Address::from_raw_public_key] {e asserts} the 64-byte width and
    panics otherwise. The width is a real hazard rather than a formality: hashing
    the 65-byte tagged form, or a 33-byte compressed key, yields a perfectly
    well-formed address that simply belongs to nobody, with no error anywhere to
    say so. Here it is reported instead of assumed. *)

val to_address : string -> Tn_types.Units.Address.t option
(** [to_address key] is [keccak256 key] truncated to its low 20 bytes, or [None]
    unless [key] is exactly 64 bytes: the affine X coordinate then Y, each a
    32-byte big-endian integer with leading zeros {e preserved} and with no
    [0x04] tag — precisely the shape {!Secp256k1.recover} returns. The truncation
    itself cannot fail, since a Keccak digest is 32 bytes and its last 20 always
    form an address, which is why the width is the only [None]. *)
