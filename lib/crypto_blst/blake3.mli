(** Pure-OCaml BLAKE3, default (unkeyed) hash mode only.

    This module exists because no opam BLAKE3 binding builds on this
    toolchain; it is the in-repo backend of [Tn_crypto.Digest] for the real
    [tn_crypto_blst] implementation, following the house precedent of the
    pure-zarith secp256k1. It implements exactly the slice the seam needs:
    one-shot hashing of a byte string to a 32-byte digest. Keyed hashing,
    [derive_key], incremental/streaming input and extended (XOF) output are
    deliberately absent and must not be added speculatively.

    The kernel is the reference algorithm: the 8-word IV shared with
    SHA-256/BLAKE2s, 64-byte blocks, 1024-byte chunks, flags
    [CHUNK_START]/[CHUNK_END]/[PARENT]/[ROOT], 7 rounds of the G
    quarter-round with the fixed message-word permutation between rounds,
    chaining values threaded across blocks, and the left-leaning binary tree
    over chunk chaining values (a subtree completes at the largest
    power-of-two chunk count; [ROOT] is set only on the final output
    compression). All 32-bit arithmetic is masked to [0xffffffff] on the
    native int. Total, pure, exception-free; correctness is pinned by the 35
    official BLAKE3 test vectors in [test/fixtures/blake3_official_vectors.txt]. *)

val hash : string -> string
(** [hash s] is the 32-byte BLAKE3 digest (default hash mode) of the byte
    string [s]. The result is always exactly 32 bytes; the width is fixed by
    the implementation itself, not by a caller-supplied output length. *)
