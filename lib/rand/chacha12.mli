(** ChaCha12 keystream, the core of rand 0.9.2's [StdRng]
    ([rand_chacha-0.9.0/src/guts.rs]; telcoin's Cargo.lock pins both crates).
    The committee shuffle seeds [StdRng::from_seed(randomness)]
    ([tn-reth/src/evm/block.rs:438-443]) and every draw must match
    bit-for-bit, so this module is a transliteration of the crate source, not
    of an algorithm description. *)

type t
(** Keystream state: key, 64-bit block counter, buffered block words.
    Persistent; dispensing returns the advanced state. *)

val of_key : Tn_hash32.Hash32.t -> t
(** Total: the 32 bytes are the ChaCha key verbatim and the stream id and
    block counter start at zero ([ChaCha12Core::from_seed],
    [rand_chacha-0.9.0/src/chacha.rs] with [guts.rs]'s [init_chacha] on an
    all-zero eight-byte nonce). {!Tn_hash32.Hash32.t} is 32 bytes by
    construction, so no length error can exist. *)

val next_word : t -> int * t
(** The next u32 of the keystream (little-endian words; the value fits a
    native [int]), in exactly rand's [BlockRng] dispensing order: word order
    within a block, then the next block
    ([rand_core-0.9.5/src/block.rs:186-194]). Persistent: returns the
    advanced state. *)
