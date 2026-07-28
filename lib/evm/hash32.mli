(** Re-export of {!Tn_hash32.Hash32}, the 32-byte gate for every header field
    that is neither a keccak digest nor a protocol digest: the four trie
    roots, the close-epoch randomness, and the two pinned constants.

    The module itself lives in the leaf library [tn_hash32] since chunk 32:
    [tn_rand] seeds its RNG from this type ([StdRng::from_seed(randomness)],
    [block.rs:438-443]) and [tn_evm] now sits {e above} [tn_rand] (the
    committee shuffle consumes the RNG), so the type moved below both. This
    alias preserves every existing [Tn_evm.Hash32] reference and the type
    equality [Tn_evm.Hash32.t = Tn_hash32.Hash32.t]; each item's contract is
    documented at its home, {!Tn_hash32.Hash32}. *)

include module type of struct
  include Tn_hash32.Hash32
end
