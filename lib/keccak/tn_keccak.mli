(** Ethereum's Keccak-256.

    This is {e not} the protocol hash. {!Tn_crypto.Digest.hash} lives behind a
    dune virtual library precisely so that its implementation is a link-time
    choice: BLAKE3 in production, BLAKE2S in the stub, and protocol code never
    learns which. Ethereum's Keccak is the opposite kind of fact. It is fixed
    forever, it is what every deployed contract's [CREATE2] address and every
    storage-trie key already commit to, and a link-time substitution of it would
    change consensus while every type still checked. Routing it through that
    seam would file a constant as a choice.

    It is a leaf library, depending on nothing in this port. That is
    load-bearing: {!Tn_state.Account} will need it for a code hash in the next
    chunk, and {!Tn_state} is upstream of {!Tn_evm}, so the only placement that
    needs no later move is below both.

    The backing functor is [Digestif.KECCAK_256]. Its neighbour
    [Digestif.SHA3_256] has the same module type, the same digest width, and
    differs only in the domain-separation byte the padding appends (0x01 against
    0x06). The wrong one compiles, runs, and forks the chain. {!empty} is pinned
    to a published vector and the test suite additionally asserts that it is not
    SHA3-256's, so the hazard is named at the point of failure rather than
    merely covered. *)

type t
(** A Keccak-256 digest: exactly {!length} bytes.

    Abstract, and {!digest} is its {e only} producer. There is deliberately no
    [of_bytes], no [of_word] and no [zero], so a value of this type is always
    the hash of a byte string that really was hashed. That is what will let the
    next chunk express "the code hash of an account that does not exist" as a
    constructor which provably is not a digest, rather than as a [None] whose
    default someone later simplifies to {!empty}. Adding a second producer here
    would remove that theorem before it is used. *)

val length : int
(** [32]. Read from [Digestif.KECCAK_256.digest_size] rather than written, so
    the width is the library's fact and not a number repeated here. *)

val digest : string -> t
(** The Keccak-256 of a byte string. Total: every string is a pre-image, and the
    empty string hashes to {!empty}. *)

val empty : t
(** [digest ""], computed once at module initialisation:
    [c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470].

    The specifications call it [KECCAK_EMPTY]. It is the word [KECCAK256] pushes
    for a zero-length input, and it will be the code hash of a codeless account.
    It is a named constant rather than a call to {!digest} at the use site
    because the zero-length path deliberately never reads memory, so it must
    never reach a hash of a byte string it did not read. *)

val to_bytes : t -> string
(** The {!length} bytes, most significant first: exactly the width
    {!Tn_state.U256.of_be_bytes} accepts. There is deliberately no [to_word]
    here, because a word would mean depending on {!Tn_state} and this library
    must stay below it. The interpreter does that conversion. *)

val to_hex : t -> string
(** Sixty-four lowercase hex digits, no [0x] prefix. *)

val equal : t -> t -> bool
