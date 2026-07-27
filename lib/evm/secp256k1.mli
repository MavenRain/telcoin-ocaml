(** Pure secp256k1 ECDSA public-key recovery, the arithmetic the [ECRECOVER]
    precompile (address [0x01]) is built on.

    The port carries no elliptic-curve library and binds no C: the field and
    curve are worked directly over {!Z} (arbitrary-precision integers). Recovery
    is not a secret-key operation, so a constant-time implementation is not
    required for safety here; the concern is only that the recovered key match
    the reference exactly, which the recovered address is pinned to by the
    published ECRECOVER vectors. The keccak hash that turns the key into an
    address stays with {!Public_key}, which both {!Precompile} and
    {!Tx_recovery} go through, so this module depends on nothing but the
    integers. *)

val recover : msg:string -> recid:int -> r:string -> s:string -> string option
(** [recover ~msg ~recid ~r ~s] is the 64-byte uncompressed public key — the
    affine X coordinate then Y, each a 32-byte big-endian integer — that signed
    the 32-byte digest [msg] under the signature ([r], [s]) with y-parity
    [recid] ([0] or [1]), or [None] when no such key exists.

    [msg], [r] and [s] are 32-byte big-endian strings. [None] is returned when
    either scalar is zero or at least the group order, when [r] is not the
    x-coordinate of a curve point, or when the recovered point is the identity.
    The result is a pure function of the inputs and independent of signature
    malleability: a high-[s] signature recovers the same key as its low-[s]
    image, because negating [s] and flipping the parity negate the recovered
    point twice over. *)

val s_is_high : string -> bool
(** [s_is_high s] is whether the 32-byte big-endian scalar [s] exceeds
    [floor(n / 2)], where [n] is the group order this module already holds — the
    EIP-2 malleability bound alloy names [SECP256K1N_HALF]
    ([alloy-consensus-1.8.3/src/crypto.rs:46-53]) and tests as
    [if signature.s() > SECP256K1N_HALF] ([crypto.rs:241-251]). The comparison is
    {b strict}: an [s] exactly equal to [floor(n / 2)] is {e not} high, and using
    [>=] would reject exactly one legal signature.

    It lives here, rather than as a second copy of the constant beside the
    transaction types, so the group order is written down once. Note that this
    bound is {e not} applied by {!recover}: transaction recovery
    ({!Tx_recovery}) gates on it, while the [ECRECOVER] precompile deliberately
    does not, and a shorter [s] is accepted on both paths since a big-endian
    scalar and its left-padding denote the same integer. *)
