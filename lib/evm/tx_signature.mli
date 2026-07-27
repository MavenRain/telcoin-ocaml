(** An ECDSA signature over a transaction: the y-parity and the two scalars.

    The port of alloy-primitives 1.5.7's [Signature]
    ([src/signature/sig.rs:14-22]) together with the two EIP-155 helpers that
    live one crate up, in alloy-consensus 1.8.3
    ([src/transaction/legacy.rs:398-422]).

    Three orders coexist in the reference and only one of them is the wire order:
    the struct declares [y_parity, r, s], the constructor takes [(r, s,
    y_parity)], and RLP writes [v] {e first}, then [r], then [s]
    ([sig.rs:358-370]). Mirroring the struct into an encoder typechecks and
    produces garbage, so this module exposes accessors only, and the wire order
    is named exactly once, in {!Tx_envelope}.

    Nothing here is validated. alloy's [Signature::new] is a plain [const]
    constructor with no range, non-zero or curve-order check ([sig.rs:113-117]),
    and its RLP decoder adds none ([sig.rs:98-109]): a signature with [r = 0],
    [s = 0] or [s >= n] decodes successfully and fails later, in recovery.
    Rejecting any of them here would refuse transactions the reference accepts,
    which is a fork. The one rule that {e is} a rejection — EIP-2's low-[s] — is
    a gate in front of recovery, and it is {!Secp256k1.s_is_high}, phrased over
    the group order that module already holds so that the constant is written
    down exactly once in the port. *)

type word = Tn_state.U256.t

type t
(** A signature. Abstract: built by {!make} and read through the accessors, so
    the declaration order can never be mistaken for the wire order. *)

val make : parity:bool -> r:word -> s:word -> t
(** Assemble a signature from its three components. Total, and deliberately
    unvalidated (see the module comment): [r] and [s] may be zero, or at or above
    the group order, exactly as alloy's constructor allows. *)

val parity : t -> bool
(** The y-parity of the point [R]: [true] for an odd y. This is what a typed
    (EIP-2718) transaction writes as its [v], and what recovery passes as the
    recovery id — never [27]/[28] and never an EIP-155 value. *)

val r : t -> word
(** The signature's [r] scalar, the x-coordinate of [R] reduced modulo the group
    order. Encoded as an RLP {e scalar} (leading zeros stripped), never as a
    fixed 32-byte string: an [r] below [2^248] makes the envelope one byte
    shorter and the transaction hash different. *)

val s : t -> word
(** The signature's [s] scalar. Encoded as an RLP scalar like {!r}. *)

val to_eip155_value : parity:bool -> chain_id:word option -> word
(** The legacy [v] an envelope carries: [35 + 2 * chain_id + parity] when there
    is a chain id and [27 + parity] when there is not (alloy-consensus
    [legacy.rs:398-404]). alloy computes it in [u128] so that a chain id of
    [u64::MAX] cannot overflow; a {!word} is wider still, so the sum is exact for
    every chain id up to [(2^256 - 36) / 2], that is [2^255 - 18]. Above that the
    256-bit addition wraps, exactly as every other {!Tn_state.U256} operation in
    this port does. The bound is stated rather than enforced because it cannot be
    reached from any transaction: it sits far above the [u64] range alloy's
    [ChainId] holds, which is in turn the whole of what {!of_eip155_value}
    admits, so a wrapping [v] can only be produced by calling this function
    directly with a chain id no envelope could carry. [chain_id = Some 0] gives
    [35]/[36], which is {e not} the same as [None]'s [27]/[28]. *)

val of_eip155_value : word -> (bool * word option) option
(** The inverse: the parity and chain id a legacy [v] encodes, or [None] when
    [v] encodes neither (alloy-consensus [legacy.rs:406-422]).

    Accepted: [27] (parity false, no chain id), [28] (parity true, no chain id),
    and every [v >= 35] whose derived [(v - 35) / 2] fits a [u64]. Rejected: [0],
    [1], [2..26], [29..34], and any [v] whose chain id would exceed [u64::MAX].
    Note that [0] and [1] are rejected: alloy-primitives' [normalize_v]
    ([utils.rs:12-45]) accepts them, but it sits on the 65-byte raw-signature
    path and not on this one, so using it here would silently admit transactions
    alloy refuses.

    The caller must already have rejected a [v] wider than 16 bytes on the wire:
    alloy decodes it as a [u128], so an over-wide payload is an {e overflow}
    error and not an invalid-parity one, and only the caller still knows which it
    saw ({!Tx_envelope.Scalar_too_wide} against
    {!Tx_envelope.Invalid_parity_value}). *)
