(** Sender recovery: the signed envelope to the address that signed it.

    The port of alloy-consensus 1.8.3's [SignerRecoverable for Signed<T>]
    ([src/signed.rs:480-516]) and the [crypto::secp256k1::recover_signer] it
    calls ([src/crypto.rs:241-251]). Three steps, in this order: reject a high
    [s] (EIP-2), re-derive the signing digest {e from the decoded payload} rather
    than from the received bytes, and recover.

    The curve arithmetic is {!Secp256k1} and the final keccak-and-truncate is
    {!Public_key}, so this module is the policy and none of the mathematics. It
    deliberately offers no unchecked variant. alloy has one, and it is not merely
    "the same without the check": under its k256 backend it silently normalises a
    high [s] and flips the recovery id, returning the same address for a
    malleated signature ([crypto.rs:374-391]). A repository-wide sweep of
    telcoin-network finds zero callers of it, so the safest surface is the one
    that cannot express it.

    Recovery is also where this port is {e stricter} than its own [ECRECOVER]
    precompile, deliberately: the EIP-2 low-[s] gate applies to transactions and
    not to the precompile, which accepts a high [s] by design. That asymmetry is
    upstream's, and it is why the gate lives here rather than inside
    {!Secp256k1.recover}. *)

open Tn_types

type error =
  | High_s
      (** EIP-2: the signature's [s] exceeds [floor(n / 2)]. The comparison is
          {b strict}, so an [s] exactly equal to it is accepted — alloy's
          [if signature.s() > SECP256K1N_HALF] ([crypto.rs:246-248]) — and the
          one signature that distinction decides is a pinned test. The bound
          itself is {!Secp256k1.s_is_high}, phrased over the group order that
          module already holds. *)
  | Unrecoverable
      (** No public key corresponds to the digest and signature: [r] or [s] is
          zero or at or above the group order — all four already rejected by the
          curve primitive at [lib/evm/secp256k1.ml:109] — or [r] is no curve
          point's x-coordinate, or the recovered point is the identity. alloy
          collapses every library failure into one opaque [RecoveryError] with no
          source ([crypto.rs:236-238]), so distinguishing these would invent
          information the reference discards. *)

val error_to_string : error -> string
(** Render a recovery {!error} as a short human-readable string. *)

val recover_signer : Tx_envelope.t -> (Units.Address.t, error) result
(** The externally owned account that signed the envelope.

    The digest is {!Tx_envelope.signature_hash} of the envelope's {e payload} —
    re-derived, never taken from the bytes the envelope was decoded from, which
    is what makes the recovered sender a function of the transaction and not of
    its framing. The recovery id handed to the curve is the raw parity, [0] or
    [1]: alloy writes [signature.v() as u8] into byte 64 of its 65-byte input
    ([crypto.rs:219-239]) and that is the [bool], never [27]/[28] and never an
    EIP-155 [v]. [r] and [s] go in fixed 32-byte form here, unlike the RLP path,
    matching alloy's [to_be_bytes::<32>()] ([crypto.rs:223-226]).

    Malleability needs no handling: {!Secp256k1.recover} returns the same key for
    a signature and its high-[s] image, which is what both of alloy's backends
    also do, one by construction and one by normalising. That is precisely why
    the {!High_s} gate is a policy rejection rather than an arithmetic
    accident. *)

val recover : Tx_envelope.t -> (Transaction.t, error) result
(** {!recover_signer} followed by {!Tx_payload.to_transaction}: the executable
    transaction {!Executor.execute} takes. This is the seam the port deferred to
    as "the sender is pre-recovered" — it is now recovered here, from a real
    signature, rather than assumed by the caller. *)
