(** One EIP-7702 authorization: the three signed-over fields at their true
    widths, the [0x05] signing preimage, the six-item wire encoder, and the
    three {e pure} checks the authorization loop performs before it touches any
    state.

    Ground truth is alloy-eip7702 0.6.3 ([src/auth_list.rs],
    [src/constants.rs]) for the value and its signature, and revm-handler 15.0.0
    ([src/pre_execution.rs:190-272]) for the checks.

    {2 Three widths that are not the transaction's}

    [chain_id] is a full 256-bit word ([auth_list.rs:47]), not the transaction's
    [u64] ([alloy-primitives] [aliases.rs:118]). A chain id of [2^64] {e decodes}
    inside an authorization and merely fails check 1, while the same value in a
    transaction is an RLP overflow. Modelling both at one width would reject
    transactions the reference accepts.

    [nonce] is a [u64], carried here as a {!word} bounded to eight bytes by
    {!make} rather than as a {!Tn_state.Nonce.t}, whose native [int] stops at 63
    bits. Check 2 is precisely "is the nonce [2^64 - 1]"
    ([pre_execution.rs:223-226]); narrowing the field would make that check
    vacuous and would turn a per-entry skip into a whole-envelope decode error.

    [y_parity] is a [U8]: a value above one decodes fine and only then makes
    that {e one} authorization a no-op ([auth_list.rs:135-141]). A
    {!Tx_signature.t} therefore cannot carry it - its parity is a [bool], which
    has no third case - so this module keeps its own signature triple and offers
    {!signature} as the single place the wire value narrows.

    {2 Nothing here can reject a transaction}

    revm's [apply_auth_list] constructs no [InvalidTransaction] anywhere
    ([pre_execution.rs:214-266]). The empty {e list} is the only authorization
    rule that invalidates a transaction, and that rule belongs to validation,
    not here. So {!screen} returns an option rather than a result and this
    module has no error type at all: every way an authorization can fail is the
    same silent skip, and inventing names for them would invent information the
    reference discards.

    {2 What this module is not}

    It holds no state and knows nothing of {!Effects}, which is why nothing it
    touches can close a module cycle. The state-touching half of the loop -
    warming the authority, checks 5 and 6, the refund test and the write - is
    the authorization {e list}'s job, one layer up. *)

open Tn_types

type word = Tn_state.U256.t
(** The 256-bit word the wire carries these fields as. *)

type t
(** The three signed-over fields of one authorization. Abstract, with {!make}
    its only producer, so a nonce too wide for the wire cannot be written
    down. *)

val make : chain_id:word -> address:Units.Address.t -> nonce:word -> t option
(** [None] exactly when [nonce] is at or above [2^64], a nonce no [u64] field
    can carry. The chain id is deliberately unbounded: it really is a 256-bit
    value, and rejecting a wide one here would reject an authorization revm
    merely skips. *)

val chain_id : t -> word
(** The chain the authorization is valid on, or zero for "any chain". *)

val address : t -> Units.Address.t
(** The address the authority is delegating {e to}. Zero is legal and means
    revocation - see {!Tn_state.Delegation.assignment}. *)

val nonce : t -> word
(** The authority's expected account nonce. Below [2^64] by construction. *)

val encode : t -> string
(** The derived [RlpEncodable] of alloy's [Authorization]
    ([auth_list.rs:45-58]): a list header, then [chain_id] as a minimal-length
    scalar, [address] as a fixed twenty bytes, [nonce] as a minimal-length
    scalar, in declaration order. Three items, never six. *)

val magic : int
(** [0x05] ([alloy-eip7702] [constants.rs:14]).

    {b Not} the type byte [0x04]. The two are one apart and both plausible, and
    using the wrong one does not fail: it recovers a different, perfectly
    well-formed address that belongs to nobody, for every authorization ever
    signed. *)

val signature_hash : t -> string
(** [keccak256(MAGIC || rlp([chain_id, address, nonce]))]
    ([auth_list.rs:83-93]), as thirty-two raw bytes.

    The magic is a bare byte {e outside} the RLP list, and the list covers the
    three unsigned fields only. Dropping the list header, or folding
    [y_parity]/[r]/[s] into it, each recovers a different well-formed address
    with no error anywhere to say so. Only a {!t} can reach this function, never
    a {!signed}, so the six-item encoder physically cannot feed it. *)

type signed
(** An authorization together with the [(y_parity, r, s)] the wire carried,
    {e unvalidated}: alloy's decoder checks nothing cryptographic
    ([auth_list.rs:202-221]), and neither does this. *)

val sign : t -> y_parity:word -> r:word -> s:word -> signed
(** Total, and deliberately unvalidated, matching alloy's constructor. A
    [y_parity] of two, an [r] of zero and an [s] above the curve order are all
    representable here, because they are all representable on the wire; each
    becomes a skip at {!screen} and none of them is an error. *)

val unsigned : signed -> t
(** The three signed-over fields, and the only route from a {!signed} to
    {!signature_hash}. *)

val y_parity : signed -> word
val r : signed -> word
val s : signed -> word

val encode_signed : signed -> string
(** alloy's hand-written six-item encoder ([auth_list.rs:224-233]): a list
    header, then [chain_id], [address], [nonce], [y_parity], [r], [s].

    The parity comes {b first} of the three signature items, not last, which is
    the opposite of the [r, s, v] ordering the rest of Ethereum's wire uses.
    Each scalar is minimal-length, so a [y_parity] of zero is the single byte
    [0x80] and never a literal [0x00]. *)

val signature : signed -> Tx_signature.t option
(** alloy's [SignedAuthorization::signature] ([auth_list.rs:135-141]): [None]
    when {!y_parity} is neither zero nor one.

    This is the one seam where a wire value wider than a [bool] narrows to one,
    and it sits on the {e recovery} path, never the decode path. A parity of two
    must decode without complaint and only then make its own authorization a
    no-op. *)

val secp256k1n_half : word
(** [SECP256K1N_HALF], the EIP-2 malleability bound
    ([alloy-eip7702] [constants.rs:30-31]).

    Not written as a literal: it is {e read} from {!Secp256k1.s_is_high} by a
    binary search over the 256-bit range at module initialisation, exploiting
    the fact that the predicate is monotone in its scalar, so the greatest value
    it answers [false] for is exactly the bound. That keeps the group order
    written down once, in [secp256k1.ml], and {!high_s_is_strict} pins the
    result against alloy's decimal literal so the derivation cannot go quietly
    wrong.

    The comparison is {b strict}: an [s] exactly equal to the bound is
    {e accepted} ([auth_list.rs:248-256]). Note that this is the same curve
    constant {!Tx_recovery} enforces but a {e different policy}: there a high
    [s] rejects the whole transaction, here it costs the authorization its
    25000 and does nothing else. *)

type screened
(** An authorization past checks 1, 2 and 3, carrying the authority those checks
    recovered.

    Abstract, with {!screen} its only producer, and that is the whole point.
    Checks 1 to 3 produce {b no} state effects, while check 4 warms the
    authority {b unconditionally} ([pre_execution.rs:217-237]), so this type
    {e is} the boundary between the two halves of the loop. The step that warms
    accepts nothing else, so an entry that failed a pure check can never reach
    the warming, and an entry that passed them can never bypass it. *)

val screen : chain_id:word -> signed -> screened option
(** Checks 1, 2 and 3 in revm's order ([pre_execution.rs:217-232]).

    1. The authorization's chain id is zero - meaning "any chain" - or equal to
       [~chain_id]. Compared over all 256 bits, so a value that merely truncates
       to the chain id is still rejected.
    2. The nonce is not [2^64 - 1]. Checked {b before} recovery, so such an
       entry never recovers an authority and, one layer up, never warms
       anything.
    3. Recovery succeeds: the parity is zero or one, [s] is not above
       {!secp256k1n_half} (strictly), [r] and [s] lie in [1..n], [r] is a real
       curve point's x-coordinate, and the recovered point is not the identity.

    [None] is a {b skip}, never an error, and the three checks are deliberately
    not distinguished in the result: revm collapses every one of them into the
    same [continue]. *)

val authority : screened -> Units.Address.t
(** The address recovered at check 3. It exists only on a {!screened} value, so
    a recovered authority and an unrecovered one are different types and cannot
    be passed to the same function. *)

val screened_nonce : screened -> word
(** The authorization's nonce, carried through for check 6's comparison against
    the authority's live account nonce. *)

val screened_assignment : screened -> Tn_state.Delegation.assignment
(** What this authorization installs: a designator, or a revocation when the
    address is zero. Routing through {!Tn_state.Delegation.assignment} is what
    makes a designator pointing at the zero address unwritable. *)
