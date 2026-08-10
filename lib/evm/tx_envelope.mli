(** The signed transaction: its signing pre-image, its EIP-2718 bytes, its hash
    and its decoder.

    Four distinct byte strings belong to one transaction and conflating any two
    of them is a fork, so this module names three of them and refuses the fourth.

    - the {e signing payload} ({!signing_payload}) is what the signature is over;
    - the {e EIP-2718 envelope} ({!encode_2718}) is the consensus form: the tx
      hash's pre-image, the transactions-trie leaf value, and the bytes a telcoin
      batch carries;
    - the {e transaction hash} ({!hash}) is [keccak256] of that envelope;
    - the {e network} form — the 2718 bytes behind an extra RLP string header —
      is devp2p's and is deliberately {b not} provided, exactly as
      {!Receipt_envelope} provides no network receipt: it must never reach the
      trie, and an encoder that exists is an encoder someone will feed to it.

    Ported from alloy-consensus 1.8.3: the shared machinery in
    [src/transaction/rlp.rs:24-113] and the legacy overrides in
    [src/transaction/legacy.rs:113-235] that make type 0 carry {e no} type byte
    and {e no} outer header. The signature tail is [v], then [r], then [s]
    (alloy-primitives 1.5.7 [src/signature/sig.rs:358-370]), inside the {e same}
    list as the body fields — never a nested sub-list — and the list header is
    sized over body and signature together ([rlp.rs:40-44]), which the port gets
    for free because {!Tn_rlp.Rlp.encode_list} takes already-encoded chunks and
    computes the header itself.

    {2 The accept set is canonical framings only, and that is narrower than alloy}

    {!decode_2718} accepts exactly two shapes: a bare RLP {e list} of nine items
    (legacy, no type byte, no outer header), and a single type byte [0x01],
    [0x02] or [0x04] followed by an RLP list of eleven, twelve or thirteen
    items. A type-4 envelope is ONE thirteen-item list covering body {e and}
    signature (never a nested [\[body, sig\]]) and the framing rules below
    apply to it verbatim, or the round-trip theorem would hold for three
    types and not four. Everything else is an {!error}. Two rejections
    deserve their standing spelled out, and (chunk-34 correction) those
    standings are OPPOSITE, not the pair of narrowings this comment once
    claimed:

    - [0xb8 ‖ len ‖ L], where [L] is a well-formed signed typed transaction:
      {b agreement with alloy on TN's path}, not a narrowing. The leading
      byte is above [0x7f], so there is no type byte, and the payload is an
      RLP {e string} rather than a list. This port answers {!Outer_string};
      alloy's [decode_2718_exact] (what TN's [recover_raw_transaction]
      calls on batch bytes) rejects the same input with [UnexpectedType(0)],
      empirically pinned against the vendored crates. Only devp2p's
      [network_decode], which TN never runs on a batch, accepts the wrapped
      form.
    - [0x00 ‖ L], the [0x00]-tagged legacy form: a {b real deliberate
      narrowing}. Alloy on TN's path decodes it to the same transaction as
      the untagged list, then re-encodes and re-hashes it {e untagged}, so
      two byte strings share one transaction hash. This port answers
      {!Zero_type_byte} and keeps its canonical accept set; the batch
      boundary compensates: [Tn_batch.Tx_shape] accepts the tagged form
      exactly as alloy does, and [Tn_batch.Batch_payload] strips the tag
      before re-entering this decoder. {!Unrepresentable_scalar} is the
      other compensated narrowing (a nonce or gas limit in [2^62, 2^64)
      decodes in [Tx_shape]; the payload layer then drops, never errs,
      mirroring TN's own execute-then-skip).

    Both standings were re-confirmed against the pinned crates on TN's
    actual ingress path rather than reasoned about (an earlier revision of
    this comment claimed alloy accepts the wrapped form there; that was
    the devp2p path's behavior, not [decode_2718_exact]'s). The
    tagged-legacy acceptance is a decoder accident of alloy's
    [TransactionEnvelope] derive, which tries each variant in declaration
    order over a buffer it never restores between attempts
    ([alloy-tx-macros-1.8.3/src/expand.rs:564-571], each arm reaching
    [alloy-consensus-1.8.3/src/signed.rs:549-551]), while
    [alloy-rlp-0.3.13/src/header.rs:21-94] advances the cursor {e before}
    raising [UnexpectedString]. Reproducing that here would mean emulating
    alloy's cursor state across failed parses (carrying a decoder's
    accidents, not its rules), so this module declines and the TN-mirror
    batch decoder [Tn_batch.Tx_shape] carries it instead.

    The batch boundary is the port's only network ingress, and it accepts
    the tagged form through [Tn_batch.Tx_shape] exactly as TN does, so the
    availability divergence an earlier revision flagged as latent is now
    discharged where TN semantics actually apply. The narrowing also buys a
    theorem the lenient form cannot have, namely that {!encode_2718}
    recovers its input byte for byte (see {!decode_2718}).

    Framing is not the only place this decoder is narrower than alloy's, and it
    would be dishonest to imply otherwise. On {e canonically framed} input it
    also refuses every EIP-4844 (type [0x03]) envelope, which alloy decodes and
    which is a real transaction on a Prague chain. That is this port's standing
    deferral of the blob transaction type, stated in {!Transaction} and in the
    README, surfacing at the decoder; it closes only when that chunk lands.
    Below Cancun the same refusal is not a deferral at all but the correct
    answer, since revm itself rejects a type-[0x03] transaction before
    execution with [Eip4844NotSupported] whenever Cancun is not enabled
    ([revm-handler] [validation.rs:177-180]); so on a Shanghai-only chain such
    as {!Fork_schedule.mainnet} this decoder is already faithful, and the gap is
    exactly the Cancun-and-later acceptance. That is why the deferral is not
    gated on {!Spec.t} here: a gate would only turn one refusal into a
    differently-named refusal until the blob structure exists to accept.
    (EIP-7702 was such a deferral until chunk 33 narrowed the gap by exactly one
    type byte.) A wide scalar is {e not} such a case: a [chain_id],
    [nonce] or [gas_limit] above [2^64] is refused here as {!Scalar_too_wide}
    and refused by alloy while decoding the integer into its [u64], so the two
    agree on the verdict and differ only in which error they name. Nor is the
    empty authorization list: it {b decodes successfully by design}, because
    alloy's [Vec<SignedAuthorization>] does, and its rejection is a validation
    identity ([revm-handler] [validation.rs:199-203]) that a decoder error here
    would silently move and diverge.

    The decoder is otherwise the {e typed} layer {!Tn_rlp.Rlp} explicitly leaves
    to its caller: [Rlp] enforces structural canonicity (header forms, lengths,
    truncation) and this module adds integer and fixed-width canonicity — a
    leading-zero scalar, an over-wide scalar, a wrong-width address or storage
    key, a non-boolean parity, an invalid EIP-155 [v]. It validates {e no}
    cryptography: [r = 0], [s = 0] and [s >= n] all decode successfully, because
    alloy's does ([sig.rs:98-109]) and a stricter decoder would reject
    transactions the network executes. *)

type t
(** A signed transaction: a {!Tx_payload.t} and a {!Tx_signature.t}. Abstract,
    with no cached hash — alloy memoises one in a [OnceLock]
    ([src/signed.rs:26-46]) because its value is mutable-adjacent; here {!hash}
    is a pure function of a persistent value, so a stale cache has no way to
    exist. *)

val make : payload:Tx_payload.t -> signature:Tx_signature.t -> t
(** Pair a payload with a signature. Total: no combination is rejected, matching
    alloy, where a signature is attached without validation and every
    cryptographic rejection happens in recovery. *)

val payload : t -> Tx_payload.t
(** The unsigned payload. *)

val signature : t -> Tx_signature.t
(** The signature. *)

(** {1 Signing} *)

val signing_payload : Tx_payload.t -> string
(** The exact bytes a signature is taken over.

    Type 0 with a chain id is the nine-item list
    [\[nonce; gas_price; gas_limit; to; value; input; chain_id; 0x80; 0x80\]],
    and without one is the same list truncated to its first six items
    ([legacy.rs:98-107,328-343]). The two trailing items are the {e number} zero,
    so they are [0x80] each and never [0x00] — writing literal zero bytes changes
    the digest and therefore every recovered address.

    Type 1 is [0x01] then the eight-item list, type 2 is [0x02] then the
    nine-item list, and type 4 is [0x04] then the ten-item list — the 1559 nine
    with the authorization list appended after the access list
    ([eip2930.rs:226-234], [eip1559.rs:259-272], [eip7702.rs:240-247]); the type
    byte is written raw, not RLP-wrapped, and the body is a LIST with no outer
    string header. *)

val signature_hash : Tx_payload.t -> string
(** [keccak256] of {!signing_payload} — the 32-byte digest that is signed and
    that {!Tx_recovery} re-derives (alloy-consensus
    [src/transaction/mod.rs:249-299]). *)

(** {1 The consensus envelope} *)

val encode_2718 : t -> string
(** The verbatim EIP-2718 bytes: the transactions-trie leaf value, the
    transaction hash's pre-image, and the payload a telcoin batch carries.

    Type 0 is the bare nine-item RLP list
    [\[nonce; gas_price; gas_limit; to; value; input; v; r; s\]] with {b no} type
    byte, where [v] is {!Tx_signature.to_eip155_value}; type 1 is [0x01] then an
    eleven-item list, type 2 is [0x02] then a twelve-item list and type 4 is
    [0x04] then a thirteen-item list, each the body fields followed by
    [y_parity], [r], [s] — ONE list covering body and signature together, never
    a nested [\[body, sig\]] ([rlp.rs:53-69]). The transaction hash is keccak
    over these BARE 2718 bytes ([rlp.rs:104-108]). No outer string header is
    added — that is the network form, and it must never reach the trie.

    Feed the result straight to {!Block_roots.transactions_root}, which wraps it
    exactly once inside the leaf node, or use
    {!Block_roots.transactions_root_of}. *)

val hash : t -> string
(** The 32-byte transaction hash, [keccak256 (encode_2718 t)]
    ([src/transaction/rlp.rs:104-108], legacy override [legacy.rs:170-174], which
    discards the type argument so that no [0x00] is ever hashed). *)

val hash_of_2718 : string -> string
(** [keccak256] of an envelope's bytes, without decoding them. Total on any
    input, which is what makes it the escape hatch for a transaction
    {!decode_2718} cannot represent (see {!Unrepresentable_scalar}): such an
    envelope can still be hashed and rooted from the bytes as received. For every
    envelope {!decode_2718} accepts it agrees with {!hash}, because the accept
    set is exactly the canonical framings and {!encode_2718} reproduces them
    byte for byte. *)

(** {1 Decoding} *)

type error =
  | Rlp of Tn_rlp.Rlp.error
      (** A structural or header-canonicity failure below the typed layer:
          truncation, a non-canonical single byte or long-form size, a
          leading-zero length, or bytes left over after the envelope. *)
  | Empty_input
      (** A zero-length buffer. alloy reaches this through its untagged fallback
          and reports [UnexpectedType(0)]
          ([alloy-tx-macros-1.8.3/src/expand.rs:564-590]); the rejection is the
          same and the name is honest. *)
  | Zero_type_byte
      (** A leading [0x00]: the [0x00]-tagged legacy form, which this port
          refuses and alloy accepts. See the module comment — this is a decided
          narrowing, and it is the reason {!encode_2718} recovers its input
          exactly rather than merely up to framing. *)
  | Unknown_type_byte of int
      (** A leading byte at or below [0x7f] that is not [0], [1], [2] or [4] —
          an EIP-4844 ([3]) transaction, or an unassigned type. The blob type is
          out of scope here exactly as it is for {!Transaction} and {!Executor};
          type 4 stopped being so in chunk 33, which narrowed this constructor
          by exactly one byte. *)
  | Outer_string
      (** The envelope, after any type byte, is an RLP byte string rather than a
          list: the [0xb8 ‖ len ‖ list] framing devp2p's [network_decode]
          accepts and both this port and alloy's [decode_2718_exact] (TN's
          batch path) refuse. See the module comment. *)
  | Unexpected_string
      (** A byte string where a list was required {e inside} the envelope: the
          access list or the authorization list, or one of either's items. *)
  | Unexpected_list
      (** A list where a byte string was required: any scalar, the [to] field,
          the calldata, an address or a storage key. *)
  | Field_count of { expected : int; got : int }
      (** A list of the wrong length: the envelope, or an access-list item that
          is not exactly an address and a key list. alloy detects the same
          condition by comparing consumed bytes against the header's declared
          payload and calls it [ListLengthMismatch] or [UnexpectedLength]
          depending on the path ([src/transaction/rlp.rs:142-165]); the rejection
          set is identical and only the name differs. *)
  | Leading_zero_scalar
      (** An integer field whose payload begins with [0x00] — a nonce written
          [0x00] rather than [0x80], or [0x82 0x00 0x01]. alloy's
          [Error::LeadingZero] ([alloy-rlp-0.3.13/src/decode.rs:214-233],
          [ruint-1.17.2/src/support/alloy_rlp.rs:76-95]). *)
  | Scalar_too_wide
      (** An integer field wider than its type: over 8 bytes for a chain id,
          nonce or gas limit, over 16 for a gas price, a fee cap or a legacy [v],
          over 32 for a value or for [r]/[s]. alloy's [Error::Overflow].

          Inside an {e authorization} the widths differ, because the types do:
          its [chain_id] is a full [U256] ([alloy-eip7702] [auth_list.rs:47]),
          so 32 bytes decode and a transaction-fatal chain id like [2^64] merely
          fails the loop's chain check; its [nonce] is a [u64] (8 bytes); and
          its [y_parity] is a one-byte {e scalar}, not the RLP bool — a parity
          of 2 decodes and no-ops that one authorization at recovery
          ([auth_list.rs:135-141]), where {!Invalid_bool} would have killed the
          whole envelope. *)
  | Unrepresentable_scalar
      (** A [u64] field — the nonce or the gas limit — above [Int.max_int]. alloy
          accepts the full [u64] range; OCaml's native [int] is 63 bits, so the
          top quarter of it has no representation here. This is the port's one
          value narrowing, and it is confined to transactions no block could
          execute (a gas limit above [2^62] exceeds every block's). {!hash} and
          {!hash_of_2718} are unaffected, so such an envelope can still be rooted
          and hashed from its bytes. *)
  | Fixed_width of { expected : int; got : int }
      (** A fixed-width byte string of the wrong length: a [to] or access-list
          address that is not 20 bytes, or a storage key that is not 32. alloy's
          [Error::UnexpectedLength] ([alloy-rlp-0.3.13/src/decode.rs:59-65]).
          These are {e not} scalars: leading zeros are preserved and a short
          encoding is a rejection, not a value. *)
  | Invalid_bool
      (** A typed transaction's [y_parity] that is neither [0x80] nor [0x01]
          ([alloy-rlp-0.3.13/src/decode.rs:48-57]). A literal [0x00] is
          {!Leading_zero_scalar} instead, which is exactly where alloy puts
          it. The {e authorization}-level [y_parity] can never reach this
          constructor: it is a one-byte scalar there, and a value above one is a
          decode {e success} — see {!Scalar_too_wide}. *)
  | Invalid_parity_value
      (** A legacy [v] outside [{27, 28}] and [\[35, ..\]], or one whose derived
          chain id exceeds [u64::MAX]. alloy's [Custom("invalid parity value")]
          ([legacy.rs:200-206,406-422]). *)

val error_to_string : error -> string
(** Render a decode {!error} as a short human-readable string, for diagnostics
    and test failure messages. *)

val decode_2718 : string -> (t, error) result
(** Decode a verbatim EIP-2718 envelope, rejecting anything left over — the port
    of [Decodable2718::decode_2718_exact]
    ([alloy-eips-1.8.3/src/eip2718.rs:144-151]), which is the only variant
    telcoin calls ([reth-rpc-eth-types/src/utils.rs:35-45]). The lenient
    [decode_2718], which silently leaves trailing bytes in the buffer, is not
    offered: in a consensus decoder that is a footgun, not a feature.

    Routing follows [eip2718.rs:84-125]: a leading byte at or below [0x7f] is a
    type flag and is stripped — [0x01], [0x02] and [0x04] have readers, the rest
    are {!Unknown_type_byte} — and anything else, in practice a list header, is
    the untagged legacy form. Of the two non-canonical framings, alloy on TN's
    path additionally accepts only the [0x00]-tagged legacy form
    ({!Zero_type_byte}, the compensated narrowing); the outer-string wrap it
    rejects exactly as this decoder does, so {!Outer_string} is agreement. The
    module comment says why, and both arise for a type-4 envelope exactly as
    for the other three.

    Because the accept set is exactly the canonical framings, the round trip
    holds on the nose: [encode_2718 e = b] for every [b] this function decodes to
    [e]. No cryptographic validation is performed — [r] and [s] may be zero or at
    or above the group order, and a high [s] decodes fine. Those are recovery's
    business ({!Tx_recovery}), and a decoder that pre-empts them over-rejects. *)
