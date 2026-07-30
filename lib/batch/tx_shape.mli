(** The batch-transaction wire boundary, mirroring exactly what TN accepts.

    TN validates every batch transaction with reth v1.11.3's
    [recover_raw_transaction] ([reth-rpc-eth-types/src/utils.rs:26-45] at the
    pinned commit d6324d63), which is alloy 1.8.3 [decode_2718_exact]
    (trailing bytes rejected, [alloy-eips-1.8.3/src/eip2718.rs:144-151])
    followed by CHECKED signer recovery: [try_into_recovered] routes to
    [recover_signer] and its EIP-2 strict low-s gate
    ([alloy-consensus-1.8.3/src/crypto.rs:246-251]), never the unchecked
    variant.

    This is a SEPARATE decoder from {!Tn_evm.Tx_envelope}. That module keeps
    the port's canonical accept set and its byte-exact round-trip theorem;
    this one reproduces alloy's wider set on TN's path: the [0x00]-tagged
    legacy framing (ground-truth exhibit 24, empirically confirmed against the
    pinned crates), full-u64 nonce and gas_limit scalars (exhibit 26), and
    well-formed EIP-4844 envelopes, so validator rules 5 and 6 keep TN's error
    identities. Scalars are held as validated minimal wire bytes; there is no
    native-int narrowing anywhere in this module. Drift against [Tx_envelope]
    is controlled by a differential test over the whole existing signed-tx
    fixture corpus. *)

(** TN's three observable arms, mirroring reth [EthApiError]
    ([reth-rpc-eth-types/src/utils.rs:26-45]). reth discards the underlying
    alloy taxonomy ([map_err(|_| ...)], so its message string can never carry
    an alloy error name); finer distinctions here would invent information the
    reference destroys. *)
type error =
  | Empty_input
      (** [EmptyRawTransactionData]: the zero-length buffer, and only it. *)
  | Failed_to_decode
      (** [FailedToDecodeSignedTransaction]: any 2718/RLP failure: wrong
          width, leading zero, trailing bytes, bad framing, wrong field
          count, unknown type byte. *)
  | Invalid_signature
      (** [InvalidTransactionSignature]: a high [s] (strict [> floor(n / 2)])
          or an unrecoverable signature. *)

val error_to_string : error -> string
(** Human rendering; feeds the batch validator's [Recover_transaction]
    message. *)

type t
(** A decoded batch transaction: exactly the observables batch validation
    needs (hash, type class, gas limit, recoverability). Not executable;
    execution re-materialises through the payload seam's drop layer. *)

val decode : string -> (t, error) result
(** alloy [decode_2718_exact] semantics over the whole input.

    A first byte at or below [0x7f] is a type flag and dispatches
    ([eip2718.rs:87-89, 118-125]); type [0] routes to the LEGACY grammar on
    the remainder, which itself demands an RLP list, so [0x00] followed by a
    non-list rejects: alloy's [typed_decode(0)] errors [UnexpectedString]
    ([signed.rs:539-547] over [rlp.rs:150-154]), and the naive
    strip-and-recurse would wrongly accept [0x00], then [0x02], then a
    1559 list. A first byte above [0x7f] is the untagged legacy form. Types
    1, 2, 3 and 4 use their alloy field grammars and widths (u64 nonce and
    gas_limit as at-most-8-byte scalars, u128 fees 16-byte, U256 value and
    [r]/[s] 32-byte; signed field counts 9/11/12/13, and EIP-4844 is 11
    unsigned fields plus the 3 signature items in one 14-item list with a
    MANDATORY 20-byte [to]). Anything else is {!Failed_to_decode}. The whole
    input must be consumed. *)

val recover_signer : t -> (Tn_types.Units.Address.t, error) result
(** Checked recovery over the type's signing digest, re-derived from the wire
    fields: EIP-155 or the 27/28 pre-155 form for legacy,
    [keccak(ty || rlp(unsigned))] for typed INCLUDING EIP-4844 (its 11-field
    unsigned list, blob fields in). The EIP-2 strict high-s gate fires first,
    then {!Tn_evm.Secp256k1} recovery and the keccak-truncate address through
    {!Tn_evm.Public_key}. Only {!Invalid_signature} here. *)

val decode_and_recover : string -> (t, error) result
(** [decode], then {!recover_signer} with the address discarded: the exact
    composition TN performs in validator rule 5
    ([tn-reth/src/txn_pool.rs:369-373]). *)

val hash : t -> Tn_keccak.t
(** TN's transaction hash: keccak of the CANONICAL EIP-2718 re-encoding. For
    a [0x00]-tagged legacy input this equals the untagged bytes' hash; that
    is pinned empirically against the vendored pinned crates (the tagged and
    untagged decodes share one tx hash), not argued. *)

val is_eip4844 : t -> bool
(** True exactly for a well-formed type-3 envelope; feeds validator rule 6. *)

val gas_limit : t -> int64
(** The declared gas limit, full u64 carried as raw bits in [int64]; feeds
    validator rule 7. *)
