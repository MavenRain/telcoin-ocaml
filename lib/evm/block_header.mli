(** The execution-layer block header: the record, the assembler, the RLP and the
    hash.

    One module, because {!t} must be abstract with NO public constructor so that
    {!assemble} is its sole producer. Entirely greenfield: the port had no EL
    header type at all (the consensus DAG header in [lib/vertex/header.mli] is a
    different object producing a {!Tn_types.Digests.Header_digest.t}).

    The result is that no TN header can be named whose [ommers_hash] is not a
    batch digest, whose [nonce] is not an [(epoch, round)] pair, whose
    [extra_data] disagrees with its withdrawals root, or whose state root is not
    the root of the world its own block produced. *)

type root_field = State_root | Transactions_root | Receipts_root | Withdrawals_root
(** Which of the four 32-byte roots failed the width gate. A closed
    four-constructor sum, so a fifth root cannot be added without revisiting
    every reader. *)

val root_field_to_string : root_field -> string
(** Render a {!root_field} as the lowercase field name, for diagnostics and test
    failure messages. *)

type error =
  | Root_unrepresentable of root_field
      (** A root {!Block_roots} or {!Epoch_boundary} returned was not 32 bytes.
          Unreachable on any real input, and reachable in principle through
          [block_roots.ml:5-10]'s error-STRING collapse; surfaced so that path
          ends in a visible error rather than in a header that hashes to
          something no other node computes.

          The [Epoch_close_state_deferred] variant that used to sit beside
          this one is retired, exactly as its own doc pre-announced: the
          epoch-close state transitions now run in
          {!Block_execution.finish}, and {!assemble} takes the
          {!Block_execution.Finished.t} that proves they ran, so the world it
          refused to root can no longer be offered at all. *)

val error_to_string : error -> string
(** Render an {!error} as a short human-readable string, for diagnostics and
    test failure messages. *)

val empty_requests_hash : Hash32.t
(** [0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855], which
    is [sha256("")] and [Requests::default().requests_hash()]
    ([alloy-eips-1.8.3/src/eip7685.rs:9-13, 226]). Telcoin hard-codes
    [Some(EMPTY_REQUESTS_HASH)] ([block.rs:1001]), consistent with [finish]'s
    [Requests::default()] and its "don't support prague deposit requests"
    ([block.rs:790-791]). A pinned literal and not a computation: this port has
    no SHA-256.

    HONEST LIMIT, the same one {!System_contracts} states for its addresses: the
    32-byte width of this literal is not a type fact here. {!Hash32.of_bytes} is
    the only width-checking constructor and it is partial, so the value is
    collapsed with [Option.value ~default:Hash32.zero] and both the width and
    the hex are pinned by test instead. A typo in the literal therefore lands as
    thirty-two zero bytes in every header this port emits, which is loud in a
    golden-vector test and silent nowhere else. *)

val empty_ommer_root : Hash32.t
(** [0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347], which
    is [keccak256(rlp([]))]. Exposed for one reason: so a test can assert that a
    TN header NEVER carries it. It is pinned and collapsed exactly as
    {!empty_requests_hash} is, with the same honest limit. *)

type t
(** An assembled TN execution-layer header. Abstract with no [make]:
    {!assemble} is its only producer, which is why the assembler lives in this
    module. *)

val assemble :
  context:Block_context.t ->
  finished:Block_execution.Finished.t ->
  (t, error) result
(** Telcoin's [TNBlockAssembler::assemble_block] ([block.rs:940-1008]), over
    a FINISHED block.

    {2 Where each field comes from}

    From [context]: [parent_hash], [ommers_hash] (its batch digest), [nonce],
    [difficulty] (its position's word), [extra_data], [withdrawals],
    [withdrawals_root] and [parent_beacon_block_root]. From the context's
    {!Env.Block.t}: [beneficiary] ([coinbase]), [mix_hash] ([prevrandao]) and
    [base_fee_per_gas], with [number], [gas_limit] and [timestamp] read off the
    context's already-narrowed integers rather than re-narrowed here. From
    [finished]: [gas_used], [transactions_root], [receipts_root] and
    [logs_bloom] off {!Block_execution.Finished.outcome}, and the
    [state_root] over {!Block_execution.Finished.world}.

    {2 It takes no [state_root] parameter, and that is a deliberate divergence}

    Telcoin destructures one out of [BlockAssemblerInput] and never touches a
    trie or a state provider ([block.rs:950, 984]), because reth computes it at
    [builder.finish(&state_provider)] ([crates/tn-reth/src/lib.rs:736-745]).
    This port has {!Block_roots.state_root}, a TOTAL function of a
    {!Tn_state.World_state.t}, and the finished token carries the world.
    Taking the root as a parameter would be a chance to pass the root of some
    other world; computing it from {!Block_execution.Finished.world} makes
    "this header's state root is the root of the state this block produced,
    epoch close included" a fact of the type. {!Block_execution.finish} is
    the only producer of the argument and its Closing arm runs the
    epoch-close writes, so the unfinished closing world the retired
    [Epoch_close_state_deferred] variant used to refuse is now unofferable
    rather than refused.

    It takes no transaction list either: {!Block_execution.transactions} is the
    list, so [transactions_root] and [receipts_root] commit the same block.

    {2 The three repurposed fields}

    [ommers_hash] is the consensus BATCH DIGEST ([block.rs:965, 982]), not
    [keccak(rlp(ommers))] and never {!empty_ommer_root}; telcoin's body ommers
    are simultaneously [Default::default()] (empty) ([block.rs:1004-1007]), so
    the header's hash intentionally does not match the body and a port that
    recomputes it diverges. This module models no ommer list at all, so the
    repair is inexpressible. [nonce] is the subdag leader's
    [(epoch << 32) | round] ([block.rs:966]). [difficulty] is the packed
    [(batch_index << 16) | worker_id] word ([block.rs:967, 995]), and NOT what
    the EVM saw, which is the unshifted batch index on the build path and
    [U256::ZERO] on replay ([config.rs:99, 135]).

    {2 The blob and requests fields are structurally constant}

    [excess_blob_gas] is a hard-coded [0] ([block.rs:959-960]).
    [blob_gas_used] is [0] by TYPE rather than by arithmetic:
    {!Tx_envelope.decode_2718} refuses type [0x03] ([tx_envelope.mli:29-43]), so
    a blob transaction cannot be in {!Block_execution.transactions}; telcoin
    reaches the same zero by summing [blob_gas_used().unwrap_or_default()]
    ([block.rs:961-962]) over a list its batch builder and validator have
    already purged of 4844 transactions ([batch-builder/src/batch.rs:88-94],
    [batch-validator/src/validator.rs:198-206]). [requests_hash] is
    {!empty_requests_hash}, unconditionally. *)

val of_persisted :
  parent_hash:Tn_keccak.t ->
  ommers_hash:Tn_types.Digests.Batch_digest.t ->
  beneficiary:Tn_types.Units.Address.t ->
  state_root:Hash32.t ->
  transactions_root:Hash32.t ->
  receipts_root:Hash32.t ->
  logs_bloom:Bloom.t ->
  position:Batch_position.t ->
  number:int ->
  gas_limit:int ->
  gas_used:int ->
  timestamp:int ->
  extra_data:string ->
  mix_hash:Tn_state.U256.t ->
  nonce:Tn_types.Units.Sequence_number.t ->
  base_fee_per_gas:Tn_state.U256.t ->
  withdrawals:Withdrawal.t list ->
  withdrawals_root:Hash32.t ->
  parent_beacon_block_root:Tn_types.Digests.Output_digest.t ->
  blob_gas_used:int ->
  excess_blob_gas:int ->
  requests_hash:Hash32.t ->
  t
(** Rebuild a header from the fields a durable artefact stored. RESERVED for the
    storage chunk, the precedent [Tn_consensus.Dag.insert_recovered] sets.

    {2 Why it cannot be avoided}

    {!assemble} is the only other producer and it needs a
    {!Block_execution.Finished.t} — a whole executed block — so no decoder can
    rebuild a header from bytes without it. Storing only
    [(hash, number, base_fee, gas_limit)] instead was considered and refused:
    [Tn_engine.Anchor.header] would come back [None], which
    [lib/engine/anchor.mli] says "would tell the engine its parent has no header
    when it has one". [encode_rlp] exists, but there is no RLP decoder and the
    RLP deliberately omits {!withdrawals}, so it is not a round trip either.

    {2 What is and is not restated}

    One labelled argument per STORED field, twenty-two of them, in the record's
    own declaration order. {!difficulty} is deliberately not among them: it is
    [Batch_position.word] of {!position} and taking it as a twenty-third
    argument would be a second door to one value, which is the drift this
    module removed when it stopped storing it.

    {2 The obligation it moves rather than discharges}

    {!assemble} guarantees that the four roots are the roots of the block this
    header commits to, and this function guarantees nothing of the kind: it
    trusts its arguments exactly as far as the artefact they were read from is
    trusted. That is the same trade [Tn_engine.Engine.persisted] documents for
    its world — "the world is carried, not proven" — and it is stated here so
    the weaker guarantee travels with the entry point rather than with the
    caller. Nothing is recomputed, so {!hash} of a restored header equals
    {!hash} of the header that was stored, which is the property a resumed
    chain needs. *)

val parent_hash : t -> Tn_keccak.t
(** The previous execution block's hash, as a real digest rather than as bytes.
    *)

val ommers_hash : t -> Tn_types.Digests.Batch_digest.t
(** The consensus batch digest, in the slot a non-TN chain fills with
    [keccak(rlp(ommers))]. Typed as a batch digest, so the repair is a type
    error. *)

val beneficiary : t -> Tn_types.Units.Address.t
(** The block's fee recipient, the [COINBASE] every frame read. *)

val state_root : t -> Hash32.t
(** The root of the world this block produced, epoch close included: computed
    by {!assemble} from {!Block_execution.Finished.world} and never supplied
    by a caller. *)

val transactions_root : t -> Hash32.t
(** The root of the trie over {!Block_execution.transactions}. *)

val receipts_root : t -> Hash32.t
(** The root of the trie over {!Block_execution.receipts}, which commits the
    same list {!transactions_root} does. *)

val logs_bloom : t -> Bloom.t
(** The block's logs bloom, taken verbatim from {!Block_execution.logs_bloom} so
    the header never computes a second one. *)

val position : t -> Batch_position.t
(** The batch's position in its consensus output. Kept as the typed position
    rather than only as {!difficulty}, so the header and the EIP-4788 gate read
    one value. *)

val difficulty : t -> Tn_state.U256.t
(** [Batch_position.word (position t)], the packed word the [difficulty] slot
    carries. Derived and not stored, so it cannot drift from {!position}. *)

val number : t -> int
(** The block number, non-negative because {!Block_context} narrowed it once. *)

val gas_limit : t -> int
(** The block gas limit, non-negative for {!number}'s reason. It is the real
    block limit and emphatically not {!System_call.gas_limit}. *)

val gas_used : t -> int
(** {!Block_execution.gas_used}: the transactions only, never the pre-block
    system calls. *)

val timestamp : t -> int
(** The block timestamp, non-negative for {!number}'s reason. It is also the
    value the EIP-4788 contract derives its two storage slots from. *)

val extra_data : t -> string
(** Empty on an open boundary and the 32 bytes of the close-epoch randomness on
    a closing one ([block.rs:969-970]). Empty, {e not} thirty-two zero bytes:
    telcoin's [unwrap_or_default()] on a [Bytes]. *)

val mix_hash : t -> Tn_state.U256.t
(** The [prevrandao] every frame read at opcode [0x44]. Thirty-two raw bytes in
    the RLP and never a scalar. *)

val nonce : t -> Tn_types.Units.Sequence_number.t
(** The subdag leader's [(epoch << 32) | round]. Stored TYPED, which is why
    nothing in this chunk needs a [Sequence_number.of_int64] inverse: the header
    is the only consumer and it encodes rather than decodes. *)

val base_fee_per_gas : t -> Tn_state.U256.t
(** The block's base fee, [Some] unconditionally in telcoin ([block.rs:992]),
    which is why it is not an option here. *)

val withdrawals : t -> Withdrawal.t list
(** The EIP-4895 withdrawals this block commits to, empty on an open boundary.
    They belong to the block BODY rather than to the header, and are carried
    here so that {!withdrawals_root} and the list it roots cannot be obtained
    separately. They are consequently NOT part of {!encode_rlp}. *)

val withdrawals_root : t -> Hash32.t
(** The root of {!withdrawals}. Always a root, never absent: telcoin's
    [withdrawals_root] is [Some] in BOTH arms of the close-epoch branch
    ([block.rs:971-978]). *)

val parent_beacon_block_root : t -> Tn_types.Digests.Output_digest.t
(** The digest of the [ConsensusHeader] this block descends from, which is also
    the EIP-4788 calldata. One field, so the header and the system call cannot
    disagree. *)

val blob_gas_used : t -> int
(** Always [0]: a 4844 envelope cannot be decoded by this port at all
    ([tx_envelope.mli:29-43]), so the sum has no nonzero summand. *)

val excess_blob_gas : t -> int
(** Always [0], hard-coded by telcoin ([block.rs:959-960]). *)

val requests_hash : t -> Hash32.t
(** Always {!empty_requests_hash} ([block.rs:1001]). *)

val encode_rlp : t -> string
(** The canonical post-Prague execution-header RLP: ONE 21-element list, in the
    order [parent_hash, ommers_hash, beneficiary, state_root,
    transactions_root, receipts_root, logs_bloom, difficulty, number, gas_limit,
    gas_used, timestamp, extra_data, mix_hash, nonce, base_fee_per_gas,
    withdrawals_root, blob_gas_used, excess_blob_gas, parent_beacon_block_root,
    requests_hash]. "Post-Prague" names the SHAPE and not the block's fork
    level: the same 21 chunks are written for a block executing at any level of
    {!Spec.t}, for the reason set out under DO NOT NARROW below.

    Hashes, the 256-byte bloom, the address and [extra_data] take the
    byte-string rule ({!Tn_rlp.Rlp.encode_bytes}, leading zeros PRESERVED);
    [difficulty] and [base_fee_per_gas] take the scalar rule
    ({!Tn_rlp.Rlp.encode_scalar} over {!Tn_state.U256.to_be_bytes}, leading
    zeros stripped); the five integers take {!Tn_rlp.Rlp.encode_nat};
    [mix_hash] is 32 raw bytes and NOT a scalar; and [nonce] is EIGHT raw
    big-endian bytes and not a scalar, because the Rust field is a [B64].
    Confusing the two rules is the classic RLP bug this port's codec is
    explicitly shaped to prevent ([rlp.mli:15-17]).

    Every post-merge field is present unconditionally, so there is no trailing
    [Option] prefix to get wrong. Justified because TN fills all six on every
    block it emits: [base_fee_per_gas] is [Some] unconditionally
    ([block.rs:992]), [withdrawals_root] is [Some] in BOTH arms of the
    close-epoch branch ([block.rs:971-978]), [excess_blob_gas] and
    [blob_gas_used] are both [Some] ([block.rs:959-962]), [requests_hash] is
    hard-coded [Some] ([block.rs:1001]), and [parent_beacon_block_root] comes
    from a payload that always supplies it ([payload.rs:117-120]). The
    narrowing, stated: this port cannot encode a foreign pre-Prague header.

    DO NOT NARROW this list on account of the fork level, and note that chunk
    42 sharpened the temptation rather than removing it: TN mainnet runs at
    [SpecId::SHANGHAI], and {!Fork_schedule.mainnet} now makes that chain
    expressible in the port ({!Env} states the schedule once, [env.mli:26-64]),
    so the "consistency fix" of dropping the four post-Shanghai fields for it
    finally has a value to hang itself on. It would still be wrong, and the
    reason is that the header SHAPE is fork-independent upstream where the
    pre-block system calls are not. TN's assembler writes
    [parent_beacon_block_root], [blob_gas_used], [excess_blob_gas] and
    [requests_hash] unconditionally, with no fork gate of any kind
    ([tn-reth/src/evm/block.rs:998-1001]) — the contrast with the two calls
    telcoin DOES gate, at [:610] and [:665], is the whole point — and nothing
    downstream rejects the fork-inconsistent header, because [TNExecution]'s
    HeaderValidator/Consensus/FullConsensus impls are unconditional [Ok(())]
    ([tn-reth/src/traits.rs:50-53]). TN mainnet headers are therefore
    post-Prague-SHAPED even at Shanghai semantics, and the 21-element list
    above is correct for BOTH networks as it stands. Accordingly no function in
    this module takes a {!Spec.t}, and adding one would be the narrowing by
    another route.

    {2 Where the field order came from, and how it is certified}

    The order above is the protocol-canonical post-Prague header order, taken
    from the field order the EIPs themselves append in: the Yellow Paper's
    fifteen ([parent_hash] through [nonce]), then [base_fee_per_gas] appended by
    EIP-1559, then [withdrawals_root] by EIP-4895, then [blob_gas_used] and
    [excess_blob_gas] by EIP-4844 in that order, then
    [parent_beacon_block_root] by EIP-4788, then [requests_hash] by EIP-7685.
    Each hardfork appends its new fields at the end, which is what makes the
    sequence recoverable from the EIPs without reading a client.

    It is fixed by consensus rather than by alloy, since a client that reordered
    would fork, and it is emphatically NOT the struct-literal order at
    [block.rs:980-1002], which is a different permutation and which a port must
    not transcribe.

    It is still not a line this port has read: alloy-consensus 1.8.3 is not
    among the extracted sources and is not in the cargo registry. The order was
    therefore DERIVED rather than cited, and a derived order is exactly the kind
    of mistake every field-accessor test passes through: if it were wrong, every
    block hash this port computes would be wrong and nothing else would move. It
    is instead certified end to end against a block this port did not compute.
    [test_block_header.ml]'s [the canonical order reproduces a real mainnet
    block hash] encodes the twenty-one fields of Ethereum mainnet block 23068672
    ([test/block_vectors.ml], fetched by [eth_getBlockByNumber]) through the
    order and the per-field rules above and reproduces the block hash the
    network published; [encode_rlp agrees with the certified encoder] then
    asserts this function is byte-identical to that encoder on a TN header. The
    two together are the certification. *)

val hash : t -> Tn_keccak.t
(** [Tn_keccak.digest (encode_rlp t)]. It returns a {!Tn_keccak.t} and not a
    string so a parent hash stays a real digest all the way into
    {!Block_context.make} and {!Block_hashes.of_recent}, which accept nothing
    else and for which {!Tn_keccak} deliberately provides no [of_bytes]
    ([tn_keccak.mli:26-42]).

    The golden vector this value was gated on now passes: the twenty-one-field
    order and the byte-string versus scalar rule of each position reproduce the
    published hash of Ethereum mainnet block 23068672, and {!encode_rlp} is
    byte-identical to the encoder that does so. See {!encode_rlp} for the two
    halves of that argument. What remains outside it is narrow and named there:
    a TN header's own repurposed fields ([ommers_hash] as a batch digest,
    [nonce] as an (epoch, round) pair, [difficulty] as a packed batch position)
    are TN's semantics for standard-shaped fields, so no mainnet block can
    witness them and each is pinned separately. *)

val equal : t -> t -> bool
(** Componentwise equality over every stored field, including {!withdrawals},
    which {!encode_rlp} does not commit to. Two headers can therefore be RLP
    identical and unequal here, and that is the intended direction: the list is
    body data the header carries, and losing it silently is the failure this
    catches. *)
