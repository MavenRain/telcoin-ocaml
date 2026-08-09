(** The BCS codecs the durable checkpoint is made of.

    Eleven codecs, ordered by dependency so that a reader meets a type before
    the one that contains it. Each is stated once here and nowhere else: the
    container in {!Checkpoint_file} carries a magic, a format number and a body
    tag, and everything below the tag is one of these.

    {2 The rule every codec below obeys}

    A decoder never hands back a value it assembled behind a type's own
    constructors. Where a type has a total producer, the decoder calls it
    ({!storage} folds [Storage.set], {!recent_hashes} calls
    [Recent_hashes.of_genesis], {!checkpoint} calls
    [Tn_driver.Checkpoint.of_execution]); where the producer can refuse, the
    refusal travels as a decode failure ({!committee} through
    [Committee.create]). What that buys is that the invariants the abstract
    types exist to protect are RE-ESTABLISHED from the wire rather than trusted
    from it, and the one that matters most — the pairing of an engine with the
    consensus block whose execution produced it (the reason
    [Tn_driver.Checkpoint.t] is abstract at all) — cannot be skipped silently,
    because re-establishing it means naming [of_execution].

    {2 What is deliberately not on the wire}

    A cached digest is never written: [Tn_execution.Consensus_block]'s codec
    lets [create] recompute it, so a tampered digest is inert rather than
    adopted. A derived field is never written either: [Block_header.difficulty]
    is a projection of its position, and [Tn_driver.Checkpoint]'s watermark,
    accumulator, epoch, committee, sealed flag and closing time are all
    projections of the two values {!checkpoint} does write. *)

val storage : Tn_state.Storage.t Tn_codec.Bcs.t
(** B1. A BCS map from slot to word over [Storage.bindings], rebuilt by folding
    [Storage.set] from [Storage.empty]. Canonical in both directions: the
    bindings are ascending and a zero word is unrepresentable, because [set]
    removes the slot instead of storing it. *)

val account : Tn_state.Account.t Tn_codec.Bcs.t
(** B2. Nonce, balance, code and {!storage}, rebuilt through [Account.make],
    [Account.with_code] and [Account.with_storage].

    A delegation is NOT a field: [Account.delegation] is
    [Delegation.of_code] of the account's own code, so persisting the code
    restores it exactly, whereas routing it through [Account.delegate] would
    also bump the nonce and so decode to a different account than the one
    encoded. *)

val world_state : Tn_state.World_state.t Tn_codec.Bcs.t
(** B3. A BCS map from address to {!account} over [World_state.accounts],
    rebuilt by folding [World_state.set_account] from [World_state.empty].

    The fold is lossy for one class of entry and provably meets none: the fold
    prunes an [Account.is_absent] account, and [World_state.accounts] never
    lists one, because [set_account] is the only writer and it prunes on the
    same predicate. The suite pins the direction with an [equal]-based round
    trip over a fixture carrying a sentinel row. *)

val block_header : Tn_evm.Block_header.t Tn_codec.Bcs.t
(** B4. All twenty-two stored header fields, rebuilt through
    [Block_header.of_persisted]. The header's own [difficulty] is not on the
    wire: it is a projection of the persisted position. *)

val anchor : Tn_engine.Anchor.t Tn_codec.Bcs.t
(** B5. A two-arm sum, discriminated exactly as [Anchor.header] discriminates:
    arm zero is the configured genesis anchor (hash, base fee, gas limit) and
    arm one is a {!block_header}. Rebuilt through [Anchor.of_genesis] and
    [Anchor.of_header], so an anchor whose hash and header disagree stays
    unrepresentable across the wire. *)

val recent_hashes : Tn_engine.Recent_hashes.t Tn_codec.Bcs.t
(** B6. The newest hash and the ancestors below it, newest first, rebuilt
    through [Recent_hashes.of_genesis]. The window is written whole rather than
    as the anchor's hash plus a length: [Tn_engine.Engine.resume] renormalises
    the newest entry from the anchor, so a codec that dropped the field would
    make "reload equals never closed" false while [resume] papered over it. *)

val rewards_counter : Tn_evm.Rewards_counter.t Tn_codec.Bcs.t
(** B7. The installed committee, if any, and the raw per-authority leader
    counts, rebuilt by folding [Rewards_counter.inc_leader_count] on top of
    [Rewards_counter.set_committee]. No new producer is used: the decoder
    reaches every value through the counter's own four operations. *)

val committee : Tn_types.Committee.t Tn_codec.Bcs.t
(** B8. The epoch and the authorities, rebuilt through [Committee.create], so
    a wire committee that is too small or that repeats a protocol key is a
    decode failure rather than a committee with forged thresholds. *)

val phase : Tn_engine.Engine.phase Tn_codec.Bcs.t
(** B9. The two-arm epoch phase, each arm carrying its own timestamp and its
    {!committee}. One sum, so "sealed with no closing time" stays
    unrepresentable on the wire as well as in memory. *)

val engine_persisted : Tn_engine.Engine.persisted Tn_codec.Bcs.t
(** B10. The five fields of the transparent persisted record, in declaration
    order: {!anchor}, {!world_state}, {!recent_hashes}, {!rewards_counter},
    {!phase}. *)

val checkpoint : Tn_driver.Checkpoint.t Tn_codec.Bcs.t
(** B11. {!engine_persisted} paired with the optional last-executed consensus
    block, decoded through [Tn_driver.Checkpoint.of_execution].

    That call is the whole point of this codec. [Checkpoint.t] is abstract for
    exactly one reason — nothing else in the type system pins "this engine
    state is the one that block's execution produced" — and a decoder that
    assembled the pair some other way would be a third producer free to mispair
    silently. It cannot: the only two producers are [of_execution] and
    [Checkpoint.genesis], and reaching the first means naming it.

    Everything a checkpoint answers is written or derived from what is written,
    the [BLOCKHASH] window included. The window is the field a decoder is most
    tempted to normalise, since [Tn_engine.Engine.resume] re-seats it from the
    anchor anyway; normalising it here would silently repair a skewed
    checkpoint instead of round-tripping it, so this codec does not, and the
    suite carries a deliberately skewed fixture that says so. *)
