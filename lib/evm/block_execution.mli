(** The block-execution spine: [apply_pre_execution_changes], then the
    per-transaction left fold over {!Executor.execute}.

    {!Pre_block.t} is a constructorless phase token that CARRIES the
    post-pre-block world, so the transaction fold cannot run before EIP-4788 and
    EIP-2935 have been applied: there is no other way to obtain the argument
    {!run_transactions} takes. That is {!Access.warmth}'s bargain, a witness
    built from the step it witnesses ([access.ml:36-44]), and it is strictly
    stronger than {!Mutability.permit}, which [mutability.mli:26-39] honestly
    discloses is fabricable from a literal inside its own module.

    The {!outcome} carries the executed envelopes AND the receipts, so a block's
    transactions root and its receipts root cannot commit different lists.
    Telcoin's assembler receives the two as independent fields of
    [BlockAssemblerInput] ([block.rs:945-952]), and its builder is the thing that
    makes them disagree. *)

type error =
  | Consensus_root_call of System_call.error
      (** Telcoin's [BlockValidationError::BeaconRootContractCall]
          ([block.rs:672-681]). *)
  | Blockhashes_call of System_call.error
      (** Telcoin's [BlockValidationError::BlockHashContractCall]
          ([block.rs:713-721]). *)
  | Recovery of { index : int; error : Tx_recovery.error }
      (** A transaction whose signer could not be recovered, carrying its
          zero-based position in the block. The envelope decoded, so this is a
          malformed signature and not a framing error. *)
  | Transaction_rejected of { index : int; error : Executor.error }
      (** A transaction {!Executor.execute} refused.

          It is an ERROR and not a skip, and that resolves a question the port
          had left open. Telcoin has both behaviours: the block EXECUTOR raises
          [BlockValidationError::InvalidTx] ([block.rs:879-882]) while the block
          BUILDER logs it and [continue]s
          ([crates/tn-reth/src/lib.rs:783-800]), so its assembled transaction
          list can be shorter than the batch it was handed. This module is the
          executor, so it refuses; a builder that drops invalid transactions
          belongs above it and would simply hand this function a shorter list.
          Mixing the two is exactly what makes a transactions root and a
          receipts root disagree, which is why {!transactions} lives on the
          outcome. *)
  | Gas_limit_above_available of {
      index : int;
      transaction_gas_limit : int;
      block_available_gas : int;
    }
      (** Telcoin's [TransactionGasLimitMoreThanAvailableBlockGas]
          ([block.rs:870-876]). It is checked against the REMAINING block gas
          and fires BEFORE execution, so it is strictly stronger than revm's own
          [CallerGasLimitMoreThanBlock], which compares against the TOTAL limit
          ([revm-handler-15.0.0/src/validation.rs:210-214]) and which
          {!Executor.Gas_limit_above_block} already reproduces. Both fire, and
          this one fires first. *)
  | Block_gas_exceeded of { index : int }
      (** {!Block_gas.charge_receipt} refused. Unreachable given the check above
          and revm bounding a transaction's gas by its own limit; present so the
          fold is total without an [assert]. *)

val error_to_string : error -> string
(** Render an {!error} as a short human-readable string, for diagnostics and
    test failure messages. *)

(** The phase token for "both pre-block system calls have run, in order",
    together with the two dispositions that say what each call decided. *)
module Pre_block : sig
  (** What the EIP-4788 consensus-root step did. Three constructors, because
      "no call was made" has two different causes and a test that cannot tell
      them apart is not testing the gate. *)
  type consensus_root =
    | Root_skipped_at_genesis
        (** Block zero: telcoin makes no call ([block.rs:643-665]). The genesis
            rule itself, that the root be zero, is already discharged by
            {!Block_context.make}. *)
    | Root_skipped_after_first_batch
        (** Not batch zero of this consensus output, so the digest is already
            written ([block.rs:775-779]). *)
    | Root_written of System_call.outcome
        (** The EIP-4788 call ran, and this is what it produced. *)

  (** What the EIP-2935 blockhashes step did. Two constructors and not three:
      genesis is its only skip, because it carries no [first_batch] gate. *)
  type blockhashes =
    | Hash_skipped_at_genesis
        (** Block zero: telcoin makes no call ([block.rs:698-706]). *)
    | Hash_written of System_call.outcome
        (** The EIP-2935 call ran, and this is what it produced. It is NOT
            gated on {!Block_context.first_batch}, which is the whole point of
            keeping the two dispositions apart. *)

  type t
  (** A world that has had both pre-block calls applied, in order. Abstract and
      constructorless, so the only source of one is {!apply_pre_block}, and it
      CARRIES the world rather than sitting beside it, so the token and the
      state it certifies cannot be separated or crossed.

      It carries the two dispositions rather than discarding them so the gates
      are OBSERVABLE: a test can assert not only that the beacon-roots slots
      were left alone but that they were left alone for the right reason. *)

  val world : t -> Tn_state.World_state.t
  (** The world after both calls, which is the world the transaction fold
      starts from. *)

  val consensus_root : t -> consensus_root
  (** What the EIP-4788 step decided. *)

  val blockhashes : t -> blockhashes
  (** What the EIP-2935 step decided. *)
end

val apply_pre_block :
  Tn_state.World_state.t ->
  context:Block_context.t ->
  (Pre_block.t, error) result
(** Telcoin's [apply_pre_execution_changes] ([block.rs:769-785]) in order: the
    EIP-4788 consensus-root call ONLY when {!Block_context.first_batch}, then
    the EIP-2935 blockhashes call UNCONDITIONALLY. The order is fixed and the
    second call is not gated on [first_batch]; a port that gates both writes a
    different state root on every non-first batch of every consensus output.

    The 4788 payload is the 32 bytes of {!Block_context.consensus_root} into
    {!System_contracts.beacon_roots_address}; the 2935 payload is the 32 bytes
    of {!Block_context.parent_hash} into
    {!System_contracts.history_storage_address}. Both skip at block number zero.
    Neither reads {!Block_context.boundary}.

    The two gates NEST the way telcoin nests them for every block this module
    can be handed: [first_batch] is the outer gate ([block.rs:775]) and the
    genesis check lives inside [apply_consensus_root_contract_call]
    ([block.rs:643-665]). So a block that is both block zero and not the first
    batch reports {!Pre_block.Root_skipped_after_first_batch}, because that is
    the gate telcoin actually stops at, and both dispositions agree on the only
    fact that reaches state, namely that no call was made.

    One block telcoin executes cannot reach this module at all, and the
    asymmetry is worth stating rather than glossing. Because the genesis
    zero-root rule is hoisted OUT of the gate and enforced at construction
    ({!Block_context.Genesis_consensus_root_not_zero}), a block that is number
    zero, NOT the first batch, and carries a nonzero consensus root has no
    {!Block_context.t} at all. Telcoin runs that block happily: its
    [first_batch()] test is false, so [apply_consensus_root_contract_call] is
    never entered and the zero-root check inside it never fires. This port is
    therefore strictly stricter on exactly that one shape. The trade is
    deliberate. Hoisting the rule buys a context type that cannot represent an
    illegal genesis at all, which is the idiom this port uses everywhere, and
    the refused block is one no TN consensus output can produce, since batch
    index zero is what makes a block number zero in the first place.

    {2 Three upstream steps are deliberately absent}

    The two hardfork gates telcoin carries are ABSENT, not skipped. Telcoin
    gates 4788 on [is_cancun_active_at_timestamp] and 2935 on
    [is_prague_active_at_timestamp] ([block.rs:643, 698]). This port has no fork
    schedule ({!Env} targets Prague and says so, [env.mli:21-24]) and TN's own
    chain configs set [shanghaiTime], [cancunTime] and [pragueTime] all to [0]
    ([chain-configs/testnet/genesis.yaml:15-17]), so both predicates are true
    for every block TN can produce. The cost is exact and worth naming: on a
    chain config with a nonzero [cancunTime] or [pragueTime] this port would
    make a system call telcoin would skip, and the state roots would diverge
    from the first block before activation. That input cannot arise from TN's
    configs, and the check belongs with a fork schedule when one exists, not
    here.

    Telcoin's [set_state_clear_flag] ([block.rs:771-773]) has no counterpart
    either: EIP-161 pruning is unconditional here, because
    {!Tn_state.World_state.set_account} prunes an {!Tn_state.Account.is_absent}
    account ([world_state.ml:16-17]) and there is no flag to turn that off.

    {2 The fee accounting diverges, inherited rather than introduced}

    The fold routes every transaction through {!Executor.execute}, which
    implements revm's {e mainnet} post-execution fee split: the caller is
    refunded its whole unused allowance and the base fee is burned
    ([executor.ml:139-140]). Telcoin does not run that handler. Its block
    executor drives [TNEvmHandler] for every transaction
    ([evm/mod.rs:147-162]), whose [reimburse_caller] withholds a gas-limit
    penalty from the refund ([evm/handler.rs:109-131]) and whose
    [reward_beneficiary] credits [basefee * gas_used] to a configured
    [basefee_address] ([evm/handler.rs:162-168]) rather than burning it.

    The cost is exact and consensus-visible. For any block carrying a nonzero
    base fee, or any transaction that spends under a tenth of the gas limit it
    declared, this port's post-state differs from telcoin's: the caller keeps
    wei telcoin withholds, and [basefee_address] is absent from the trie where
    telcoin has credited it. Every root taken over that world differs in turn,
    so {!Block_header.assemble} emits a header telcoin would reject.

    It is named here rather than fixed here because it is not this module's.
    It arrives with {!Executor} and is recorded on that module's [PORTING.md]
    row; closing it means changing {!Executor}'s post-execution and giving
    {!Block_context} a [basefee_address], which is a change to an already
    reviewed surface and belongs to its own chunk. This module inherits the
    divergence wholesale and adds nothing to it. *)

type outcome
(** What executing a block's transactions produced. Abstract, and
    {!run_transactions} is its only producer. *)

val world : outcome -> Tn_state.World_state.t
(** The world after the last transaction committed. This is the world
    {!Block_header.assemble} roots, which is what makes "this header's state
    root is the root of the state this block produced" a fact of the type. *)

val transactions : outcome -> Tx_envelope.t list
(** The envelopes that executed, in block order. This lives on the OUTCOME and
    is not a separate argument to the assembler, so a block's transactions root
    and its receipts root cannot commit different lists. Telcoin's assembler
    receives [transactions] and [receipts] as two independent fields of
    [BlockAssemblerInput] ([block.rs:945-952]), and its builder is the thing
    that makes them disagree. *)

val receipts : outcome -> (int * Receipt.t) list
(** [(type_byte, receipt)] in block order, exactly the shape
    {!Block_roots.receipts_root} consumes, with {!Block_roots.type_byte} of the
    transaction that produced each. Same length and order as {!transactions}, by
    construction: one fold builds both. *)

val gas_used : outcome -> int
(** The block's [gas_used]: {!Block_gas.used} at the end of the fold, which is
    the running sum of {!Receipt.gas_used} NET of refund and therefore the same
    prefix sum {!Block_roots.receipts_root} recomputes internally
    ([block_roots.mli:48-52]).

    It EXCLUDES the pre-block system calls, which produce no receipt and never
    reach the meter: telcoin advances [gas_used] only in [commit_transaction]
    ([block.rs:887-908]), so a system call also does not consume the block gas
    available to later transactions. *)

val logs_bloom : outcome -> Bloom.t
(** The block's logs bloom, computed once here so the header cannot compute a
    second one. It is {!Bloom.of_logs} over every receipt's logs concatenated,
    which is what telcoin does
    ([logs_bloom(receipts.iter().flat_map(|r| r.logs()))], [block.rs:957]), and
    NOT a union of per-receipt blooms. The two are bit-identical because accrual
    is a monotone bitwise OR ([bloom.mli:1-3]), and this port deliberately does
    not add a [Bloom.union] that would make the second formulation writable.
    {!Receipt.t} carries logs only on {!Receipt.Success}, so reverted and halted
    transactions contribute nothing, matching [RethReceiptBuilder]'s
    [result.into_logs()]. A pre-block system call contributes nothing either,
    because no receipt is built from one at all. *)

val run_transactions :
  Pre_block.t ->
  context:Block_context.t ->
  Tx_envelope.t list ->
  (outcome, error) result
(** The fold. For each envelope in order: recover the signer
    ({!Tx_recovery.recover}); refuse it if its gas limit exceeds
    {!Block_gas.available}; run {!Executor.execute} against the running world
    and {!Block_context.block}; advance the meter by the receipt; append
    [(type_byte, receipt)] and the envelope. Mirrors [commit_transaction]'s
    order ([block.rs:887-908]), where the addition PRECEDES the receipt build so
    a receipt's cumulative gas includes its own transaction.

    It is a LEFT fold and cannot be a map: {!Executor.execute} threads the
    world, and each call needs the previous call's output world
    ([executor.mli:89-93]).

    It takes a {!Pre_block.t} and not a world. That is the whole ordering
    contract: the pre-block calls run first in telcoin because the trait calls
    them first, and they run first here because nothing else can produce the
    argument.

    {2 Two upstream underflow hatches are closed structurally}

    Telcoin's guard reads [recovered.tx().gas_limit()] while execution uses a
    separately supplied [tx_env], so a caller whose [tx_env] carries a larger
    limit defeats the bound ([block.rs:864, 870]); here there is one
    {!Transaction.t}, produced by {!Tx_recovery.recover} from the envelope, so
    there is one gas limit and the checked number is the spent number. And
    [commit_transaction] is a public trait method with no gas check of its own;
    here it is a step of a private fold with no call site outside it. See
    {!Block_gas.available}.

    {2 The closing epoch}

    This function behaves IDENTICALLY whether {!Block_context.boundary} is
    {!Epoch_boundary.Open} or {!Epoch_boundary.Closing}.
    [apply_pre_execution_changes] never reads [close_epoch] (it touches only
    [first_batch], [parent_beacon_block_root] and [parent_hash],
    [block.rs:769-785]) and neither does the transaction loop. What telcoin does
    with it happens strictly afterwards, in [finish()] ([block.rs:787-835]): the
    consensus-registry fork, [apply_consensus_block_rewards],
    [apply_closing_epoch_contract_call], and the
    [merge_transitions(BundleRetention::Reverts)] that follows them. All four
    are a later chunk, and none is silently skipped: three of them WRITE STATE,
    so a closing block's world is incomplete and {!Block_header.assemble}
    refuses to root it ({!Block_header.Epoch_close_state_deferred}). The refusal
    is at the assembler and not here because this fold is genuinely correct for
    a closing block; it is the state root that would be a lie.

    [merge_transitions] has no image at all: it is reth bundle-state
    bookkeeping and this port has no bundle layer. Worth recording for the later
    chunk that telcoin calls it ONLY inside the close-epoch branch
    ([block.rs:833-835]), so on every other block the surrounding driver merges.

    Independent of the boundary, telcoin's [finish] also sets
    [requests = Requests::default()] and [blob_gas_used = 0]
    ([block.rs:837-845]). Neither reaches the header, because the assembler
    discards both and recomputes ([block.rs:945-952]), so neither appears in
    {!outcome}. *)

val execute :
  Tn_state.World_state.t ->
  context:Block_context.t ->
  Tx_envelope.t list ->
  (Pre_block.t * outcome, error) result
(** {!apply_pre_block} then {!run_transactions}. The {!Pre_block.t} is returned
    rather than consumed so a caller, in practice a test, can assert the two
    dispositions without re-running the block. *)
