(** The system-call path: EIP-4788's beacon-roots write and EIP-2935's
    block-hash write, as telcoin performs them.

    Two illegal states are removed by SHAPE rather than by rule. There is no
    [caller] parameter, so a system call from anything but
    {!System_contracts.system_address} is unnameable. And the raw post-call
    world never escapes, so committing an account other than the target is
    unnameable: {!world} is the only way out and it has already done the
    [retain].

    Execution goes through the port's existing {!Executor.execute} on a
    synthetic Legacy transaction, because that IS telcoin's full-pipeline shape.
    See {!run} for the twelve-way argument that the synthetic transaction
    survives every one of {!Executor}'s rejections.

    {2 The one divergence that survives into this path}

    revm's [transfer_loaded] short-circuits on a zero balance after touching
    only the recipient, so the frame never touches the caller
    ([revm-context-13.0.0/src/journal/inner.rs:317-339]), whereas this port's
    {!Effects.transfer} writes both endpoints back ([effects.ml:160-165]). The
    extra touch lands on {!System_contracts.system_address}, which {!world}
    discards, so no committed byte differs. It is named here rather than left
    for a reader to rediscover.

    {2 Gas is not metered here, and that is telcoin's behaviour}

    The 30M allowance neither enters a receipt's cumulative gas nor consumes
    block-available gas. Telcoin advances [self.gas_used] only inside
    [commit_transaction] ([block.rs:887-908]), which no system call goes
    through, so a system call is free against the block's budget. Nothing in
    this module touches {!Block_gas} and nothing should. *)

type error =
  | Rejected of Executor.error
      (** The synthetic transaction was rejected in validation. Every
          constructor of {!Executor.error} is discharged by the environment
          {!run} builds, see the twelve-way argument on {!run}, so this is
          unreachable by construction. It is surfaced rather than collapsed
          because this port does not answer "cannot happen" with an [assert]
          ([block_roots.ml:5-10] is the precedent): if a future change to
          {!Executor} falsifies the argument, a caller gets a value it must
          handle instead of a wrong state root. It is also the port's image of
          telcoin's [Err] arm, which becomes
          [BlockValidationError::BeaconRootContractCall] and
          [BlockHashContractCall] ([block.rs:675, 717]). *)

val error_to_string : error -> string
(** Render an {!error} as a short human-readable string, for diagnostics and
    test failure messages. *)

val gas_limit : int
(** [30_000_000], the literal telcoin puts in the system [TxEnv]
    ([evm/mod.rs:176]) and simultaneously swaps into [block.gas_limit], so
    [GASLIMIT] inside a system call reads 30M and not the real block limit. *)

type outcome
(** A completed system call: the receipt it produced, and the world with ONLY
    the target's account committed. The two travel together and the world is
    already pruned. *)

val receipt : outcome -> Receipt.t
(** The full outcome of the frame. The two pre-block callers deliberately ignore
    it, matching telcoin ([block.rs:667-692, 708-731] match on [Ok]/[Err] only
    and never inspect [res.result], so a revert or a halt of the beacon-roots
    contract is silently accepted). It is exposed anyway because the deferred
    epoch-close callers must NOT ignore it, [block.rs:174-181] checks
    [res.result.is_success()] and errors out, and because the test suite must be
    able to assert a real success on every spine fixture, which is the price of
    running real bytecode through this port's interpreter. *)

val succeeded : outcome -> bool
(** [Receipt_envelope.status (receipt o)], true only for {!Receipt.Success}.
    Named here so the later chunk cannot reinvent the predicate. A [bool] is
    safe to expose for {!Access.mem_account}'s reason: nothing in this port
    prices or gates execution from a [bool]. *)

val world : outcome -> Tn_state.World_state.t
(** The post-call world, ALREADY reduced to the pre-call world with exactly the
    target contract's account replaced:
    [World_state.set_account before contract (World_state.account after contract)].
    This is telcoin's [res.state.retain(|addr, _| *addr == TARGET)] followed by
    [db.commit] ([block.rs:688, 728]), expressed as a rebuild from the pre-call
    world rather than as a filter, because {!Tn_state.World_state} has no
    restriction operator.

    It is load-bearing, not hygiene. The full pipeline bumps and touches the
    caller's nonce ([revm-handler-15.0.0/src/pre_execution.rs:158-178], with an
    unconditional [account_touched] at
    [revm-context-13.0.0/src/journal/inner.rs:270-288], and in this port at
    [executor.ml:236-250]); a nonzero nonce makes the account non-empty under
    EIP-161, so committing it would insert
    [{nonce: N; balance: 0; codeHash: KECCAK_EMPTY}] into the state trie and the
    state root would differ from every node that drops it. Dropping it also
    means each system call in a block sees the system address back at nonce
    zero, which is what lets the 4788 and the 2935 call both pass the nonce
    check inside one block.

    Note the epoch-close paths use [res.state.remove(&SYSTEM_ADDRESS)] instead
    ([block.rs:185]), KEEPING every other touched account. That is a different
    commit rule, so the later chunk must not reuse this function. *)

val run :
  Tn_state.World_state.t ->
  block:Env.Block.t ->
  contract:Tn_types.Units.Address.t ->
  data:string ->
  (outcome, error) result
(** Run a system call into [contract] with [data] as calldata, from
    {!System_contracts.system_address}.

    There is no [caller] parameter, and that is the point: telcoin's
    [transact_system_call] takes one ([evm/mod.rs:164-171]) but every call site
    passes [SYSTEM_ADDRESS], and passing anything else would re-enable
    [reimburse_caller] and [reward_beneficiary], whose guards are literally
    [tx.caller() == SYSTEM_ADDRESS] ([evm/handler.rs:78-88, 137-147]). Making
    the caller unnameable is cheaper than modelling handler overrides for a
    caller no call site uses.

    A [contract] that holds no code is not an error. {!Executor}'s first frame
    consults {!Precompile.invoke} first and falls through to {!Code.of_string}
    of the empty account code ([executor.ml:314-320]); {!Code.byte_at} past the
    end returns [0] ([code.ml:14]) and byte [0] decodes to {!Opcode.Stop}
    ([interpreter.ml:968]), so the frame stops immediately with empty output and
    no state change. That matches revm ([frame.rs:166-229]) and telcoin's
    silent no-op acceptance ([block.rs:672-681]), and it preserves revm's
    precompile-before-empty-code ordering ([frame.rs:192-208]).

    {2 Why this runs {!Executor.execute} and not a bespoke frame}

    Telcoin does NOT use revm's [run_system_call] fast path
    ([revm-handler-15.0.0/src/handler.rs:108-137]). [TNEvm::transact_system_call]
    hand-builds a [TxEnv] and calls [self.transact], that is, the FULL
    [Handler::run] ([evm/mod.rs:164-221]): intrinsic gas IS charged, the
    caller's nonce IS bumped, the access set IS the ordinary one.
    {!Executor.execute} is that pipeline, so reusing it is the faithful choice
    AND leaves no second execution path to drift.

    The synthetic transaction is {!Transaction.make} with [sender] =
    {!System_contracts.system_address}, [kind = Call contract],
    [value = U256.zero], [data], [access_list = []], [chain_id = None],
    [fee = Legacy { gas_price = U256.zero }], [gas_limit] = {!gas_limit}, and
    [nonce] = the LIVE nonce of the system address in the supplied world. Each
    field discharges one of {!Executor}'s twelve rejections.
    [Invalid_chain_id] needs a [Some] chain id and there is none;
    [Missing_chain_id] is Legacy-exempt ([executor.ml:180-184]);
    [Gas_price_below_base_fee] holds [0 >= 0] after the basefee rebuild
    ([:188-198]); [Priority_fee_above_max_fee] is Dynamic-only ([:191-197]);
    [Gas_limit_above_block] is a STRICT [>] against the rebuilt 30M
    ([:201-203]); [Init_code_size_limit] is Create-only ([:205-210]);
    [Intrinsic_gas_above_limit] and [Gas_floor_above_limit] need only 30M above
    roughly 22k ([:212-213]); [Sender_has_code] passes because the system
    address is codeless, and EIP-3607 is not disabled upstream either
    ([revm-handler-15.0.0/src/pre_execution.rs:83-118]); [Nonce_mismatch] is an
    EQUALITY ([:218-222]), so supplying the live nonce IS
    [cfg.disable_nonce_check] with the identical bump either way; and
    [Insufficient_funds] and [Overflow_payment] are vacuous because the maximum
    spend is [gas_limit * 0 + 0 = 0] ([:224-232]), matching revm's own
    [saturating_sub(0)] ([pre_execution.rs:125-154]).

    Post-execution is a no-op for the same reason telcoin's handler overrides
    are: [finalize] credits the caller [effective * (gas_limit - used)] and the
    beneficiary [(effective - base_fee) * used] ([executor.ml:140-147]), and
    with [effective = base_fee = 0] both are [U256.zero], so
    [Account.credit acc U256.zero] returns the account unchanged and
    [World_state.set_account] on an unchanged account is the identity. The
    handler comment at [evm/handler.rs:143-145] says exactly this: "gas_price
    and basefee are both 0, so all amounts are 0".

    {2 The block environment is rebuilt, not assumed harmless}

    [block] is rebuilt through {!Env.Block.make} with [gas_limit] set to
    {!gas_limit} and [basefee] set to zero, carrying the other six fields
    through unchanged; this reproduces telcoin's [core::mem::swap] pair
    ([evm/mod.rs:194-212]). Both replacements are readable INSIDE the frame,
    [GASLIMIT] returns 30M and [BASEFEE] returns 0, so this is a semantic step
    and not a validation trick, even though neither pinned bytecode contains
    either opcode today. The third swap, [cfg.disable_nonce_check], is
    reproduced by the live-nonce choice above: an equality that always holds is
    a disabled check. {!Env.Block} has no [with_] updater, so a rebuild is the
    only expression of this, and it is total because all eight accessors exist
    ([env.mli:53-78]). *)
