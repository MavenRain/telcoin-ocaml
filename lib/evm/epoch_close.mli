(** The epoch-close system calls ([block.rs:145-232, 392-424, 496-522,
    607-638]): the eligible-pool and committee-size reads, then
    [applyIncentives] and [concludeEpoch] under the
    remove-SYSTEM-then-commit-ALL rule with MANDATORY success checks.

    Every call here runs through {!System_call.run}, so the environment is
    the 4788/2935 one by construction ([evm/mod.rs:164-212]): 30M gas limit
    and zero basefee visible inside the frame regardless of the enclosing
    block. Per call only the commit rule and the success discipline differ
    from the pre-block writes: a revert or a halt of either registry call is
    FATAL ([block.rs:174-181, 214-218]), never the pre-block callers'
    log-and-continue.

    Reads return decoded values only. No world accessor exists on the read
    path, so committing a read is unrepresentable, the shape of
    [try_read_state_on_chain], which transacts and never commits
    ([block.rs:607-623]).

    {2 The pool read is the LEGACY one-call path}

    The pinned genesis registry fixture carries the PRE-fork bytecode (the
    [forks.rs:23-24] code hash, [registry_genesis.ml]), whose dispatcher
    answers [getValidators] ([0x8cc05eda]) and not [getValidatorsInfo]
    ([0x2870259d]). So {!read_eligible_pool} is the image of
    [read_committee_eligible_pool_legacy] ([block.rs:573-583]): ONE
    [getValidators(Active)] call whose return the pre-fork contract answers
    with the full eligible union. The post-fork three-call union
    ([block.rs:507-522]) becomes reachable only once a post-fork storage
    fixture exists; its encoder is already in {!Registry_abi} and the
    {!error} constructors already carry the status a failing per-status call
    was reading, so widening is additive. *)

(** Everything that can abort the close, each constructor naming the call it
    came from so a failure log states WHICH registry interaction died.
    [Rewards_unsuccessful] and [Conclude_unsuccessful] are the mandatory
    success checks ([block.rs:174-181, 214-218]); the [_call] constructors
    are {!System_call.error}'s unreachable-by-construction rejection,
    carried rather than collapsed for {!System_call.run}'s own reason. *)
type error =
  | Rewards_call of System_call.error
      (** [applyIncentives] was rejected in validation. *)
  | Rewards_unsuccessful
      (** [applyIncentives] reverted or halted: FATAL ([block.rs:174-181]). *)
  | Conclude_call of System_call.error
      (** [concludeEpoch] was rejected in validation. *)
  | Conclude_unsuccessful
      (** [concludeEpoch] reverted or halted: FATAL ([block.rs:214-218]). *)
  | Pool_read of { status : Registry_abi.Eligible_status.t; error : System_call.error }
      (** The pool read for [status] was rejected in validation. *)
  | Pool_read_unsuccessful of Registry_abi.Eligible_status.t
      (** The pool read for [status] reverted or halted
          ([block.rs:613-618]). *)
  | Pool_decode of Registry_abi.decode_error
      (** The pool read succeeded but its return is not a
          [ValidatorInfo[]]. *)
  | Size_read of System_call.error
      (** [getNextCommitteeSize] was rejected in validation. *)
  | Size_read_unsuccessful
      (** [getNextCommitteeSize] reverted or halted. *)
  | Size_decode of Registry_abi.decode_error
      (** [getNextCommitteeSize]'s return is not a uint16 word. *)

val error_to_string : error -> string
(** Render an {!error} as a short human-readable string, for diagnostics and
    test failure messages. *)

val read_eligible_pool :
  Tn_state.World_state.t ->
  block:Env.Block.t ->
  (Registry_abi.Validator_info.t list, error) result
(** The committee-eligible pool, by the legacy path (module preamble): one
    [getValidators(Active)] call ([block.rs:573-583]) decoded strictly, in
    the contract's return order, which is consensus-relevant input to the
    shuffle and is never re-sorted here. Returns the list ONLY: reads are
    structurally non-committing. *)

val read_next_committee_size :
  Tn_state.World_state.t -> block:Env.Block.t -> (int, error) result
(** The next committee's size: [getNextCommitteeSize()] decoded as uint16
    and widened ([block.rs:630-638]). A size the pool cannot fill is NOT an
    error here or anywhere in the port: Rust has no local check and lets the
    on-chain [concludeEpoch] be the judge ([block.rs:461-482]). *)

type disposition
(** Constructorless record of the two mandatory calls IN SEQUENCE: the
    calldata each was sent, in the order they ran, beside each call's
    {!System_call.outcome}. Call order is thereby a port-internal assertion,
    selector prefix by selector prefix, independent of whether the contract
    would tolerate a swap. *)

val first_calldata : disposition -> string
(** The calldata of the call that ran FIRST: [applyIncentives(...)], selector
    [0x0a36cdef] ([block.rs:159-161] runs before [block.rs:214];
    [system_calls.rs:160] documents the obligation). *)

val second_calldata : disposition -> string
(** The calldata of the call that ran SECOND: [concludeEpoch(...)], selector
    [0x7b55a300], carrying the ascending committee. *)

val rewards_outcome : disposition -> System_call.outcome
(** The [applyIncentives] outcome. Its receipt is NEVER pushed to the block's
    receipts and its gas never moves [gas_used] ([block.rs:221-226,
    399-404]); it is exposed for tests to assert a real success on real
    bytecode. *)

val conclude_outcome : disposition -> System_call.outcome
(** The [concludeEpoch] outcome, exposed for the same reason. *)

val close :
  Tn_state.World_state.t ->
  block:Env.Block.t ->
  rewards:(Tn_types.Units.Address.t * int) list ->
  randomness:Hash32.t ->
  (Tn_state.World_state.t * disposition, error) result
(** The [Some]-arm of the close gate ([block.rs:794-835], the one-time
    adiri fork step compiled out), in its exact order:

    (1) [applyIncentives] with [rewards] encoded {e as given}. The caller
    owes ascending address order, which is what
    {!Rewards_counter.address_counts} produces ([gas_accumulator.rs:125,
    148]). Success REQUIRED; committed under
    {!System_call.world_keeping_all_but_system} ([block.rs:184-187]).

    (2) Against the POST-rewards world: the pool and size reads, the
    {!Committee_shuffle.shuffle} seeded with [randomness], the ascending
    sort of the truncated committee HERE at encode time ([block.rs:394-395];
    the shuffle's output order is pinned unsorted), then [concludeEpoch].
    Success REQUIRED; same commit rule ([block.rs:223-226]).

    The returned world is the post-conclude commit. No receipt, no log and
    no gas of either call reaches the enclosing block ([block.rs:221-226,
    893]); [merge_transitions] has no image in this port. *)
