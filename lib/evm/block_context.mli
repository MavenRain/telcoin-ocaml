(** The port of telcoin's [TNBlockExecutionCtx], paired with the {!Env.Block.t}
    it belongs to.

    Pairing the two is load-bearing three times over. It lets the genesis rule
    be a CONSTRUCTOR obligation rather than a check buried in the pre-block hook
    ([block.rs:642-665]); it removes the possibility of assembling a header from
    a different block environment than the executor ran under, because there is
    only one environment to reach; and it does every [U256 -> int] narrowing
    once, up front, so {!Block_gas.start} and header assembly are total
    functions rather than fallible ones.

    {2 What this module is not}

    The full replay rebuild of a context from a sealed header
    ([config.rs:150-178]) is a later chunk's wiring: it also needs the chain id
    and the [BLOCKHASH] window, which are chain facts rather than header facts.
    The one part the spine owes now is the [close_epoch] round trip, which is
    {!Epoch_boundary.of_extra_data}'s 0/32/error length discipline. Telcoin
    deliberately raises [TnRethError::EVMCustom] rather than
    [B256::from_slice]-ing a wrong-length slice ([config.rs:157-167]), and this
    port declines for the same reason. *)

type block_field = Number | Timestamp | Gas_limit
(** Which of the three [U256] block fields failed to narrow to a native [int].
    A closed three-constructor sum, so a fourth narrowed field cannot be added
    without revisiting every reader. *)

val block_field_to_string : block_field -> string
(** Render a {!block_field} as the lowercase field name, for diagnostics and
    test failure messages. *)

type error =
  | Genesis_consensus_root_not_zero
      (** Block zero with a nonzero consensus root. Telcoin raises
          [CancunGenesisParentBeaconBlockRootNotZero] from inside the pre-block
          hook ([block.rs:642-665]); it is raised here instead, at construction,
          so no context able to reach {!Block_execution.apply_pre_block} can
          violate it.

          Hoisting it out of the hook makes this port strictly stricter than
          telcoin on exactly one shape, and the earlier claim that the two
          reject the same blocks was wrong. Telcoin reaches its check only
          through [first_batch()] ([block.rs:775-779]), so a block that is
          number zero, NOT the first batch, and carries a nonzero root skips the
          hook entirely and executes. Here it has no {!t} at all. The trade is
          deliberate: an illegal genesis becomes unrepresentable rather than
          merely rejected, and the block given up is one no consensus output can
          produce, since a batch index of zero is what makes a block number zero
          to begin with. {!Block_execution} states the same asymmetry from the
          gate's side. *)
  | Block_field_above_int of { field : block_field }
      (** A block number, timestamp or gas limit that does not fit a native
          [int]. Telcoin narrows with [saturating_to()]
          ([block.rs:954, 993-994]), which silently CLAMPS; this refuses,
          because a clamped number would make the EIP-2935 slot
          [(n - 1) mod 8191] wrong with no symptom. *)

val error_to_string : error -> string
(** Render an {!error} as a short human-readable string, for diagnostics and
    test failure messages. *)

type t
(** One block's execution context: the environment every frame reads, plus the
    six consensus facts telcoin carries beside it. Abstract, {!make} its only
    producer. *)

val make :
  block:Env.Block.t ->
  parent_hash:Tn_keccak.t ->
  consensus_root:Tn_types.Digests.Output_digest.t ->
  nonce:Tn_types.Units.Sequence_number.t ->
  batch_digest:Tn_types.Digests.Batch_digest.t ->
  position:Batch_position.t ->
  boundary:Epoch_boundary.t ->
  (t, error) result
(** Telcoin's [TNBlockExecutionCtx] has seven fields ([block.rs:51-75]); this
    has six, each typed for what it is rather than for its width.

    - [parent_hash] is a {!Tn_keccak.t}, matching {!Block_hashes.of_recent},
      which already refuses raw bytes.
    - [consensus_root] is a {!Tn_types.Digests.Output_digest.t}. Telcoin's field
      is called [parent_beacon_block_root] and documented as "the digest of the
      [ConsensusHeader]" ([block.rs:55-56]); naming it for what it is makes
      passing an actual beacon root a type error. It is NOT an option: on the
      build path [TNPayload::parent_beacon_block_root] is always [Some]
      ([payload.rs:117-120]), and telcoin's [MissingParentBeaconBlockRoot] fires
      only when Cancun is active, which in this Prague-only port is always. The
      [None] case is therefore EXCLUDED, not deferred: the rejection set is
      identical, it just moves from execution to construction. If a
      fork-configurable spec ever lands, this must become an option again and
      that error variant must return.
    - [nonce] is a {!Tn_types.Units.Sequence_number.t}, which already {e is} the
      [(epoch << 32) | round] packing the header nonce carries
      ([units.mli:76-88], [crates/types/src/primary/header.rs:163-166]); the
      port had the right type before it had the field, and [deconstruct_nonce]
      ([helpers.rs:283-288]) is two accessors rather than arithmetic anyone
      repeats. The Rust field's own doc comment ("The index for the batch",
      [block.rs:57]) is STALE and is not reproduced.
    - [batch_digest] is the header's [ommers_hash] and has nothing to do with
      the body's ommers, which are always empty.
    - [position] replaces the packed [difficulty] word.
    - [boundary] replaces [close_epoch] and folds in what
      {!Rewards_counter.generate_withdrawals} supplies.

    The seventh Rust field, [rewards_counter], is not carried HERE: it is a
    shared handle ([gas_accumulator.rs:89-96]) the executor reads only inside
    the close-epoch branch of [finish] ([block.rs:793-831]), and its image,
    {!Rewards_counter}, lives with the driver that accumulates it. Its one
    in-scope consequence, the withdrawals list, is carried by
    {!Epoch_boundary.Closing} as DATA, and {!Block_execution.finish} derives
    the [applyIncentives] pairs from that same list, so the context cannot
    pay rewards its own header does not commit to. The two upstream hazards
    once recorded here now have named homes: [get_address_counts]'s silent
    EMPTY map with no committee handle ([gas_accumulator.rs:123-142]) is
    {!Rewards_counter.address_counts}'s documented no-committee behaviour,
    and the [BTreeMap<Address, u32>] ascending iteration is that same
    function's pinned ordering.

    The three narrowings run before the genesis rule, because the rule is a
    statement about block {e zero} and there is no block number to compare
    against until [number] is an [int]. *)

val block : t -> Env.Block.t
(** The environment every frame of every transaction in this block reads. It is
    the same value {!Block_execution} hands to {!Executor.execute}, which is
    what makes "assembled from the block it ran in" true by construction. *)

val parent_hash : t -> Tn_keccak.t
(** The previous execution block's hash, as a real digest rather than as bytes,
    so it can flow into {!Block_hashes.of_recent} unchanged. *)

val consensus_root : t -> Tn_types.Digests.Output_digest.t
(** The digest of the [ConsensusHeader] this block descends from. It is the
    calldata of the EIP-4788 system call and the header's
    [parent_beacon_block_root], which is why it is one field and not two. *)

val nonce : t -> Tn_types.Units.Sequence_number.t
(** The leader's commit sequence number, the [(epoch, round)] pair the header
    nonce carries. Typed, so nothing has to re-derive the packing. *)

val batch_digest : t -> Tn_types.Digests.Batch_digest.t
(** The worker batch this block executes, which the header carries in the
    [ommers_hash] slot. *)

val position : t -> Batch_position.t
(** The batch's position in its consensus output: the packed word the header
    carries as [difficulty] and the value {!first_batch} reads. *)

val boundary : t -> Epoch_boundary.t
(** Whether this is the last batch of a closing epoch, together with the
    randomness and the withdrawals such a batch commits to. *)

val number : t -> int
(** The block number, narrowed once at construction and non-negative because
    {!Tn_state.U256.to_int} succeeded on an unsigned word. Narrowing here rather
    than at each use is what makes {!Block_gas.start} and header assembly
    total. *)

val timestamp : t -> int
(** The block timestamp, narrowed and non-negative for {!number}'s reason. *)

val gas_limit : t -> int
(** The block gas limit, narrowed and non-negative for {!number}'s reason. This
    is the number {!Block_gas.start} meters against, and it is emphatically not
    the limit a system call runs under: {!System_call} rebuilds the environment
    with its own 30M ceiling. *)

val is_genesis : t -> bool
(** [number t = 0]. A [bool] is safe to expose for {!Access.mem_account}'s
    reason: nothing prices or gates from a [bool], and the pre-block hook takes
    a whole {!t}, so a fabricated [true] has nowhere to go. *)

val first_batch : t -> bool
(** [Batch_position.is_first_batch (position t)]. Named here because it is the
    pre-execution gate ([block.rs:775]) and a reader should not have to know it
    is a property of the difficulty word. *)

val equal : t -> t -> bool
(** Componentwise equality of the seven constructor arguments. The three
    narrowed integers are a function of [block] and are deliberately not
    compared again: two contexts equal on their inputs cannot differ on a
    derived field. *)
