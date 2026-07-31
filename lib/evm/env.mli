(** The context an execution frame reads but cannot change: the block it runs
    in, the transaction it belongs to, and the call that entered it.

    Everything here is fixed for the whole run, so it is threaded {e beside} the
    machine as an argument, exactly as {!Code.t} already is, rather than carried
    inside it. The split into three is by lifetime and it is load-bearing rather
    than tidy. The block fields are fixed for every frame of every transaction
    in the block. The transaction fields — [ORIGIN] and [GASPRICE] — are fixed
    for every frame of one transaction, and revm sources them from the
    transaction and not from the frame ([revm-interpreter]
    [instructions/tx_info.rs], where [ORIGIN] reads the transaction's sender, not
    the immediate caller). The call fields change on every frame. Because
    {!with_call} is the only function producing a changed {!t}, the call chunk
    will be structurally unable to rebind [ORIGIN] when it enters a sub-frame,
    which is the classic port bug made a compile error.

    [CHAINID] is folded into {!Block} although revm reads it from configuration
    ([instructions/block_info.rs]); it is invariant across the whole chain, so a
    one-field third record would enforce nothing.

    [PREVRANDAO] and [DIFFICULTY] are the same code byte [0x44]. revm chooses
    between them by fork; this port targets Prague, where the beacon-randomness
    reading always applies, so the field is named for the reading that holds and
    the pre-merge one is not representable.

    {2 The fork level, stated once}

    This is the port's SINGLE statement of its fork scope; every other module
    that needs the claim cites this paragraph rather than restating it. Prague
    is the level of TN {e testnet} (chain 2017) and of the TN test suite:
    [chain-configs/testnet/genesis.yaml:15-17] sets [shanghaiTime],
    [cancunTime] and [pragueTime] all to [0], and every test genesis routes
    through [set_genesis_defaults], which backfills [prague_time]
    ([crates/types/src/genesis.rs:24, 71-74]). TN {e mainnet} (chain 487) runs
    at [SpecId::SHANGHAI]: its committed genesis declares [shanghaiTime] as
    its only timestamp fork ([chain-configs/mainnet/genesis.yaml:15]),
    [Config::load_mainnet] deserialises it directly, never calling
    [set_genesis_defaults] ([crates/config/src/node.rs:155-156]), and reth
    filter-maps an absent fork time to [ForkCondition::Never]
    ([reth] [chainspec/src/spec.rs:896-901]), which is never active. On that
    chain a type-[0x04] transaction is rejected with [Eip7702NotSupported]
    before pre-execution ([revm-handler] [validation.rs:191-195]),
    [TLOAD]/[TSTORE]/[MCOPY] halt [NotActivated], and neither BEACON_ROOTS
    nor HISTORY_STORAGE is ever written, because telcoin's own gates are
    timestamp-driven ([tn-reth/src/evm/block.rs:643-645, 698-700]). This port
    models the TESTNET configuration, unconditionally; the enumerated
    inventory of what a mainnet-faithful fork schedule would have to gate
    lives in [block_execution.mli].

    Before chunk 33 the port rejected a type-4 transaction as
    [Unknown_type_byte 4], which agreed with TN mainnet for the wrong reason.
    It now executes one. That accidental agreement is deliberately given up in
    exchange for modelling the chain the port actually targets.

    Two fields the real machine has are absent, and their absence is the point.
    There is no static-call flag, so [SSTORE]'s [require_non_staticcall] guard
    ([instructions/host.rs:229]) has nothing to test and is not written; it
    arrives with [STATICCALL]. There is no call depth and no return-data buffer,
    for the same reason. And {!Call} has no [code] field: the frame's own code is
    already {!Interpreter.run}'s [~code] argument, and a delegatecall's split
    between code address and storage address cannot arise until calls do. *)

open Tn_types

type word = Tn_state.U256.t

module Block : sig
  type t
  (** What every frame of every transaction in one block reads. *)

  val make :
    coinbase:Units.Address.t ->
    timestamp:word ->
    number:word ->
    prevrandao:word ->
    gas_limit:word ->
    basefee:word ->
    basefee_address:Units.Address.t ->
    chain_id:word ->
    blob_gasprice:word ->
    hashes:Block_hashes.t ->
    t

  val coinbase : t -> Units.Address.t
  (** [COINBASE]: the block's beneficiary. EIP-3651 pre-warms it, which is
      {!Access.of_transaction}'s business, not this module's. *)

  val timestamp : t -> word
  val number : t -> word

  val prevrandao : t -> word
  (** [PREVRANDAO] ([0x44]): the beacon chain's randomness for this block. *)

  val gas_limit : t -> word
  val basefee : t -> word

  val basefee_address : t -> Units.Address.t
  (** The account {!Executor}'s telcoin fee split credits with the base fee and
      the gas-limit penalty ([tn-reth/src/evm/handler.rs:28-44]). Chain
      configuration rather than EVM environment: no opcode reads it ([BASEFEE]
      reads {!basefee}), and telcoin fixes it once per chain from genesis with
      the governance safe as the default
      ([lib.rs:198-210], {!System_contracts.governance_safe_address}). It rides
      here because this record is the executor's only environment, for the same
      reason {!chain_id} does. *)

  val chain_id : t -> word
  (** [CHAINID]. Held here rather than in a configuration record of its own —
      see this module's header. *)

  val blob_gasprice : t -> word
  (** [BLOBBASEFEE] ([0x4a]): the blob base fee of this block. Named for revm's
      accessor chain [Host::blob_gasprice -> block().blob_gasprice()], which the
      interpreter's one-line projection collapses, exactly as [BASEFEE] and
      [CHAINID] already do. It is a required field with no default so that every
      construction site binds it consciously; the value a consensus-faithful
      caller binds is {!consensus_blob_gasprice}. *)

  val consensus_blob_gasprice : word
  (** [2^128 - 1], the value TN consensus execution runs under, and the port's
      single two-surface divergence, documented here once.

      TN's one production execution path binds the blob env at construction:
      engine [execute_payload -> build_block_from_batch_payload ->
      builder_for_next_block -> next_evm_env] hard-codes
      [BlobExcessGasAndPrice { excess_blob_gas: 0, blob_gasprice: u128::MAX }]
      ([config.rs:139-142], via [lib.rs:801-802]), so [BLOBBASEFEE] pushes
      [u128::MAX] during all consensus execution, leader and follower alike.

      TN's read-only surface, [evm_env(header)] (RPC and system reads, never
      consensus), instead derives the price from the header's hard-coded
      [excess_blob_gas = 0]: [calc_blob_fee(0) = fake_exponential(1, 0,
      5_007_716) = 1] wei. That surface has no image in this port and no
      [fake_exponential] is ported; the 1-wei value lives only in this
      paragraph. Consensus state is only ever produced under [u128::MAX].

      System calls observe this same value: [transact_system_call] swaps only
      [gas_limit], [basefee] and [disable_nonce_check] ([evm/mod.rs:198-203]),
      so the blob env rides through {!System_call}'s rebuild untouched. *)

  val hashes : t -> Block_hashes.t
  (** What [BLOCKHASH] can see: the hashes of this block's recent ancestors.

      It is a supplied window rather than a lookup because this port has no chain
      database, which is the same reason the timestamp and the coinbase are
      fields here. {!Block_hashes} states exactly what a caller owes and what a
      short window means. *)

  val equal : t -> t -> bool
end

module Tx : sig
  type t
  (** What every frame of one transaction reads. *)

  val make :
    origin:Units.Address.t ->
    gas_price:word ->
    access_list:(Units.Address.t * word list) list ->
    t

  val origin : t -> Units.Address.t
  (** The externally owned account that signed the transaction — never a
      contract, and never the immediate caller. It equals {!Call.caller} only in
      the top-level frame. *)

  val gas_price : t -> word
  (** The {e effective} gas price, base fee included. Computing it from
      [maxFeePerGas] is the transaction layer's job, so it enters as a number. *)

  val access_list : t -> (Units.Address.t * word list) list
  (** The EIP-2930 access list exactly as the transaction declared it: slots
      grouped under their address, order and repeats preserved, because this is
      literally transaction data.

      It is not a warm set and nothing warms anything from it today.
      {!Interpreter.run} deliberately pre-warms nothing, so an environment
      carrying a declaration and an {!Effects.t} built on {!Access.empty} is the
      expected pairing right now and not a mismatch. Assembling the starting
      {!Access.t} belongs to the transaction layer, which this port does not
      have yet; when it arrives it is the consumer of this field, and it reads
      it through {!declared_warm} rather than by reshaping it itself. *)

  val declared_warm : t -> Units.Address.t list * (Units.Address.t * word) list
  (** The declared access list in exactly the two shapes
      {!Access.of_transaction} consumes, as [(addresses, slots)].

      The addresses are every account the list names, since naming one warms it:
      EIP-2930 charges [ACCESS_LIST_ADDRESS_COST] for an entry that carries no
      slots at all. The slots are every [(address, slot)] pair the grouping
      implies, because {!Access} prices a slot by that pair and never by the
      slot number alone.

      This is the only place the grouped wire form is flattened, which is what
      keeps the declaration and the warm set one fact rather than two. It is
      total — the empty list gives [([], [])] — and it neither sorts nor
      deduplicates, because {!Access.of_transaction} folds both components into
      sets where a repeat costs nothing and order is not observable.

      The EIP-2929 and EIP-3651 warmings — the origin, the call target, the
      block coinbase — are deliberately absent: they are not access-list
      entries, and the transaction layer prepends them to the [~addresses]
      argument itself. *)

  val equal : t -> t -> bool
end

module Call : sig
  type t
  (** What one frame reads and the next frame replaces. *)

  val make :
    target:Units.Address.t ->
    caller:Units.Address.t ->
    value:word ->
    data:Data.t ->
    mutability:Mutability.t ->
    t

  val target : t -> Units.Address.t
  (** [ADDRESS]: the account whose code is running, whose storage [SLOAD] and
      [SSTORE] address, and whose balance [SELFBALANCE] reads. *)

  val caller : t -> Units.Address.t
  (** [CALLER]: the immediate caller, which is {!Tx.origin} only at the top
      level. *)

  val value : t -> word
  (** [CALLVALUE]: the wei this call carried. *)

  val data : t -> Data.t
  (** [CALLDATA...]: the input, read through {!Data}'s zero-extension rule. *)

  val mutability : t -> Mutability.t
  (** Whether this frame may change anything outside itself (EIP-214).

      It sits here rather than on {!Block} or {!Tx} because staticness is a
      property of the {e call}: [STATICCALL] makes the frame it enters static and
      every frame beneath it static too, while the transaction and the block are
      the same either way. It is therefore replaced by {!with_call} along with
      the rest of the call context, which is what will make a sub-frame inherit
      it correctly by default when the calls chunk arrives.

      The interpreter never branches on this directly. It converts it to a
      {!Mutability.permit}, which is the argument the writes demand. *)

  val equal : t -> t -> bool
end

type t
(** The three contexts together. *)

val make : block:Block.t -> tx:Tx.t -> call:Call.t -> t
val block : t -> Block.t
val tx : t -> Tx.t
val call : t -> Call.t

val with_call : t -> Call.t -> t
(** The environment of a sub-frame: a new call context inside the same block and
    the same transaction. It is the only way to build a changed {!t}, so the
    fields a sub-call must not touch cannot be touched. *)

val equal : t -> t -> bool
(** Componentwise equality of the three contexts. *)
