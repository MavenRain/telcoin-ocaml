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
    chain_id:word ->
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

  val chain_id : t -> word
  (** [CHAINID]. Held here rather than in a configuration record of its own —
      see this module's header. *)

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
