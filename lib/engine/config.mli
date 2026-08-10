(** What the engine must be told before its first output.

    A runtime value, not a functor argument, because telcoin's engine learns all
    of this at spawn: the anchor comes from [lookup_head()] against a database
    that already exists ([crates/engine/src/lib.rs:96-118]), not from anything
    fixed when the code was compiled. A record also keeps two engines with
    different genesis base fees two values rather than two functor
    applications. *)

type t
(** One engine's starting facts. Abstract: an engine's anchor, world and
    committee are read from here once, at {!Engine.create}, and never set
    again. *)

val create_on_schedule :
  fork_schedule:Tn_evm.Fork_schedule.t ->
  anchor:Anchor.t ->
  ancestors:Tn_keccak.t list ->
  world:Tn_state.World_state.t ->
  chain_id:Tn_state.U256.t ->
  basefee_address:Tn_types.Units.Address.t ->
  epoch_boundary:Tn_types.Units.Timestamp.t ->
  committee:Tn_types.Committee.t ->
  t
(** Gather them, on a stated fork schedule. [fork_schedule] is when each fork
    activates on this chain; it is required here so neither production
    conversion site - {!Chain_spec.engine_config} at cold start, [Engine.resume]
    behind [Driver.resume] at resumption - can forget to forward the chain's
    own. Every other argument is as {!create} describes it. *)

val create :
  anchor:Anchor.t ->
  ancestors:Tn_keccak.t list ->
  world:Tn_state.World_state.t ->
  chain_id:Tn_state.U256.t ->
  basefee_address:Tn_types.Units.Address.t ->
  epoch_boundary:Tn_types.Units.Timestamp.t ->
  committee:Tn_types.Committee.t ->
  t
(** Gather them. [ancestors] are the anchor's own ancestor hashes, newest first
    and EXCLUDING the anchor's, and are [[]] at a true genesis; a node resuming
    mid-chain owes the real ones, because a short list reads zero for the
    ancestors it omits rather than failing ({!Recent_hashes.of_genesis}).
    [committee] is the one that resolves this epoch's leaders to execution
    addresses, and it must be here rather than discovered later: until a
    committee is installed, the leader counts an output advances resolve to no
    address at all ([gas_accumulator.rs:115-120]).

    This is {!create_on_schedule} on {!Tn_evm.Fork_schedule.testnet}, the
    Shanghai/Cancun/Prague-all-at-zero schedule this port assumed before one
    existed, so an engine configured through it builds exactly the blocks it
    built before. It is a separate constructor rather than an optional
    argument because OCaml erases an optional argument only when a positional
    argument follows it, and this constructor has none. *)

val anchor : t -> Anchor.t
(** The block the engine's first output builds on. *)

val ancestors : t -> Tn_keccak.t list
(** The anchor's ancestor hashes, newest first, excluding the anchor's own. *)

val world : t -> Tn_state.World_state.t
(** The state the first block executes against. *)

val chain_id : t -> Tn_state.U256.t
(** The chain id every block's EVM environment answers [CHAINID] with. *)

val basefee_address : t -> Tn_types.Units.Address.t
(** Where the base fee and the gas penalty are credited, which telcoin makes a
    configured address rather than a burn ([tn-reth/src/lib.rs]). *)

val epoch_boundary : t -> Tn_types.Units.Timestamp.t
(** The timestamp at or past which a committed output closes the epoch. The
    engine recomputes {!Tn_batch.Output.closes_epoch} against it rather than
    trusting a flag off the wire, as upstream demands of its deserializers
    ([output.rs:79-83]). *)

val committee : t -> Tn_types.Committee.t
(** The committee whose members' leader counts become the closing block's
    withdrawals. *)

val fork_schedule : t -> Tn_evm.Fork_schedule.t
(** When each fork activates on this chain. The engine is where per-block
    timestamps exist, so this is where the schedule has to reach: every block
    it builds resolves its own {!Tn_evm.Spec.t} from this value and its own
    timestamp, once, and hands it to the block environment. *)
