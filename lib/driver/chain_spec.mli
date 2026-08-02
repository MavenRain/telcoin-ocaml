(** The port's stand-in for the chain spec telcoin reads from
    [chain-configs/<net>/genesis.yaml]: chain id, basefee address, the genesis
    anchor and the genesis world, behind ONE smart constructor.

    Abstract on purpose (D8): a spec whose world lacks the ConsensusRegistry
    account or the EIP-4788/EIP-2935 predeploys is unconstructible, because
    {!create} seats the caller's registry entry at
    {!Tn_evm.System_contracts.consensus_registry_address} and then applies
    {!Tn_evm.System_contracts.predeploy}. The registry runtime itself stays a
    caller-supplied {!Tn_state.Genesis_account.t}: the port has no YAML
    loader, and a library must not carry one chain's data. A future loader
    chunk replaces this constructor's body (or adds a loader that calls it)
    without changing a single caller, because [t] is abstract.

    Where a caller finds the cited scalars: chain id testnet 2017
    ([chain-configs/testnet/genesis.yaml:3]), mainnet 487
    ([mainnet/genesis.yaml:3]); gas limit [0x1c9c380] = 30,000,000
    ([testnet/genesis.yaml:23], [mainnet:21]); base fee [0x7]
    ([testnet:264], [mainnet:221]); genesis timestamp [0x69fceea7]
    ([testnet/genesis.yaml:21]); the basefee address's compile-time default
    is {!Tn_evm.System_contracts.governance_safe_address}
    ([tn-reth/src/lib.rs:197-210]).

    The genesis BLOCK HASH is not derivable in-port:
    [Tn_evm.Block_header.assemble] needs a finished execution, and a genesis
    the node did not execute has no header ({!Tn_engine.Anchor.of_genesis}).
    It is therefore a required argument documented as UNVERIFIED here, never
    an invented constant. *)

(** The epoch length in whole seconds, strictly positive by construction -
    upstream a [uint32] of seconds ([IStakeManager.sol:41],
    [tn-reth/src/system_calls.rs:95]), testnet default 28800 = 60*60*8
    ([tn-reth/src/test_utils.rs:836]).

    Divergence, recorded: upstream re-reads [epochDuration] from the
    registry's stake config at every epoch entry ([run_epoch.rs:140-145]);
    the port has no registry reader yet, so the duration is configuration
    with exactly one consumer to repoint when a reader exists. Positivity
    keeps the engine's strict boundary advance well-founded; whether the
    engine's [Boundary_not_advanced] can still fire is the driver's error
    surface to document, not a claim this module makes (P12). *)
module Epoch_duration : sig
  type t
  (** A strictly positive number of seconds. *)

  val of_secs : int -> t option
  (** [Some] exactly when the argument is positive. Zero or negative seconds
      would put an epoch's closing boundary at or before its own opening. *)

  val to_secs : t -> int
  (** The seconds back; always [> 0]. *)

  val equal : t -> t -> bool
  (** Same length. *)
end

type t
(** One chain's starting facts. Abstract: every value went through {!create},
    so its world carries the registry and both system predeploys, and its
    epoch duration is positive. *)

type error =
  | Alloc of Tn_state.World_state.alloc_error
      (** The registry entry or an extra alloc entry was refused by
          {!Tn_state.World_state.of_genesis_alloc}: storage on a codeless
          account, or a malformed delegation designator. *)

val error_to_string : error -> string
(** Render an {!error} for diagnostics. *)

val create :
  chain_id:Tn_state.U256.t ->
  basefee_address:Tn_types.Units.Address.t ->
  genesis_hash:Tn_keccak.t ->
  genesis_base_fee:Tn_state.U256.t ->
  genesis_gas_limit:int ->
  genesis_timestamp:Tn_types.Units.Timestamp.t ->
  epoch_duration:Epoch_duration.t ->
  ?ancestors:Tn_keccak.t list ->
  registry:Tn_state.Genesis_account.t ->
  extra_alloc:(Tn_types.Units.Address.t * Tn_state.Genesis_account.t) list ->
  unit ->
  (t, error) result
(** The one producer. [genesis_hash] is the caller's CLAIM about the
    committed genesis block - unverifiable in-port (see the module comment),
    so it is threaded, never checked. [ancestors] (default [[]]) are the
    genesis anchor's ancestor hashes, newest first and excluding the anchor's
    own, seeding the EIP-2935 window; [[]] is right only for a true genesis,
    and a spec resuming mid-chain owes the real ones, because a short list
    reads zero for the ancestors it omits ({!Tn_engine.Config.create}). The
    world is {!Tn_state.World_state.of_genesis_alloc} of the alloc followed
    by {!Tn_evm.System_contracts.predeploy}. The registry entry is appended
    AFTER [extra_alloc], so under the alloc's later-entry-wins rule an
    [extra_alloc] entry at the registry address cannot displace it - the
    registry belongs in [~registry], and nowhere else. The only refusal is
    {!error}. *)

val anchor : t -> Tn_engine.Anchor.t
(** The genesis anchor: the caller's hash, base fee and gas limit at height
    [Tn_engine.Block_number.genesis], with no header
    ({!Tn_engine.Anchor.of_genesis}). *)

val world : t -> Tn_state.World_state.t
(** The genesis world: the alloc with the registry seated, plus both system
    contracts and both deployer EOAs predeployed. *)

val chain_id : t -> Tn_state.U256.t
(** What [CHAINID] answers on this chain. *)

val basefee_address : t -> Tn_types.Units.Address.t
(** Where every block's base fee and gas penalty are credited. *)

val genesis_timestamp : t -> Tn_types.Units.Timestamp.t
(** The committed genesis block's timestamp - epoch 0's opening instant
    (epoch 0 pins genesis, [node/tests/it/main.rs:2542-2544]). *)

val epoch_duration : t -> Epoch_duration.t
(** The epoch length this spec runs at. *)

val ancestors : t -> Tn_keccak.t list
(** The anchor's ancestor hashes, newest first, excluding the anchor's own;
    [[]] at a true genesis. *)

val first_boundary : t -> Tn_types.Units.Timestamp.t
(** [genesis_timestamp + epoch_duration]: the instant at or past which epoch
    0's closing output closes it. Every LATER boundary is minted from the
    closing output's own commit time plus the duration, never from this one
    ([tn-reth/src/lib.rs:1832-1836]); this value exists because epoch 0 has
    no closing output behind it yet. *)

val engine_config : t -> committee:Tn_types.Committee.t -> Tn_engine.Config.t
(** The {!Tn_engine.Config.t} a cold start hands to the engine: this spec's
    anchor, ancestors, world, chain id and basefee address, with the epoch
    boundary at {!first_boundary}. The committee stays the caller's argument:
    upstream reads it back from the registry at epoch entry, and the port has
    no registry reader ([tn-reth/src/lib.rs:1867-1913]). *)
