(** When each fork activates on a chain, and therefore which {!Spec.t} a block
    executes at.

    This mirrors the genesis config surface exactly. A Telcoin genesis declares
    a fork by giving it an activation timestamp; it declares that a fork never
    activates by leaving the key out entirely, which reth filter-maps to
    [ForkCondition::Never]. So Cancun and Prague are options here, and absence
    is not the same value as zero. TN mainnet sets [shanghaiTime: 0] and nothing
    else. TN testnet sets [shanghaiTime], [cancunTime] and [pragueTime] all to
    0, which is the port's historical assumption and stays the default
    everywhere.

    The type is abstract and smart-constructed: {!make} rejects a schedule whose
    forks do not activate in order, so an out-of-order schedule cannot reach
    {!active_at}, and {!active_at} is therefore total with no error case of its
    own. *)

open Tn_types

type t

type error =
  | Cancun_before_shanghai
      (** A Cancun activation earlier than the Shanghai one. *)
  | Prague_before_cancun
      (** A Prague activation earlier than the Cancun one. *)
  | Prague_without_cancun
      (** Prague activated on a chain that never activates Cancun. Skipping a
          fork is rejected rather than modelled: both committed configs are
          monotone with no skipped fork, and every Cancun behavior is a
          precondition of the Prague ones this port implements. *)

val error_to_string : error -> string
(** A short one-line description of a rejection, for logs and test failure
    messages. Total. *)

val make :
  shanghai:Units.Timestamp.t ->
  cancun:Units.Timestamp.t option ->
  prague:Units.Timestamp.t option ->
  (t, error) result
(** A schedule from its three activation times, where [None] means the fork
    never activates. Shanghai has no [None] case because it is the floor of
    {!Spec.t}: a chain that never activates it has no representable fork level.
    Rejects a non-monotone schedule and a Prague without a Cancun. Total. *)

val mainnet : t
(** The TN mainnet schedule: Shanghai at 0, Cancun never, Prague never, read
    off [chain-configs/mainnet/genesis.yaml] where [shanghaiTime: 0] is the only
    fork-time key. Every mainnet block is at {!Spec.Shanghai}. *)

val testnet : t
(** The TN testnet schedule: Shanghai, Cancun and Prague all at 0, read off
    [chain-configs/testnet/genesis.yaml]. Every testnet block is at
    {!Spec.Prague}, which is what this port assumed before the schedule
    existed, so this value is the default wherever a schedule is optional. *)

val active_at : t -> timestamp:Units.Timestamp.t -> Spec.t
(** The highest fork activated at [timestamp], where a fork activates when its
    time is [timestamp] or earlier. Total.

    A timestamp below the Shanghai activation still answers {!Spec.Shanghai}.
    That clamp is deliberate and unreachable on both committed configs, which
    activate Shanghai at 0: {!Spec.t} has no pre-Shanghai constructor, so there
    is no other answer to give. *)

val equal : t -> t -> bool
(** Whether two schedules activate every fork at the same time, treating a
    never-activating fork as equal only to another never-activating one. *)

val to_string : t -> string
(** The three activation times on one line, with [never] for an absent fork.
    For logs and test failure messages. Total. *)
