(** The EVM fork level a block executes at.

    This is the port's analog of revm's [SpecId], narrowed to the three levels
    the two committed Telcoin chain configs can reach. TN mainnet's genesis
    declares [shanghaiTime: 0] and carries no [cancunTime] or [pragueTime] key
    at all, so a mainnet block never leaves Shanghai; the testnet genesis
    declares all three at 0, so a testnet block is always at Prague. Every gated
    behavior in this library phrases itself as {!is_enabled}, mirroring revm's
    [spec_id().is_enabled_in(SpecId::$min)] guard.

    The type is a PUBLIC finite sum, not abstract, and that is deliberate. The
    house rule that an .mli hides its types yields here to the house rule that a
    finite sum is matched exhaustively: a client that dispatches on the fork
    level must be able to match, and a fourth constructor must then be a
    compiler error at every one of those match sites rather than a silent
    fall-through. {!Opcode.t} is public for the same reason.

    Levels below Shanghai are unrepresentable on purpose. Both committed configs
    activate Shanghai at timestamp 0, so no block of either chain can execute
    below it, and the behaviors that changed before Shanghai (PREVRANDAO,
    EIP-3651, EIP-3860, EIP-161 state clearing) are therefore invariant across
    every value of this type. *)

type t =
  | Shanghai  (** The subset floor: EIP-3651, EIP-3855, EIP-3860, withdrawals. *)
  | Cancun
      (** Adds EIP-1153 transient storage, EIP-5656 [MCOPY], EIP-4844's
          [BLOBHASH] and [BLOBBASEFEE], EIP-4788 beacon-root storage and the
          EIP-6780 restriction on [SELFDESTRUCT]. *)
  | Prague
      (** Adds EIP-2935 block-hash history, EIP-7702 delegation
          (transaction type 4) and the EIP-7623 calldata gas floor. *)

val compare : t -> t -> int
(** The activation order, [Shanghai < Cancun < Prague]: negative, zero or
    positive in the usual way. Total. *)

val is_enabled : t -> from:t -> bool
(** [is_enabled spec ~from] is [true] when [spec] is [from] or any later fork,
    that is, when a behavior introduced at [from] is active at [spec]. This is
    the single phrasing every fork gate in this library uses. Total. *)

val to_string : t -> string
(** The lowercase fork name, for logs and test failure messages. Total. *)
