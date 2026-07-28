(** [RewardsCounter] ([gas_accumulator.rs:94-174]) as a persistent value, not
    an [Arc<Mutex<HashMap>>] beside an [Arc<RwLock<Option<Committee>>>]: the
    engine's fold threads the value where Rust threads shared handles.

    Determinism note the port relies on: Rust's per-authority counts live in a
    [HashMap] whose iteration order is arbitrary, but every consumer first
    folds them into a [BTreeMap<Address, u32>] ([gas_accumulator.rs:123-141]),
    so the only order that ever escapes is ascending address order, and the
    merge on a shared address is a sum, which no iteration order can change.
    Here the same shape holds: counts are keyed by {!Tn_types.Authority_id}
    and only leave through {!address_counts}, which merges into an
    address-keyed map whose traversal is ascending byte order, exactly
    [BTreeMap]'s ordering on a 20-byte address. *)

type t
(** Per-authority leader counts plus the committee used to resolve an
    authority to its execution address. Abstract: counts can only grow one
    increment at a time, so a negative count is unrepresentable. *)

val empty : t
(** No counts, no committee: Rust's [Default] ([gas_accumulator.rs:168-175]). *)

val inc_leader_count : t -> Tn_types.Authority_id.t -> t
(** +1 for the leader, inserting 1 if absent ([gas_accumulator.rs:100-107]).
    Incremented once per [ConsensusOutput] even when the output has no batches
    and execution is skipped ([payload_builder.rs:19-30]); startup recovery
    replays the same increments from the consensus DB
    ([consensus_pack.rs:1284-1291]). *)

val set_committee : t -> Tn_types.Committee.t -> t
(** Install the committee that resolves authority ids to execution addresses.
    Must happen before any consensus output is executed
    ([gas_accumulator.rs:115-120]); until then {!address_counts} is silently
    empty, mirroring Rust's [None] arm rather than erroring. *)

val clear : t -> t
(** Counts emptied, committee kept: Rust's [clear] takes only the
    [leader_counts] lock ([gas_accumulator.rs:109-113]). Called at epoch
    boundaries. *)

val address_counts : t -> (Tn_types.Units.Address.t * int) list
(** The [BTreeMap<Address, u32>] of [get_address_counts]
    ([gas_accumulator.rs:122-142]): ascending execution-address (byte) order,
    counts {e summed} when two authorities share one execution address,
    authorities absent from the committee contributing nothing, and the whole
    list empty when no committee is set. This is the [applyIncentives]
    calldata order and the withdrawals order, both of which iterate the map
    as-is ([block.rs:414-424], [gas_accumulator.rs:146-158]). *)

type error =
  | Negative_amount of { address : Tn_types.Units.Address.t; amount : int }
      (** {!Withdrawal.make} refused a scalar. Unreachable from this module's
          own values (counts only grow from zero); surfaced rather than
          asserted, per the port's no-panic rule. *)

val error_to_string : error -> string
(** Diagnostic rendering, one line. *)

val generate_withdrawals : t -> (Withdrawal.t list, error) result
(** [generate_withdrawals] ([gas_accumulator.rs:144-158]): one record per
    {!address_counts} entry, in that (ascending-address) order, with
    [index = 0], [validator_index = 0] and [amount] the {e raw} leader count,
    never gwei and never a balance. These are informational records in the
    closing block's body and withdrawals root; rewards are paid solely by the
    [applyIncentives] system call, and no balance-application path for these
    records exists in the Rust workspace. Exactly what
    {!Epoch_boundary.Closing} carries. *)
