(** The validator registry for one epoch.

    A committee is built only through {!create}, which enforces the standing
    invariants — at least two authorities, no duplicate keys — and derives the
    Byzantine thresholds once. Downstream code therefore receives a committee
    whose quorum ([2f+1]) and validity ([f+1]) thresholds are correct by
    construction and cannot be forged.

    With every authority holding {!Units.Stake.one}, total stake equals the
    committee size, and the thresholds reduce to the classic table: size 4 gives
    quorum 3 / validity 2; size 7 gives 5 / 3; size 10 gives 7 / 4. *)

type t

type error =
  | Too_small of int
      (** Fewer than two authorities; the count is reported. *)
  | Duplicate_public_key  (** Two authorities share a protocol key. *)

val error_to_string : error -> string

val create : epoch:Units.Epoch.t -> Authority.t list -> (t, error) result

val epoch : t -> Units.Epoch.t
val size : t -> int
val total_stake : t -> Units.Stake.t

val quorum_threshold : t -> Units.Stake.t
(** [2f+1]: the stake a certificate or parent set must reach. *)

val validity_threshold : t -> Units.Stake.t
(** [f+1]: the support a leader needs to be committed, and the threshold above
    which at least one honest authority is present. *)

val authorities : t -> Authority.t list
(** In ascending {!Authority_id} order — the canonical traversal order. *)

val authority : t -> Authority_id.t -> Authority.t option
val contains : t -> Authority_id.t -> bool

val index_of : t -> Authority_id.t -> int option
(** The authority's position in the id-sorted list, i.e. its bit position in a
    certificate's signer bitmap. [None] if not a member. *)

val nth : t -> int -> Authority.t option
(** The authority at a bitmap position. Total: out-of-range yields [None]. *)

val stake_of : t -> Authority_id.Set.t -> Units.Stake.t
(** Total stake of the given members; non-members contribute nothing. *)

val reaches_quorum : t -> Units.Stake.t -> bool
val reaches_validity : t -> Units.Stake.t -> bool
