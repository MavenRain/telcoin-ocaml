(** Deterministic leader election with reputation-driven swaps — the port of
    Rust's [LeaderSchedule] and [LeaderSwapTable].

    The baseline is a round-robin over the id-sorted committee: the leader of
    round [r] is authority [(r/2 - 1) mod size]. On top sits an optional swap
    table built from end-of-schedule {!Reputation_scores}: authorities more than
    two (truncated integer) standard deviations of score below the top are
    {e bad} and, when elected, are replaced by a deterministically chosen
    {e good} node (within one deviation of the top). Three Rust panics are
    unrepresentable here:

    - {b no odd-round election}: {!leader} takes a {!Tn_types.Leader_round.t},
      so Rust's [assert!(round % 2 == 0)] has nothing to check.
    - {b swaps need good nodes}: the populated table carries its good nodes as a
      non-empty list, so Rust's [expect("at least one good node")] has no
      counterpart.
    - {b threshold range}: {!Threshold.of_percent} admits only [0..33].

    Unlike the Rust [Arc<RwLock<_>>], the schedule is a plain immutable value
    threaded by the commit rule; installing a table returns a new schedule. *)

open Tn_types
open Tn_vertex

type t

(** The bad-nodes list cap as a percentage of committee size. *)
module Threshold : sig
  type t

  val of_percent : int -> t option
  (** [Some] only within [0, 33] — Rust's constructor assertion as a smart
      constructor. Note [0] still admits one bad node: the list cap is
      [max 1 (size * percent / 100)], a quirk preserved from Rust. *)

  val to_percent : t -> int

  val default : t
  (** 33 — Rust's [DEFAULT_BAD_NODES_STAKE_THRESHOLD]. Despite the Rust name it
      is a percentage of node {e count} (stake is uniform here). *)
end

val create : Committee.t -> threshold:Threshold.t -> t
(** A schedule with no swap table — the [LeaderSwapTable::default()] state every
    epoch starts from: pure round-robin, nothing is ever swapped. *)

val committee : t -> Committee.t

val leader : t -> Leader_round.t -> Authority.t
(** The elected authority: round-robin index into the id-sorted roster, then
    remapped through the swap table when the elected authority is currently bad.
    The replacement is drawn from the good nodes by a {!Tn_std.Prng} seeded with
    the queried round, so the same round always swaps to the same authority.
    Total. *)

val leader_certificate :
  t -> Dag.t -> Leader_round.t -> Authority.t * Certificate.t option
(** {!leader} plus the DAG's certificate for that authority at that round. The
    identity half never depends on certificate existence — a missing certificate
    is how the commit rule reports [Leader_not_found]; there is no fallback to
    another authority's certificate. *)

val note_final_scores :
  t -> activation:Leader_round.t -> Reputation_scores.t -> t option
(** [Some] with a freshly built swap table iff the scores are marked final — the
    schedule boundary. [None] means mid-schedule scores: no change. Mirrors
    Rust's [update_leader_schedule] boolean: a [Some] result signals that any
    leaders still queued must be re-elected. The new table may legitimately swap
    nothing (uniform scores give zero deviation), yet still counts as a schedule
    change, exactly as in Rust. *)

val from_store : Committee.t -> threshold:Threshold.t -> Committed_log.t -> t
(** Rebuild the schedule from the committed sub-DAG log — Rust's
    [LeaderSchedule::from_store]. Takes the most recent commit whose reputation
    scores are final and installs the swap table those scores build (exactly the
    table the commit rule had installed at the last schedule boundary), so no
    replay of intermediate commits is needed. A log with no final-scores commit
    recovers to the round-robin schedule {!create} gives. *)

val good_nodes : t -> Authority.t list
(** Score-descending; empty when the current table swaps nothing. Observability
    for tests and logs. *)

val bad_nodes : t -> Authority_id.Set.t
(** Empty when the current table swaps nothing. Observability. *)
