(** The Bullshark commit rule — the port of [Bullshark::process_certificate]
    together with the commit half of Rust's [ConsensusState] (the certificate
    half already lives in {!Dag}).

    Feeding a certificate inserts it into the DAG and, when its round is [r + 1]
    for an electable leader round [r], attempts a commit: the scheduled leader of
    [r] must hold a certificate that at least [f+1] voting power of round-[r+1]
    children name as a parent. A committable leader first drags in every earlier
    uncommitted leader it is linked to through the DAG, oldest first; each one's
    causal history is flattened into a {!Sub_dag}, reputation scores are tallied,
    and a schedule boundary crossed mid-chain re-elects the remaining leaders
    under the new swap table before continuing.

    Rust's shape is reworked in three type-level ways, none behavioral:

    - {b commit iff sub-DAGs}: Rust overrides the final outcome to
      [Outcome::Commit] whenever the accumulated sub-DAG list is non-empty,
      whatever the last attempt said. Here {!outcome} is either [Committed] of a
      non-empty list or a {!no_commit} reason — a commit with nothing committed,
      or a reason with commits attached, cannot be expressed.
    - {b [Schedule_changed] is internal}: the retry is a recursion whose depth is
      bounded because every retry has strictly advanced the committed round; the
      variant never escapes this module.
    - {b leader rounds are witnesses}: election and the backwards leader scan
      work on {!Tn_types.Leader_round.t}, so the even / [>= 2] asserts vanish.

    Errors are the DAG's own insertion errors, reused rather than wrapped,
    exactly as {!Vote_aggregator} reuses {!Tn_vertex.Certificate.error}. *)

open Tn_std
open Tn_types
open Tn_vertex

type t

type no_commit =
  | Certificate_below_commit_round
      (** The certificate was at or below the GC round (dropped without storing)
          or not beyond its author's committed watermark (stored for parent
          resolution, but no election). *)
  | No_leader_round
      (** [round - 1] is odd or below 2, so no leader is defined there. Rust
          calls this [NoLeaderElectedForOddRound], but it fires on even-round and
          genesis-adjacent insertions too; this name says what is true. *)
  | Leader_below_commit_round
      (** The candidate leader round is at or below the committed round — already
          ordered, nothing to do. *)
  | Leader_not_found
      (** The scheduled authority holds no certificate at the leader round. Never
          a fallback to another authority. *)
  | Not_enough_support
      (** The children naming the leader as a parent carry less than [f+1] voting
          power. *)

type outcome =
  | Committed of Sub_dag.t Nonempty.t
      (** Oldest leader first; the triggering round's leader is last unless a
          schedule change re-elected it into failure — in which case the earlier
          sub-DAGs still commit, exactly Rust's outcome override. *)
  | No_commit of no_commit

val no_commit_to_string : no_commit -> string
val outcome_to_string : outcome -> string
val equal_outcome : outcome -> outcome -> bool

val create :
  committee:Committee.t ->
  schedule:Leader_schedule.t ->
  sub_dags_per_schedule:int ->
  gc_depth:int ->
  t
(** A fresh instance over an empty DAG. [sub_dags_per_schedule] is the reputation
    schedule window (Rust exercises 3, 4, 5 and 100 in tests); values below 1 are
    clamped to 1 — a zero window is meaningless and Rust never runs one.
    [gc_depth] is the DAG retention window (Rust default 50). *)

val of_store :
  committee:Committee.t ->
  schedule:Leader_schedule.t ->
  sub_dags_per_schedule:int ->
  gc_depth:int ->
  certificates:Certificate.t list ->
  committed:Committed_log.t ->
  (t, Dag.error) result
(** Reconstruct the commit state at restart — the port of Rust's
    [ConsensusState::new_from_store]. The DAG is rebuilt from [certificates] (the
    persisted certificate store; {!Dag.recover} folds them parent-check-disabled
    and drops any below the recovered GC round), and the committed watermark,
    committed round, and last committed sub-DAG are derived from [committed] (the
    persisted commit log). [schedule] is the separately recovered leader schedule
    ({!Leader_schedule.from_store}), which must be built before this call, exactly
    as Rust installs the swap table before spawning consensus. Fails with a
    {!Dag.error} if the certificate slice equivocates (Rust panics there). *)

val process_certificate :
  t -> Certificate.t -> (t * outcome, Dag.error) result
(** Insert, then elect and commit as far as the DAG allows. Several sub-DAGs can
    come out of one call (recursive commit of leaders skipped during asynchrony).
    The returned state has the DAG garbage-collected per committed certificate,
    the last committed sub-DAG chained, and the schedule advanced past any
    boundary the commit crossed. *)

val dag : t -> Dag.t
(** The live DAG — committed certificates pruned by GC, watermarks advanced.
    Read-only observability for tests and recovery. *)

val schedule : t -> Leader_schedule.t

val last_sub_dag : t -> Sub_dag.t option
(** The most recently committed sub-DAG — Rust's [state.last_committed_sub_dag],
    the chaining point for timestamps and carried scores. *)

val max_inserted_round : t -> Round.t
(** Monotone maximum over successfully inserted certificate rounds. Bookkeeping
    only; no part of the commit rule. *)
