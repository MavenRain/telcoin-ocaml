(** Per-authority leader-support tallies — the port of Rust's
    [ReputationScores].

    Each committed sub-DAG carries the running scores: an authority earns a
    point whenever its certificate at the round after the previously committed
    leader names that leader as a parent. Every [sub_dags_per_schedule] commits
    the scores are marked {e final}, feed the {!Leader_schedule} swap table, and
    reset. Two Rust asserts live in the type instead of at runtime:

    - {b full committee coverage}: a value is born only through {!fresh}, which
      seeds a zero for every committee member, and {!bump} can only touch
      existing entries — the key set can never drift from the committee,
      replacing Rust's [assert_eq!(total_authorities, committee.size())].
    - {b finality is data}: [final_of_schedule] rides on the value, so a swap
      table can only be requested from scores that say they are final
      ({!Leader_schedule.note_final_scores} reads the flag; no caller ever
      re-derives it). *)

open Tn_types

type t

val fresh : Committee.t -> t
(** Zero for every committee member, not final — the value of the very first
    commit and the reset point at each schedule boundary. *)

val bump : t -> Authority_id.t -> t
(** One more point for an authority. Total: an id with no entry (never a
    committee member, by the coverage invariant) leaves the scores unchanged
    rather than growing the map. *)

val with_final : bool -> t -> t
(** The schedule-cadence flag, recomputed by the commit rule on every sub-DAG. *)

val is_final : t -> bool

val get : t -> Authority_id.t -> int
(** Total: an absent id reads as zero, matching Rust's missing-entry rule. *)

val bindings : t -> (Authority_id.t * int) list
(** Ascending authority id — the canonical traversal and encode order. *)

val by_score_desc : t -> (Authority_id.t * int) list
(** Descending score with ties broken by {e descending} id — exactly Rust's
    [authorities_by_score_desc], the order the swap table is carved from. *)

val total_authorities : t -> int
val all_zero : t -> bool

val equal : t -> t -> bool
