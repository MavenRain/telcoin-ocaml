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

val of_persisted : bindings:(Authority_id.t * int) list -> final:bool -> t
(** Rebuild a scores value field-wise from a decoded binding set. RESERVED for
    the storage chunk's decoder, the precedent {!Dag.insert_recovered} sets: no
    live consensus path may call it, because {!fresh} and {!bump} are what tie
    the key set to a committee. A decoder has no committee, and rebuilding a
    score of [k] by [k] {!bump} calls is O(total score), so a total field-wise
    producer is both cheaper and honest. The last binding for a repeated id
    wins; {!codec} never feeds it one, since its map section rejects a
    non-ascending key. *)

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

val codec : t Tn_codec.Bcs.t
(** The wire codec, byte-identical to Rust's derived [ReputationScores]
    (primary/reputation.rs:8-18). TWO sections and no third: the
    ULEB128-counted map of BARE 32-byte authority ids to little-endian u64
    scores in ascending id order, then the {!is_final} flag.

    {!total_authorities} is deliberately NOT on the wire. It is the cardinality
    of the binding set, so carrying it would be a field that can only ever
    agree with the bytes beside it, and Rust does not carry it either. Sorting
    by id means two equal score sets cannot produce two byte strings, so a
    byte-level differential over this codec stays meaningful. These are the
    same bytes {!Sub_dag.preimage} hashes for its scores section. *)

val equal : t -> t -> bool
