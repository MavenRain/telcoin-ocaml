(** The committed sub-DAG log — the recovery-facing port of Rust's consensus
    pack (the persisted stream of {!Tn_consensus.Sub_dag}s a node commits).

    A node's consensus output is a sequence of committed sub-DAGs. Persisting that
    sequence is all a restart needs to rebuild the parts of consensus state that
    are {e derived} rather than stored: the per-author committed watermark, the
    last committed sub-DAG (for reputation and timestamp continuity), and the
    latest final-scores sub-DAG (for the leader swap table). This module holds the
    log and those three derivations; it is the single artifact
    {!Tn_consensus.Bullshark.of_store} and {!Tn_consensus.Leader_schedule.from_store}
    read at recovery.

    The Rust node keeps this in RocksDB (the consensus pack) and its scans are
    bounded — [read_last_committed] walks the last 50 commits, the swap-table scan
    the last 1000. The port scans the whole log instead: everything a bounded scan
    would miss sits at or below the GC round and is dropped on insertion, so the
    unbounded scan agrees with Rust on every round that survives recovery while
    keeping {!last_committed} an exact match for the live DAG's watermark map. *)

open Tn_std
open Tn_types
open Tn_vertex

type t

val empty : t

val append : t -> Sub_dag.t -> t
(** Record one committed sub-DAG. The most recently appended is {!latest}. *)

val of_list : Sub_dag.t list -> t
(** A log from sub-DAGs in commit order (oldest first). *)

val to_list : t -> Sub_dag.t list
(** The sub-DAGs in commit order, oldest first. *)

val latest : t -> Sub_dag.t option
(** The most recently committed sub-DAG — Rust's [latest_consensus_header], the
    chaining point restored as [last_committed_sub_dag]. *)

val last_committed : t -> Round.t Authority_id.Map.t
(** The per-author committed watermark, the max round over every header (the
    leader included) of every committed sub-DAG — Rust's
    [ConsensusChain::read_last_committed]. Seeds the recovered DAG's watermark
    map; an author never committed is absent (and reads as {!Tn_types.Round.genesis}). *)

val last_committed_round : t -> Round.t
(** The maximum watermark, {!Tn_types.Round.genesis} for an empty log — Rust's
    [last_committed_round], the anchor for the recovered committed and GC rounds. *)

val latest_final_scores : t -> Sub_dag.t option
(** The most recently committed sub-DAG whose reputation scores are marked final —
    Rust's [read_latest_commit_with_final_reputation_scores]. The swap table in
    force at the crash was built from exactly these scores, so recovering it needs
    no replay. [None] for a log with no final-scores commit (a fresh epoch), which
    recovers to the round-robin schedule. The whole log is one epoch here (one
    committee), so no epoch filter is applied. *)
