(** The recovery gap as a value whose contiguity is a type fact: the ascending,
    hash-linked run of durable records between a resumed node's executed
    watermark and its durable-store tip.

    Upstream collects this range with a bare loop over
    [last_executed.number + 1 ..= last_db.number], looking each number up and
    pushing whatever comes back ([state-sync/src/lib.rs:155-189]). Two readers
    of that loop disagreed about what a mid-range miss does — the [if let]
    silently skips it, the [?] one line above aborts — and the line-level
    evidence says an in-epoch miss is an [Err] and aborts, with the silent-skip
    arm architecturally reserved for cross-epoch lookups
    ([storage/src/consensus.rs:837-849]). This module resolves the pair by
    removing the loop from the caller: {!collect} walks the range itself, so a
    caller cannot hand a non-contiguous list to anything, and a hole is an
    [Error] rather than a policy choice.

    It carries the chain check too, because the gap's whole job is to be
    re-minted. Every collected block's [parent_hash] must be its predecessor's
    digest, and the first's must be the [parent] the caller states — which for
    a resuming driver is the digest of the block it last executed. That is the
    port's stand-in for upstream's per-step [digest_from_parts] re-derivation in
    [catch_up_consensus_from_to] ([state-sync/src/lib.rs:339-349, 391-401]),
    moved from mid-replay to collection time: with a chain-verified run and an
    accumulator seeded at [parent], the block re-minted at each height equals the
    stored one by induction, so no mid-replay comparison is left to make.

    It lives here, in the execution seam, so [Tn_driver] can consume a gap
    without naming any store implementation — the driver sits ABOVE this
    library and this library must not depend on it. *)

open Tn_types
open Tn_consensus

type t
(** An ascending, gapless, hash-linked run of durable records: for each, the
    consensus block and every batch body its sub-DAG references. Possibly
    empty — a node that crashed with nothing outstanding has an empty gap, and
    replaying it is the no-op upstream's every-epoch-entry safety net relies on
    ([run_epoch.rs:37-79]). *)

(** Why a range could not be collected. Both arms mean the store is internally
    wrong rather than merely behind: the invariant [replay_missed_consensus]
    documents is that every header in the range WAS durably stored before the
    crash, so a miss inside it signals corruption or a lying cursor
    ([start_epoch.rs:64-67]). *)
type break =
  | Hole of { number : Consensus_block.Number.t }
      (** [fetch] could not supply [number], which lies strictly inside the
          requested range. Unreachable through {!Tn_execution.Consensus_store}'s
          own writer, which accepts only next-slot-or-identical-resubmit, and
          kept anyway (P12): it is the corruption vocabulary an implementation
          with an independent import path — upstream's [stream_import]
          ([storage/src/consensus.rs:484-499]) — can produce. *)
  | Broken_link of {
      number : Consensus_block.Number.t;
      expected : Digests.Output_digest.t;
      found : Digests.Output_digest.t;
    }
      (** The block at [number] does not link to its predecessor (or, at the
          floor, to the stated [parent]). At the floor this is the only signal
          that a checkpoint and a store came from two different runs. *)

val break_to_string : break -> string
(** Human rendering, one arm per variant; numbers render as decimal and digests
    as lowercase hex. *)

val collect :
  after:Consensus_block.Number.t ->
  parent:Digests.Output_digest.t ->
  upto:Consensus_block.Number.t ->
  fetch:
    (Consensus_block.Number.t -> (Consensus_block.t * Batch.t list) option) ->
  (t, break) result
(** Walk [Number.succ after .. upto] in ascending order, pulling each height
    through [fetch] and checking that it links to the one before it, with
    [parent] as the link the first must satisfy. [upto] at or below [after]
    yields the empty run, so a caught-up node's collection is cheap and
    idempotent rather than a special case.

    This is the ONE place the range is walked and the chain is verified, shared
    by every implementation of {!Tn_execution.Consensus_store.S} rather than
    re-derived per implementation, because it is the only operation in the seam
    with a correctness argument. *)

val after : t -> Consensus_block.Number.t
(** The floor the run was collected above: the resuming node's executed
    watermark. The first block's number is its {!Consensus_block.Number.succ}. *)

val upto : t -> Consensus_block.Number.t
(** The ceiling the run was collected against — the store's own tip, never a
    caller's guess. Equal to {!after} for an empty run. After a clean replay a
    resumed driver's watermark equals this, which is how the port recovers
    upstream's [last_consensus_parent] max rule as a post-condition rather than
    as an anchor ([state-sync/src/lib.rs:135-151]). *)

val is_empty : t -> bool
(** Whether there is nothing to replay. *)

val length : t -> int
(** How many records the run holds. *)

val blocks : t -> Consensus_block.t list
(** The durable consensus blocks, ascending. A resumed driver does not execute
    these: it re-mints each one from its sub-DAG and the accumulator, and the
    chain check above is what makes the two agree. *)

val sub_dags : t -> Sub_dag.t list
(** The committed sub-DAGs, ascending: exactly what a resumed driver folds, in
    the shape [Driver.fold] already takes. *)

val bodies : t -> Batch.t list
(** Every body of every record, ascending by record and in each record's own
    sub-DAG payload order. Duplicates are preserved: a digest under two
    certificates is one body resolved twice, and the ephemeral store a replayed
    step is handed keys on the derived digest anyway. *)

val last : t -> Consensus_block.t option
(** The run's final block, or [None] when empty. *)
