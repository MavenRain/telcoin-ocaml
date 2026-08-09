(** The real durable backend: an append-only log on a filesystem, read back
    through the reference store itself.

    This is where the byte layer of {!Tn_durable} meets the chain rules of
    {!Tn_execution.Consensus_store}, and the whole design is one sentence: the
    disk holds frames, the frames are folded through the reference's OWN
    [create], [receive] and [open_epoch], and the value that fold produces is
    the read surface. There is no second index, no manifest and no disk-side
    notion of a valid chain, so nothing can drift out of step with anything.

    The durability contract this module implements, stated as claims a case can
    kill rather than as prose:

    - {b Durable on return.} {!receive} answers [Ok] only after the frame
      carrying the record has been written in full and flushed. There is no
      second persist call to forget.
    - {b The mirror never leads the disk.} The read surface advances strictly
      after that flush returns, so no reader has ever observed a record that
      the device had not taken. A flush that fails leaves the caller holding
      the pre-call store.
    - {b A refusal is free.} Every protocol check runs against {!mirror}, in
      the reference's own order, before the first system call. A refused
      {!receive} writes zero bytes and costs zero flushes, so the reference's
      free rollback is bought rather than assumed. Pinned by
      {!bytes_appended} and {!fsyncs}.
    - {b An idempotent re-file is free.} A number already held under the same
      digest returns the store unchanged, before anything is encoded.
    - {b Exactly one flush per accepted write.} One for {!receive}, one for an
      accepted {!open_epoch}, two for an {!open_} that creates the log (the
      file, then the directory).
    - {b No fail-stop.} Every operating-system failure on every path is a
      typed arm of {!fault}. Nothing here exits and nothing raises.

    {b Scope of the guarantee.} Unconditional against process death.  Against
    operating-system crash wherever POSIX [fsync] is honoured.  NOT against
    power loss on macOS, where [fsync] does not flush the drive cache and
    [F_FULLFSYNC] is out of reach from stock [Unix]. That limit is reported as
    the value [report.durability] rather than left in a comment. *)

open Tn_types
open Tn_execution

type t
(** An open store: the log, the lock on its root, and the mirror rebuilt from
    the log's own durable bytes. Immutable, like the reference it mirrors —
    every accepted write returns a new value and never touches its argument, so
    a refused write leaves the caller holding a store that is still exactly
    what is on disk. *)

type origin = {
  dir : string;  (** The root directory this handle holds. *)
  epoch : Units.Epoch.t;  (** The epoch its file header states. *)
  anchor : Consensus_block.Number.t;
      (** The anchor height its file header states. *)
  parent : Digests.Output_digest.t;
      (** The digest of the block that anchor names, as the header states it. *)
}
(** The four values an {!open_} was asked for. *)

val origin : t -> origin
(** [origin t] is the root and the chain identity this handle was opened with:
    exactly the arguments {!open_} validated the stored file header against.

    Deliberately NOT the store's current epoch facts, which move with every
    {!open_epoch} and are read off {!mirror}. It exists so a caller that must
    close a handle and open the SAME root again — a restart, or a test that
    wants the scan-rebuilt mirror rather than the one in memory — has the four
    values without keeping a second copy of them beside the handle, where they
    could drift. *)

(** Why a store could not be opened, written or closed. Everything below the
    chain rules is one of the first three arms; the last three are the replay
    diagnoses, and each carries the offset and sequence number of the frame it
    refused, so an operator gets a place to look rather than a verdict. *)
type fault =
  | Io of Tn_durable.Io.error  (** The operating system refused a call. *)
  | Log of Tn_durable.Append_log.error
      (** The physical layer refused: damage, a foreign header, a payload
          outside the frame bounds. *)
  | Lock of Tn_durable.Store_lock.error
      (** Another handle, in this process or another, holds this root. Lifted
          out of {!Log} so single-writer contention is one named arm rather
          than a case inside a case. *)
  | Decode of { at : int; seq : int; error : Record_codec.error }
      (** A frame that framed correctly but whose payload is not the value its
          kind claims. *)
  | Meta_disagrees of { at : int; seq : int; field : string }
      (** An epoch-open frame states an epoch fact that disagrees with the one
          re-derived from the tip at that point in the replay. The frame is a
          CROSS-CHECK, never a source of truth, so a disagreement is refused
          rather than adopted. [field] names the first fact that differs. *)
  | Replayed_refusal of { at : int; seq : int; cause : Consensus_store.error }
      (** A frame that is tag-valid and decodes, but whose record the chain
          rules refuse. Recovery uses the SAME acceptance rules as the live
          write path — literally {!Consensus_store.receive} — so no byte
          sequence can install a store the live path would have rejected, and
          the reference's own five-arm error is carried out verbatim. *)

val fault_to_string : fault -> string
(** A one-line rendering of a {!fault}. *)

(** Why a write did not happen. The split is the operational one: a
    {!Refused} store is intact and the caller is wrong, a {!Fault} store may
    have met a device problem and the caller should stop. *)
type write_error =
  | Refused of Consensus_store.error
      (** The chain rules said no. Zero bytes were written and zero flushes
          were spent. *)
  | Fault of fault  (** The write reached the operating system and failed. *)

val write_error_to_string : write_error -> string
(** A one-line rendering of a {!write_error}. *)

type report = {
  heal : Tn_durable.Append_log.heal;
      (** What the open had to repair, if anything. *)
  frames : int;  (** How many frames were durable when the store opened. *)
  created : bool;  (** [true] when this open created the log. *)
  durability : [ `Fsync_no_fullsync ];
      (** Stated as a VALUE, not a footnote: this platform's flush is POSIX
          [fsync] and not [F_FULLFSYNC], so the guarantee stops at the
          operating system and does not reach the drive cache. *)
}
(** What an {!open_} found and what it did about it. *)

val open_ :
  ?ops:Tn_durable.Io_ops.t ->
  dir:string ->
  epoch:Units.Epoch.t ->
  anchor:Consensus_block.Number.t ->
  parent:Digests.Output_digest.t ->
  unit ->
  (t * report, fault) result
(** [open_ ?ops ~dir ~epoch ~anchor ~parent ()] takes the root and returns the
    store its bytes describe. Unconditional, non-destructive and idempotent.

    It creates the log on first use, otherwise adopts it: the stored 64-byte
    header is validated field by field against [epoch], [anchor] and [parent],
    so a root belonging to another chain is refused before a single frame is
    parsed; a torn tail is truncated and REPORTED; interior damage is refused
    with nothing truncated.

    Every durable payload is then folded through the reference's own
    [create]/[receive]/[open_epoch], in sequence order, which is what makes
    acceptance have exactly one definition on both paths. A payload that will
    not decode is {!Decode}, an epoch fact that disagrees with the tip is
    {!Meta_disagrees}, and a record the chain rules refuse is
    {!Replayed_refusal}. Any of the three gives the root back before returning,
    so a caller that repairs the cause and retries is not blocked by its own
    earlier attempt.

    [ops] defaults to the stock system-call table; a test passes a
    fault-injecting one. *)

val mirror : t -> Consensus_store.t
(** THE read surface: a real {!Consensus_store.t} built only from frames that
    are already durable, so every read member of the reference — [epoch],
    [epoch_start], [epoch_parent], [expected_next], [earliest],
    [latest_received], [record_at], [record_by_digest], [cardinal], [gap] — is
    the tested reference implementation rather than a second one written
    against bytes. A resuming driver takes this value with no signature change
    anywhere. *)

val receive : t -> Consensus_store.Record.t -> (t, write_error) result
(** [receive t record] files one record, durably.

    The record is validated against {!mirror} FIRST, so every refusal and every
    idempotent re-file writes zero bytes and costs zero flushes. On acceptance:
    encode, one write of the whole frame, one flush, and only then does the
    mirror advance. Durable on return. *)

val open_epoch : t -> epoch:Units.Epoch.t -> (t, write_error) result
(** [open_epoch t ~epoch] rolls to a new epoch and makes the roll durable.

    Exactly the reference's semantics and no more: strictly advancing, or
    [Refused Epoch_not_advanced]. The epoch-open frame states the three facts
    the reference derived for the roll and is durable before this returns.
    Keeping this member exactly the reference's is what lets the conformance
    differential stay exact with no excluded case; the restart path that needs
    to redo a roll it already made has its own name, {!reopen_epoch}. *)

val reopen_epoch : t -> epoch:Units.Epoch.t -> (t, write_error) result
(** [reopen_epoch t ~epoch] is the RESTART path, and the reason it is a
    separate name.

    A crash between an epoch-open frame becoming durable and the checkpoint
    beside it being republished leaves the store open at the new epoch while
    the checkpoint is still sealed at the old one. A resuming driver heals that
    skew and the shell re-runs its epoch opening, which a strictly advancing
    {!open_epoch} would refuse. This member returns [Ok t] unchanged, having
    written nothing, when [epoch] is ALREADY the open epoch and the durable
    epoch-open frame is byte-identical to the facts the store now states. In
    every other case, including a different epoch whose meta happens to match,
    it delegates to {!open_epoch} and inherits its refusal. *)

val durable_tip : t -> Consensus_block.Number.t option
(** The height of the last record that is on the device, or [None] when none
    is. It is the mirror's own tip, because the mirror holds nothing else. *)

val fsyncs : t -> int
(** How many flushes THIS HANDLE has performed since it opened. An accepted
    {!receive} costs exactly one; a refused one costs zero. Counted off the
    handle's own log, so concurrent [Tn_durable] IO elsewhere in the process —
    a checkpoint save, a second root — never inflates it. *)

val bytes_appended : t -> int
(** How many bytes this handle has appended since it opened, frame overhead
    included. A refused {!receive} appends none. The same handle-local basis
    as {!fsyncs}. *)

val close : t -> (unit, fault) result
(** [close t] closes the log and releases the root. Both are attempted even if
    the first fails, so a failed close never strands a root. *)
