(** What driving committed consensus output leaves a shell holding (D6): one
    module, one vocabulary, so the two terminal shapes of a fold cannot be
    paired up wrongly (design patch P2).

    An {!advance} is the durable unit: the minted consensus block, the attached
    output and every execution block it produced travel TOGETHER, because
    telcoin persists the consensus block first ([state-sync/src/lib.rs:106-121])
    and then commits the whole output's blocks plus markers in one transaction
    ([tn-reth/src/lib.rs:1019-1030]); two separate returns would let a caller
    persist a block against the wrong output. [blocks] may legitimately be
    empty while the chain still advanced: telcoin executes nothing for an
    empty non-closing output yet the leader count and the consensus chain both
    move ([payload_builder.rs:99-114]).

    {!t}'s halted arm deliberately carries NO driver: after a terminal error
    there is nothing to resume, so "resume after an error" is unrepresentable
    rather than merely discouraged (the fail-stop commitment; telcoin halts
    the engine task in process with no retry arm,
    [executor/src/subscriber.rs:588-605]).  The epoch seal is NOT such an
    error: upstream a boundary-crossing output is routine control flow (the
    subscriber merely marks the epoch done, [subscriber.rs:362], and
    [run_epoch.rs:142] re-enters), so a fold that meets the seal mid-stream
    returns the {!Sealed} arm - the sealed driver, the executed prefix and
    the unconsumed suffix - because the driver it carries is exactly what
    [Driver.begin_epoch] needs to resume the chain. *)

(** One successfully executed output: what a shell persists. *)
type advance = {
  consensus : Tn_execution.Consensus_block.t;
      (** The block minted for this output by the consensus-chain fold. *)
  output : Tn_batch.Output.t;
      (** The attached output the engine consumed, carrying that same minted
          block ({!Tn_batch.Output.consensus}). *)
  blocks : Tn_engine.Executed_block.t list;
      (** The execution blocks the output produced, in chain order; possibly
          empty (an empty non-closing output executes nothing). *)
  closes_epoch : bool;
      (** Whether this output's closing block sealed the epoch: the engine's
          phase read back AFTER the execute, never a flag threaded into it. *)
}

(** Everything one step can fail on. Every arm is terminal: none of them
    returns a driver, so an engine that survived its own error is
    unconstructible from this type. *)
type error =
  | Receive of Subscriber.error
      (** Minting-and-attaching refused the output: a body the store could
          not supply, or an author the address table could not resolve. *)
  | Execute of Tn_engine.Engine.error
      (** The engine refused or failed the attached output. The arm's TYPE is
          the whole engine error surface - nothing in this library prunes it
          (P12) - but through [Driver.step] it carries exactly what
          [Tn_engine.Engine.execute] can return; [Boundary_not_advanced] is
          minted only by [Tn_engine.Engine.begin_epoch], and a driver caller
          meets that refusal as [Driver.begin_epoch]'s own [Engine_refused]
          arm, never here. The engine's boundary comparison is against the
          closing commit time on a sealed engine and against the installed
          boundary on a running one ([Tn_engine.Engine.begin_epoch]'s
          frontier), which is why no arm of this type is claimed
          unreachable. *)
  | Epoch_mismatch of {
      installed : Tn_types.Units.Epoch.t;
          (** The installed committee's epoch. *)
      output : Tn_types.Units.Epoch.t;
          (** The refused output's leader epoch. *)
    }
      (** The output's leader epoch is not the installed committee's epoch -
          the per-output analogue of TN's hard [InvalidPackEpoch] refusal
          ([storage/src/consensus.rs:732-765], H8): a stale (or premature)
          output must never execute under a committee it was not committed
          by, because the executed block's gas cap and the credited leader
          are both functions of the output's own epoch. The driver refuses
          BEFORE minting, so a refused output consumes no consensus
          number. *)
  | Sealed_needs_handoff
      (** The epoch has sealed: the closing block is already built, and the
          epoch handoff ([Driver.begin_epoch]) is owed before any further
          output. The DRIVER refuses, without consulting the engine: it tests
          its own phase rather than discovering the seal through the engine's
          [Epoch_sealed] refusal, exactly as the engine's .mli instructs its
          caller to (obligation 9; the engine deliberately leaves its own
          [begin_epoch] unguarded, H12, so this guard is the driver's to own).
          Unlike its siblings this arm is a demand rather than a defect, and
          only [Driver.step] surfaces it - the pre-step driver the caller
          already holds IS the sealed driver, and [Driver.begin_epoch] on it
          resumes the chain. [Driver.fold] never wraps it into {!Halted}: the
          fold stops BEFORE the sealed step and returns {!Sealed}, which
          carries the driver this arm's caller was promised to be holding. *)

val error_to_string : error -> string
(** Human rendering, delegating to the failing layer's own renderer. *)

(** The one value a fold returns. ['driver] is the driver's own type,
    abstract here because the driver sits above this module; the halted arm
    has no field of that type AT ALL, which is the compile-time fact the
    fail-stop tests lean on. The sealed arm DOES carry the driver, because a
    seal is a demand, not a defect: what it demands ([Driver.begin_epoch]) is
    a function of the sealed driver, so a sealed arm without one would make
    the demanded handoff unperformable from a fold's return value. *)
type 'driver t =
  | Advance of {
      driver : 'driver;  (** The driver after the last folded output. *)
      advances : advance list;
          (** Every output's {!advance}, in fold order. *)
    }
      (** Every output folded and the epoch still running; the caller may
          keep going. *)
  | Sealed of {
      driver : 'driver;
          (** The SEALED driver: the one [Driver.begin_epoch] resumes. *)
      advances : advance list;
          (** The executed prefix, in fold order; its last advance is the
              epoch-closing one ([closes_epoch = true]) unless the fold's
              INPUT driver was already sealed, in which case this is [[]]. *)
      rest : Tn_consensus.Sub_dag.t list;
          (** The unconsumed suffix, in input order: what to fold after the
              handoff. Possibly [[]] - a stream whose LAST output closes the
              epoch still returns this arm, so "handoff owed" has exactly one
              representation. *)
    }
      (** The epoch sealed mid-stream: the handoff is owed before the rest
          ([subscriber.rs:362] marks the epoch done and [run_epoch.rs:142]
          re-enters - routine control flow, never a halt). *)
  | Halted of {
      advances : advance list;
          (** The contiguous prefix that DID execute, in fold order - the
              last of these is the watermark a restarted node resumes from. *)
      error : error;  (** What the first failing output failed on. *)
    }
      (** A terminal error: the good prefix and the error, and deliberately
          no driver. *)
