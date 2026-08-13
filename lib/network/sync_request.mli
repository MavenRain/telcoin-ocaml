(** The two bulk-sync request types (crates/network-libp2p/src/sync/request.rs,
    GT:109-120), each carried inside {!Sync_frame.Req}.

    [PrimarySyncRequest]'s tag numbering is pinned upstream by
    [request_tags_are_stable] (request.rs:151-179), ported verbatim into
    test_network.ml. *)

open Tn_types

type worker =
  | Batches of {
      batch_digests : Digests.Batch_digest.t list;
          (** Rust's [BTreeSet<BlockHash>]: ascending and duplicate-free on
              encode, permissive on decode. bcs reads a sequence with no
              order or uniqueness check (de.rs:611-617) and Rust's
              [BTreeSet::deserialize] resorts and collapses, so refusing an
              unsorted request here would reject bytes every Rust node
              accepts. *)
      epoch : Units.Epoch.t;
    }  (** index 0, the worker's only sync request. *)

type primary =
  | Epoch_pack of { epoch : Units.Epoch.t }  (** index 0. *)
  | Missing_certificates of {
      exclusive_lower_bound : Round.t;
      skip_rounds : (Authority_id.t * string) list;
          (** Per authority, the roaring blob of rounds to skip, carried as
              opaque length-prefixed bytes exactly as Rust's [Vec<u8>]. *)
    }  (** index 1. *)
  | Epoch_pack_partial of { epoch : Units.Epoch.t; last_consensus_number : int64 }
      (** index 2. *)
  | Consensus_output of { number : int64 }  (** index 3. *)

val worker_codec : worker Tn_codec.Bcs.t
val primary_codec : primary Tn_codec.Bcs.t
val worker_equal : worker -> worker -> bool
val primary_equal : primary -> primary -> bool
