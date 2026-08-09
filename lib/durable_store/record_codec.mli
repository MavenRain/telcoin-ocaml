(** The payload codec for a durable consensus record, and for the epoch meta a
    frame carries beside it.

    This is the whole of the storage chunk's Tier-A wire: what a durable frame's
    payload bytes mean. It touches no filesystem, so every rule about what a
    reader may and may not trust is decided here, before a descriptor exists.

    One rule runs through all of it. A field a reader can re-derive is never
    read from the byte stream: the consensus block's digest, the sub-DAG's
    digest and the record's body ordering and multiplicity are all recomputed
    from the decoded fields, so no byte sequence can install a value whose
    cached parts disagree with the parts they summarise. *)

(** Why a payload is not the value it claims to be. Three diagnoses, kept apart
    because each names a different layer: the bytes, the frame's length, and
    the chain rules the decoded parts have to satisfy. *)
type error =
  | Bcs of Tn_codec.Bcs.error
      (** The byte stream is not a well-formed encoding of the wire shape. *)
  | Trailing of { left : int }
      (** The wire shape decoded, but [left] bytes of the payload were left
          over. A canonical encoding admits none, and a frame whose payload is
          longer than its content is a different frame. *)
  | Rebuild of Tn_execution.Consensus_store.Record.error
      (** Lifted {!Tn_execution.Consensus_store.Record.Missing_body}: the
          decoded bodies do not cover the block's own [payload_digests], so the
          record is refused rather than silently accepted with bodies that
          disagree with its header. *)

val error_to_string : error -> string
(** Human rendering; digests render as lowercase hex. *)

val encode_record : Tn_execution.Consensus_store.Record.t -> string
(** The record as payload bytes: the consensus block, then the bodies in the
    commit order the record already holds them in. *)

val decode_record :
  string -> (Tn_execution.Consensus_store.Record.t, error) result
(** Decodes [(Consensus_block.t * Batch.t list)], indexes the bodies by
    [Batch.digest], then rebuilds through
    {!Tn_execution.Consensus_store.Record.of_wire}. Multiplicity and commit
    order are therefore RE-DERIVED from the sub-DAG at every read, never
    trusted from the byte stream, and a body list that cannot cover the block's
    payload digests decodes to {!Rebuild} rather than to a record. A payload
    with bytes left over is {!Trailing}. *)

(** The epoch facts a frame states beside its record.

    A CROSS-CHECK, never a source of truth. Replay re-derives the epoch facts
    from the tip exactly as the store's own [open_epoch] does and compares;
    disagreement is a fault at the layer above. No epoch record is
    reintroduced. *)
module Meta : sig
  type t = {
    epoch : Tn_types.Units.Epoch.t;  (** The epoch this frame opens. *)
    epoch_start : Tn_execution.Consensus_block.Number.t;
        (** The height the epoch starts at. *)
    epoch_parent : Tn_types.Digests.Output_digest.t;
        (** The digest the epoch's first block links to. *)
  }
  (** Transparent on purpose: this is a stated triple to be compared against a
      re-derivation, not a value with an invariant to protect. *)

  val encode : t -> string
  (** The three fields as payload bytes. *)

  val decode : string -> (t, error) result
  (** The inverse. {!Trailing} on leftover bytes, {!Bcs} on a malformed one;
      {!Rebuild} cannot occur here. *)

  val equal : t -> t -> bool
  (** Field-wise. *)
end
