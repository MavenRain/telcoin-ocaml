(** The pure gossipsub statics (GT RD sections 1-4).

    Chunk 44 ships the topic strings, the application-level size cap, the
    message-id rule, the publisher allowlist lookup, and the two pure
    decisions the acceptance pipeline makes on top of them ({!verify} and
    {!penalty}). The mesh runtime, scoring, heartbeats and the
    [MessageAuthenticity::Signed] envelope are deferred (design section 6),
    and so is everything {!penalty} names: applying a [Penalty::Fatal] is the
    peer manager's job, and the peer manager is not ported. *)

val max_gossip_message_size : int
(** 12_000 (crates/config/src/network.rs:117, GT:569). An
    application-level cap, stricter than libp2p's own 65536, enforced on
    publish and on receive. Identical on every honest node by design, so it is
    a constant here and not a parameter. *)

val primary_topic : chain_id:int -> string
(** ["tn-primary-{chain_id}"], where certificates are gossiped (GT:528). *)

val consensus_output_topic : chain_id:int -> string
(** ["tn-consensus-output-{chain_id}"] (GT:529). *)

val epoch_vote_topic : chain_id:int -> string
(** ["tn-epoch-vote-{chain_id}"] (GT:530). *)

val worker_batch_topic : chain_id:int -> string
(** ["tn-worker-{chain_id}"] (GT:531). Note it carries the CHAIN id, not a
    worker id. *)

type topic_kind =
  | Primary_certificate  (** {!primary_topic}: a [PrimaryGossip]. *)
  | Consensus_output  (** {!consensus_output_topic}: a [PrimaryGossip]. *)
  | Epoch_vote  (** {!epoch_vote_topic}: a [PrimaryGossip]. *)
  | Worker_batch  (** {!worker_batch_topic}: a [WorkerGossip]. *)

val topic_of_kind : chain_id:int -> topic_kind -> string
val topic_kind : chain_id:int -> string -> topic_kind option
(** The keyed lookup behind {!decode}: [None] for a topic this node does not
    speak. Topics are [IdentTopic]s, so the hash IS the string (GT:533) and no
    hashing happens here. *)

type payload =
  | Primary_payload of Primary_msg.gossip
      (** The three primary topics all carry [PrimaryGossip], and which
          variant is legitimate on which topic is a publisher-side rule, not a
          codec rule. *)
  | Worker_payload of Worker_msg.gossip

type error =
  | Unknown_topic of { topic : string }  (** No {!topic_kind} matched. *)
  | Bcs of Tn_codec.Bcs.error  (** The payload did not decode. *)

val error_to_string : error -> string

val decode : chain_id:int -> topic:string -> string -> (payload, error) result
(** Dispatch on the topic, then decode with that topic's codec. *)

val message_id : source:string option -> sequence_number:int64 option -> string
(** The default message id of libp2p-gossipsub 0.49.4, which Telcoin does not
    override (GT:565): base58 of the source peer id, or of the fallback bytes
    [00 01 00] when the message carries no source, followed by the DECIMAL
    sequence number, or [0] when it carries none. No hash of the data enters
    it.

    The sequence number is a Rust [u64]. The [int64] carrier here renders
    UNSIGNED: a signed rendering agrees with Rust only below 2^63, and a peer
    is free to choose a sequence number above that, so signed formatting would
    split the duplicate-detection cache between this port and every Rust peer.
    The stage-0 harness rows include 2^63 and [u64::MAX] for exactly this
    reason. *)

type publishers =
  | Open  (** Rust's [Some(None)]: subscribed, any publisher allowed. *)
  | Restricted of Bls_public_key.t list
      (** Rust's [Some(Some(set))]: only these BLS keys may publish. *)

val publisher_allowed :
  authorized:(string * publishers) list ->
  topic:string ->
  source:string option ->
  author:Bls_public_key.t option ->
  bool
(** The allowlist rule of consensus.rs:1590-1600 (GT:537-540). [source] is the
    message's own peer id, and [gossip.source.is_some_and(..)] wraps the WHOLE
    rule, so a message carrying no source is refused before the topic is even
    looked up, an {!Open} topic included. Given a source: a topic absent from
    [authorized] is not subscribed here and is rejected; an {!Open} topic
    accepts anything; a {!Restricted} one accepts only a RESOLVED author, the
    BLS key that source maps to, in its set, so an unresolved author ([None])
    is rejected. All four production topics are restricted (GT:541). *)

type reject_reason =
  | Too_large  (** The payload passed {!max_gossip_message_size}. *)
  | Unauthorized_author
      (** The author is not an allowed publisher on this topic, or did not
          resolve to a BLS key at all. *)

type acceptance =
  | Accept  (** Forward to the mesh and deliver to the application. *)
  | Reject of reject_reason
      (** Drop. Rust's [MessageAcceptance] conversion never produces [Ignore]
          (consensus.rs:2240-2245, GT:599), so there is no third constructor
          here either. *)

type penalty_target =
  | Fatal_relayer
      (** Ban the peer that RELAYED the message. An honest relayer under
          [ValidationMode::Strict] would not have forwarded it (GT:602). *)
  | Fatal_author  (** Ban the AUTHOR, never the relayer (GT:603). *)
  | Skip
      (** The accountable peer's BLS identity did not resolve, so no penalty
          is applied at all (GT:604). *)

val verify :
  data_len:int ->
  topic:string ->
  source:string option ->
  author:Bls_public_key.t option ->
  authorized:(string * publishers) list ->
  acceptance
(** [verify_gossip] (consensus.rs:1580-1605, GT:595-597), the two checks in
    Rust's order: SIZE FIRST, then author authorization. The order is
    observable, because an oversized message from an unauthorized author
    penalises the relayer rather than the author, and swapping the checks
    would move the ban. *)

val penalty :
  reject_reason -> relayer_resolved:bool -> author_resolved:bool -> penalty_target
(** [RejectReason::penalty] (consensus.rs:1872-1886, GT:601-604). Each reason
    has exactly one accountable peer, and when THAT peer's identity is
    unresolved the answer is {!Skip}: the other peer's resolution never
    substitutes for it. *)
