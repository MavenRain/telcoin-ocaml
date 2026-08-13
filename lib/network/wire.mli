(** The seam between the wire and [Tn_consensus.Node] (GT RC section 4;
    design 1c lines 152-173).

    [Node.command] and [Node.event] are NOT changed by chunk 44, and cannot
    be: this library sits above [tn_consensus] precisely so the pure Mealy
    machine stays where it is. What this module adds is the translation table
    a shim would otherwise write inline, plus an honest name for every wire
    surface that has no [Node] counterpart yet.

    Two asymmetries are the whole point of the module:

    - one [Node.command] can be several wire actions. [Broadcast_header] is
      one [Request] PER committee member, because Rust's [request_vote] is an
      N-way fan-out (certifier.rs:124,172, GT:494), and the fan-out target set
      is not carried in the command;
    - several wire surfaces are not [Node.event]s at all. The executor and
      epoch-manager layers they belong to are not ported (GT:499-501), so they
      surface as {!Not_a_node_event} with a named constructor rather than
      being silently dropped.

    The 2-round-trip [MissingParents] retry choreography stays in the shim
    (GT open question :512): this module ships {!retry_vote_request}, the
    second leg's message, and takes no position on who decides to send it. *)

open Tn_types

type outbound =
  | Publish of { topic : string; payload : string }
      (** A gossip publish: the topic string and the BCS payload bytes. *)
  | Request of { to_ : Authority_id.t; request : Primary_msg.request }
      (** One request-response leg to one peer. *)
  | Response of { response : Primary_msg.response }
      (** An answer on a channel the shim is already holding; the channel is
          shim state, so no addressee appears here (GT:503-508). *)
  | Local
      (** The command has no wire action at this layer: [Arm_timer] is a local
          timer and [Emit_committed] is local consensus output whose gossip
          publish happens downstream, in a layer this port has not reached
          (GT:498-499). *)

type unmapped =
  | Peer_exchange_request  (** [PrimaryRequest::PeerExchange]: peer manager. *)
  | Epoch_record_request  (** [PrimaryRequest::EpochRecord]: epoch manager. *)
  | Missing_parents_response
      (** [PrimaryResponse::MissingParents] arriving at the REQUESTER. Rust
          turns it into the second leg of the vote round trip
          (network/mod.rs:415, GT:496); [Node] has no event for it because the
          choreography is not in the pure core. *)
  | Epoch_record_response  (** [PrimaryResponse::EpochRecord]. *)
  | Peer_exchange_response  (** [PrimaryResponse::PeerExchange]. *)
  | Rpc_error_response  (** [PrimaryResponse::Error]. *)
  | Recoverable_rpc_error_response
      (** [PrimaryResponse::RecoverableError]. *)
  | Consensus_gossip
      (** [PrimaryGossip::Consensus]: the executor's subscriber layer
          (GT:499). *)
  | Epoch_vote_gossip  (** [PrimaryGossip::EpochVote]: the epoch manager. *)
  | Worker_batch_gossip  (** [WorkerGossip::Batch]: the worker layer. *)

type inbound_verdict =
  | Event of Tn_consensus.Node.event
      (** The message maps onto a [Node] event and can be fed to [step]. *)
  | Not_a_node_event of unmapped
      (** It does not, and this names which surface it belongs to. *)

type error =
  | Vote_ingress of Vote_wire.error
      (** A vote could not cross the wire boundary in either direction. *)
  | Certificate_ingress of Certificate_wire.error
      (** A certificate could not, most often because [to_checked] refused a
          claim that does not re-verify against the committee. *)
  | Gossip_decode of Gossip.error
      (** The topic was unknown here, or the payload did not decode. *)

val error_to_string : error -> string
(** A one-line rendering carrying the underlying module's own message. *)

val outbound_of_command :
  committee:Committee.t ->
  chain_id:int ->
  Tn_consensus.Node.command ->
  (outbound list, error) result
(** Translate one command into the wire actions it stands for.

    [Broadcast_header] fans out to one {!Request} per member of [committee],
    in committee order, with [parents = \[\]]: parents ride only the retry leg
    (certifier.rs:133-183, GT:494). [Broadcast_certificate] becomes a
    {!Publish} on [Gossip.primary_topic ~chain_id].

    It is fallible because two of the six commands carry a domain value that
    must be rendered as wire bytes, and the crypto seam's signature width is a
    property of the linked implementation rather than of the wire: a seam
    whose signatures are not the wire's 48 bytes says so here instead of
    encoding something else. *)

val retry_vote_request :
  header:Tn_vertex.Header.t ->
  parents:Certificate_wire.t list ->
  Primary_msg.request
(** The second leg of the vote round trip: the same [Vote] request with the
    parent certificates the peer said it was missing now attached
    (certifier.rs:133-183). Deciding to send it is the shim's, and the open
    question at GT:512 is which layer that shim belongs to. *)

val event_of_request :
  committee:Committee.t ->
  from_:Authority_id.t ->
  Primary_msg.request ->
  (inbound_verdict, error) result
(** An inbound request. [Vote] becomes [Node.Vote_request], its parents run
    through [Certificate_wire.to_checked committee] so nothing unverified
    enters the DAG layer; the other two are {!Not_a_node_event}. *)

val event_of_response :
  Primary_msg.response -> (inbound_verdict, error) result
(** An inbound response to a request we made. [Vote] becomes
    [Node.Vote_received]; the other five are {!Not_a_node_event}. *)

val event_of_gossip :
  committee:Committee.t ->
  chain_id:int ->
  topic:string ->
  string ->
  (inbound_verdict, error) result
(** An inbound gossip message, decoded by topic. [PrimaryGossip::Certificate]
    becomes [Node.Certificate_received] through
    [Certificate_wire.to_checked]; [Consensus], [EpochVote] and every worker
    payload are {!Not_a_node_event} (GT:499-501). *)
