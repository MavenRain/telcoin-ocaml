(** The libp2p protocol identifier strings (GT:656-670).

    Every one is chain-id namespaced, so two chains can never negotiate a
    shared substream, and every one is built through {!owned_protocol}, which
    is where Rust turns a malformed name into [NetworkError::ProtocolError]
    instead of panicking (types.rs:166-168).

    Only the STRINGS are ported. The upgrade flow, the behaviours that
    advertise them and their timeouts are deferred (design section 6). *)

type node =
  | Primary  (** The primary's own protocols. *)
  | Worker of int  (** A worker's protocols, namespaced by worker id. *)

type error =
  | Missing_leading_slash of { name : string }
      (** libp2p requires a protocol name to start with ['/']. *)

val error_to_string : error -> string

val owned_protocol : string -> (string, error) result
(** The gate every builder below passes through. *)

val req_res_protocol : node:node -> chain_id:int -> (string, error) result
(** The consensus RPC protocol, version [/0.0.2]: it is the ONE protocol the
    #739 legacy-variant deletion bumped, because that deletion shifted BCS
    discriminants (GT:670). *)

val kad_protocol : node:node -> chain_id:int -> (string, error) result
(** The Kademlia protocol, version [/0.0.1]. *)

val sync_protocol : node:node -> chain_id:int -> (string, error) result
(** The bulk-sync stream protocol, version [/0.0.1]. *)

val peer_exchange_protocol : node:node -> chain_id:int -> (string, error) result
(** The dedicated goodbye protocol, version [/0.0.1]. *)

val gossip_protocol_id_prefix : chain_id:int -> string
(** ["/tn-meshsub-{chain_id}"]. The gossipsub builder appends its own
    ["/1.1.0"] and ["/1.0.0"], so this one carries no version and cannot
    fail. *)
