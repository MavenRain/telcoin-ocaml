(** The primary's request-response and gossip messages
    (crates/consensus/primary/src/network/message.rs, GT:34-62).

    Three independent sums plus the standalone
    {!missing_certificates_request}. Variant order IS the BCS discriminant
    order, so the constructors below are listed in wire order and their
    indices are pinned by golden rows rather than by comment.

    Constructor names carry a per-type prefix ([Req_]/[Res_]/[Gossip_])
    because the three sums share concepts and OCaml would otherwise resolve a
    bare [Vote] by whichever type was defined last. *)

open Tn_types

type request =
  | Req_vote of {
      header : Tn_vertex.Header.t;
          (** Rust wraps it in [Arc], which serde treats transparently. *)
      parents : Certificate_wire.t list;
    }  (** index 0. *)
  | Req_peer_exchange of Peer_exchange.t  (** index 1. *)
  | Req_epoch_record of {
      epoch : Units.Epoch.t option;  (** [Option] tag then u32 LE. *)
      hash : Tn_crypto.Digest.t option;
          (** [Option] tag then ULEB128(32)+32B. *)
    }  (** index 2, the only surface with two independent Options (GT:40). *)

type response =
  | Res_vote of Vote_wire.t  (** index 0. *)
  | Res_missing_parents of Digests.Header_digest.t list  (** index 1. *)
  | Res_epoch_record of {
      record : Epoch_record.t;
      certificate : Epoch_certificate.t;
    }  (** index 2. *)
  | Res_peer_exchange of Peer_exchange.t  (** index 3. *)
  | Res_error of string  (** index 4, [PrimaryRPCError(String)]. *)
  | Res_recoverable_error of string  (** index 5. *)

type gossip =
  | Gossip_certificate of Certificate_wire.t
      (** index 0; Rust boxes it, which serde treats transparently. *)
  | Gossip_consensus of Consensus_result.t  (** index 1. *)
  | Gossip_epoch_vote of Epoch_vote.t  (** index 2. *)

type missing_certificates_request = private {
  exclusive_lower_bound : Round.t;  (** u32 LE. *)
  skip_rounds : (Authority_id.t * string) list;
      (** Per authority, an opaque length-prefixed blob. *)
  max_response_size : int64;
      (** Rust's [usize], which bcs writes as u64 LE, 8 bytes (GT:43). The
          port fixes the width rather than following the host word size. *)
}
(** message.rs:80-92, carried on its own and not as a {!request} variant. *)

val make_missing_certificates_request :
  exclusive_lower_bound:Round.t ->
  skip_rounds:(Authority_id.t * string) list ->
  max_response_size:int64 ->
  missing_certificates_request

val request_codec : request Tn_codec.Bcs.t
val response_codec : response Tn_codec.Bcs.t
val gossip_codec : gossip Tn_codec.Bcs.t
val missing_certificates_request_codec : missing_certificates_request Tn_codec.Bcs.t
val request_equal : request -> request -> bool
val response_equal : response -> response -> bool
val gossip_equal : gossip -> gossip -> bool
