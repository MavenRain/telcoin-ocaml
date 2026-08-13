(** The worker's request-response and gossip messages
    (crates/consensus/worker/src/network/message.rs, GT:70-89).

    Two facts these codecs pin, both easy to get wrong:
    - [WorkerResponse::ReportBatch] is a UNIT variant, so its whole encoding
      is the bare tag byte [0x00] with no payload;
    - [WorkerGossip::Batch] carries a [BlockHash], which is an alloy
      [FixedBytes<32>] and therefore LENGTH-PREFIXED: [0x20] then 32 bytes,
      not a bare 32 (GT:87). *)

open Tn_types

type request =
  | Wreq_report_batch of Batch.Sealed.t  (** index 0. *)
  | Wreq_peer_exchange of Peer_exchange.t  (** index 1. *)

type response =
  | Wres_report_batch of unit  (** index 0, the unit variant: a bare tag. *)
  | Wres_peer_exchange of Peer_exchange.t  (** index 1. *)
  | Wres_error of string  (** index 2, [WorkerRPCError(String)]. *)
  | Wres_recoverable_error of string  (** index 3. *)

type gossip =
  | Wgossip_batch of {
      epoch : Units.Epoch.t;  (** u32 LE. *)
      block_hash : Digests.Batch_digest.t;  (** ULEB128(32) then 32 bytes. *)
    }  (** index 0, a tuple variant in Rust. *)

val request_codec : request Tn_codec.Bcs.t
val response_codec : response Tn_codec.Bcs.t
val gossip_codec : gossip Tn_codec.Bcs.t
val request_equal : request -> request -> bool
val response_equal : response -> response -> bool
val gossip_equal : gossip -> gossip -> bool
