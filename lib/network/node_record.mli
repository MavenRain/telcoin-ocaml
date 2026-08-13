(** [NodeRecord] (crates/network-libp2p/src/types.rs:846-855, GT:132-139):
    the signed value a node publishes into the Kademlia DHT.

    Only the CODEC and the compatibility predicate are ported. The Kademlia
    runtime is deferred (design section 6), and so is
    [NodeRecord::build]'s signing payload: GT:132 does not pin what
    [build]/[verify] sign, so this module never signs and never verifies.

    THE LEGACY LAYOUT. A pre-upgrade peer wrote [NetworkInfo] without its
    trailing [rpc] field (types.rs:864-880). The two layouts hold the same
    values here: a legacy record is one whose [rpc] is [None], and the
    difference is which bytes were on the wire, which {!record_or_legacy}
    reports. The comment at types.rs:928-938 observes that the layouts are
    BCS-distinguishable, because a current record ends in an [Option] tag
    [0x00]/[0x01] while a legacy one ends in the [0x30] ULEB128 length of its
    48-byte signature. That observation is DOCUMENTATION only: like Rust's
    [try_decode_compat], {!decode_compat} tries the current layout and falls
    back to the legacy one, and never inspects the last byte. *)

type rpc_info = private {
  http : string;  (** A [url::Url], serialized as a String (GT:136). *)
  ws : string option;  (** The websocket URL, if the node serves one. *)
}

type network_info = private {
  pubkey : Var_bytes.t;  (** [NetworkPublicKey], protobuf bytes (GT:172). *)
  multiaddrs : Var_bytes.t list;  (** The node's dialable addresses. *)
  timestamp : int64;  (** [TimestampSec], u64 LE. *)
  rpc : rpc_info option;  (** Absent on every legacy record. *)
}

type t = private {
  info : network_info;
  signature : Bls_signature.t;  (** Never checked here; see above. *)
}

type record_or_legacy =
  | Current of t  (** The bytes carried the [rpc] Option tag. *)
  | Legacy of t  (** The bytes stopped before it; [rpc] is [None]. *)

type error =
  | Both_layouts_rejected of {
      current : Tn_codec.Bcs.error;  (** Why the current layout failed. *)
      legacy : Tn_codec.Bcs.error;  (** Why the legacy fallback failed. *)
    }

val error_to_string : error -> string
val make_rpc_info : http:string -> ws:string option -> rpc_info

val make_network_info :
  pubkey:Var_bytes.t ->
  multiaddrs:Var_bytes.t list ->
  timestamp:int64 ->
  rpc:rpc_info option ->
  network_info

val make : info:network_info -> signature:Bls_signature.t -> t

val codec : t Tn_codec.Bcs.t
(** The current layout: pubkey, addresses, timestamp, the [rpc] Option, then
    the signature. *)

val legacy_codec : t Tn_codec.Bcs.t
(** The pre-upgrade layout, which has NO [rpc] field. Encoding a record whose
    [rpc] is [Some] through this codec DROPS that field, because a
    pre-upgrade peer had no way to express it; use {!codec} for anything a
    current peer will read. Decoding always yields [rpc = None]. *)

val decode_compat : string -> (record_or_legacy, error) result
(** Rust's [try_decode_compat] (types.rs:942-967): the current layout first,
    the legacy layout second, and the errors of BOTH attempts when neither
    parses. *)

val equal : t -> t -> bool
