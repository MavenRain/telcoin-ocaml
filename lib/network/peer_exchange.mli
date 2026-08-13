(** [PeerExchangeMap] (crates/network-libp2p/src/peers/types.rs:168-169,
    GT:175-176): the map a peer sends on the goodbye protocol, from a BLS
    identity to that peer's network key and addresses.

    CANONICAL ON THE WIRE, despite being a Rust [HashMap]. bcs 0.1.6's map
    serializer sorts and deduplicates entries by ENCODED KEY BYTES
    (ser.rs:545-546) and its deserializer rejects any key that is not strictly
    greater than its predecessor, [NonCanonicalMap] (de.rs:765-767). Both
    polarities were reproduced against the pinned crate in stage 0
    (verified-facts.md section 3), so GT:26 and GT:176 are wrong on this point
    and this module follows the crate: encoding sorts, decoding refuses
    unsorted and duplicate keys.

    The inner address collection is a [HashSet], which bcs writes as a plain
    sequence with NO order or uniqueness check on decode (de.rs:611-617). It
    is therefore kept in the order it arrived, with duplicates collapsed the
    way Rust's [HashSet] collapses them on collect. *)

type entry = private {
  key : Bls_public_key.t;  (** The peer's BLS identity, the map key. *)
  network_key : Var_bytes.t;  (** [NetworkPublicKey], protobuf bytes (GT:172). *)
  multiaddrs : Var_bytes.t list;  (** Opaque multiaddrs, first occurrence order. *)
}

type t
(** A canonical map. Abstract: the ascending, duplicate-free key order is the
    invariant that makes {!codec} reproduce Rust's bytes. *)

type error =
  | Duplicate_key
      (** Two entries handed to {!of_entries} share a key; bcs would silently
          drop one, so the port refuses instead. *)

val error_to_string : error -> string

val make_entry :
  key:Bls_public_key.t ->
  network_key:Var_bytes.t ->
  multiaddrs:Var_bytes.t list ->
  entry
(** Deduplicates [multiaddrs], keeping first-occurrence order. *)

val empty : t
(** The empty map, one [0x00] byte on the wire. *)

val of_entries : entry list -> (t, error) result
(** Sorts by encoded key bytes. A duplicate key is {!Duplicate_key}. *)

val entries : t -> entry list
(** In encoded-key-byte order, which is the order {!codec} writes. *)

val codec : t Tn_codec.Bcs.t
(** ULEB128 entry count, then per entry the 96-byte key and the pair of the
    network key and the address sequence. Decoding rejects a non-strictly
    increasing key sequence, duplicates included. *)

val equal : t -> t -> bool
