(** Stable validator identity.

    An authority's id is the protocol hash of its compressed public key (Rust:
    [blake3] of the 96-byte BLS key). It is a stable 32-byte handle whose
    byte-wise ordering drives every deterministic committee traversal — leader
    election indexes the id-sorted authority list, and certificate signer
    bitmaps are indexed in id order. *)

type t

val zero : t
(** The all-zero identifier (Rust [AuthorityIdentifier::default()]). Not a
    real committee member; used as a total default when reconstructing an id
    from a fixed-width byte field. *)

val of_public_key : Tn_crypto.Public_key.t -> t
val to_bytes : t -> string

val of_bytes : string -> t option
(** [Some] only for exactly 32 bytes. *)

val to_hex : t -> string
val equal : t -> t -> bool
val compare : t -> t -> int

module Map : Map.S with type key = t
module Set : Set.S with type elt = t
