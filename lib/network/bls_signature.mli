(** A BLS signature exactly as it appears on the wire: 48 opaque bytes.

    Rust's [BlsSignature] serializes as [serialize_bytes] over the 48-byte
    compressed blst min_sig point, so the wire form is the ULEB128 length
    [0x30] then 48 bytes (GT:171). That [0x30] is also what makes a legacy
    [NodeRecord] distinguishable from a current one (GT:139).

    Opaque for the same reason as {!Bls_public_key}: the port's crypto seam is
    swappable and its signature width is a property of the linked seam, not of
    the wire. {!Certificate_wire} and {!Vote_wire} convert to the seam's own
    type at the ingress boundary, where a refusal is a named error. *)

type t
(** A 48-byte signature. Abstract, so the width is an invariant. *)

val length : int
(** 48. *)

val of_bytes : string -> t option
(** [Some] only for an input of exactly {!length} bytes. *)

val to_bytes : t -> string
(** The 48 bytes, without the wire length prefix. *)

val codec : t Tn_codec.Bcs.t
(** The wire codec: ULEB128(48) then the 48 bytes. *)

val equal : t -> t -> bool
val compare : t -> t -> int
