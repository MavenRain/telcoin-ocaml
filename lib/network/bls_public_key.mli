(** A BLS public key exactly as it appears on the wire: 96 opaque bytes.

    Rust's [BlsPublicKeyBytes([u8;96])] reaches bcs through
    [serializer.serialize_bytes], so the wire form is the ULEB128 length [0x60]
    followed by 96 bytes (GT:170). The key is kept OPAQUE here rather than
    routed through {!Tn_crypto.Public_key}, because the crypto seam is
    swappable: the stub seam's key is 32 bytes wide, so binding this wire field
    to the seam would make the byte layout depend on which seam is linked. A
    consumer that needs group arithmetic converts explicitly, and the
    conversion is allowed to fail. *)

type t
(** A 96-byte key. Abstract, so the width is an invariant no caller can
    break. *)

val length : int
(** 96. *)

val of_bytes : string -> t option
(** [Some] only for an input of exactly {!length} bytes. *)

val to_bytes : t -> string
(** The 96 bytes, without the wire length prefix. *)

val codec : t Tn_codec.Bcs.t
(** The wire codec: ULEB128(96) then the 96 bytes. A prefix naming any other
    length is refused at its own offset rather than re-framed. *)

val equal : t -> t -> bool
val compare : t -> t -> int
(** Lexicographic over the bytes, which for a uniform width is also the order
    bcs sorts map keys by (see {!Tn_codec.Bcs.encoded_compare}). *)
