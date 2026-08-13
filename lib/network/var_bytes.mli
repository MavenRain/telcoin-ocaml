(** A variable-length opaque byte field: ULEB128 length then the bytes.

    Two wire types take this shape and neither is traced any further by the
    chunk-44 ground truth: [NetworkPublicKey], whose serde writes the
    protobuf encoding of a libp2p key (GT:172), and [Multiaddr], which GT:136
    records as "not traced further". Modelling them as opaque bytes keeps the
    port byte-exact without importing libp2p's structure; a later chunk that
    needs multiaddr parsing can refine this type without changing the layout.

    The stage-0 harness note records this as an ASSUMPTION for [Multiaddr]
    rather than a verified fact (verified-facts.md section 7), so the golden
    rows keep multiaddr contents to bytes the harness itself produced. *)

type t
(** Opaque bytes of any length. *)

val of_bytes : string -> t
(** Total: every byte string is a valid field value. *)

val to_bytes : t -> string
val codec : t Tn_codec.Bcs.t
(** ULEB128 length then the raw bytes, the layout of {!Tn_codec.Bcs.bytes}. *)

val equal : t -> t -> bool
val compare : t -> t -> int
