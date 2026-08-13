(** [Vote] exactly as Rust puts it on the wire
    (crates/types/src/primary/vote.rs:13-27, GT:152): six plain fields, no
    attributes.

    The port's {!Tn_vertex.Vote} has no codec, because until chunk 44 no
    layer of the port put a vote on a wire; its only constructor is [sign].
    This module supplies the codec and the ingress: {!to_vote} runs the
    claim-style constructor added to lib/vertex, and {!to_verified} runs
    [Vote.verify] on top, so a caller that wants a vote it can trust has one
    call that gives it. *)

open Tn_types

type t
(** A decoded wire vote: a claim, verified by nobody yet. *)

type error =
  | Signature_rejected
      (** The crypto seam refused the 48 wire bytes as one of its own
          signature encodings, or refused to render its signature as 48. The
          blst seam agrees with the wire at 48 bytes; the stub seam does
          not, and says so here rather than silently reframing. *)
  | Does_not_verify
      (** The signature is not the author's over this header digest. *)

val error_to_string : error -> string

val make :
  header_digest:Digests.Header_digest.t ->
  round:Round.t ->
  epoch:Units.Epoch.t ->
  origin:Authority_id.t ->
  author:Authority_id.t ->
  signature:Bls_signature.t ->
  t

val header_digest : t -> Digests.Header_digest.t
val round : t -> Round.t
val epoch : t -> Units.Epoch.t

val origin : t -> Authority_id.t
(** The header's author. *)

val author : t -> Authority_id.t
(** The voter. *)

val signature : t -> Bls_signature.t

val codec : t Tn_codec.Bcs.t
(** The digest LENGTH-PREFIXED (ULEB128(32)+32B), round and epoch as u32 LE,
    both authority identifiers as 32 BARE bytes, then the 48-byte signature
    with its own prefix. *)

val to_vote : t -> (Tn_vertex.Vote.t, error) result
(** The ingress, through [Vote.claim]: no verification, exactly like Rust's
    decoder. *)

val to_verified :
  Tn_crypto.Public_key.t -> t -> (Tn_vertex.Vote.t, error) result
(** {!to_vote} followed by [Vote.verify] against the author's key. *)

val of_vote : Tn_vertex.Vote.t -> (t, error) result
(** The other direction. Fails when the seam's signature encoding is not the
    wire's 48 bytes. *)

val equal : t -> t -> bool
