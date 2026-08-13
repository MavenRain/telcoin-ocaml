(** A vote on a header.

    [author] signs a claim that [origin]'s header — and, transitively, the
    causal history the header's parents point to — is available. The signature
    is over the intent-wrapped header digest, exactly the Rust pre-image shape,
    so the same bytes are what a certificate later re-verifies in aggregate. *)

open Tn_types

type t

val sign : Tn_crypto.Secret_key.t -> voter:Authority_id.t -> Header.t -> t
(** Produce [voter]'s vote on a header, signing the intent-wrapped digest. *)

val claim :
  header_digest:Digests.Header_digest.t ->
  round:Round.t ->
  epoch:Units.Epoch.t ->
  origin:Authority_id.t ->
  author:Authority_id.t ->
  signature:string ->
  t option
(** Wire ingress: assemble a vote out of fields that arrived from a peer,
    WITHOUT verifying anything, the way [Batch.Sealed.claim] (batch.mli:106)
    pairs a batch with a claimed digest. Chunk 44's [Vote_wire] decoder is the
    only intended caller.

    [signature] is the crypto seam's own signature encoding, and the result is
    [None] when the seam refuses it, so no [Vote.t] can hold a signature field
    that is not a signature. That is the ONLY check: whether the signature is
    [author]'s over this digest stays with {!verify}, and a caller that skips
    {!verify} is holding an unverified claim by construction. *)

val signing_message : Digests.Header_digest.t -> string
(** The exact byte string a vote signs for a given header digest:
    [Intent.wrap Consensus_vote (0x20 :: digest bytes)], the BCS
    length-prefixed encoding of the digest ({!Tn_crypto.Digest.length} is 32,
    so this is 33 bytes), for 36 bytes total. Shared with certificate
    verification so the aggregate is checked against the very bytes signed. *)

val header_digest : t -> Digests.Header_digest.t
val round : t -> Round.t
val epoch : t -> Units.Epoch.t
val origin : t -> Authority_id.t  (** The header's author. *)
val author : t -> Authority_id.t  (** The voter. *)
val signature : t -> Tn_crypto.Signature.t

val verify : Tn_crypto.Public_key.t -> t -> bool
(** True when the vote's signature is [author]'s over this header digest. *)
