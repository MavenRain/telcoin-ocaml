(** A vote on a header.

    [author] signs a claim that [origin]'s header — and, transitively, the
    causal history the header's parents point to — is available. The signature
    is over the intent-wrapped header digest, exactly the Rust pre-image shape,
    so the same bytes are what a certificate later re-verifies in aggregate. *)

open Tn_types

type t

val sign : Tn_crypto.Secret_key.t -> voter:Authority_id.t -> Header.t -> t
(** Produce [voter]'s vote on a header, signing the intent-wrapped digest. *)

val signing_message : Digests.Header_digest.t -> string
(** The exact byte string a vote signs for a given header digest:
    [Intent.wrap Consensus_vote (digest bytes)]. Shared with certificate
    verification so the aggregate is checked against the very bytes signed. *)

val header_digest : t -> Digests.Header_digest.t
val round : t -> Round.t
val epoch : t -> Units.Epoch.t
val origin : t -> Authority_id.t  (** The header's author. *)
val author : t -> Authority_id.t  (** The voter. *)
val signature : t -> Tn_crypto.Signature.t

val verify : Tn_crypto.Public_key.t -> t -> bool
(** True when the vote's signature is [author]'s over this header digest. *)
