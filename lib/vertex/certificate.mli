(** Quorum certificates — the "illegal states unrepresentable" module.

    A {!t} exists only through {!assemble}, {!genesis}, or {!check}. Each of
    those establishes that a quorum of committee stake validly signed the
    header, so possessing a [Certificate.t] is itself the proof of validity.
    Rust's five-state [SignatureVerificationState] enum and its [is_verified()]
    gate have no counterpart here: an unverified certificate is simply not a
    value of this type. The only distinction the type keeps is genesis, which
    carries no signatures by protocol definition. *)

open Tn_types

type t

type error =
  | Empty  (** No votes supplied to {!assemble}. *)
  | Wrong_header  (** A vote references a different header digest. *)
  | Unknown_voter  (** A voter is not a committee member. *)
  | Duplicate_voter  (** Two votes from the same authority. *)
  | Bad_signature  (** A vote's signature does not verify. *)
  | Not_enough_stake  (** Signers fall short of the quorum threshold. *)

val error_to_string : error -> string

val assemble : Committee.t -> Header.t -> Vote.t list -> (t, error) result
(** Certify a header from its votes. Checks, in order, that every vote is for
    this header, from a distinct committee member, with a valid signature, and
    that the signers reach {!Committee.quorum_threshold}; only then are the
    signatures aggregated into a certificate. *)

val genesis : Committee.t -> t list
(** The genesis certificates: one round-0 header per authority, unsigned by
    protocol definition. The DAG is seeded with these. *)

val check : Committee.t -> t -> (unit, error) result
(** Re-verify a certificate against a committee, as would be done for one
    received over the wire. Genesis certificates always pass. *)

val header : t -> Header.t
val digest : t -> Digests.Header_digest.t  (** The certified header's digest. *)
val round : t -> Round.t
val epoch : t -> Units.Epoch.t
val origin : t -> Authority_id.t  (** The header's author. *)
val signers : t -> Authority_id.Set.t

val aggregate_signature : t -> Tn_crypto.Aggregate.t option
(** The aggregated quorum signature this certificate was assembled from; [None]
    exactly for genesis certificates, which are unsigned by protocol definition.
    Feeds the committed sub-DAG's randomness value. *)

val is_genesis : t -> bool

val equal : t -> t -> bool
(** By certified-header digest. *)

val compare : t -> t -> int
