(** Collect certificates for one round until a quorum of parents is available.

    As certificates for a round arrive, the proposer needs to know when enough of
    them ({b 2f+1} by stake) exist to serve as the parents of a header in the
    next round. One aggregator tracks one round and releases parents once quorum
    is reached.

    Two behaviours are carried over from the Rust [CertificatesAggregator] and
    matter for liveness:

    - {b the weight never resets}. After quorum is first reached, later
      certificates from authors not yet counted keep raising the weight, and each
      one releases again. This is deliberate: if the proposer has not yet
      advanced the round, a straggler certificate must still reach it.
    - {b a repeat author is ignored}, not an error. A second certificate from an
      author already counted (equivocation or a simple resend) leaves the
      aggregator unchanged and releases nothing, even after quorum.

    Each release carries only the certificates accumulated {e since the previous
    release}, and that buffer is then drained, exactly like the Rust [drain(..)].
    The proposer appends successive releases to the parents it holds for the
    round (it does not re-collect a full set each time), so the delta is what it
    expects; a cumulative re-release would double-count a parent's stake there. *)

open Tn_std
open Tn_types
open Tn_vertex

type t

val empty : t
(** A fresh aggregator for one round, holding no certificates. *)

val add : t -> Committee.t -> Certificate.t -> t * Certificate.t Nonempty.t option
(** Add one certificate (already known to be for this round). The returned option
    is [Some delta] whenever the accumulated authors reach quorum, carrying the
    certificates buffered since the previous release, and [None] otherwise,
    including when the certificate's author was already counted. *)

val pending : t -> Certificate.t list
(** The certificates buffered since the last release, in arrival order. Empty
    right after a release. *)

val reached_quorum : t -> Committee.t -> bool
(** Whether the accumulated authors already reach the committee's quorum. *)
