(** Collect votes on a proposed header until a quorum certifies it.

    A proposer, after broadcasting its own header, starts one aggregator and
    feeds it each vote as it arrives. Every author gets a single slot per header:
    the first vote seen from an author claims that slot, whether or not the vote
    then validates, so a peer cannot follow a rejected vote with another one.
    This mirrors the Rust [VotesAggregator], whose equivocation set is updated
    before the vote is checked. Only votes that pass validation are counted
    toward quorum. The moment the counted signers reach the committee's quorum
    threshold, the accumulated votes are turned into a
    {!Tn_vertex.Certificate.t}.

    One aggregator serves one proposal: the caller discards it once it yields a
    certificate and starts a fresh {!empty} for the next header.

    Errors are reported in {!Tn_vertex.Certificate.error} vocabulary, since a
    vote that fails here is exactly a vote that could not contribute to a
    certificate. A repeat vote from an author already seen is
    {!Tn_vertex.Certificate.Duplicate_voter}. *)

open Tn_types
open Tn_vertex

type t

val empty : t
(** A fresh aggregator, holding no votes. *)

val add :
  t -> Committee.t -> Header.t -> Vote.t ->
  t * (Certificate.t option, Certificate.error) result
(** Validate and accumulate one vote on [header]. The aggregator {e always}
    advances: a first-seen author is recorded even when the vote is then
    rejected, so the returned aggregator must be used rather than the argument.
    The result is [Ok (Some certificate)] whenever the counted signers reach
    quorum (so once past quorum every accepted vote yields a certificate, and the
    caller stops at the first), [Ok None] while still short of it, and
    [Error _] for a vote that is a repeat, for the wrong header, from a
    non-member, or badly signed. *)

val voters : t -> Authority_id.Set.t
(** The authors whose votes have been accepted (counted toward quorum) so far. *)
