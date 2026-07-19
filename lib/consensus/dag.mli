(** The consensus DAG: certificates indexed by round and author.

    This is the port of the certificate-storage half of Rust's [ConsensusState]
    (the Bullshark commit bookkeeping, [last_committed_sub_dag] and the ordering
    machinery, arrives with the commit rule). The store is a
    [Round.Map] of [Authority_id.Map] of {!Tn_vertex.Certificate.t}, the direct
    analogue of the Rust
    [BTreeMap<Round, HashMap<AuthorityIdentifier, (HeaderDigest, Certificate)>>],
    with a second index from header digest to certificate so parent links and
    (later) the commit traversal resolve in log time rather than by scanning.

    Three invariants are enforced on every insert, matching the Rust node:

    - {b one certificate per (round, author)}: a second, different certificate
      for a slot already taken is equivocation and is rejected. Re-inserting the
      same certificate is idempotent.
    - {b parents must exist}: past the genesis band, every parent digest a
      certificate names must already be stored at the previous round.
    - {b garbage collection}: certificates at or below the GC round are never
      stored, and committing advances the GC round, purging everything below it.

    A certificate only enters this store once it is a {!Tn_vertex.Certificate.t},
    which is itself proof a quorum signed it, so the DAG never re-checks
    signatures. Its job is purely the structural shape of the graph. *)

open Tn_types
open Tn_vertex

type t

type error =
  | Equivocation of Round.t * Authority_id.t
      (** A different certificate is already stored for this (round, author). *)
  | Missing_parent of Digests.Header_digest.t
      (** A named parent is not present at the previous round. *)
  | Missing_parent_round of Round.t
      (** The entire previous round is absent, so no parent can be resolved. *)

val error_to_string : error -> string

val create : gc_depth:int -> t
(** An empty DAG. [gc_depth] is how many rounds behind the latest committed
    round are retained; the Rust default is 50. The genesis certificates are
    round 0 and so are never stored (round 0 is at or below the initial GC round
    of 0); the round-1 genesis-parent rule below is what lets their children in. *)

val try_insert : t -> Certificate.t -> (t * bool, error) result
(** Insert a certificate. Returns the updated DAG and whether the certificate is
    {e newly relevant}, meaning its round is beyond its author's last committed
    round (the signal the commit rule uses to decide whether to consider it).

    The certificate is dropped without error, returning [false], when its round
    is at or below the GC round. Otherwise parents are checked, then the
    certificate is stored:

    - a certificate whose round is at or below {b GC round + 1} skips the parent
      check entirely. This is the genesis-parent rule: round-1 certificates point
      at genesis certificates, which are not stored, so their parents cannot and
      need not be resolved.
    - above that band, every parent digest must resolve to a certificate stored
      at the previous round, or {!Missing_parent} / {!Missing_parent_round} is
      returned.
    - if a certificate is already stored for this (round, author) with a
      different digest, {!Equivocation} is returned; the same digest is a no-op. *)

val update : t -> Certificate.t -> t
(** Record that [certificate] has been committed and garbage-collect. Advances
    the author's last committed round and the global committed round (both by
    maximum, so they never move backwards), recomputes the GC round as
    [committed_round - gc_depth] (saturating at 0), and purges every certificate
    at or below the new GC round from both indexes. *)

val get : t -> Round.t -> Authority_id.t -> Certificate.t option
(** The certificate stored for an (round, author) slot, if any. *)

val get_by_digest : t -> Digests.Header_digest.t -> Certificate.t option
(** Resolve a certificate by its header digest through the secondary index. *)

val contains_digest : t -> Digests.Header_digest.t -> bool

val round_certificates : t -> Round.t -> Certificate.t list
(** Every certificate stored at a round, in ascending author-id order. Empty for
    a round that holds nothing. *)

val rounds : t -> Round.t list
(** The rounds currently holding at least one certificate, ascending. *)

val committed_round : t -> Round.t
val gc_round : t -> Round.t
