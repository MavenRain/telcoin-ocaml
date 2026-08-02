(** The batch-body seam: telcoin's local body tier (the batch fetcher's hot
    cache plus the pack reader, [batch_fetcher.rs:101-111,206-293]) reduced to
    exactly what {!Tn_batch.Output.attach}'s frozen [~lookup] argument
    consumes.

    An immutable map keyed by {!Tn_types.Digests.Batch_digest.t} (this module
    instantiates its own [Map.Make]: the digest modules are bare signatures
    with no [Map] submodule). Its promises, each a type fact rather than a
    runtime check:

    - TOTAL: {!find} returns an option and never raises. Absence becomes a
      protocol error exactly once, at attach, as [Missing_batch] - never
      here.
    - NON-CONSUMING: [t] is immutable, so the same digest answers the same
      body every time, and a digest under two certificates resolves twice
      with the same body. Upstream executes such a legal duplicate twice; its
      [remove] is a clone-avoidance optimisation, not a semantics, and a
      take-once store would invert the duplicate into a fatal miss.
    - ORDER-INDEPENDENT: lookup is by digest, never by position, so the store
      cannot desynchronise from the duplicate-preserving flat digest list the
      way a positional reader silently drops entries
      ([storage/src/consensus.rs:1119-1133]).
    - KEY DERIVED: {!add} computes the key as [Batch.digest body] itself and
      no [add ~key] exists, so a store whose key disagrees with its body is
      unrepresentable - the invariant telcoin enforces at runtime in the pack
      reader ([consensus_pack.rs:1275-1279]).
    - DEDUPED and EPOCH-LESS: two adds of an equal body leave one entry,
      matching [collect_batches]' [BTreeMap] ([consensus_pack.rs:1312-1326]).
      Multiplicity belongs to the sub-DAG walk and the epoch to the caller;
      the hot tier upstream is epoch-less too ([batch_fetcher.rs:101-111]).

    Bodies are passed to the driver per step, never held in driver state,
    because the driver must not pretend to own a database.

    Two honesty notes. First, the transaction bytes inside a stored body are
    placeholders in this chunk: the engine records them as skipped, so what
    the store underwrites is block production and chain threading, not
    transaction execution (risk R4). Second, body equality is structural
    INCLUDING [received_at] ({!Tn_types.Batch.equal}) and this store never
    stamps it; a future network chunk that stamps fetched bodies owes a
    re-derivation of the equality-based tests here (risk R8). *)

type t
(** An immutable digest-keyed body store. *)

val empty : t
(** The store holding no bodies. *)

val add : t -> Tn_types.Batch.t -> t
(** [add store body] keys [body] under [Batch.digest body] - the key is
    always derived, never supplied. Adding an equal body again replaces the
    equal entry, leaving {!cardinal} unchanged. *)

val of_bodies : Tn_types.Batch.t list -> t
(** {!add} folded left over the list from {!empty}; a later duplicate
    replaces its equal predecessor. *)

val find : t -> Tn_types.Digests.Batch_digest.t -> Tn_types.Batch.t option
(** The body whose derived key equals the digest, or [None]. Total,
    non-consuming, order-independent - the module comment's contract. *)

val cardinal : t -> int
(** How many DISTINCT bodies the store holds. *)
