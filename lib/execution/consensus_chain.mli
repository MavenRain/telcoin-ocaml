(** The consensus-chain fold: the ONE place committed consensus output becomes
    the next hash-linked {!Consensus_block}.

    Rust's executor decides each committed sub-DAG's [(parent_hash, number)]
    eagerly, in the same select arm that received it — [parent_hash =
    last_parent; number = last_number + 1] — long before any batch body is
    fetched, let alone executed ([executor/src/subscriber.rs:367-371]). This
    module is the port of that pair of locals: a seedable accumulator that
    mints one block per committed sub-DAG and advances to the block it just
    minted. Because minting cannot fail, {!append} is total and returns no
    [result].

    It lives here, in the execution seam, so the port has exactly ONE fold
    rather than two that drift: {!Engine.Noop} holds an accumulator of this
    type, and the execution driver above this library (the [Tn_driver]
    subscriber — named in brackets on purpose: it sits ABOVE this library and
    this library must not depend on it) folds the same accumulator before it
    attaches bodies and executes. Upstream itself keeps three copies of this
    fold (subscriber mint, state-sync verify, [iter_to_output]); the port keeps
    one. *)

open Tn_types
open Tn_consensus

type t
(** The accumulator: everything the fold needs to mint the NEXT block — the
    digest the next block links to, the number of the last block minted, and
    that block itself when this accumulator has minted one. Immutable: {!append}
    returns the advanced accumulator and never touches its argument. *)

val genesis : t
(** The cold-start accumulator: the next block links to
    {!Consensus_block.genesis_parent} and is numbered
    [Number.succ Number.genesis] (one — the genesis anchor itself is never
    minted). Its {!tip} is [None]. *)

val resume :
  parent:Digests.Output_digest.t -> number:Consensus_block.Number.t -> t
(** The accumulator of a chain resumed at a known tip: the next block links to
    [parent] and is numbered [Number.succ number]. This is the seed a restarted
    node derives from its durable store, upstream's
    [state-sync/src/lib.rs:142-151]. The resumed accumulator's {!tip} is [None]:
    the block behind [parent] was minted in a previous life and is not
    reconstructed here. *)

val append : t -> Sub_dag.t -> t * Consensus_block.t
(** Fold ONE committed sub-DAG into the chain: mint the block at
    [Number.succ (number t)] linking to [parent t], and advance the accumulator
    to it. Total — minting cannot fail and EVERY committed sub-DAG consumes
    exactly one number, an empty output no less than a full one, because the
    number is consumed at receipt, before anything looks at a body
    ([executor/src/subscriber.rs:367-371]). *)

val tip : t -> Consensus_block.t option
(** The block this accumulator last minted, or [None] for {!genesis} and for a
    {!resume} that has not yet appended. *)

val parent : t -> Digests.Output_digest.t
(** The digest the NEXT block will link to: the last minted block's digest, or
    the seed ({!Consensus_block.genesis_parent} for {!genesis}, the [parent]
    argument for {!resume}). *)

val number : t -> Consensus_block.Number.t
(** The number of the last block minted (or the {!resume} seed); the next block
    is numbered one above it. {!Consensus_block.Number.genesis} for
    {!genesis}. *)
