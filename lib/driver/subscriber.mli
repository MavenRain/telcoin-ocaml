(** The driver's receive arm: the port of the executor subscriber's mint plus
    batch fetch ([executor/src/subscriber.rs:360-371,430-529]), kept as its own
    module so one OCaml file diffs against one Rust file.

    {!receive} mints FIRST, mirroring the subscriber's eager locals
    ([subscriber.rs:367-371]): the running {!Tn_execution.Consensus_chain}
    accumulator decides the minted block's [(parent, number)] at receipt, so
    an empty output consumes a number exactly like a full one. Only then are
    bodies attached, through the frozen {!Tn_batch.Output.attach} with
    {!Batch_store.find} as its [lookup]. Body-independence of the mint is a
    fact of {!Tn_execution.Consensus_chain.append}'s TYPE - it has no body
    parameter to read - not a runtime property any test could see fail; with
    both operations pure, the source ORDER is likewise unobservable, so it
    is maintained as the upstream mirror rather than claimed as tested
    behaviour. The suite pins the type-level fact as a tripwire against a
    future body-parameterised mint.

    The subscriber owns nothing but the accumulator: bodies and the address
    table arrive per call (the driver must not pretend to own a database),
    and the watermark, the engine and the epoch all live above, in the
    driver (upstream keeps them out of the subscriber too: that is
    [run_epoch.rs]). Receiving is fail-stop: an attach failure returns the
    error ALONE, with no advanced subscriber and no minted block, and there
    is deliberately no skip arm and no retry arm, so resuming past a
    protocol violation is unrepresentable rather than merely discouraged. *)

type t
(** The subscriber state: exactly the consensus-chain accumulator, wrapped so
    a caller can neither advance the chain without attaching nor attach
    without advancing. Immutable: {!receive} returns the advanced subscriber
    and never touches its argument. *)

(** Everything receiving can fail on: attachment, and nothing else, because
    minting is total. Both attach failures are protocol-fatal upstream, which
    is why no skip arm and no retry arm exist. *)
type error =
  | Attach of Tn_batch.Output.error
      (** {!Tn_batch.Output.attach} refused the payload: a body the store
          could not supply, or a header author (or leader) the address table
          could not resolve. *)

val error_to_string : error -> string
(** Human rendering; delegates to {!Tn_batch.Output.error_to_string}. *)

val create : Tn_execution.Consensus_chain.t -> t
(** A subscriber over an accumulator:
    {!Tn_execution.Consensus_chain.genesis} for a cold start, a
    [resume]-seeded accumulator for a restarted chain. *)

val receive :
  t ->
  Tn_consensus.Sub_dag.t ->
  bodies:Batch_store.t ->
  address_of:(Tn_types.Authority_id.t -> Tn_types.Units.Address.t option) ->
  (t * Tn_execution.Consensus_block.t * Tn_batch.Output.t, error) result
(** Fold ONE committed sub-DAG: mint the next consensus block from the
    accumulator, then attach every referenced batch body from [bodies] and
    every author's execution address from [address_of], returning the
    advanced subscriber, the minted block and the attached output as one
    tuple. On [Error] nothing else comes back: the mint that preceded the
    failed attach is discarded with the subscriber that made it, so a caller
    holds either the state before the output or the state after it, never a
    half-received one. *)

val number : t -> Tn_execution.Consensus_block.Number.t
(** The number of the last block minted (or the accumulator's seed):
    {!Tn_execution.Consensus_chain.number} of the wrapped accumulator. *)
