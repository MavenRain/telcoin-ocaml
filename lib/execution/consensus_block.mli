(** The consensus-chain block — the port of Rust's [ConsensusHeader].

    The consensus chain is the hash-linked ledger of committed consensus output
    that the execution layer extends. Each block wraps exactly one committed
    {!Tn_consensus.Sub_dag} (the unit of consensus output), carries a {!Number}
    that counts its ancestors (the genesis anchor is zero, the first committed
    block is one), and links to its predecessor by that predecessor's {!digest}.

    Rust assembles this stream in the executor's subscriber, folding each
    committed sub-DAG into the next header with [number = previous + 1] and
    [parent_hash = previous.digest()]. The port keeps that fold in
    {!Consensus_chain}, which {!Engine.Noop} and the execution driver share
    (the driver lives ABOVE this library, in [Tn_driver] — bracketed prose on
    purpose), and this module is the block it produces. Only {!create} builds a
    block, so its cached digest is always consistent with its fields. *)

open Tn_types
open Tn_consensus

(** The block number: the count of ancestor blocks, genesis anchor {!genesis}
    (Rust's [u64], documented as "the number of ancestor blocks; the genesis
    block has a number of zero"). A monotone counter, never an index into a
    collection, so it is its own type. *)
module Number : sig
  type t

  val genesis : t
  (** Zero — the genesis anchor's number, below the first committed block. *)

  val succ : t -> t
  (** The next block's number. Total (saturates at the maximum representable
      value, unreachable in any finite run). *)

  val to_int : t -> int
  (** The height as a plain integer, for display and assertions. *)

  val of_int : int -> t option
  (** The inverse of {!to_int}: [None] below genesis, because a negative height
      is not a count of ancestors. RESERVED for the storage chunk's decoder,
      the precedent {!Tn_consensus.Dag.insert_recovered} sets. Without it a
      decoder would have to fold {!succ} [n] times to reach height [n]. *)

  val codec : t Tn_codec.Bcs.t
  (** The persisted wire codec: an 8-byte little-endian height, the same field
      {!to_int64} puts into the digest pre-image, refined through {!of_int} so
      a below-genesis or unrepresentable wire value is refused rather than
      wrapped. RESERVED for the storage chunk. *)

  val to_int64 : t -> int64
  (** The value as it enters the digest pre-image: an 8-byte little-endian
      field, matching Rust's [number.to_le_bytes()]. *)

  val equal : t -> t -> bool
  (** Numeric equality of two heights. *)

  val compare : t -> t -> int
  (** Numeric ordering of two heights. *)

  val to_string : t -> string
  (** The height rendered in decimal. *)
end

type t

val genesis_parent : Digests.Output_digest.t
(** The parent digest the {e first} committed block links to — the anchor of the
    chain. Rust has no hardcoded constant for it either: it digests
    [ConsensusHeader::default()] (block.rs:58-75), which is number zero, a zero
    parent, a zero [extra], and a sub-DAG holding one default [Header], empty
    non-final scores, a stored timestamp of zero and the
    {!Tn_consensus.Sub_dag.default_randomness}. This value is COMPUTED from
    exactly those parts rather than pinned, so it tracks the {!Tn_crypto} seam
    and cannot drift from the pre-image {!digest} hashes. On a fresh chain
    Rust's [last_consensus_parent] resolves to the same header
    (crates/state-sync/src/lib.rs:138-151). *)

val create :
  parent_hash:Digests.Output_digest.t ->
  sub_dag:Sub_dag.t ->
  number:Number.t ->
  t
(** A block at height [number] extending [parent_hash] with [sub_dag], with the
    zero {!extra} every producer writes. The digest is computed once from the
    frozen pre-image and cached. *)

val of_persisted :
  parent_hash:Digests.Output_digest.t ->
  sub_dag:Sub_dag.t ->
  number:Number.t ->
  extra:Tn_hash32.Hash32.t ->
  t
(** {!create} with an explicit {!extra}. RESERVED for the wire decoder, the
    precedent {!Tn_consensus.Sub_dag.of_persisted} sets: [extra] round-trips,
    so a reader must be able to rebuild the value it was handed, while no
    producer in this port ever chooses a non-zero one. The digest is
    recomputed, never taken from the wire, and does not depend on [extra]. *)

val parent_hash : t -> Digests.Output_digest.t
(** The digest of the block this one extends (the chain anchor for the first). *)

val sub_dag : t -> Sub_dag.t
(** The committed sub-DAG this block records. *)

val number : t -> Number.t
(** This block's height in the chain. *)

val extra : t -> Tn_hash32.Hash32.t
(** Rust's currently-unused [extra: B256] (block.rs:29-31). It is on the wire
    and it round-trips, but it is NOT in the digest: {!preimage} folds in
    [B256::default()] whatever this holds, so two blocks differing only here
    share a digest and differ in their encoding. *)

val preimage : t -> string
(** The digest pre-image: the 32-byte [parent_hash],
    then the 32-byte {!Tn_consensus.Sub_dag.digest}, then the 8-byte
    little-endian {!Number}, then 32 zero bytes — [B256::default()], NOT
    {!extra}, because Rust's last update reads the default regardless
    (block.rs:51-53). 104 bytes in all. This byte layout is the frozen
    wire-compatibility contract: the exact field order of Rust's
    [ConsensusHeader::digest_from_parts]. The crypto seam may change only the
    hash function, never this layout. *)

val digest : t -> Digests.Output_digest.t
(** Protocol hash of the BARE {!preimage}, with no tag and no prefix, exactly as
    Rust's [ConsensusHeader::digest_from_parts] hashes it (primary/block.rs:
    42-55). *)

val codec : t Tn_codec.Bcs.t
(** The persisted wire codec. RESERVED for the storage chunk. FOUR fields, in
    Rust's declaration order (block.rs:17-32): the LENGTH-PREFIXED
    {!parent_hash} ([0x20] then 32 bytes), the {!sub_dag}, the 8-byte
    {!Number}, and the LENGTH-PREFIXED {!extra} — rebuilt through
    {!of_persisted}. The pre-image writes its 32-byte fields bare; only the
    wire prefixes them.

    The cached {!digest} is {e not} on the wire; {!of_persisted} recomputes it,
    so a decoded block's digest is always the hash of the bytes beside it and a
    reader cannot be handed a block that claims a digest it does not have. *)

val equal : t -> t -> bool
(** By digest. *)

val compare : t -> t -> int
(** Total order by digest. *)
