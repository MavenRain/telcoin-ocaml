(** The block the next one is built on: exactly the four facts telcoin reads
    off [canonical_header] ([crates/engine/src/payload_builder.rs:60-88]).

    No genesis {!Tn_evm.Block_header.t} is ever manufactured. Chunk 34 made
    {!Tn_evm.Block_header.assemble} the only producer of a header, and it needs
    a finished execution to assemble one, so a node starting from a genesis it
    did not execute has a hash, a base fee and a gas limit but no header at all.
    That is what {!of_genesis} names, and it is why {!header} is an option: the
    engine's first block reads the parent hash, number, base fee and gas limit
    it needs without any header existing to read them from. *)

type t
(** A parent: its hash, its height, and the two fields the child derives from
    it. Abstract, with exactly two producers, so an anchor whose hash and
    header disagree is unrepresentable. *)

val of_genesis :
  hash:Tn_keccak.t -> base_fee:Tn_state.U256.t -> gas_limit:int -> t
(** The anchor a node is configured with rather than one it executed: the
    genesis block's hash and the two parent-derived fields, at height
    {!Block_number.genesis}. {!header} is [None] for it. *)

val of_header : Tn_evm.Block_header.t -> t
(** The anchor a produced block leaves behind. Every field is read off the
    header, so the engine's chaining never re-derives what it just assembled. *)

val hash : t -> Tn_keccak.t
(** The parent hash the next block carries. *)

val number : t -> Block_number.t
(** The parent's height; the next block's is its {!Block_number.succ}. *)

val base_fee : t -> Tn_state.U256.t
(** The parent's base fee per gas, which the close-epoch empty block inherits
    verbatim ([payload_builder.rs:116-150]). Total, and zero stays zero: this
    port has no fee market to fall back on. *)

val gas_limit : t -> int
(** The parent's gas limit, inherited by the close-epoch empty block for the
    same reason. *)

val header : t -> Tn_evm.Block_header.t option
(** The parent's header, or [None] for a genesis anchor, which is the one case
    where a parent exists and no header for it does. *)
