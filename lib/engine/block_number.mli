(** The execution chain's own numbering.

    A different type from {!Tn_execution.Consensus_block.Number}, with no
    conversion in either direction, because the two are different chains: the
    consensus chain advances once per commit
    ([executor/src/subscriber.rs:347-371]), this one advances once per block a
    commit produces and not at all for a commit that produces none
    ([crates/engine/src/payload_builder.rs:99-114]). A single type serving both
    would let a driver put a consensus height in an execution-height slot and
    compile. *)

type t
(** One execution block's height. Abstract, so the only heights nameable are
    {!genesis}, its successors, and the number read back off a header. *)

val genesis : t
(** Zero: the height the engine's anchor stands on before it has produced any
    block of its own. *)

val succ : t -> t
(** The next block's height, and the only way the engine advances one. *)

val of_int : int -> t
(** The height a header already carries ({!Tn_evm.Block_header.number}), which
    is how {!Anchor.of_header} names a block the engine may not have produced
    itself. Total: a header's number is a native int, and this module reads it
    rather than re-validating what the assembler already built. *)

val to_int : t -> int
(** The height as a plain int, for rendering and for the word conversions the
    EVM environment wants. *)

val equal : t -> t -> bool
(** Same height. *)

val compare : t -> t -> int
(** Ascending height, so a chain's blocks sort into chain order. *)
