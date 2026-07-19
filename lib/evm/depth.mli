(** A stack depth in [\[1, 16\]] — the operand carried by [DUP] and [SWAP].

    [DUP n] duplicates the [n]-th word counted from the top of the stack, so
    [DUP1] duplicates the top word; [SWAP n] exchanges the top word with the word
    [n] places below it, so [SWAP1] exchanges the top two. The EVM encodes the
    depth in the opcode byte itself — [DUP1] to [DUP16] occupy [0x80] to [0x8f]
    and [SWAP1] to [SWAP16] occupy [0x90] to [0x9f] — so exactly sixteen depths
    exist. Holding that in the type makes every other depth unrepresentable, and
    the stack's duplicate and exchange operations total on the range they accept
    rather than partial on an unchecked integer. *)

type t

val of_int : int -> t option
(** A depth from its one-based value, [None] outside [\[1, 16\]]. *)

val to_int : t -> int
(** The one-based depth. *)

val all : t list
(** Every depth, ascending — the sixteen [DUP] and [SWAP] variants. *)

val equal : t -> t -> bool
