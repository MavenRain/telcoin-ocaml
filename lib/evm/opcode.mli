(** The instruction set the interpreter executes, and the decoding of a code byte
    into it.

    This is the pure-computation subset of the EVM: arithmetic, comparison,
    bitwise and shift operations (dispatched to {!Alu}), stack manipulation,
    memory, gas and control flow. The opcodes that read the environment or touch
    the world — storage, calls, contract creation, the block and transaction
    context — are deliberately absent, because each needs state this chunk does
    not yet wire up; a code byte naming one of them decodes to [None] exactly as
    an unassigned byte does, and the interpreter halts on it. That is a
    {e temporary} divergence from a full node, and the only one: within this
    subset the byte values, immediate sizes and semantics are those of the real
    machine (revm's [revm-bytecode] opcode table).

    Every operand a byte can carry is held in a type that admits only the legal
    range — {!Push_bytes} for the [1, 32] immediate width and {!Depth} for the
    [1, 16] duplicate and exchange depth — so a decoded instruction cannot name
    an immediate or a depth the EVM has no encoding for. *)

module Push_bytes : sig
  (** The width of a [PUSH] immediate, in bytes: [PUSH1] through [PUSH32] occupy
      the contiguous byte range [0x60] to [0x7f], so exactly the widths [1] to
      [32] exist. [PUSH0] carries no immediate and is a separate instruction. *)

  type t

  val of_int : int -> t option
  (** A width, [None] outside [\[1, 32\]]. *)

  val to_int : t -> int
  (** The width in bytes. *)

  val all : t list
  (** Every width, ascending. *)

  val equal : t -> t -> bool
end

type t =
  | Stop
  | Add
  | Mul
  | Sub
  | Div
  | Sdiv
  | Mod
  | Smod
  | Addmod
  | Mulmod
  | Exp
  | Signextend
  | Lt
  | Gt
  | Slt
  | Sgt
  | Eq
  | Iszero
  | And
  | Or
  | Xor
  | Not
  | Byte
  | Shl
  | Shr
  | Sar
  | Pop
  | Mload
  | Mstore
  | Mstore8
  | Jump
  | Jumpi
  | Pc
  | Msize
  | Gas
  | Jumpdest
  | Push0
  | Push of Push_bytes.t
  | Dup of Depth.t
  | Swap of Depth.t
  | Return
  | Revert
  | Invalid
      (** The designated invalid instruction [0xfe]. It is a defined byte that
          always halts exceptionally — distinct from an unassigned byte, which
          {!decode} rejects, though both halt the machine the same way. *)

val decode : int -> t option
(** The instruction a code byte names, [None] for a byte that is unassigned or
    outside this subset. The argument is a byte value; anything outside
    [\[0, 255\]] is [None]. *)

val to_byte : t -> int
(** The code byte that encodes an instruction — the inverse of {!decode}, which
    round-trips: [decode (to_byte op) = Some op] for every [op]. *)

val immediate_bytes : t -> int
(** How many bytes of immediate data follow the opcode byte: the width for a
    [PUSH1]–[PUSH32] and zero for every other instruction, [PUSH0] included.
    Both the program counter and the jump-destination analysis step over this
    many bytes. *)

val equal : t -> t -> bool
val to_string : t -> string
