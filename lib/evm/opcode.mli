(** The instruction set the interpreter executes, and the decoding of a code byte
    into it.

    This is the single-frame subset of the EVM: arithmetic, comparison, bitwise
    and shift operations (dispatched to {!Alu}), stack manipulation, memory, gas
    and control flow, the instructions that read the block and transaction
    context, read the calling frame's calldata and its own code, and read and
    write account storage, and — since the hash landed — [KECCAK256], the logs
    and EIP-1153 transient storage.

    The external-code readers — [EXTCODESIZE], [EXTCODECOPY] and [EXTCODEHASH] —
    are in as of this chunk: code now lives on an account, which is all they
    needed, and none of them opens a second frame. What remains absent is what
    needs a {e second} frame or a piece of state this port has not built: the
    return-data readers, [BLOCKHASH], the blob instructions, the calls, the
    creations and [SELFDESTRUCT]. A code byte naming one of them decodes to
    [None] exactly as
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
  | Address
  | Balance
  | Origin
  | Caller
  | Callvalue
  | Calldataload
  | Calldatasize
  | Calldatacopy
  | Codesize
  | Codecopy
  | Extcodesize
      (** [0x3b]. The size of {e another} account's code, unlike [CODESIZE]'s
          own-frame reading. It warms the account (EIP-2929) and pushes the
          length, zero for an account with no code or no entry. *)
  | Extcodecopy
      (** [0x3c]. Copies another account's code into memory, through the same
          zero-extension rule as [CODECOPY], and warms the account. Its account
          surcharge falls {e after} the copy price and the expansion, and is
          paid even for a zero length. *)
  | Extcodehash
      (** [0x3f]. EIP-1052: the Keccak-256 of another account's code, or zero for
          an account that is empty (EIP-161) or absent. A codeless account that
          nonetheless exists hashes to [KECCAK_EMPTY], not zero. *)
  | Gasprice
  | Coinbase
  | Timestamp
  | Number
  | Prevrandao
      (** [0x44]. The byte revm still calls [DIFFICULTY]
          ([instructions.rs:188]); post-merge it names the beacon chain's
          randomness, and the name here is the one the semantics deserve. *)
  | Gaslimit
  | Chainid
  | Selfbalance
  | Basefee
  | Sload
  | Sstore
  | Mcopy
  | Keccak256
  | Tload
  | Tstore
  | Log of Topic_count.t
      (** [LOG0]-[LOG4] as one constructor carrying its arity, because the five
          bytes [0xa0]-[0xa4] are one instruction with an operand and not five
          instructions. The operand then determines the byte encoded, the number
          of topic words popped, the {!Log.Topics.t} constructor built and the
          price charged, so a [LOG3] that pops two topics is not an
          implementation that exists. Note the offset is zero-based, unlike
          {!Push_bytes} and {!Depth}, so this family does not go through the
          shared one-based helper. *)

val decode : int -> t option
(** The instruction a code byte names, [None] for a byte that is unassigned or
    outside this subset. The argument is a byte value; anything outside
    [\[0, 255\]] is [None].

    The subset grew; the mechanism did not. Every still-deferred instruction has
    no arm here, so its byte decodes to [None] and halts the machine rather than
    silently doing the wrong thing. Being absent from a total decoder {e is} the
    mechanism — it needs no allow-list, no feature flag and no code.

    The asymmetry is deliberate. Adding a constructor to {!t} breaks compilation
    in {!to_byte}, in {!Gas.static_cost} and in the interpreter's dispatch, all
    three of which are exhaustive with no wildcard; adding an arm {e here} is a
    separate, deliberate edit. That is what keeps a decoded byte a promise that
    the instruction is really implemented. *)

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
