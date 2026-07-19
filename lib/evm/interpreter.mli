(** The EVM interpreter: run bytecode against a gas allowance and report how it
    halted.

    This is the machine the {!Alu} was built for. It holds the three things an
    execution frame owns — an operand {!Stack}, a byte-addressed {!Memory} and a
    {!Gas} allowance — and folds them through a bytecode program until the
    program halts. It is a pure function: the same code and allowance always
    produce the same outcome, and nothing outside the frame is touched. That is
    what lets two nodes agree on the result by construction, the execution-layer
    counterpart of the consensus agreement the rest of the port establishes.

    {2 What it can run}

    Everything a computation needs that does not reach outside the frame:
    arithmetic, comparison, bitwise and shift operations, the full stack
    ([PUSH0]–[PUSH32], [DUP1]–[DUP16], [SWAP1]–[SWAP16], [POP]), memory
    ([MLOAD], [MSTORE], [MSTORE8], [MSIZE]), introspection ([PC], [GAS]) and
    control flow ([JUMP], [JUMPI], [JUMPDEST], [STOP], [RETURN], [REVERT],
    [INVALID]). The opcodes that read the world or the transaction — storage,
    the environment, calls, contract creation, logs — are not here: each needs
    state this chunk does not yet have, and every one of them is a code byte that
    simply fails to decode, so a program using one halts rather than silently
    doing the wrong thing. See {!Opcode}.

    One frame-local opcode is deferred with them: [MCOPY], whose per-word copy
    price is the same one the rest of the copy family ([CODECOPY],
    [CALLDATACOPY], [RETURNDATACOPY]) is charged, and those do need data from
    outside the frame. Pricing the family once, when its other members arrive, is
    less likely to get the price wrong than pricing one member early.

    {2 Termination}

    Every instruction that lets execution continue costs at least one unit of
    gas, so each step strictly decreases a finite allowance and {!run} always
    returns. There is no step limit and no way to write a program that hangs it.

    {2 Halting, and what a halt costs}

    A run ends in exactly one of four ways, and the type says which of them can
    leave gas behind:

    - {!Stopped} — [STOP], or the program counter walking off the end of the
      code, which is the same thing. Unspent gas survives.
    - {!Returned} — [RETURN], with the bytes it selected from memory. Unspent gas
      survives.
    - {!Reverted} — [REVERT]: the frame's effects are abandoned but the bytes it
      returns are kept, and so is its unspent gas. (This layer has no effects to
      abandon yet; that appears when storage and the world state are wired in.)
    - {!Failed} — an exceptional halt. It carries no gas, because there is none
      left to carry: the caller of a frame that halts exceptionally forfeits the
      {e entire} allowance it forwarded. Only [OutOfGas] zeroes the counter
      inside revm's interpreter; the other exceptional halts leave it set and the
      frame boundary confiscates it regardless ([revm-handler] [frame.rs:478-488],
      which returns unspent gas only for a success or a revert). Making {!Failed}
      gasless states that outcome directly rather than storing a number no
      observer can ever see.

    The same reasoning is why {!error} need not match revm's [InstructionResult]
    variant for variant. Every value of it denotes the same observable event —
    the frame is discarded, all its gas is consumed, and no output is produced —
    so the distinction is a diagnostic, not a semantic. Where this port names a
    condition differently from revm it does so to name it more coarsely or more
    precisely, and each place it happens is documented: {!Stack.dup} on the
    underflow it reports as an underflow rather than an overflow;
    {!Offset_too_large} below; and {!Out_of_gas}, which covers both revm's plain
    [OutOfGas] and its [MemoryOOG] for an expansion the allowance cannot pay. *)

type error =
  | Out_of_gas
      (** The allowance could not cover an instruction's cost, whether its fixed
          price or the memory it asked to reach. *)
  | Stack_underflow  (** An instruction wanted more operands than were there. *)
  | Stack_overflow  (** A push past the 1024-word limit. *)
  | Invalid_jump
      (** A jump to an offset that is not a [JUMPDEST] instruction — including
          one inside push data, one past the end of the code, and one too large
          to be an offset at all. *)
  | Invalid_opcode of int
      (** The byte at the program counter names no instruction this interpreter
          runs: an unassigned byte, the designated invalid instruction [0xfe], or
          one of the opcodes deferred to a later chunk. revm separates the first
          two ([OpcodeNotFound] and [InvalidFEOpcode]); both are exceptional
          halts, and so is this. *)
  | Offset_too_large
      (** A memory offset or length too large to represent, which is to say too
          large for any allowance to pay for reaching. revm calls the same
          condition [InvalidOperandOOG]. *)

val error_to_string : error -> string

type outcome =
  | Stopped of { gas_left : Gas.t }
  | Returned of { output : string; gas_left : Gas.t }
  | Reverted of { output : string; gas_left : Gas.t }
  | Failed of error

val outcome_to_string : outcome -> string

val run : code:Code.t -> gas:Gas.t -> outcome
(** Execute [code] from offset zero with an empty stack and empty memory,
    spending at most [gas]. Total: it terminates on every input and returns an
    outcome rather than raising. *)
