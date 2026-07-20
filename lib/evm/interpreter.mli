(** The EVM interpreter: run bytecode against a gas allowance and report how it
    halted.

    This is the machine the {!Alu} was built for. It holds the four things an
    execution frame owns — an operand {!Stack}, a byte-addressed {!Memory}, a
    {!Gas} allowance and the {!Effects.t} it is accumulating — reads the {!Env.t}
    it was entered with, and folds them through a bytecode program until the
    program halts. It is still a pure function: the same environment, code,
    allowance and starting effects always produce the same outcome, and the only
    thing that leaves the frame is the value {!run} returns. That is what lets
    two nodes agree on the result by construction, the execution-layer
    counterpart of the consensus agreement the rest of the port establishes.

    {2 What it can run}

    Everything a computation needs that does not reach outside the frame:
    arithmetic, comparison, bitwise and shift operations, the full stack
    ([PUSH0]–[PUSH32], [DUP1]–[DUP16], [SWAP1]–[SWAP16], [POP]), memory
    ([MLOAD], [MSTORE], [MSTORE8], [MSIZE], [MCOPY]), introspection ([PC],
    [GAS]) and control flow ([JUMP], [JUMPI], [JUMPDEST], [STOP], [RETURN],
    [REVERT], [INVALID]).

    It now also runs everything that reads the frame's context or the account's
    own state, which is what the {!Env} and {!Effects} arguments are for: the
    call context ([ADDRESS], [CALLER], [CALLVALUE], [CALLDATALOAD],
    [CALLDATASIZE], [CALLDATACOPY], [CODESIZE], [CODECOPY], [SELFBALANCE]), the
    transaction ([ORIGIN], [GASPRICE]), the block ([COINBASE], [TIMESTAMP],
    [NUMBER], [PREVRANDAO], [GASLIMIT], [CHAINID], [BASEFEE]) and the world
    ([BALANCE], [SLOAD], [SSTORE]).

    Since the hash landed it also runs [KECCAK256], the logs ([LOG0]–[LOG4]) and
    EIP-1153 transient storage ([TLOAD], [TSTORE]). [KECCAK256] and [TLOAD] are
    pure frame-local instructions with no static-frame interaction: the first
    only reads memory, the second only reads the transient map. The {e writes}
    among the new instructions are [TSTORE] and the logs, and they join [SSTORE]
    as the three that {!Mutability} guards: each is refused in a static frame,
    and the refusal is an argument they demand rather than a branch each one has
    to remember. That guarded set is exactly the one {!Mutability} names.

    The external-code readers [EXTCODESIZE], [EXTCODECOPY] and [EXTCODEHASH]
    joined this set as of this chunk: code now lives on an account, which is all
    they wanted, and none of them opens a second frame. What is still absent
    needs a {e second frame} or a piece of state this port has not built: [CALL]
    and its relatives, [CREATE], [RETURNDATA*], [BLOCKHASH], [SELFDESTRUCT] and
    the blob instructions. Each remains a code byte that simply fails to decode,
    so a program using one halts rather than silently doing the wrong thing. See
    {!Opcode}.

    {2 Termination}

    Every instruction that lets execution continue costs at least one unit of
    gas, so each step strictly decreases a finite allowance and {!run} always
    returns. There is no step limit and no way to write a program that hangs it.

    Gas bounds the number of steps but not the work inside one, and that gap is
    real: the memory-expansion curve stays payable up to a byte extent of roughly
    [1.55e12], so a single [CALLDATACOPY] could once buy itself an allocation no
    host can serve and leave the run hanging rather than halting. {!Memory}
    closes it with {!Memory.max_extent}, a fixed bound on the extent any
    instruction may reach, past which the instruction fails with
    {!Offset_too_large}. The bound refuses nothing a payable program could do —
    the memory it names costs more than a million blocks' worth of gas, derived
    at that constant — so what it buys is that "returns an outcome" holds on
    {e every} input, not merely on every input a real block could carry.

    {2 Halting, and what a halt costs}

    A run ends in exactly one of four ways, and the type says which of them can
    leave gas behind:

    - {!Stopped} — [STOP], or the program counter walking off the end of the
      code, which is the same thing. Unspent gas survives, and so do the effects.
    - {!Returned} — [RETURN], with the bytes it selected from memory. Unspent gas
      survives, and so do the effects.
    - {!Reverted} — [REVERT]: the frame's effects are abandoned but the bytes it
      returns are kept, and so is its unspent gas.
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
    [OutOfGas] and its [MemoryOOG] for an expansion the allowance cannot pay.

    {2 Why only two outcomes carry effects}

    A frame that reverts abandons its effects, and a frame that halts
    exceptionally abandons them too. Rather than returning a world and
    documenting that the caller must throw it away — which every caller must then
    remember, and one eventually will not — {!Reverted} and {!Failed} simply have
    no such field. The post-state of a reverted frame is not discarded by
    convention; it is unnameable.

    That absence covers three things at once that revm needs three mechanisms
    for. The storage writes are undone, because the caller still holds the
    {!Effects.t} it passed in and the one containing the writes was never
    returned. The EIP-2929 warm set is un-warmed, which is what revm's journal
    does explicitly ([revm-context-interface] [journaled_state/entry.rs:317-319]
    and [:391-398], both [mark_cold]) — so a reverted [SLOAD] leaves its slot
    cold. And the EIP-3529 refund counter is dropped, which is correct: a
    reverted frame refunds nothing.

    {2 Termination, restated}

    Every instruction that continues costs at least one unit and so strictly
    decreases a finite allowance — {e except} [SSTORE], whose table price is zero
    ([revm-interpreter] [instructions.rs:201-203]) so that EIP-2200's sentry can
    read an undecremented allowance. Its body charges 100 through
    {!Gas.sstore_entry} before it can continue, so the invariant holds; but it
    holds because of that body and not because of the dispatch loop. Any future
    edit that lets an [SSTORE] path continue without charging makes {!run}
    diverge, and the type system will not notice. A property test pins it. *)

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
      (** A memory offset or length this machine will not reach: one too large to
          represent, or one whose extent passes {!Memory.max_extent}. Either way
          it names memory no allowance could pay for. revm calls the nearest
          condition [InvalidOperandOOG]; the {!Memory.max_extent} half has no revm
          counterpart at all outside an optional feature, which is that
          constant's subject.

          It is reported here rather than as {!Out_of_gas} because the refusal
          never consults the allowance: a frame holding every unit of gas that
          exists is refused on exactly the operand that refuses a frame holding a
          thousand, so naming a shortfall would name a cause that is not the
          cause. Nothing observable turns on the choice — as this module's header
          argues, every {!error} denotes the same event — but a diagnostic should
          be true.

          Note that no {e source} offset can produce this. The source
          offset of [CALLDATALOAD] and of the copy family saturates instead and
          reads zeros ([revm-interpreter] [instructions/system.rs:92,174]), so
          the two offsets of one [CALLDATACOPY] are governed by different rules
          on purpose. See {!Data}. *)
  | Reentrancy_sentry
      (** [SSTORE] attempted with an allowance at or below the 2300-unit call
          stipend. EIP-2200 makes this a halt {e before} anything is charged and
          before anything is written, so that a frame entered on a bare stipend
          cannot mutate storage; revm names it
          [InstructionResult::ReentrancySentryOOG] and reaches it at
          [revm-interpreter] [instructions/host.rs:237-244].

          It is kept distinct from {!Out_of_gas}, which it resembles, because it
          is not a shortfall: the allowance may be more than sufficient to pay.
          It is a categorical refusal. As this module's header argues, every
          value of {!error} denotes the same observable event, so the distinction
          costs nothing semantic and is worth the one thing it buys — a reader
          debugging a halted frame learns it was the sentry and not the price. *)
  | Static_state_change
      (** [SSTORE], [TSTORE] or a [LOG] attempted in a frame entered by
          [STATICCALL]. EIP-214 makes it an exceptional halt, and revm spells it
          [require_non_staticcall!] as the first statement of [sstore]
          ([instructions/host.rs:229]) and [log] ([:319]), and as the statement
          after the Cancun hardfork check in [tstore] ([:294], the check itself
          at [:293]); this port has no hardfork gate, so at Prague the two orders
          coincide.

          Being first is observable, and the tests pin it: a static frame
          reports this even when the stack could not have supplied the operands
          and even when the allowance could not have paid, because the refusal
          precedes both. The guard itself is not a branch an instruction author
          has to remember — see {!Mutability} — but its {e position} is, and
          that part is a test obligation.

          It cannot arise in this chunk's own runs, because nothing yet builds a
          static frame except a test constructing one directly: [STATICCALL] is
          the calls chunk. It is here now because the write sites are here now,
          and a guard added after the writes it guards is a guard added late. *)

val error_to_string : error -> string

type outcome =
  | Stopped of { gas_left : Gas.t; effects : Effects.t }
  | Returned of { output : string; gas_left : Gas.t; effects : Effects.t }
  | Reverted of { output : string; gas_left : Gas.t }
  | Failed of error

val outcome_to_string : outcome -> string

val run :
  env:Env.t -> code:Code.t -> gas:Gas.t -> effects:Effects.t -> outcome
(** Execute [code] from offset zero with an empty stack and empty memory,
    spending at most [gas], reading its context from [env] and threading
    [effects] through every instruction that touches the world.

    [effects] is both the input world and the output accumulator: the state the
    frame reads is {!Effects.world} of what is passed in, and what a successful
    outcome carries is that value plus everything the run did to it. A caller
    that keeps its own copy therefore holds the pre-frame state for free, which
    is what makes {!Reverted} and {!Failed} carrying nothing sufficient rather
    than lossy.

    Nothing here pre-warms. This function does not add the call target, the
    origin or the block coinbase to the access set on the caller's behalf, and it
    would be wrong to: EIP-2929, EIP-2930 and EIP-3651 warm those {e before} the
    first frame starts, which is the transaction layer's business and is what
    {!Effects.start} takes an {!Access.t} for. Passing {!Access.empty} models a
    frame in which even the executing account is cold — no real transaction
    produces one, and the difference is observable, notably on [SELFBALANCE].

    {!Effects.start} also pins EIP-2200's [original]: every [SSTORE] this run
    performs nets against the world as it stood when [start] was called, not
    against the world as it stood when this frame was entered. While a run is a
    single frame those are the same state; see {!Effects}.

    Total: it terminates on every input and returns an outcome rather than
    raising — on every input without qualification, including one naming an
    absurd offset or copy length, which halts with {!Offset_too_large} instead of
    being handed to the host's allocator. {!Memory.max_extent} is what makes that
    sentence true rather than merely likely; see the {e Termination} section
    above. *)
