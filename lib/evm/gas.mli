(** Gas: the allowance an execution frame spends, and the price list it spends
    against.

    Gas is what makes the interpreter total. Every instruction that lets
    execution continue costs at least one unit — only the four that halt
    ([STOP], [RETURN], [REVERT], [INVALID]) are free — so a run started with a
    finite allowance takes finitely many steps, whatever the bytecode does. No
    step budget, no loop detection and no timeout is needed; the fuel {e is} the
    termination argument.

    Costs are those of revm's schedule at Cancun and Prague (the named tiers
    [ZERO], [BASE], [VERYLOW], [LOW], [MID], [HIGH] and [JUMPDEST] are 0, 2, 3,
    5, 8, 10 and 1). Two instructions cost more than their fixed price:
    [EXP] pays {!exp_cost} for the size of its exponent, and every instruction
    that touches memory pays {!expansion_cost} for the words it makes the frame
    reach.

    An allowance is a non-negative native [int]. The real machine counts gas in
    a [u64]; a native [int] is 63-bit, so the top bit of that range is not
    representable — which no allowance approaches, since a block's whole gas
    limit is around [2^25]. *)

type word = Tn_state.U256.t

type t
(** A remaining allowance, never negative. *)

val of_int : int -> t option
(** An allowance, [None] for a negative one. *)

val remaining : t -> int
(** The units left — the value [GAS] pushes, after that instruction's own cost
    has been charged. *)

val charge : int -> t -> t option
(** [charge cost t] spends [cost] units, [None] when the allowance cannot cover
    it (the machine then halts out of gas, having spent everything). *)

val static_cost : Opcode.t -> int
(** The fixed price of an instruction, charged before it executes — so an
    instruction that then fails on its operands has still paid, exactly as in
    revm, where [Interpreter::step] deducts the static gas before dispatching. *)

val exp_cost : word -> int
(** [EXP]'s dynamic price: 50 units per byte of the exponent (zero for a zero
    exponent), on top of its fixed 10. Charged after the exponent is popped. *)

val memory_cost : int -> int option
(** The total price of having expanded memory to a given number of words:
    [3 * words + words * words / 512]. No words costs nothing, and so does any
    count below zero, which no caller produces — {!Memory.words_needed} is the
    only source of one and it never returns a negative.

    [None] when that total exceeds the largest representable allowance, which
    can only happen for a memory far larger than any allowance could pay for —
    so the caller treats [None] as out of gas, and doing so is exact rather than
    approximate: the cost really is unpayable. *)

val expansion_cost : current:int -> next:int -> int option
(** The price of growing memory from [current] to [next] words: the difference
    of the two totals, since the frame has already paid for what it holds.
    [Some 0] when [next] does not exceed [current]. [None] as in
    {!memory_cost}. *)
