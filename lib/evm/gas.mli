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
    5, 8, 10 and 1). Several instructions cost more than their fixed price:
    [EXP] pays {!exp_cost} for the size of its exponent, every instruction that
    touches memory pays {!expansion_cost} for the words it makes the frame reach,
    the copying instructions pay {!copy_cost} per word moved, and the
    state-reading instructions pay an EIP-2929 surcharge
    ({!storage_access_cost}, {!account_access_cost}) when their first touch of a
    slot or an account is a cold one.

    [SSTORE] is the exception to the whole shape of this module: its price is not
    a function of the instruction alone but of what the write does to the slot
    over the {e transaction}, so it is split across {!sstore_entry},
    {!sstore_dynamic_cost} and {!sstore_refund}, and its {!static_cost} is zero
    on purpose. {!sstore_entry} says why.

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
    revm, where [Interpreter::step] deducts the static gas before dispatching.

    Two entries are Berlin overrides rather than tier members and read oddly
    against the yellow paper: [BALANCE] and [SLOAD] are 100, not 20 and 50
    ([revm-interpreter] [instructions.rs:118-119] overriding [:168] and [:200]).
    EIP-2929 moved the bulk of their price into the cold surcharge, so 100 is the
    {e warm} price and the rest arrives through {!account_access_cost} and
    {!storage_access_cost}.

    [SSTORE] is 0, and that is not an omission: see {!sstore_entry}. *)

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

val warm_storage_read : int
(** 100 — [WARM_STORAGE_READ_COST] ([revm-context-interface] [cfg/gas.rs:100]).
    The static price of [SLOAD] and [BALANCE] from Berlin on, charged by
    {!static_cost} before those instructions run, not by them. *)

val call_stipend : int
(** 2300 — [CALL_STIPEND] ([revm-context-interface] [cfg/gas.rs:108]). Only used
    here as EIP-2200's sentry threshold; the calls that give it its name are
    deferred. *)

val storage_access_cost : Access.warmth -> int
(** [SLOAD]'s cold surcharge on top of the 100 already charged: 2000 when the
    touch was cold, nothing when warm — 2100 and 100 in total.

    2000 is [cold_storage_additional_cost], built as
    [COLD_SLOAD_COST - WARM_STORAGE_READ_COST] ([revm-context-interface]
    [cfg/gas_params.rs:272-273]) and charged at [revm-interpreter]
    [instructions/host.rs:203,209].

    Note that this is {e not} the constant [SSTORE] uses; see
    {!sstore_dynamic_cost}. They differ by exactly the static 100 and are easy to
    swap.

    revm additionally refuses the underlying database read when the remaining
    allowance is below the surcharge and halts out of gas
    ([instructions/host.rs:204,214]). That is an I/O optimisation with no
    observable consequence — a warm slot is still served, and a cold one that
    cannot be paid for halts either way — so this port touches and then charges.
    Do not "restore" the branch. *)

val account_access_cost : Access.warmth -> int
(** [BALANCE]'s cold surcharge on top of the 100 already charged: 2500 cold,
    nothing warm — 2600 and 100 in total. 2500 is
    [COLD_ACCOUNT_ACCESS_COST_ADDITIONAL], [2600 - 100]
    ([revm-context-interface] [cfg/gas.rs:97-98], wired at
    [cfg/gas_params.rs:270-271], charged at [revm-interpreter]
    [instructions/macros.rs:54-62]). *)

val copy_cost : int -> int
(** Three units per thirty-two-byte word copied, rounded up — the price
    [CALLDATACOPY], [CODECOPY] and [MCOPY] share
    ([revm-context-interface] [cfg/gas.rs:54] where [COPY = 3], wired identically
    for all three at [cfg/gas_params.rs:203-205], computed at [:619-628] and
    [:377-380]). Charged on top of the instruction's static 3, {e before} any
    offset conversion and before memory expansion, and charged even for a zero
    length, where it is zero.

    [MCOPY] was deferred out of the frame-local chunk so this price would be
    written once. It is written once. Do not alias it with the linear term of the
    expansion curve, which is also 3 ([cfg/gas.rs:42], [MEMORY]): they are
    different prices that happen to coincide, and a program pays both.

    Returns an [int] rather than an [int option] and cannot overflow: the word
    count is at most [max_int / 32], so three times it is representable. This is
    unlike {!memory_cost}, whose quadratic term genuinely can leave the range. *)

val keccak_word_cost : int -> int
(** Six units per thirty-two-byte word of input to [KECCAK256], rounded up
    ([revm-context-interface] [cfg/gas.rs:52], [KECCAK256WORD = 6]), charged on
    top of the instruction's static 30 and on top of the memory expansion its
    window forces.

    Six, not three. This shares the {e rounding rule} with {!copy_cost} and
    nothing else: there are three word prices in this schedule — the expansion
    curve's linear term (3), the copy family (3) and this one (6) — the first
    two coincide and the third does not, and a hashing instruction pays this one
    and the expansion. Cannot overflow, for {!copy_cost}'s reason with six in
    place of three. *)

val log_dynamic_cost : topics:Topic_count.t -> length:int -> int option
(** A log's dynamic half: [375] per topic plus [8] per byte of data
    ([cfg/gas.rs:44,46,48]), on top of the flat [375] every [LOG] pays through
    {!static_cost}. So a [LOG2] over 32 bytes of data costs
    [375 + 750 + 256 = 1381] in all, plus whatever expansion its window forces.

    Per {e byte}, not per word: this is the one dynamic price in the schedule
    applied to a raw length rather than to a word count, which is why it is the
    one that has to be checked. [None] means the true price exceeds [max_int],
    and since no allowance can reach that, treating it as out of gas is exact
    rather than conservative. *)

type sstore_entry_error =
  | Reentrancy_sentry
      (** The allowance is at or below {!call_stipend}. EIP-2200 refuses the
          write outright rather than charging for it. Note the comparison is
          [<=], not [<] ([revm-interpreter] [instructions/host.rs:238]). *)
  | Insufficient
      (** The allowance cannot cover the 100-unit static charge. *)

val sstore_entry : t -> (t, sstore_entry_error) result
(** [SSTORE]'s entry: the EIP-2200 sentry and the 100-unit static charge, fused
    into one function because their order is the whole point and a caller that
    could perform them separately could perform them in the wrong one.

    The sentry runs first, against the allowance {e before} anything is taken
    ([revm-interpreter] [instructions/host.rs:237-244], with the charge following
    at [:246-249]). A frame running on a bare 2300-unit stipend must not be able
    to mutate storage, and charging first would let an allowance of 2350 slip
    past a boundary that 2250 fails — a divergence invisible except at the exact
    threshold.

    This is also why {!static_cost} returns 0 for [SSTORE]. revm leaves its table
    entry at zero for precisely this reason ([instructions.rs:201-203]), because
    the interpreter's pre-dispatch charge would move the sentry by 100. The cost
    is that [SSTORE] is the one instruction the dispatch loop does not charge
    for, so the termination argument is restored here rather than there — see
    {!Interpreter.run} and the property test that pins it.

    The 100 is [WARM_STORAGE_READ_COST] ([cfg/gas_params.rs:269]): [SSTORE] pays
    the warm access price unconditionally, and coldness is surcharged inside
    {!sstore_dynamic_cost}. *)

val sstore_dynamic_cost : Access.warmth -> Sstore_state.t -> int
(** What the write itself costs, on top of the 100 {!sstore_entry} already took:
    a cold surcharge of {e 2100} plus a change term of 19900, 2800 or nothing.

    The two terms are additive — a cold fresh set pays 22000 here and 22100 in
    all ([revm-context-interface] [cfg/gas_params.rs:433-451]).

    The cold surcharge is 2100 and {e not} the 2000 of {!storage_access_cost}.
    [SSTORE] adds [cold_storage_cost = COLD_SLOAD_COST] ([gas_params.rs:437],
    wired at [:274]) while [SLOAD] adds [cold_storage_additional_cost], which is
    that constant less the warm 100 ([:272-273]). The difference is exactly the
    static charge each instruction has already paid, and swapping the two leaves
    both numbers looking plausible while a cold [SSTORE] undercharges by 100 —
    which is why the two constants are written separately here and never shared.

    The change term is an exhaustive match on {!Sstore_state.classify}: 19900 for
    a {!Sstore_state.Fresh_set} ([SSTORE_SET] less the warm 100,
    [gas_params.rs:279-280]), 2800 for a {!Sstore_state.Fresh_reset}
    ([WARM_SSTORE_RESET] less the warm 100, [:277-278]), and nothing for a
    {!Sstore_state.No_op} or a {!Sstore_state.Dirty} slot, which the transaction
    has already paid to disturb. *)

val sstore_refund : Sstore_state.t -> int
(** What the write contributes to the transaction's refund counter, which may be
    negative — a transcription of [revm-context-interface]
    [cfg/gas_params.rs:456-506] at Istanbul and later.

    This is the one formula in the schedule that resists being tidied, and the
    shape is load-bearing. Its first two cases {e return}: a no-op refunds
    nothing ([:469-471]), and clearing a slot the transaction found untouched
    refunds 4800 ([:475-477]). Its last two {e accumulate} into a single total
    ([:479-505]) and are independent, so one [SSTORE] can both claw back the 4800
    it was credited earlier and take back the 2800 it paid to reset — restructure
    them into an if/else chain and that write silently loses one of the two
    terms.

    4800 is [WARM_SSTORE_RESET + ACCESS_LIST_STORAGE_KEY], EIP-3529's replacement
    for the old clearing schedule ([gas_params.rs:296-297]); 19900 and 2800 are
    the same two constants {!sstore_dynamic_cost} charges, refunded when the
    write restores the slot to what the transaction started with
    ([:281-284]).

    The result is unclamped. EIP-3529's cap at a fifth of the gas spent
    ([revm-interpreter] [gas.rs:113-120]) is a property of a whole transaction;
    see {!Refund}. *)
