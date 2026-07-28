(** Delegation resolution for a call target ([call_helpers.rs:165-186] and
    [handler.rs:317-332], which are the SAME rule duplicated at revm's two
    entry points; fixing only the CALL path leaves a transaction sent directly
    to a delegated EOA wrong, and that is the canonical sponsored shape). One
    module, named by both {!Interpreter}'s four call opcodes and
    {!Executor}'s depth-0 frame, so the two cannot disagree. *)

type t
(** A resolved call target. Abstract, {!resolve} its only producer, so a
    delegate warmed without its surcharge computed, or priced without being
    warmed, is unrepresentable: both come out of one value. *)

val resolve : Effects.t -> Tn_state.Account.t -> t
(** [resolve effects account] where [account] is the target the caller has
    ALREADY loaded and warmed (the interpreter's step 5, the executor's own
    load), so this never re-touches the target and the caller keeps its one
    {!Access.warmth}.

    {b If the account bears no designator this is the IDENTITY}: [effects]
    comes back physically unchanged, {!surcharge} is [0], {!delegate} is
    [None] and {!code} is [Code.of_string (Tn_state.Account.code account)],
    the exact expression both call sites evaluated before this module existed.
    That is the entire correctness argument for the hot path, it is one record
    literal of implementation, and it is pinned by a property test over
    generated non-designator codes (test_eip7702_calls.ml).

    If it IS a designator, exactly ONE hop is followed: both revm sites are a
    single [if let] with no loop and no re-check. A delegate whose own code is
    itself a designator is handed to the frame as those 23 bytes, which halt
    on the first byte: [0xEF] is undefined ([opcode.rs:637-638]) and an
    unknown opcode burns the whole allowance ([handler.rs:353-362]), which is
    NOT a revert and carries no return data. That is revm's behaviour, not an
    error. *)

val code : t -> Code.t
(** The bytecode the frame runs. EMPTY is legal and means the frame stops at
    once with empty output AFTER the value transfer ([frame.rs:225-229]); this
    port gets that for free because an empty {!Code.t} reads [STOP] at offset
    zero. *)

val effects : t -> Effects.t
(** The effects with the DELEGATE warmed as a SECOND, INDEPENDENT address
    ([call_helpers.rs:150-154]). Warming the designator never warms the
    delegate and vice versa; a single-flag port under- or over-charges the
    next call to either. *)

val surcharge : t -> int
(** [Gas.delegation_cost (warmth of the delegate)]: [0] when not delegated,
    else a flat {!Gas.warm_storage_read} (100) plus
    {!Gas.account_access_cost} of the DELEGATE's own warmth (2500 cold),
    i.e. 100 warm / 2600 cold, ON TOP of the target's own cold charge and of
    the opcode's 100 static base, which is already in the table
    ([gas.ml:106-123]) and must NOT be charged again ([call_helpers.rs:133]:
    "Assumption is that warm gas is already deducted").

    The interpreter charges this. The depth-0 transaction frame does NOT:
    [handler.rs:314-332] resolves outside any gas metering and
    [first_frame_input] has no [Gas] in scope, so both accounts are warmed
    for free at depth 0. The executor therefore ignores this field,
    deliberately and with a comment at its call site. *)

val delegate : t -> Tn_types.Units.Address.t option
(** The address one hop away; [None] is exactly "this target bears no
    designator". For tests and for the executor's pre-warm set. *)
