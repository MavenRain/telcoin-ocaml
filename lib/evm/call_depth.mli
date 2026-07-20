(** How deeply nested the running frame is — the call-stack depth EIP-150 caps.

    A transaction's outermost frame runs at {!zero}; every sub-frame a
    [CALL]/[CALLCODE]/[DELEGATECALL]/[STATICCALL] enters runs at one more than its
    parent ({!succ}). The depth is fixed for the whole life of a frame — an
    instruction never changes it — so it is threaded {e beside} the machine as an
    argument, exactly as {!Env.t} and {!Code.t} are, rather than carried inside
    {!Interpreter}'s mutable frame state. That placement is the same lifetime
    argument {!Env} makes for itself: a value constant across a frame does not
    belong in the record an instruction body may rewrite.

    It is a newtype rather than a bare [int] so the two depth-like quantities in
    the port cannot be confused: {!Depth} is the [1, 16] operand of [DUP] and
    [SWAP], a wholly different concept, and reusing it here would type-check while
    meaning nothing. The only observations are {!within_limit} — which prices no
    gas, it decides whether a sub-frame may be entered at all — and {!to_int},
    for tests. *)

type t
(** A call-stack depth in [\[0, 1024\]] region; abstract, so the only way to
    build one is {!zero} and {!succ}. *)

val zero : t
(** The transaction's outermost frame — depth zero, before any [CALL]. *)

val succ : t -> t
(** The depth of a child frame: one more than its parent's. *)

val within_limit : t -> bool
(** Whether a frame at this depth may run: [true] iff the depth does not exceed
    [CALL_STACK_LIMIT = 1024] ([revm] [primitives/constants.rs], imported at
    [revm-handler] [frame.rs:23]).

    A caller checks the {e child} depth — [within_limit (succ depth)] — because
    revm rejects a sub-call by testing the depth the child {e would} run at
    against the limit ([frame.rs:162-164], [depth > 1024]). So a frame at depth
    1024 cannot call (its child would be 1025), while a frame at 1023 still can
    (its child is exactly 1024). *)

val to_int : t -> int
(** The depth as a native count — for tests and for reasoning, not for
    execution, which only ever asks {!within_limit}. *)
