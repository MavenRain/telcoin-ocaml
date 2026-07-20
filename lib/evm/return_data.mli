(** The return-data buffer: the bytes the most recent sub-call handed back, read
    by [RETURNDATASIZE] and [RETURNDATACOPY] (EIP-211).

    Every [CALL]/[CALLCODE]/[DELEGATECALL]/[STATICCALL] replaces this buffer with
    its child's output — the returned bytes on a success or a revert, and the
    empty string on a [STOP] or an exceptional halt (revm sets it unconditionally,
    [revm-handler] [frame.rs:462]). Because it evolves step by step across a
    frame's life, exactly as {!Memory} does, it lives on {!Interpreter}'s machine
    beside the memory rather than being threaded as a constant argument.

    {2 Why not {!Data}}

    It deliberately does {e not} reuse {!Data.t}, though both wrap a byte string.
    {!Data} answers an out-of-range read with zeroes and saturates an oversized
    source offset — the [CALLDATACOPY]/[CODECOPY] rule. [RETURNDATACOPY] has the
    {e opposite} rule: a read whose end passes the buffer is an exceptional halt
    ([OutOfOffset], revm [instructions/system.rs:203-206]), never a zero-fill.
    Backing this with {!Data} would silently succeed exactly where the machine
    must halt, so the read here is a {e strict} {!read} returning an option, and
    the type is distinct so the two rules can never be confused. *)

type t
(** A buffer of bytes; abstract, so a value of it is only ever a sub-call's
    output read through {!read}'s strict bounds. *)

val empty : t
(** No bytes — the buffer a fresh frame starts with, and the buffer left by a
    child that stopped or halted without returning anything. *)

val of_string : string -> t
(** The buffer holding a sub-call's output bytes. Total. *)

val size : t -> int
(** The number of bytes — the value [RETURNDATASIZE] pushes. *)

val read : t -> offset:int -> length:int -> string option
(** [length] bytes from [offset], {e strictly} bounded: [Some] exactly when
    [offset + length] (a saturating add, so it cannot wrap to a small end) does
    not exceed {!size}, and [None] otherwise. A [None] is [RETURNDATACOPY]'s
    [OutOfOffset] halt ([revm] [instructions/system.rs:203-206]); the caller
    turns it into an exceptional halt rather than zero-filling.

    A zero [length] succeeds at any [offset] up to and including {!size} (its end
    is [offset], which equals {!size} at the boundary and so does not exceed it),
    and fails past it — matching revm's [data_end > buffer.len()] test on a
    saturating [data_offset + len].

    This is the exact contrast with {!Data.read}, which is total and zero-extends
    on the same inputs. Both take a caller-supplied [offset] and [length] the
    caller has already converted; the difference is only which one halts. *)
