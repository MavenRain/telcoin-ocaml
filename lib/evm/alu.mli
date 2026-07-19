(** The EVM arithmetic and logic unit — the pure word operations the interpreter
    dispatches its arithmetic, comparison, bitwise and shift opcodes to.

    Each function has the exact, total semantics of the opcode it names: division
    and remainder by zero yield zero, comparisons yield the one-or-zero word the
    EVM uses for a boolean, and the signed operations read their operands as
    two's-complement 256-bit integers. Everything here is a pure function of its
    word operands alone — no gas, no stack, no world state; those belong to the
    interpreter that will call this. The arithmetic itself lives in
    {!Tn_state.U256}, whose (mathematically honest, partial-on-zero-divisor) raw
    operations these total functions wrap. Operand order follows the opcode: the
    word popped first from the stack is the first argument. *)

type word = Tn_state.U256.t
(** The 256-bit EVM word. *)

val add : word -> word -> word
(** [ADD] — addition modulo [2^256]. *)

val sub : word -> word -> word
(** [SUB] — subtraction modulo [2^256]. *)

val mul : word -> word -> word
(** [MUL] — multiplication modulo [2^256]. *)

val div : word -> word -> word
(** [DIV] — truncating unsigned division, zero on division by zero. *)

val sdiv : word -> word -> word
(** [SDIV] — truncating two's-complement signed division, zero on division by
    zero. [sdiv (-2^255) (-1)] is [-2^255] (the quotient wraps). *)

val modulo : word -> word -> word
(** [MOD] — unsigned remainder, zero on a zero modulus. *)

val smod : word -> word -> word
(** [SMOD] — signed remainder taking the sign of the dividend, zero on a zero
    modulus. *)

val addmod : word -> word -> word -> word
(** [ADDMOD a b n] — [(a + b) mod n] over the true 257-bit sum, zero when [n] is
    zero. *)

val mulmod : word -> word -> word -> word
(** [MULMOD a b n] — [(a * b) mod n] over the true 512-bit product, zero when
    [n] is zero. *)

val exp : word -> word -> word
(** [EXP a b] — [a ^ b] modulo [2^256]. *)

val signextend : word -> word -> word
(** [SIGNEXTEND b x] — sign-extend [x] from the byte at index [b], counted from
    the least-significant byte; [x] is returned unchanged when [b >= 31]. *)

val lt : word -> word -> word
(** [LT] — unsigned less-than, one or zero. *)

val gt : word -> word -> word
(** [GT] — unsigned greater-than. *)

val slt : word -> word -> word
(** [SLT] — signed less-than. *)

val sgt : word -> word -> word
(** [SGT] — signed greater-than. *)

val eq : word -> word -> word
(** [EQ] — equality. *)

val iszero : word -> word
(** [ISZERO] — one exactly when the word is zero. *)

val logand : word -> word -> word
(** [AND]. *)

val logor : word -> word -> word
(** [OR]. *)

val logxor : word -> word -> word
(** [XOR]. *)

val lognot : word -> word
(** [NOT] — bitwise complement. *)

val byte : word -> word -> word
(** [BYTE i x] — the [i]-th byte of [x] counted from the most-significant, as a
    word in the low byte; zero when [i >= 32]. *)

val shl : word -> word -> word
(** [SHL shift value] — logical left shift of [value] by [shift], zero when
    [shift >= 256]. *)

val shr : word -> word -> word
(** [SHR shift value] — logical right shift of [value] by [shift], zero when
    [shift >= 256]. *)

val sar : word -> word -> word
(** [SAR shift value] — arithmetic (sign-propagating) right shift of [value] by
    [shift]. *)
