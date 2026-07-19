(** Legacy contract bytecode, and the jump-destination analysis every jump is
    checked against.

    A jump may only land on a [JUMPDEST] byte that is really an instruction —
    never on a [0x5b] that happens to sit inside a [PUSH]'s immediate data. That
    cannot be decided by looking at the target byte alone, so it is decided once,
    when the code is admitted, by walking the code from the start and stepping
    over each [PUSH] immediate. Analysing once and consulting a set afterwards is
    also what makes a jump [O(log n)] rather than a rescan.

    Reading a byte is total: every offset past the end reads as zero, which is
    [STOP]. That is exactly the behaviour revm produces by physically padding the
    code — appending enough zero bytes to cover a truncated trailing immediate
    plus a terminal [STOP] — so a [PUSH] whose data runs off the end reads
    zero-extended, and a program counter that walks off the end halts instead of
    faulting. Modelling the padding as a total read rather than a real string
    keeps the analysed code identical to the code that was given.

    The padding is never a valid jump destination, since the analysis only ever
    marks offsets within the original code. *)

type t
(** Analysed bytecode: the code as given, plus its valid jump destinations. *)

val of_string : string -> t
(** Admit and analyse a byte string. Total — every string is legal bytecode,
    including the empty one, which is a program that immediately stops. *)

val length : t -> int
(** The code's length in bytes, as given. *)

val byte_at : t -> int -> int
(** The byte at an offset, or zero ([STOP]) at any offset outside the code —
    including a negative one, which no execution produces. *)

val is_valid_jumpdest : t -> int -> bool
(** Whether an offset holds a [JUMPDEST] instruction, and so may be jumped to.
    False for a [0x5b] byte inside push data, for any offset outside the code,
    and for any other instruction. *)

val jumpdests : t -> int list
(** Every valid destination, ascending. *)
