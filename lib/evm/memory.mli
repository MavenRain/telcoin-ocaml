(** The EVM's byte-addressed volatile memory: zero-filled, expanding in 32-byte
    words, private to one execution frame.

    Memory is conceptually an infinite array of zero bytes of which a prefix has
    been {e paid for}. Two things follow, and this module keeps them apart.
    Reading is total — a byte that was never written is zero — so nothing here
    can fail. Expansion is where the cost lives: touching a byte at some offset
    obliges the frame to pay for every 32-byte word up to and including it, and
    that charge is the caller's business ({!Gas.expansion_cost}), because only
    the caller holds the gas. The interpreter therefore always computes
    {!words_needed}, charges the difference, and only then calls {!expand} and
    reads or writes.

    The size a program observes ([MSIZE]) is that paid-for prefix in bytes,
    always a multiple of 32 — so a single [MSTORE8] at offset zero makes [MSIZE]
    report 32, not 1.

    The representation is canonical: only nonzero bytes are stored, so {!equal}
    is exact content equality regardless of how the contents were written. It is
    a persistent map keyed by byte offset, chosen for that canonicity and for
    being immutable — a word access is therefore logarithmic in what has been
    written rather than the constant-time index into a flat buffer revm uses, and
    a sparse write far from the rest costs nothing in space. That trade favours
    clarity over speed deliberately; a flat representation is a later change that
    no caller of this interface can observe. *)

type word = Tn_state.U256.t

type t
(** A frame's memory: a word count that has been paid for, and its contents. *)

val empty : t
(** Zero words, all bytes zero — the memory a frame begins with. *)

val words : t -> int
(** The number of 32-byte words the frame has expanded to. *)

val size_bytes : t -> int
(** The expanded size in bytes — [32 * ]{!words}, the value [MSIZE] pushes. *)

val words_needed : offset:int -> length:int -> int option
(** The word count that reading or writing [length] bytes from [offset]
    requires: [ceil ((offset + length) / 32)].

    Zero for a zero [length] at any offset — a zero-length operation touches no
    memory at all, so it neither expands nor pays, and its offset is irrelevant
    even when that offset is enormous (the rule [RETURN] and [REVERT] rely on).

    [None] when [offset + length] cannot be represented, which means an offset so
    far out that no gas allowance could pay for reaching it. See
    {!Interpreter.error} on why conflating that with any other exceptional halt
    is safe. *)

val expand : t -> int -> t
(** [expand t words] grows the paid-for prefix to [words] words. It never
    shrinks: expanding to fewer words than {!words} returns [t] unchanged, which
    is what makes charging the {e difference} correct. Expansion is [O(1)] — the
    zero bytes it exposes are not materialised. *)

val load_word : t -> int -> word
(** The 32 bytes at an offset, big-endian, as a word. Total: bytes past the
    expanded prefix read as zero. Callers expand first, so that never happens
    during execution. *)

val store_word : t -> int -> word -> t
(** Write a word's 32 big-endian bytes at an offset. *)

val store_byte : t -> int -> int -> t
(** Write one byte (the low eight bits of the argument) at an offset — [MSTORE8],
    whose stack operand is a word of which only the least-significant byte is
    stored. *)

val slice : t -> offset:int -> length:int -> string
(** [length] bytes from [offset], the output form [RETURN] and [REVERT] hand
    back, zero-filled past what was written.

    Unlike the reads above this one is {e not} total in its arguments: [length]
    must be non-negative and small enough to allocate. The caller discharges that
    by having paid for the same extent first — {!words_needed} refuses a negative
    or unrepresentable one, and {!Gas.memory_cost} prices anything large enough to
    matter beyond any allowance — so during execution the precondition always
    holds. *)

val equal : t -> t -> bool
(** Exact equality: the same paid-for size and the same bytes. *)
