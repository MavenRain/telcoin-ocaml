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

val max_extent : int
(** The greatest byte extent — [offset + length] — that any operation is
    permitted to reach: [0x1_0000_0000], four gibibytes. {!words_needed} refuses
    anything past it, and since every read and write in this module and in
    {!Data} is preceded by that call, no allocation either module performs can
    exceed it.

    {3 Why this number refuses nothing}

    Four gibibytes is [2^27] words, and the [3w + w^2/512] curve
    {!Gas.memory_cost} charges prices that memory at
    [3 * 2^27 + 2^54 / 512 = 402_653_184 + 35_184_372_088_832 =
    35_184_774_742_016] units. A frame's allowance is bounded by the gas limit of
    the block containing it, which {!Gas} notes is around [2^25]; the bound is
    therefore more than a million whole blocks' worth of gas. Every extent it
    refuses was already unpayable, so no program that could have run is stopped
    by it. That is what makes the constant exact rather than arbitrary: it is a
    cheap early refusal of something the gas schedule would refuse anyway.

    Reading the same curve the other way says something stronger, and explains
    why the precise value matters so little. Inverting [3w + w^2/512] against a
    whole block's [2^25] units gives about [130_000] words — some four
    megabytes. {e That}, not this constant, is the largest memory any real
    execution reaches, and it is what actually keeps allocations small. A frame
    cannot get near four gibibytes to begin with, so this is a backstop that
    closes the totality argument rather than a limit programs are expected to
    meet. Any value comfortably above block-reachable memory and comfortably
    below [max_int] would serve; this one is the largest extent expressible as an
    unsigned 32-bit count, chosen for being easy to state and hard to mistype.

    {3 Why it has to exist}

    Without it the arithmetic refuses only once an intermediate leaves the native
    [int] range, which takes some [1.55e12] bytes — and every extent below that
    is payable by a perfectly legal, [u64]-representable allowance. A frame
    handed one would charge its gas, succeed, and then ask {!slice} or
    {!Data.read} for a string of that length, so the run would hang allocating or
    die out of memory instead of returning an outcome. Worse, which of those
    happened would depend on the machine: one node completes a block that another
    node cannot. Host-dependent divergence is exactly what {!Interpreter.run}
    being a pure, total function exists to rule out, so the gap is closed here
    rather than left to the operator.

    {3 This is not revm parity}

    revm has the same hazard and gates it behind an {e optional} [memory_limit]
    cargo feature ([revm-interpreter] [interpreter/shared_memory.rs:132-140],
    halting with [MemoryLimitOOG] at [:573-575]) whose limit is caller-supplied
    and defaults to [u64::MAX] ([:171]). reth does not enable that feature, so
    upstream the bound is absent and the hazard is live. This port's gate is its
    own, and unconditional on purpose: a consensus machine may not have a failure
    mode that the host decides. Because no reachable extent is affected, the two
    still agree on every execution either one can actually perform. *)

val words_needed : offset:int -> length:int -> int option
(** The word count that reading or writing [length] bytes from [offset]
    requires: [ceil ((offset + length) / 32)].

    Zero for a zero [length] at any offset — a zero-length operation touches no
    memory at all, so it neither expands nor pays, and its offset is irrelevant
    even when that offset is enormous (the rule [RETURN] and [REVERT] rely on).

    [None] for a negative [offset] or [length], and for any extent past
    {!max_extent} — which includes every extent that cannot be represented, since
    the bound is far below [max_int]. All of them name memory no allowance could
    pay to reach. See {!Interpreter.error} on why conflating that with any other
    exceptional halt is safe. *)

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

val store_bytes : t -> offset:int -> string -> t
(** Write a string's bytes at an offset — the destination half of
    [CALLDATACOPY], [CODECOPY] and [MCOPY], which until now had no bulk writer at
    all.

    A zero byte in the source must {e remove} the destination key, not store a
    zero, or the canonicity that makes {!equal} exact is lost and two frames that
    wrote the same bytes by different routes would compare unequal. This is not a
    corner: a copy length routinely exceeds its source length, so writing long
    runs of zeroes over previously written memory is the common case. The
    implementation therefore folds {!store_byte}, so the zero-key rule is stated
    once and cannot be re-derived wrongly here.

    The extent must already be paid for and expanded, exactly as for {!slice}.

    [MCOPY] needs no temporary buffer and no direction test. {!slice} produces a
    string from the {e old} memory and this writes it into a new one, so
    overlapping ranges are memmove-correct by construction. revm copies within a
    flat buffer and must reason about direction ([revm-interpreter]
    [instructions/memory.rs:81]); a persistent map does not. The observable
    behaviour is identical, and a property test pins it against an independent
    [Bytes.blit] oracle. *)

val slice : t -> offset:int -> length:int -> string
(** [length] bytes from [offset], the output form [RETURN] and [REVERT] hand
    back, zero-filled past what was written.

    Unlike the reads above this one is {e not} total in its arguments: [length]
    must be non-negative and small enough to allocate. The caller discharges that
    by having reached the same extent first, and it is {!words_needed} that
    supplies the guarantee — it refuses a negative extent and any extent past
    {!max_extent}, so a [length] that arrives here is at most four gibibytes.

    The gas schedule alone does {e not} discharge this, and reading as though it
    did was a real defect: {!Gas.memory_cost} leaves extents up to roughly
    [1.55e12] bytes payable, far past what asking for a string of that length can
    survive. {!max_extent} is the reason the precondition now always holds. *)

val equal : t -> t -> bool
(** Exact equality: the same paid-for size and the same bytes. *)
