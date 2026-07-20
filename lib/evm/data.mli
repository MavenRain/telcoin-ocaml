(** A read-only byte window with the EVM's out-of-range rule built in: reading
    past the end yields zeroes, and a source offset too large to be an offset
    yields all zeroes rather than failing.

    This is where a port most easily diverges, so the rule lives in exactly one
    place. revm converts a copy's {e source} offset with [as_usize_saturated!]
    and zero-fills the shortfall — for calldata at [revm-interpreter]
    [instructions/system.rs:174] and for code at [:92] — while converting the
    {e length} and the {e destination} with [as_usize_or_fail!] ([:83], [:164],
    [:261]). A source offset of [2^255] is therefore not an error; it reads
    nothing. Only the length and the destination can halt a frame, and those are
    the caller's business because only the caller holds the memory and the gas.

    One type serves calldata and code because the rule is the same for both.
    That is not tidiness: [CALLDATACOPY] and [CODECOPY] are priced identically
    ({!Gas.copy_cost}) and specified identically, and making them call the same
    function is how this port stops them drifting apart. *)

type t
(** A byte string read through the zero-extension rule. Any string is one, so
    there is no error type here and no smart constructor to fail. *)

val empty : t
(** No bytes — the calldata of a call that sent none, and the code of an account
    that has none. *)

val of_string : string -> t
(** Admit a byte string. Total. *)

val to_string : t -> string
(** The bytes as given, without the notional zero extension, which is infinite. *)

val length : t -> int
(** The number of bytes present — what [CALLDATASIZE] and [CODESIZE] push. *)

val word_at : t -> Tn_state.U256.t -> Tn_state.U256.t
(** [CALLDATALOAD]: the thirty-two bytes at a byte offset, big-endian,
    zero-filled past the end.

    Total, and total in the {e word} rather than in an [int]: an offset that
    cannot be an [int] saturates and reads all zeroes, which is exactly what
    revm's [as_usize_saturated!] produces ([instructions/system.rs:109]), so no
    conversion can fail and the interpreter needs no error path here at all. *)

val read : t -> offset:Tn_state.U256.t -> length:int -> string
(** [length] bytes from a saturating source offset, zero-filled past the end —
    the source half of [CALLDATACOPY] and [CODECOPY]. [length] must be
    non-negative and at most {!Memory.max_extent}; the caller discharges that by
    having reached the destination extent for the same length first, exactly as
    {!Memory.slice} requires.

    Note which half of that does the work. Paying {!Gas.copy_cost} does not bound
    [length] — the copy price is linear, so lengths well past what any host can
    allocate remain affordable. The bound comes from {!Memory.words_needed},
    which the expansion goes through and which refuses any extent past
    {!Memory.max_extent}. See that constant for why a gas-only precondition here
    was a genuine hazard rather than a loose comment. *)

val equal : t -> t -> bool
(** Byte equality. Exact, because the representation is the bytes themselves:
    the zero extension is a reading rule, never a stored suffix, so no two
    distinct representations can read alike. *)
