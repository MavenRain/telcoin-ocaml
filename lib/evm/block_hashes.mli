(** The recent block hashes [BLOCKHASH] can see.

    [BLOCKHASH] is the one instruction that reads outside both the state and the
    block being executed: it reaches back into the chain's history. revm answers
    it through the host ([revm-interpreter] [instructions/host.rs:186-216]),
    which reaches a chain database this port does not have.

    So the window is supplied rather than looked up. The value holds the hashes
    of the most recent ancestors, newest first, and the caller assembling a block
    is the one that knows them. That is the same seam every other host fact in
    this port arrives through — {!Env.Block} carries the timestamp and the
    coinbase for the same reason — and it keeps the interpreter total: there is
    no database to fail, so there is no fatal halt to model, where revm has one
    ([host.rs:212], reached when its host has no hash for an in-range block).

    The honest simplification is that the window {e is} the truth. An ancestor
    the caller did not supply reads as zero, exactly as one further back than
    {!depth_limit} does. That is correct near genesis, where the ancestors really
    do not exist, and it is correct for a full window; a caller that supplies a
    short window for a mature chain is describing a chain that does not exist,
    and will read zero where a node would read a hash. Callers therefore supply
    {!depth_limit} hashes, or all of them if the chain is younger than that. *)

val depth_limit : int
(** How far back the instruction can see: [BLOCK_HASH_HISTORY], 256
    ([revm-primitives] [constants.rs]). A request older than this reads zero
    however many hashes the window holds. *)

type t
(** A window of recent block hashes. Canonical: hashes past {!depth_limit} are
    dropped when the window is built, since no request can reach them, so two
    windows that answer every request alike compare {!equal}. *)

val empty : t
(** No ancestors known, so every request reads zero. The honest window for the
    genesis block, and the one a caller that has no history must pass rather than
    be given silently. *)

val of_recent : Tn_keccak.t list -> t
(** The window from a list of ancestor hashes, {e newest first}: the head is the
    hash of the block immediately before the one being executed. Entries past
    {!depth_limit} are discarded. *)

val lookup : t -> current:Tn_state.U256.t -> requested:Tn_state.U256.t -> Tn_state.U256.t
(** The hash [BLOCKHASH] pushes for [requested], with [current] the number of the
    block being executed. Total, and zero on every request outside the window,
    which is four distinct cases revm treats alike ([host.rs:193-216]):

    - [requested] at or past [current] — a block cannot see its own hash or a
      future one, and revm's subtraction underflowing is exactly this case;
    - more than {!depth_limit} blocks back;
    - within the window but not supplied, see the note above;
    - an empty window.

    The block immediately before [current] is at a difference of one, not zero,
    so the first supplied hash answers [current - 1]. *)

val equal : t -> t -> bool
