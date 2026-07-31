(** The rolling [BLOCKHASH] window the engine carries from block to block.

    {!Tn_evm.Block_hashes} is the window a single block is executed against, and
    it reads an ancestor nobody supplied as zero, with no error anywhere. That
    makes a window handed over backwards a state-root divergence with no
    symptom, so this type removes the way to hand one over at all: there is no
    list-taking function after creation, and {!push} prepends, so newest-first
    stops being a call convention and becomes a property of the value.

    The window lives in the engine's state, which is what makes it roll across
    blocks {e and} across outputs. A skipped output leaves it untouched, and an
    error drops it with the rest of the state. *)

type t
(** The most recent ancestor hashes, newest first, never more than
    {!Tn_evm.Block_hashes.depth_limit} of them, and never empty. *)

val of_genesis : Tn_keccak.t -> ancestors:Tn_keccak.t list -> t
(** The window at engine start. The first argument is the anchor's own hash and
    is mandatory, so an empty window cannot be built; [ancestors] are the
    anchor's own ancestors, newest first and EXCLUDING it, and are [[]] at a
    true genesis. A node resuming mid-chain owes up to
    {!Tn_evm.Block_hashes.depth_limit} [- 1] real ancestors here: a short list
    is not an error, it silently reads zero for the ancestors it omits, which
    describes a chain that does not exist. *)

val push : t -> Tn_keccak.t -> t
(** Record a block just assembled: it becomes the newest entry and the oldest
    beyond the depth limit is dropped, so {!depth} never passes it. The engine
    pushes AFTER assembling a block, never before executing it, so that
    [BLOCKHASH(n-1)] answers the parent rather than block [n] itself. Note what
    this ordering does NOT buy: a block reading its OWN height already reads
    zero without it, because {!Tn_evm.Block_hashes.lookup} answers zero for any
    depth below one whatever the window holds. *)

val window : t -> Tn_evm.Block_hashes.t
(** The window as one block's executor consumes it. *)

val depth : t -> int
(** How many hashes are held. Truncation is invisible through {!window}, which
    re-truncates anyway, so this is the only place the cap can be observed. *)

val to_list : t -> Tn_keccak.t list
(** The hashes, newest first: the projection an equality assertion can compare
    across two engine states. *)
