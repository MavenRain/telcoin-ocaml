(** An execution-layer account — the port of Rust's account state.

    An account is what the world state maps an address to: its {!nonce} (the
    number of transactions it has sent), its {!balance} (its native-token
    holdings), its {!storage} (the contract slots written at that address) and
    its {!code} (the bytecode deployed there). Rust's account also carries a
    [storage_root] — the trie hash committing the slot map — which needs the
    state trie and RLP, and those this port still defers. The [code_hash] Rust
    stores is here {e derived} from the code rather than stored ({!code_hash}),
    so there is no hash-matches-bytes invariant to keep.

    Code arrives as of this chunk. It is set through {!with_code}; nothing
    produces it from execution yet, because that is [CREATE]'s job, so every
    account a run itself builds is still codeless and {!is_empty}'s code conjunct
    is [true] of it. What code enables now is the external-code readers —
    [EXTCODESIZE], [EXTCODECOPY] and [EXTCODEHASH] — reading an account seeded
    with code, at genesis or by a test, through {!World_state.set_account}. *)

type t

val make : nonce:Nonce.t -> balance:U256.t -> t
(** An account with the given nonce and balance, empty storage and no code.
    Neither storage nor code is a labelled argument: every caller that
    constructs an account constructs one that has never executed and holds
    neither, and a required [~storage] or [~code] would make each of them pass
    an empty value to say so. Slots arrive through {!set_slot} and
    {!with_storage}, code through {!with_code}, which are the only ways execution
    or a genesis produces them. *)

val empty : t
(** Zero nonce, zero balance, empty storage and no code — an account that has
    never been touched, the value the world state reads back for an address it
    holds no entry for. *)

val nonce : t -> Nonce.t
val balance : t -> U256.t
val storage : t -> Storage.t

val code : t -> string
(** The deployed bytecode, as raw bytes. This is what [EXTCODECOPY] copies out
    of an account: the interpreter wraps it in a {!Tn_evm.Data.t} to read it
    through the same zero-extension rule [CODECOPY] and [CALLDATACOPY] obey. An
    account with no code reads back the empty string. *)

val code_length : t -> int
(** The number of code bytes — what [EXTCODESIZE] pushes. Zero for a codeless or
    absent account. *)

val code_hash : t -> Tn_keccak.t
(** The Keccak-256 of the code — {!Bytecode.hash}. The digest [EXTCODEHASH]
    reports for an account that {e exists}; the zero it reports for an account
    that does not is EIP-1052's, produced by the interpreter as a bare word and
    never a digest. The hash of a codeless account is [KECCAK_EMPTY], not zero,
    which is why [EXTCODEHASH] tests emptiness rather than reads this. *)

val with_storage : t -> Storage.t -> t
(** The account with its storage replaced. Nonce, balance and code are
    untouched: [SSTORE] moves no value, sends no transaction and deploys no
    code. *)

val slot : t -> U256.t -> U256.t
(** The word at a storage slot, zero if unwritten — {!Storage.get} lifted. *)

val set_slot : t -> U256.t -> U256.t -> t
(** The account after an [SSTORE]. Writing zero clears the slot. *)

val with_code : t -> string -> t
(** The account with its code replaced by the given bytes. Nonce, balance and
    storage are untouched. This is the only writer of code, the seam a genesis
    allocation or (later) [CREATE] deploys through; until [CREATE] lands it is
    reached only by a genesis seeding a pre-deployed contract or by a test. *)

val is_empty : t -> bool
(** The EIP-161 emptiness test: zero nonce, zero balance and no code. Storage is
    deliberately {e not} a conjunct, because EIP-161 does not make it one: the
    specification deletes a touched account on nonce, balance and code alone.
    This is the predicate [EXTCODEHASH] folds to zero on (EIP-1052) and the one a
    [CALL]-to-empty surcharge will use, and it must stay literal.

    It is {e not} the predicate the world state prunes on. See {!is_absent}. *)

val is_absent : t -> bool
(** [is_empty t && Storage.is_empty (storage t)] — the predicate
    {!World_state.set_account} prunes on, and the reason {!World_state.equal} is
    still exact content equality now that accounts carry storage and code.

    The two predicates exist separately because they answer different questions.
    {!is_empty} asks what the protocol considers an empty account; {!is_absent}
    asks whether an entry carries any information at all, which is what makes
    deleting it representation-preserving. On a real chain they agree on every
    account that can exist: reaching storage requires executing [SSTORE] at that
    address, which requires the account to be running its own code, which makes
    {!is_empty} false. So the divergent class — zero nonce, zero balance, no
    code, {e nonempty storage} — cannot arise there.

    It can still arise here, and code existing did not change that. A run's
    [SSTORE] writes to the world entry of its call target while the frame
    executes the {!Tn_evm.Code.t} it was {e handed}, not the target's own code,
    so a slot can be written into an account that carries none. The two
    predicates therefore still differ on exactly that class, and pruning on the
    stronger {!is_absent} keeps the account rather than losing its writes — the
    conservative direction. What closes the gap is not code on an account but
    execution running an account's {e own} code, so that a stored slot implies
    deployed code; that arrives with [CALL] and [CREATE]. *)

val credit : t -> U256.t -> t option
(** Add to the balance, [None] on the (total-supply-unreachable) 256-bit
    overflow. *)

val debit : t -> U256.t -> t option
(** Subtract from the balance, [None] when the balance is below the amount. *)

val increment_nonce : t -> t
(** The account after sending one transaction: its nonce advanced by one. *)

val increment_nonce_checked : t -> t option
(** The same advance, [None] when the nonce is already at its maximum and there
    is no next one. Contract creation is the caller that needs the difference:
    revm abandons a creation whose creator cannot be bumped rather than reusing
    the nonce, and reusing it would derive the same address twice. See
    {!Nonce.succ_checked}. *)

val is_occupied : t -> bool
(** Whether an address is already taken, in the sense that decides a [CREATE]
    collision: it has code, or it has a nonzero nonce ([revm-context]
    [journal/inner.rs:409]).

    Balance is not part of it. An address that has only received ether is
    unoccupied and can still be created at, which is what lets a counterfactual
    [CREATE2] address be funded before its contract is deployed. This is
    therefore a strictly weaker test than the negation of {!is_empty}, and the
    two must not be substituted for each other: an account holding only a balance
    is neither empty nor occupied. *)

val equal : t -> t -> bool
(** Exact content equality over every field, storage and code included — sound
    because {!Storage.t} and {!Bytecode.t} are each canonical on their own. *)

val compare : t -> t -> int
