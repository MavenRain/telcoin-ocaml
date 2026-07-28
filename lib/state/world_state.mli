(** The world state — the map from address to {!Account}.

    The execution state maps every 20-byte address to its {!Account}. An address
    with no entry reads back as {!Account.empty} (EVM semantics: an untouched
    account has zero nonce, zero balance and no storage), so the state is total
    on addresses, and total again at the slot level: {!storage} of a slot of an
    account that does not exist is zero. The representation is kept canonical —
    an entry that carries no information is never stored — so {!equal} is exact
    content equality, and two nodes that applied the same transactions from the
    same genesis hold identical states.

    An account's storage lives {e inside} its entry rather than in a second map
    keyed by address and slot. That placement is the reason orphan storage — a
    slot surviving the account it belongs to — is not representable here, and it
    is why {!remove_account} cannot forget half of its job.

    A state root (the trie hash that commits the whole map) now exists as
    [Block_roots.state_root] in [tn_evm], with [Block_roots.agree] the state-root
    agreement oracle for block import. They live one library up because
    [tn_state] sits below [tn_trie] in the dependency graph. {!equal} is kept as
    the exact structural equality the canonicity reasoning above relies on.

    Two facts about membership that EIP-7702 makes load-bearing, recorded here
    because they are properties of this map rather than of any one function.

    First, an entry {b exists} in this map exactly when
    [not (Account.is_absent (account t addr))]. {!set_account} prunes every
    {!Account.is_absent} account ([world_state.ml:26-27]) and
    {!of_genesis_alloc} routes through it, so the two questions have one answer
    and this module deliberately offers no second membership predicate to
    disagree with the first. That equivalence is what lets EIP-7702's refund
    test - revm asks whether the authority was loaded as not existing
    ([revm-handler] [pre_execution.rs:252-259]) - key on {!Account.is_absent}
    here. The single state it costs is revm's "present in the database with an
    all-zero account info", which this representation cannot express at all;
    on a post-Spurious-Dragon chain such accounts are cleared, so the gap is
    latent rather than live.

    Second, once an authorization has been applied, the authority is
    materialised {b permanently}: {!Account.delegate} always bumps the nonce, so
    the account sits at nonce one or above and EIP-161's clearing pass can never
    prune it again ([revm-database] [states/cache.rs:193-239]). Revoking does
    not undo it. Authorizing an address that held nothing therefore adds a
    nonce-one account to the state for good. *)

open Tn_types

type t

val empty : t
(** No accounts — every address reads as {!Account.empty}. *)

val of_alloc : (Units.Address.t * U256.t) list -> t
(** The balance-only genesis: fund each listed address at nonce zero, no code,
    empty storage - the port of Rust's [GenesisAccount::with_balance]. A
    repeated address takes its last allocation; a zero allocation stores no
    entry. This is now the special case of {!of_genesis_alloc} over
    {!Genesis_account.balance_only} entries, delegating there so genesis stays
    one function; a balance-only entry cannot carry storage, so the delegation
    cannot hit {!alloc_error}. *)

type alloc_error =
  | Storage_without_code of Units.Address.t
      (** The alloc entry at this address pre-populates storage but installs no
          code. Refused rather than seeded: an account with storage and neither
          nonce, balance nor code is the exact class on which this module's
          pruning rule ({!set_account}'s {!Account.is_absent}) diverges from
          revm's EIP-161 touch-clearing, and refusing it at the genesis door
          keeps that divergence unreachable from any loaded alloc - see the
          comment at [world_state.ml]'s [set_account]. No committed telcoin
          alloc has such an entry (every storage-carrying account in
          [chain-configs/testnet/genesis.yaml] and [mainnet/genesis.yaml]
          carries code), so nothing representable is lost. *)
  | Malformed_delegation of Units.Address.t * Delegation.decode_error
      (** The alloc entry at this address installs code beginning [0xEF 0x01]
          that is not a well-formed {!Delegation.length}-byte designator.

          revm reaches such bytes only as a {e database decode failure}
          ([revm-bytecode] [bytecode.rs:101-110]), never as executable code, so
          refusing them here is what makes {!Delegation.Undecodable} unreachable
          from any world a transaction runs against - and therefore what lets
          the sites that classify account code treat that arm as a documented
          divergence rather than a live case.

          Ordered {e after} {!Storage_without_code}, so that error's identity is
          unchanged for an entry which would trip both.

          A {b well-formed} designator in a genesis allocation is accepted, and
          it is {b live}: classification keys on the first two bytes, so such an
          account delegates with no authorization anywhere in the transaction
          that calls it. *)

val error_to_string : alloc_error -> string
(** Render an {!alloc_error} for diagnostics. *)

val of_genesis_alloc : (Units.Address.t * Genesis_account.t) list -> (t, alloc_error) result
(** The genesis state as one total function of the alloc: each entry seeds its
    nonce, balance, code {e and storage} - the port of Rust's genesis [alloc]
    as [tn-reth/src/lib.rs:1626-1631] builds it for the ConsensusRegistry
    (balance, runtime code, constructor-derived storage). A repeated address
    takes its last entry; an entry whose account is {!Account.is_absent}
    stores nothing. The one refusal is {!alloc_error}: storage on a codeless
    account. Widening this constructor, rather than writing slots in
    afterwards with {!set_storage}, is what the old [of_alloc] doc demanded of
    a genesis that pre-populates storage. *)

val account : t -> Units.Address.t -> Account.t
(** The account at an address, {!Account.empty} if the state holds no entry for
    it. Total. *)

val set_account : t -> Units.Address.t -> Account.t -> t
(** Replace the account at an address. An {!Account.is_absent} account removes
    the entry, keeping the representation canonical.

    Note the predicate. This used to prune on {!Account.is_empty}, which ignores
    storage — correctly, since EIP-161 ignores storage. With storage present
    that would erase an [SSTORE] into an account of zero nonce and zero balance,
    and {!equal} would stop being exact: two states differing in that slot would
    compare equal. {!Account.is_absent} is strictly stronger and covers every
    field {!Account.equal} compares, which is exactly the condition canonicity
    needs. *)

val balance : t -> Units.Address.t -> U256.t
val nonce : t -> Units.Address.t -> Nonce.t

val storage : t -> Units.Address.t -> U256.t -> U256.t
(** The word at a slot of an account, zero for an account with no entry or a
    slot never written. Total at both levels, in both arguments. *)

val set_storage : t -> Units.Address.t -> U256.t -> U256.t -> t
(** Write a word to one slot of one account, creating the entry if the write is
    nonzero and removing it again if the account is left {!Account.is_absent}.
    Clearing the only nonzero slot of an otherwise-empty account therefore
    restores a state {!equal} to the one before the first write. *)

val remove_account : t -> Units.Address.t -> t
(** Delete an account and, with it, all of its storage — the two halves live in
    one entry, so they cannot come apart.

    Its callers are deferred: [SELFDESTRUCT] and the end-of-transaction clearing
    of touched-empty accounts. It exists now so that the rule "deleting an
    account deletes its storage" has a named home before a later chunk
    rediscovers it, and so that a design that ever splits the two halves has an
    obvious thing to break. *)

val accounts : t -> (Units.Address.t * Account.t) list
(** Every stored (non-absent) account, in ascending address order. *)

val equal : t -> t -> bool
(** Exact content equality — still sound now that accounts carry storage,
    and code, because {!Storage.t} and {!Bytecode.t} are each canonical on their
    own and {!Account.is_absent} covers every field {!Account.equal} compares. *)
