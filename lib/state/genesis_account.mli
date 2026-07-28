(** One account of a genesis alloc - Rust's [GenesisAccount] restricted to the
    four fields telcoin's allocs use: nonce, balance, code and storage
    ([tn-reth/src/lib.rs:1626-1631] builds exactly this shape for the
    ConsensusRegistry entry; the committed [chain-configs/testnet/genesis.yaml]
    states the same four per account).

    This is alloc {e input}, not execution state: it exists so that
    {!World_state.of_genesis_alloc} can be one total function of the alloc,
    per the widening [world_state.mli] itself prescribes. It deliberately has
    no behaviour of its own beyond canonical construction; turning an entry
    into an {!Account.t} is the loader's job, where the one refusal
    ({!World_state.alloc_error}) lives. *)

type t
(** An alloc entry. Canonical by construction: a repeated storage slot keeps
    the last value, a zero-valued slot stores nothing, and empty code
    collapses to no code, so {!equal} is exact content equality on meaning. *)

val make :
  nonce:Nonce.t ->
  balance:U256.t ->
  code:string option ->
  storage:(U256.t * U256.t) list ->
  t
(** Total. A repeated slot key takes its last value (later pairs win), and a
    zero value clears the slot, both via {!Storage.set}; [Some ""] normalizes
    to [None], because zero bytes of code is no code under every reader
    ({!Account.code_length}, EIP-161's code conjunct).

    Code length is deliberately {e not} EIP-170-bounded. The bound binds
    [CREATE], never alloc-installed code: the pre-fork ConsensusRegistry
    runtime is 28381 bytes, over the 24576 cap, and enters state only by
    alloc - Rust deploys it on a throwaway chain with the size limit lifted
    ([tn-reth/src/lib.rs:1528-1532]) and copies the result into the alloc. *)

val balance_only : U256.t -> t
(** The old [of_alloc] shape: the given balance at nonce zero, no code, empty
    storage - Rust's [GenesisAccount::with_balance] on a default account. *)

val nonce : t -> Nonce.t
(** The starting nonce. *)

val balance : t -> U256.t
(** The starting balance, in wei. *)

val code : t -> string option
(** The runtime bytecode to install, [None] for a codeless account. Never
    [Some ""]: {!make} normalizes empty code away. *)

val storage : t -> Storage.t
(** The pre-populated storage slots, already canonical. *)

val has_code : t -> bool
(** Whether the entry installs at least one byte of code - the half of
    {!World_state.alloc_error}'s refusal predicate this module can answer. *)

val equal : t -> t -> bool
(** Exact content equality over all four fields - sound because construction
    is canonical. *)
