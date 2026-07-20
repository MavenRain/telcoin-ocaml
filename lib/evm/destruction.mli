(** What a [SELFDESTRUCT] is about to do, priced but not yet done.

    [SELFDESTRUCT]'s cost depends on three facts that only a lookup can settle —
    whether the account has a balance to send, whether the beneficiary already
    exists, and whether the beneficiary was cold — and its {e effect} depends on
    a fourth, whether this account was created in this transaction (EIP-6780).
    revm looks all four up inside the host call that also applies the change, and
    charges the dynamic gas afterwards ([revm-interpreter]
    [instructions/host.rs:399-407]).

    This splits the two, exactly as {!Sstore_state} splits [SSTORE]'s: the plan
    is a value, the price is a function of it, and the write happens only if the
    price was paid. That ordering is not observable through the outcome — a frame
    that cannot pay halts exceptionally and its whole {!Effects.t} is dropped
    either way — but it is expressible without depending on that argument to stay
    sound, which is the same reason [SSTORE] is built this way.

    The warmth is deliberately not a field here. It travels in the
    {!Effects.load} that carries this value, so the price and the lookup that
    justifies it cannot be separated. *)

open Tn_types

type word = Tn_state.U256.t
type t

val make :
  address:Units.Address.t ->
  beneficiary:Units.Address.t ->
  balance:word ->
  beneficiary_exists:bool ->
  deletes:bool ->
  t

val address : t -> Units.Address.t
(** The account running the instruction, and the one whose balance moves. *)

val beneficiary : t -> Units.Address.t
(** Where the balance goes. It may be the account itself, which is the corner
    EIP-6780 turns into two very different outcomes: see {!deletes}. *)

val balance : t -> word
(** The whole balance of {!address} before the instruction, which is what moves.
    Read before anything is applied, so it is also what {!had_value} reports. *)

val had_value : t -> bool
(** Whether that balance was nonzero. Half of the 25000 predicate: EIP-161 makes
    bringing a beneficiary into existence free when there is nothing to send
    ([revm-interpreter] [gas/calc.rs] [dyn_selfdestruct_cost]). *)

val beneficiary_exists : t -> bool
(** Whether the beneficiary is an account that already exists, in the
    state-clearing sense of EIP-161 rather than the "has an entry" sense: an
    account with no code, no nonce and no balance does {e not} exist for this
    purpose, so sending value to it costs the 25000. *)

val deletes : t -> bool
(** EIP-6780: whether this destruction really removes the account, which it does
    only if the account was created in this same transaction. When false the
    instruction is a balance transfer that leaves the code, the storage and the
    nonce exactly where they are — and, in the one case where the beneficiary is
    the account itself, does nothing at all, because there is nowhere for the
    balance to go ([revm-context] [journal/inner.rs:540-549]). *)

val equal : t -> t -> bool
