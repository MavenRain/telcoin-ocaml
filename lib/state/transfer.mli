(** A value transfer and its state transition.

    A transfer moves native tokens from one account to another. It is the base
    case of execution — a transaction with no code to run — carrying only the
    fields a transfer needs: the {!sender} (already recovered from the signature,
    a crypto-deferred step upstream of this pure transition), the {!recipient},
    the {!value} to move and the sender {!nonce} the transfer must match.

    Gas metering and fee payment — which need a gas price, a block base fee and
    the coinbase account — arrive with the interpreter chunk; this transition
    applies the two checks a transfer always makes (the nonce must be the sender's
    current nonce and the balance must cover the value), then moves the value and
    advances the sender's nonce. It is the first engine behind the
    {!Tn_execution.Engine.ENGINE} seam to carry a genuine {!error}, in place of
    the no-op engine's uninhabited one. *)

open Tn_types

type t

val make :
  sender:Units.Address.t ->
  recipient:Units.Address.t ->
  value:U256.t ->
  nonce:Nonce.t ->
  t

val sender : t -> Units.Address.t
val recipient : t -> Units.Address.t
val value : t -> U256.t
val nonce : t -> Nonce.t

type error =
  | Nonce_mismatch of { expected : Nonce.t; actual : Nonce.t }
      (** The transfer's nonce is not the sender's current nonce. [expected] is
          the account's nonce, [actual] the transfer's. *)
  | Insufficient_balance of { balance : U256.t; value : U256.t }
      (** The sender's balance does not cover the value. *)
  | Balance_overflow
      (** Crediting the recipient would exceed [2^256]. Defends the credit and
          keeps the transition total. Not merely theoretical here: the Rust
          genesis funds several accounts with {!U256.max_value}
          ([GenesisAccount::with_balance(U256::MAX)]), so the total supply is far
          above [2^256] and a transfer into an already-near-maximal balance can
          reach it. *)

val error_to_string : error -> string

val apply : World_state.t -> t -> (World_state.t, error) result
(** Apply the transfer to the world state: check the nonce, check the balance,
    debit the sender and advance its nonce, then credit the recipient. The
    recipient is credited from the already-updated state, so a self-transfer nets
    to zero and still advances the nonce. On any [error] the state is unchanged.

    A note on how the three errors map to reth's transaction inclusion. A
    {!Nonce_mismatch} or an {!Insufficient_balance} is a pre-execution rejection
    in reth too — the transaction is invalid, never included, and no state
    changes — so returning [Error] with the state untouched is faithful.
    {!Balance_overflow}, by contrast, only surfaces mid-execution, after reth has
    already advanced the sender's nonce (and charged gas): reth includes the
    transaction as a failed one, keeping the nonce advance and reverting only the
    value movement. This pure transition has no gas or block-inclusion layer yet,
    so it reverts atomically and surfaces the overflow as an [Error]; modelling
    the included-and-failed nonce advance and the fee charge belongs with the gas
    and block-execution chunk, which owns transaction inclusion. *)
