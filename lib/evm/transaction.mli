(** A single transaction, ready for the state-transition executor.

    This is the typed input to {!Executor.execute}: the fields reth recovers from
    a signed transaction and hands the EVM, minus the two the port still defers.
    The sender is {e pre-recovered} from the signature, a crypto step upstream of
    this pure transition and the same one {!Tn_state.Transfer} already assumes, so
    it enters as an address rather than a signature. That step is now
    {!Tx_envelope.decode_2718} followed by {!Tx_recovery.recover}: the first turns
    raw envelope bytes into a signed envelope, the second recovers its signer and
    produces exactly this type, so a caller no longer has to assume the sender it
    passes. And the scope is the shared
    path for the three fee-market transaction types that share a code path in
    revm: Legacy (type 0), EIP-2930 (type 1) and EIP-1559 (type 2). EIP-7702
    set-code transactions and EIP-4844 blob transactions are deferred exactly as
    the blob and delegated-code opcodes are, so there is no authorization list and
    no blob field here.

    The {!kind} distinguishes a call from a creation, because they diverge on more
    than the presence of a [to] address: a creation carries no target, derives the
    address it deploys to from the sender's nonce, pays the EIP-3860 initcode
    surcharge, and bumps the sender's nonce {e inside} its frame rather than before
    it (see {!Executor}). The {!fee} carries the price fields each type actually
    has: a Legacy or EIP-2930 transaction has one [gas_price], while an EIP-1559
    transaction has a max fee and an optional priority fee, and the effective price
    is derived from the block's base fee through {!effective_gas_price}. *)

open Tn_types

type word = Tn_state.U256.t

type kind =
  | Call of Units.Address.t
      (** A message call to an existing account (the [to] address). An empty
          account is a plain value transfer; a coded one runs its code. *)
  | Create
      (** A contract creation ([to] absent). The address it deploys to is derived
          from the sender and the transaction nonce, and the transaction's data is
          the init code the creation frame runs. *)

type fee =
  | Legacy of { gas_price : word }
      (** A type-0 transaction: a single gas price, no access list warmed, and a
          chain id that may be omitted (EIP-155 is optional for legacy). *)
  | Access_list of { gas_price : word }
      (** A type-1 (EIP-2930) transaction: a single gas price like legacy, but its
          access list is warmed and its chain id is required. *)
  | Dynamic of { max_fee : word; max_priority : word option }
      (** A type-2 (EIP-1559) transaction: a maximum fee per gas and an optional
          priority fee (the miner tip). The effective price is
          [min(max_fee, base_fee + priority)], or [max_fee] when no priority is
          given, computed by {!effective_gas_price}. *)

type t
(** A transaction. Abstract: built by {!make} and read through the accessors. *)

val make :
  sender:Units.Address.t ->
  nonce:Tn_state.Nonce.t ->
  gas_limit:int ->
  kind:kind ->
  value:word ->
  data:string ->
  access_list:(Units.Address.t * word list) list ->
  chain_id:word option ->
  fee:fee ->
  t
(** Assemble a transaction. [gas_limit] is a native [int] because that is what an
    allowance is throughout this port (see {!Gas}); a real block's gas limit is
    around [2^25], far inside the 63-bit range. [data] is the raw calldata for a
    {!Call} or the raw init code for a {!Create}. [access_list] is the EIP-2930
    list in its declared grouped form, slots under their address; it is empty for
    a well-formed {!Legacy} transaction and warmed only for the typed ones. *)

val sender : t -> Units.Address.t
(** The externally owned account that signed the transaction, pre-recovered. *)

val nonce : t -> Tn_state.Nonce.t
(** The nonce the transaction claims, which must equal the sender's current
    account nonce for the transaction to be valid. *)

val gas_limit : t -> int
(** The maximum gas the transaction may consume. *)

val kind : t -> kind
(** Whether this is a call or a creation. *)

val value : t -> word
(** The wei moved from sender to the call target or the created contract. *)

val data : t -> string
(** The calldata (for a {!Call}) or the init code (for a {!Create}). *)

val access_list : t -> (Units.Address.t * word list) list
(** The EIP-2930 access list in declared grouped form. *)

val chain_id : t -> word option
(** The chain id the transaction commits to, or [None] for a legacy transaction
    that omitted EIP-155 replay protection. *)

val fee : t -> fee
(** The fee-market fields, which also identify the transaction type. *)

val effective_gas_price : t -> base_fee:word -> word
(** The price actually charged per unit of gas, given the block's base fee, a
    transcription of revm's default trait method
    ([revm-context-interface] [transaction.rs:147-160]).

    For a {!Legacy} or {!Access_list} transaction it is the [gas_price] verbatim.
    For a {!Dynamic} transaction with no priority fee it is the [max_fee]; with a
    priority fee it is [min(max_fee, base_fee + priority)], the addition
    saturating at the 256-bit ceiling. It is deducted per unit of {e allocated}
    gas up front and reimbursed per unit of {e unused} gas at the end. *)

val max_fee_per_gas : t -> word
(** The ceiling the sender agreed to pay per unit of gas: the [gas_price] for
    Legacy and EIP-2930, the [max_fee] for EIP-1559. This is the price the
    pre-execution balance {e check} multiplies the gas limit by, distinct from the
    {!effective_gas_price} that is actually {e deducted}. *)
