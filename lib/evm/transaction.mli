(** A single transaction, ready for the state-transition executor.

    This is the typed input to {!Executor.execute}: the fields reth recovers from
    a signed transaction and hands the EVM, minus the one the port still defers.
    The sender is {e pre-recovered} from the signature, a crypto step upstream of
    this pure transition and the same one {!Tn_state.Transfer} already assumes, so
    it enters as an address rather than a signature. That step is now
    {!Tx_envelope.decode_2718} followed by {!Tx_recovery.recover}: the first turns
    raw envelope bytes into a signed envelope, the second recovers its signer and
    produces exactly this type, so a caller no longer has to assume the sender it
    passes. And the scope is the four transaction types the port executes:
    Legacy (type 0), EIP-2930 (type 1), EIP-1559 (type 2) and — since chunk 33 —
    the EIP-7702 set-code transaction (type 4), whose authorization list rides
    in its {!Set_code} fee arm and nowhere else. Only the EIP-4844 blob
    transaction remains deferred, exactly as the blob opcodes are, so there is
    still no blob field here.

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
  | Set_code of {
      max_fee : word;
      max_priority : word;
      target : Units.Address.t;
      authorizations : Authorization.signed list;
    }
      (** A type-4 (EIP-7702) set-code transaction. Three narrowings against
          {!Dynamic}, each closing a state EIP-7702 has no encoding for:

          - [max_priority] is {e not} an option: the wire has no absent case,
            which is the argument {!Tx_payload.Eip1559} already makes for
            type 2;
          - [target] is an ADDRESS and not a {!kind}. [TxEip7702.to] is a bare
            [Address] ([alloy-consensus] [eip7702.rs:58]) against
            [eip1559.rs:56]'s [TxKind], so a set-code CREATION has no
            representation. {!kind} reports [Call target] for this arm and does
            {b not} consult the [~kind] {!make} was given — see the honesty
            clause at {!make};
          - [authorizations] lives here and nowhere else, so a type-4
            transaction cannot lack a list and a type-0/1/2 transaction cannot
            carry one. That matters for gas: revm puts {e no} transaction-type
            gate on the intrinsic term, so a non-7702 transaction carrying
            authorizations would pay 25000 each while the loop applied none
            ([pre_execution.rs:196-200]). Here the case does not arise.

          The list MAY be empty: legal at the RLP layer ({!Tx_envelope}), and
          rejected only in validation ([validation.rs:199-203]) — a rejection
          that lands with the executor stage of chunk 33, not here. *)

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
    a well-formed {!Legacy} transaction and warmed only for the typed ones.

    {b Honesty clause.} [make ~kind:Create ~fee:(Set_code ..)] remains
    constructible. It is neutralised, not excluded: [t] is abstract, {!kind} is
    the only reader, and for that arm {!kind} derives from the arm's own
    [target], so the creation is UNOBSERVABLE. The cost is one stored field that
    is dead for one arm, disclosed here and at {!kind} and pinned by a test, in
    the register [mutability.mli:22-39] established. A future refactor that
    reads the record's [kind] field directly inside [transaction.ml] would
    resurrect the illegal state. Prefer {!set_code}, which cannot even spell the
    dead value. *)

val sender : t -> Units.Address.t
(** The externally owned account that signed the transaction, pre-recovered. *)

val nonce : t -> Tn_state.Nonce.t
(** The nonce the transaction claims, which must equal the sender's current
    account nonce for the transaction to be valid. *)

val gas_limit : t -> int
(** The maximum gas the transaction may consume. *)

val kind : t -> kind
(** Whether this is a call or a creation. For a {!Set_code} fee this is
    {e derived}: it is [Call target] from the fee arm's own field, never the
    value {!make} stored, because a type-4 transaction structurally cannot
    create ([alloy-consensus] [eip7702.rs:58] types [to] as a bare [Address]).
    See the honesty clause at {!make}. *)

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

val set_code :
  sender:Units.Address.t ->
  nonce:Tn_state.Nonce.t ->
  gas_limit:int ->
  target:Units.Address.t ->
  value:word ->
  data:string ->
  access_list:(Units.Address.t * word list) list ->
  chain_id:word ->
  max_priority_fee_per_gas:word ->
  max_fee_per_gas:word ->
  authorizations:Authorization.signed list ->
  t
(** A type-4 transaction. Separate from {!make} because two of its fields are
    narrower: the target is mandatory and the chain id is not an option. [data]
    is CALLDATA and never init code — [is_create] is false for every 7702
    transaction, so neither the 32000 creation surcharge nor EIP-3860 initcode
    metering applies ([gas_params.rs:733-739]). *)

val authorizations : t -> Authorization.signed list
(** The list, EMPTY for every fee but {!Set_code}. Hand THIS to
    {!Intrinsic.initial_gas} and the authorization loop; both take the list
    rather than a count so that only listed-and-charged can be counted. *)

val effective_gas_price : t -> base_fee:word -> word
(** The price actually charged per unit of gas, given the block's base fee, a
    transcription of revm's default trait method
    ([revm-context-interface] [transaction.rs:147-160]).

    For a {!Legacy} or {!Access_list} transaction it is the [gas_price] verbatim.
    For a {!Dynamic} transaction with no priority fee it is the [max_fee]; with a
    priority fee it is [min(max_fee, base_fee + priority)], the addition
    saturating at the 256-bit ceiling. A {!Set_code} transaction prices exactly
    as a {!Dynamic} one whose priority fee is present — revm routes both through
    the same default trait method. It is deducted per unit of {e allocated}
    gas up front and reimbursed per unit of {e unused} gas at the end. *)

val max_fee_per_gas : t -> word
(** The ceiling the sender agreed to pay per unit of gas: the [gas_price] for
    Legacy and EIP-2930, the [max_fee] for EIP-1559 and EIP-7702. This is the
    price the pre-execution balance {e check} multiplies the gas limit by,
    distinct from the {!effective_gas_price} that is actually {e deducted}. *)
