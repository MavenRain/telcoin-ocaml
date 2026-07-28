(** The intrinsic gas of a transaction: what it costs before its first frame runs,
    and the EIP-7623 calldata floor its total may not fall below.

    Two numbers come out of one transaction, and they are computed the same way
    from the same calldata tokens but serve opposite ends. The {e initial} gas is
    charged up front and subtracted from the gas limit before the first frame is
    entered ([revm-context-interface] [cfg/gas_params.rs:721-739]): it pays for the
    21000-gas base, the calldata, the EIP-2930 access list and, for a creation, the
    32000 creation surcharge and the EIP-3860 initcode metering. The {e floor} gas
    is a lower bound on the whole transaction's consumption
    ([gas_params.rs:664-665, 742]): EIP-7623 makes a data-heavy transaction pay for
    the calldata it posts even if its execution was cheap, so if the gas actually
    spent (net of refund) falls below the floor, the floor is charged instead. The
    floor depends on the calldata alone, never on the access list or the creation
    surcharge.

    Both are pure functions of the transaction's fields. The executor computes them
    once, rejects the transaction if either exceeds the gas limit, forwards
    [gas_limit - initial_gas] to the frame, and enforces the floor in
    post-execution. See {!Executor}. *)

open Tn_types

type word = Tn_state.U256.t

type kind =
  | Call
      (** A message call: no creation surcharge and no initcode metering. *)
  | Create
      (** A contract creation: the 32000 surcharge and the EIP-3860 per-word
          initcode charge are added on top of the shared cost. *)

val tokens : string -> int
(** The EIP-2028 token count of calldata: one token per zero byte and four per
    nonzero byte ([cfg/gas.rs:199-203]). Every intrinsic charge that scales with
    calldata scales with this count, so it is named once. *)

val per_empty_account_cost : int
(** [25000] — [PER_EMPTY_ACCOUNT_COST] ([revm-primitives] [eip7702.rs:5-9]),
    the per-authorization intrinsic charge, installed under PRAGUE at
    [cfg/gas_params.rs:306-311] and summed into the initial gas at [:729-731].

    [PER_AUTH_BASE_COST], the constant NAMED "base cost", is 12500 and is NEVER
    CHARGED. It appears only inside the refund difference the authorization
    loop earns for a pre-existing authority, and it lives in a different module
    so the two cannot be swapped at a call site. Charging 12500 here and
    refunding 12500 double-counts the discount and makes every
    existing-authority transaction 12500 too cheap. *)

val initial_gas :
  kind:kind ->
  data:string ->
  access_list:(Units.Address.t * word list) list ->
  authorizations:Authorization.signed list ->
  int
(** The gas charged before the first frame:
    [tokens data * 4 + 2400 * access_list_addresses + 1900 * access_list_slots
    + 21000], plus {!per_empty_account_cost} for EVERY element of
    [authorizations], plus [32000 + 2 * num_words(len data)] when [kind] is
    {!Create} (the EIP-3860 initcode words, [num_words 0 = 0]). [data] is the
    calldata for a call or the init code for a creation. The access-list terms
    are the EIP-2930 per-address and per-slot costs; a legacy transaction passes
    an empty list.

    The authorization term takes the LIST, not a count, and the parameter is
    MANDATORY. Every listed entry is charged, including the ones the loop later
    skips for a wrong chain id, an unrecoverable signature, contract code or a
    nonce mismatch: revm's [calculate_initial_tx_gas] is passed
    [tx.authorization_list_len()] ([cfg/gas.rs:181-188]). A [~count:int] would
    accept the number of APPLIED authorizations, which is the one number that is
    wrong; an optional parameter would be a guard whose omission compiles. Every
    non-set-code transaction carries an empty list, so there is no
    transaction-type gate on the term, matching [pre_execution.rs:196-200] by
    construction. *)

val floor_gas : data:string -> int
(** The EIP-7623 calldata floor: [tokens data * 10 + 21000]. It depends on the
    calldata alone, so per byte it is 10 for a zero byte and 40 for a nonzero one,
    and it ignores the access list and the creation surcharge entirely.

    Its ARITY IS LOAD-BEARING. The floor is over calldata tokens ALONE
    ([cfg/gas_params.rs:664-666, 741-744]): it excludes the access-list terms,
    the creation surcharge, the initcode words AND the
    [25000 * authorizations] charge. There is no parameter here to receive the
    authorization term, so adding it is a compile error rather than a silent
    over-charge on every cheap set-code transaction. *)
