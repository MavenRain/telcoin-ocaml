(** The outcome of executing one transaction, mirroring revm's [ExecutionResult].

    A transaction that is {e included} ends in exactly one of three ways, and this
    type is the port of the sum revm returns for each ([revm-context]
    [result.rs]). {!Success} is a frame that returned or stopped: it carries its
    output, the address it created if it was a creation, the gas it used, the gas
    refunded to the sender, and the logs it emitted. {!Reverted} is a frame that
    executed [REVERT]: it carries its output and its gas, but no logs and no
    refund, because a revert keeps neither. {!Halted} is any other exceptional
    end, from an out-of-gas to a creation collision: it carries only the reason and
    the gas, which for a halt is always the entire gas limit.

    All three are {e committed} outcomes: the sender's nonce advance and the fee
    payment persist for every one of them, and only the value transfer, storage
    writes and logs of a revert or a halt are rolled back (see {!Executor}). A
    transaction that is {e rejected} in validation is categorically different and
    produces no receipt at all: {!Executor.execute} returns an [Error] and the
    world state is untouched. Conflating a halt with a rejection is the single
    easiest mistake to make here, so the type does not let a rejection reach it. *)

open Tn_types

type halt_reason =
  | Frame_halt of Interpreter.error
      (** The first frame halted exceptionally: an out-of-gas, an invalid opcode,
          a stack fault or any other {!Interpreter.error}. *)
  | Create_collision
      (** EIP-684: a creation targeted an address that already holds code or a
          nonzero nonce ([revm-context] [journal/inner.rs:411-414]). *)
  | Create_reserved_prefix
      (** EIP-3541: a creation's returned code begins with the reserved [0xEF]
          byte ([revm-handler] [frame.rs:552-559]). *)
  | Create_code_size_limit of int
      (** EIP-170: a creation's returned code exceeds
          {!Tn_state.Bytecode.max_deployed_size}, carrying the offending length
          ([frame.rs:563-566]). *)
  | Create_deposit_out_of_gas
      (** EIP-2 point 3: the creation frame could not pay the 200-per-byte deposit
          cost for the code it returned ([frame.rs:568-583]). *)
  | Create_nonce_exhausted
      (** The creator's nonce was already at its maximum and could not be bumped.
          Unreachable at any real chain state (it needs [2^64] prior
          transactions); present so the creation path is total. *)
  | Value_overflow
      (** Crediting the recipient or the created account would pass [2^256].
          Unreachable at any real total supply; present so the transfer path is
          total. *)

val halt_reason_to_string : halt_reason -> string
(** Render a {!halt_reason} as a short human-readable string, for diagnostics and
    test failure messages. *)

type t =
  | Success of {
      output : string;
      created : Units.Address.t option;
      gas_used : int;
      gas_refunded : int;
      logs : Log.t list;
    }
      (** The transaction returned or stopped. [created] is the deployed address
          for a creation and [None] for a call. [gas_used] is net of the refund;
          [gas_refunded] is the refund the sender was credited. *)
  | Reverted of { output : string; gas_used : int }
      (** The transaction executed [REVERT]. Its value transfer and writes are
          rolled back; only [output] and [gas_used] survive, with no logs and no
          refund. *)
  | Halted of { reason : halt_reason; gas_used : int }
      (** The transaction halted exceptionally. [gas_used] is the entire gas
          limit: a halt forfeits every unit forwarded. *)

val gas_used : t -> int
(** The gas the transaction consumed, net of any refund. Defined for all three
    outcomes, since the fee is charged on it regardless. *)

val logs : t -> Log.t list
(** The logs the transaction emitted, in emission order. Defined for all three
    outcomes, exactly as {!gas_used} is: {!Reverted} and {!Halted} emit none,
    because a revert rolls the journal back and a halt forfeits everything.

    It exists so the block logs bloom is one fold and not a match at a call
    site, the same reason {!gas_used} is total rather than a projection out of
    {!Success}. It is deliberately NOT paired with a [Bloom.union]: the block
    bloom is {!Bloom.of_logs} over the concatenation, which is what telcoin
    computes ([block.rs:957]), and a union would make the OR-of-blooms
    formulation writable as a second path to the same fact. *)

val to_string : t -> string
(** Render a receipt as a short human-readable string, naming the outcome and its
    gas, for diagnostics and test failure messages. *)
