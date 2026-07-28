(** The [ConsensusRegistry] ABI surface the epoch close speaks: the [sol!]
    image of [crates/tn-reth/src/system_calls.rs:26-228] restricted to the
    calls the close path actually makes, plus the legacy pre-fork pool read.

    Encoding is alloy-sol-types 1.5.7's canonical layout for these shapes:
    a 4-byte selector, one head word per argument (a dynamic array's head
    word is the byte offset of its tail, here always [0x20]), a length word,
    then the tail with every static tuple inlined and {e no} per-element
    offset words. Selectors are computed at module initialisation via {!Tn_keccak}
    from the canonical signature strings and pinned by the test suite against
    hand-derived constants.

    [applySlashes] exists in the [sol!] block ([system_calls.rs:163]) but has
    no call site anywhere in [crates/], so it deliberately has no encoder
    here: an encoder nothing calls is a selector nothing pins.

    Decoders are {e strict}: exact head offset, exact length, zero padding,
    zero trailing bytes. Whether alloy 1.5.7's [abi_decode] rejects trailing
    bytes and loose offsets is {e unverified}; the strictness tests are
    labelled port-choice, not fidelity. *)

(** The validator's eligibility status, uint8 by declaration order 0..6
    ([system_calls.rs:33-50]). This is the {e decode}-side type: a payload
    can carry any of the seven values, so all seven are representable. *)
module Validator_status : sig
  type t =
    | Undefined  (** 0: default value. *)
    | Staked  (** 1: staked, not eligible for consensus. *)
    | Pending_activation  (** 2: ready to join a committee. *)
    | Active  (** 3: actively participating. *)
    | Pending_exit  (** 4: indicated interest to exit. *)
    | Exited  (** 5: no longer participating. *)
    | Any  (** 6: match any status (also indicates retired). *)

  val to_byte : t -> char
  (** The uint8 value, ['\000'] to ['\006']. *)

  val of_byte : char -> t option
  (** [Some] exactly for bytes 0..6; the inverse of {!to_byte}. *)

  val equal : t -> t -> bool
  (** Constructor equality, via {!to_byte}. *)
end

(** The only statuses queryable on the close path. The contract reverts on
    [Undefined] (0) and [Any] (6) and never folds statuses
    ([system_calls.rs:177-179]); making the query argument this three-way
    sum leaves a reverting query unrepresentable rather than merely
    unexercised. *)
module Eligible_status : sig
  type t =
    | Active  (** Maps to {!Validator_status.Active} (3). *)
    | Pending_activation  (** Maps to {!Validator_status.Pending_activation} (2). *)
    | Pending_exit  (** Maps to {!Validator_status.Pending_exit} (4). *)

  val to_status : t -> Validator_status.t
  (** The embedding into the full decode-side sum. *)
end

(** The [ValidatorInfo] struct: seven static fields in declared order,
    [validatorAddress] address, [activationEpoch] uint32, [exitEpoch] uint32,
    [currentStatus] uint8 enum, [isRetired] bool, [stakeVersion] uint8,
    [region] uint8 ([system_calls.rs:54-74]). A static tuple, so an array of
    them packs elements inline at 224 bytes each. *)
module Validator_info : sig
  type t
  (** One decoded validator record. Abstract, so the u32/u8 field bounds
      {!make} checks hold for every value of the type; the decoder is the
      other producer and its fields are narrower than the checks by
      construction. *)

  val make :
    validator_address:Tn_types.Units.Address.t ->
    activation_epoch:int ->
    exit_epoch:int ->
    current_status:Validator_status.t ->
    is_retired:bool ->
    stake_version:int ->
    region:int ->
    t option
  (** [None] when an epoch is outside u32 or a version/region outside u8.
      For tests and fixtures; the port's production values arrive through
      {!decode_validator_info_array}. *)

  val validator_address : t -> Tn_types.Units.Address.t
  (** The address the committee list is built from ([block.rs:463]). *)

  val current_status : t -> Validator_status.t
  (** The status the shuffle partitions on ([block.rs:449-452]). *)

  val equal : t -> t -> bool
  (** All seven fields. *)
end

(** Why a strict decode refused the payload. [Truncated], [Head_offset_not_32],
    [Length_word_overflow] and [Trailing_bytes] name frame damage;
    [Padding_nonzero] names nonzero bytes outside a static value's width
    (including a bool word above one); [Status_byte] names an enum value
    outside 0..6, which alloy's checked enum conversion also rejects. *)
type decode_error =
  | Truncated of { need : int; got : int }
      (** Fewer bytes than the frame requires. *)
  | Head_offset_not_32
      (** The single head word is not exactly 0x20 (port-choice strictness). *)
  | Length_word_overflow
      (** The array length word exceeds the u32 range, so no in-memory
          payload could satisfy it. *)
  | Status_byte of int  (** Enum byte outside 0..6. *)
  | Padding_nonzero
      (** Nonzero bytes outside a static value's declared width. *)
  | Trailing_bytes of int
      (** Bytes beyond the encoded value (port-choice strictness). *)

val error_to_string : decode_error -> string
(** Diagnostic rendering, one line. *)

val conclude_epoch_calldata : Tn_types.Units.Address.t list -> string
(** [0x7b55a300] (keccak of ["concludeEpoch(address[])"],
    [system_calls.rs:159]) then the address array {e as given}: the ascending
    sort is the caller's step ([block.rs:394-395]), not the encoder's. The
    committee is the {e only} argument; the close randomness feeds the
    shuffle, never this calldata. *)

val apply_incentives_calldata : (Tn_types.Units.Address.t * int) list -> string
(** [0x0a36cdef] (keccak of ["applyIncentives((address,uint256)[])"],
    [system_calls.rs:105-110, 161]) then [RewardInfo[]] with each pair as
    [(validatorAddress, consensusHeaderCount)] in order as given, the count
    widened to uint256 unscaled ([block.rs:414-424]). A count is a u32 at its
    source ([gas_accumulator.rs:94-106]); a negative int has no Rust image
    and encodes, totally, as its 256-bit two's complement. *)

val get_validators_info_calldata : Eligible_status.t -> string
(** [0x2870259d] (keccak of ["getValidatorsInfo(uint8)"],
    [system_calls.rs:182]) then the status as a uint8 word
    ([block.rs:513-514]). Post-fork pool read; the return decodes with
    {!decode_validator_info_array}. *)

val get_validators_calldata : Eligible_status.t -> string
(** [0x8cc05eda] (keccak of ["getValidators(uint8)"], [system_calls.rs:180])
    then the status as a uint8 word: the legacy pre-fork pool read, one call
    with [Active] whose return the pre-fork contract answers with the full
    [ValidatorInfo[]] union ([block.rs:573-583]), decoded by the same
    {!decode_validator_info_array}. Kept because the pinned genesis registry
    bytecode is pre-fork code that answers {e only} this selector. *)

val get_next_committee_size_calldata : string
(** The bare 4-byte selector [0xeb8535c2] (keccak of
    ["getNextCommitteeSize()"], [system_calls.rs:203]): a nullary call has an
    empty head ([block.rs:630]). *)

val decode_validator_info_array :
  string -> (Validator_info.t list, decode_error) result
(** The return of [getValidatorsInfo] or legacy [getValidators]: a [0x20]
    offset word, a length word, then inline 224-byte elements, in the
    contract's return order (never re-sorted here; the pool order is
    consensus-relevant input to the shuffle). Strict per the module
    preamble. *)

val decode_uint16 : string -> (int, decode_error) result
(** The return of [getNextCommitteeSize]: exactly one word whose first 30
    bytes are zero ([block.rs:630-638] decodes u16). Strict per the module
    preamble. *)
