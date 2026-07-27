(** The EIP-4895 withdrawal record and its RLP.

    Greenfield: the port had no withdrawal type before this chunk. It is needed
    by the header assembler in {e both} branches of the close-epoch decision,
    since telcoin's non-closing branch still writes
    [Some(Withdrawals::default())] beside [Some(EMPTY_WITHDRAWALS)]
    ([block.rs:971-978]), so an open boundary commits to the empty list rather
    than to no list at all. *)

type t
(** One withdrawal. Abstract, so the non-negativity {!make} checks is a property
    of every value of the type rather than of every call site. *)

val make :
  index:int ->
  validator_index:int ->
  address:Tn_types.Units.Address.t ->
  amount:int ->
  t option
(** [None] on a negative scalar. TN builds every one of these with [index = 0]
    and [validator_index = 0] and uses [amount] as a leader COUNT rather than as
    gwei ([crates/types/src/gas_accumulator.rs:146-158]); the fields are still
    named for their EIP-4895 meaning, because that is what the RLP commits to.

    The refusal is this port's own bound and not RLP's:
    {!Tn_rlp.Rlp.encode_nat} is total and encodes any value at or below zero as
    [0x80] ([rlp.mli:82-86]), so a negative scalar would otherwise root
    identically to zero and no encoder would ever complain. *)

val index : t -> int
(** The withdrawal's index in the chain-wide sequence. Always [0] on TN. *)

val validator_index : t -> int
(** The withdrawing validator's index. Always [0] on TN. *)

val address : t -> Tn_types.Units.Address.t
(** The execution-layer recipient. This is the field TN's list is sorted by
    ascending, since it comes out of a [BTreeMap<Address, u32>]
    ([gas_accumulator.rs:123-158]). *)

val amount : t -> int
(** The EIP-4895 amount field. TN puts a leader COUNT here, not gwei
    ([gas_accumulator.rs:146-158]). *)

val encode_rlp : t -> string
(** The four-element RLP list [\[index; validator_index; address; amount\]] in
    exactly that order: the three integers by {!Tn_rlp.Rlp.encode_nat} and the
    address by {!Tn_rlp.Rlp.encode_bytes} (20 bytes, so [0x94] then the
    address), the four chunks wrapped by {!Tn_rlp.Rlp.encode_list}. These are
    the verbatim bytes {!Block_roots.withdrawals_root} inserts, {e not}
    re-wrapped, which is the same discipline {!Block_roots.transactions_root}
    states and for the same reason: the leaf encoder wraps each value exactly
    once. *)

val equal : t -> t -> bool
(** Field-wise equality. *)

val to_string : t -> string
(** Render a withdrawal as a short human-readable string, for diagnostics and
    test failure messages. *)
