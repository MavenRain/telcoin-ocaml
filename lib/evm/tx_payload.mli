(** The unsigned transaction — exactly the fields a signature commits to.

    {!Transaction.t} is the {e executable} transaction: its sender is
    pre-recovered, so it cannot be the thing a signature is taken over. This is
    that thing: one constructor per EIP-2718 type, carrying precisely the fields
    that type has and no others, ported from alloy-consensus 1.8.3's three
    structs ([src/transaction/legacy.rs:19-71], [src/transaction/eip2930.rs:16-65],
    [src/transaction/eip1559.rs:16-79]). {!to_transaction} closes the loop once
    {!Tx_recovery} has produced a sender.

    {b The wire order is deliberately not alloy's struct order.} alloy declares
    [max_fee_per_gas] before [max_priority_fee_per_gas] and [access_list] before
    [input], while the wire puts the priority fee first ([eip1559.rs:112-122])
    and [input] seventh, the access list eighth ([eip2930.rs:94-103],
    [eip1559.rs:112-122]). Both fee fields have the same type, so mirroring the
    struct compiles, decodes and silently inverts the fee semantics. The
    constructors below take their arguments in wire order, the implementation's
    records are declared in wire order, and {!variant} hands the encoder the
    per-type fields already discriminated, so the trap has nowhere to live.

    Two illegal states are absent by construction rather than by check: a legacy
    transaction cannot carry an access list (no constructor takes one), and a
    typed transaction cannot omit its chain id (it is a {!word}, not an
    option). *)

open Tn_types

type word = Tn_state.U256.t

type variant =
  | Legacy of { chain_id : word option; gas_price : word }
      (** Type 0. [chain_id] is [None] for a pre-EIP-155 transaction, which every
          layer of the pinned stack still accepts, and it is never an envelope
          field: it appears only as item seven of the signing payload, or folded
          into [v] in the signed envelope (see {!Tx_envelope}). *)
  | Eip2930 of { chain_id : word; gas_price : word }
      (** Type 1 (EIP-2930). The chain id is mandatory and unvalidated: [0] is a
          legal encoding ([eip2930.rs:19,95,111]). *)
  | Eip1559 of { chain_id : word; max_priority_fee_per_gas : word; max_fee_per_gas : word }
      (** Type 2 (EIP-1559), the {e tip} cap before the {e fee} cap, as the wire
          has them and as the Rust struct does not. Unlike {!Transaction.fee}'s
          [Dynamic], the priority fee is not an option: the wire format has no
          absent case, so an encoder that must write the field can never be
          handed one that is missing. *)

type t
(** An unsigned transaction. Abstract: built by {!legacy}/{!eip2930}/{!eip1559}
    and read through {!variant} and the accessors.

    {2 Two fields are wider here than on the wire}

    A [chain_id] is a {!word} but alloy's [ChainId] is a [u64], and a
    [gas_limit] is a native [int] (as an allowance is everywhere in this port)
    where the wire holds a [u64]. So the three constructors accept two things no
    transaction can carry: a chain id at or above [2^64], and a negative gas
    limit. Neither raises — the first encodes to a scalar wider than eight bytes,
    which {!Tx_envelope.decode_2718} then refuses as [Scalar_too_wide]; the
    second encodes as zero, because {!Tn_rlp.Rlp.encode_nat} maps every value at
    or below zero to [0x80]. Both therefore produce a payload whose own
    {!Tx_envelope.encode_2718} bytes this port would not decode back.

    They are documented rather than made unrepresentable because no payload on
    the live path can reach them: a payload in production comes {e out} of
    {!Tx_envelope.decode_2718}, which has already enforced both bounds (a chain
    id, nonce and gas limit each at most eight bytes). Only a hand-built payload
    can violate them, and narrowing the constructors to return an option would
    put that check on every call site to exclude a case none of them can hit. *)

val legacy :
  nonce:Tn_state.Nonce.t ->
  gas_price:word ->
  gas_limit:int ->
  kind:Transaction.kind ->
  value:word ->
  data:string ->
  chain_id:word option ->
  t
(** A type-0 transaction. The arguments are the six wire fields in order, then
    the chain id — last, because that is where it appears, out of band. *)

val eip2930 :
  chain_id:word ->
  nonce:Tn_state.Nonce.t ->
  gas_price:word ->
  gas_limit:int ->
  kind:Transaction.kind ->
  value:word ->
  data:string ->
  access_list:(Units.Address.t * word list) list ->
  t
(** A type-1 (EIP-2930) transaction: the eight wire fields in order. *)

val eip1559 :
  chain_id:word ->
  nonce:Tn_state.Nonce.t ->
  max_priority_fee_per_gas:word ->
  max_fee_per_gas:word ->
  gas_limit:int ->
  kind:Transaction.kind ->
  value:word ->
  data:string ->
  access_list:(Units.Address.t * word list) list ->
  t
(** A type-2 (EIP-1559) transaction: the nine wire fields in order, the priority
    fee before the max fee. *)

val variant : t -> variant
(** The fields that differ between the three layouts — the chain id and the fee
    caps — already discriminated by type. This is the encoder's entry point: a
    match on it names all three EIP-2718 types the port carries, so no layout can
    be reached by defaulting an absent field. Every {e shared} field is read
    through the accessors below. *)

val type_byte : t -> int
(** The EIP-2718 type: [0], [1] or [2]. For type 0 this byte is {e never} written
    (see {!Eip2718.frame}); it exists so a caller can classify a payload, and so
    {!Block_roots.type_byte}'s receipt-side counterpart has a transaction-side
    twin. *)

val chain_id : t -> word option
(** The chain id, [None] only for a pre-EIP-155 legacy payload. *)

val nonce : t -> Tn_state.Nonce.t
(** The sender nonce the payload claims. *)

val gas_limit : t -> int
(** The gas allowance. A native [int] because that is what an allowance is
    everywhere in this port (see {!Gas}); the decoder rejects the sliver of the
    [u64] range that does not fit (see {!Tx_envelope.error}). *)

val kind : t -> Transaction.kind
(** Whether this is a call or a creation — alloy's [TxKind]. Present on the wire
    either way: a creation writes an empty string, never an omitted field. *)

val value : t -> word
(** The wei moved. *)

val data : t -> string
(** The calldata for a call, or the init code for a creation. *)

val access_list : t -> (Units.Address.t * word list) list
(** The EIP-2930 access list in declared grouped form, empty for a legacy
    payload. It is neither sorted nor de-duplicated, here or in alloy: the encode
    path is a verbatim iteration ([alloy-eip2930-0.2.3/src/lib.rs:36-40]), so
    duplicate addresses and repeated keys round-trip byte for byte and
    canonicalising would change the transaction hash. *)

val fee : t -> Transaction.fee
(** The payload's fee fields as the executor's {!Transaction.fee}: {!Legacy} and
    {!Eip2930} map to their [gas_price], {!Eip1559} to
    [Dynamic { max_fee; max_priority = Some _ }]. The [Some] is total — a wire
    payload always has a priority fee — and is the only place the two fee models
    differ. *)

val to_transaction : t -> sender:Units.Address.t -> Transaction.t
(** The executable transaction, given the sender {!Tx_recovery} recovered.
    Total: every field {!Transaction.make} needs is present, and the sender is
    the one thing a payload structurally cannot supply. *)
