(** A committee member.

    Immutable per-validator data: the BLS protocol key used to sign votes and
    the execution-layer address that receives its fees. The {!id} is derived
    from the protocol key once at construction. Every authority has voting
    power {!Units.Stake.one} under the current equal-stake protocol. *)

type t

val make :
  protocol_key:Tn_crypto.Public_key.t -> execution_address:Units.Address.t -> t

val id : t -> Authority_id.t
val protocol_key : t -> Tn_crypto.Public_key.t
val execution_address : t -> Units.Address.t

val voting_power : t -> Units.Stake.t
(** Always {!Units.Stake.one} in the current protocol. *)

val equal : t -> t -> bool
(** By identity. *)

val compare : t -> t -> int
(** By identity — the byte order that determines committee traversal. *)
