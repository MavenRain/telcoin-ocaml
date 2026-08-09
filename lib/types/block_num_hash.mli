(** An execution block named by both its number and its hash: the port of alloy
    [BlockNumHash] / [NumHash] (alloy-eips-1.8.3/src/eip1898.rs:758-767, aliased
    at crates/types/src/lib.rs:59).

    It exists for exactly one field, [Header.latest_execution_block]
    (crates/types/src/primary/header.rs:31), through which a proposer tells its
    peers which execution block it has already executed. The number alone would
    not do: two forks can share a number, and the header's job is to name one
    block. *)

type t
(** A block number paired with that block's hash. Abstract, so the pair can only
    be built from a checked 32-byte hash. *)

val make : number:int64 -> hash:Tn_hash32.Hash32.t -> t
(** Total: both components are already refined. *)

val zero : t
(** Number 0 with the all-zero hash: alloy's [Default], and therefore the value
    in [HeaderInner::default()] (header.rs:51) and in every genesis header
    (certificate.rs:52-55, which builds through [HeaderBuilder::default()]). *)

val number : t -> int64
(** The block number, an unsigned [u64] on the wire; read the bits as unsigned
    even though OCaml prints [int64] signed. *)

val hash : t -> Tn_hash32.Hash32.t
(** The block hash. *)

val codec : t Tn_codec.Bcs.t
(** The BCS wire form: the number as a u64, then the hash as a LENGTH-PREFIXED
    32-byte string ([0x20] then the bytes), because alloy [B256] serializes
    through [serialize_bytes]. Forty-one bytes in total. *)

val equal : t -> t -> bool
val compare : t -> t -> int
