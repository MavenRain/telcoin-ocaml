(** Ethereum's 2048-bit (256-byte) logs bloom, m3:2048 over keccak256 of each
    input. Empty is all-clear; accrual only ever sets bits (bitwise OR). Byte
    layout on output: [255 - bit/8] holds [1 lsl (bit mod 8)]. *)
type t

val empty : t
(** The all-clear bloom: [to_bytes empty] is 256 zero bytes. *)

val accrue : t -> string -> t
(** OR into the bloom the three bits of one raw input. The input is keccak256'd
    internally (an address's 20 bytes, or a topic's 32 big-endian bytes); the
    three bits are [((h.[i] lsl 8) lor h.[i+1]) land 0x7FF] for [i] in [{0,2,4}]. *)

val of_logs : Log.t list -> t
(** The receipt logs bloom: {!accrue} folded over the address and then each topic
    of every log, each hashed separately. Bitwise-OR of every input's bits. *)

val to_bytes : t -> string
(** The 256-byte serialization, most-significant byte first (index 0 is the
    highest-order byte, matching alloy's [self.0.(255 - bit/8)]). Always 256
    bytes, built by a pure gather (no in-place mutation). *)

val of_bytes : string -> t option
(** The inverse of {!to_bytes}: [Some] exactly for a 256-byte string, reading
    each byte back into the bit indices {!to_bytes} gathered it from. RESERVED
    for the storage chunk, the precedent [Tn_consensus.Dag.insert_recovered]
    sets: a persisted header carries a bloom that no decoder could otherwise
    rebuild, because {!accrue} takes a log's pre-image and a resumed node no
    longer holds the logs. It adds no way to build a bloom that {!accrue} could
    not have built, since every 2048-bit subset is reachable by accrual. *)

val equal : t -> t -> bool
(** Same set of bits. *)
