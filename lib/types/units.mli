(** Small scalar newtypes, each a distinct abstract type.

    Grouping them here keeps the domain vocabulary in one place while still
    preventing an [Epoch] from being used as a [Stake] or a [Timestamp]: the
    compiler rejects the confusion that a shared [int] representation would
    silently permit. *)

(** Committee epoch number (Rust [u32]). *)
module Epoch : sig
  type t

  val zero : t
  val of_int : int -> t option
  val to_int : t -> int
  val succ : t -> t
  val equal : t -> t -> bool
  val compare : t -> t -> int
  val to_string : t -> string
end

(** Voting power / stake (Rust [u64]). The current protocol assigns every
    authority {!one}, so a committee's total stake equals its size. *)
module Stake : sig
  type t

  val zero : t
  val one : t
  val of_int : int -> t option
  val to_int : t -> int
  val add : t -> t -> t
  val ( >= ) : t -> t -> bool
  val compare : t -> t -> int
  val to_string : t -> string
end

(** A consensus timestamp in whole unix seconds (Rust [TimestampSec = u64]).
    This value enters the header and sub-DAG digest pre-images, so it is kept
    in seconds to stay byte-compatible with the Rust node; the simulator's
    finer-grained clock is a separate quantity that is coarsened to seconds
    here. *)
module Timestamp : sig
  type t

  val zero : t
  val of_sec : int64 -> t option
  val to_sec : t -> int64
  val max : t -> t -> t

  val add_secs : t -> int -> t
  (** Add a whole-second offset, saturating at the maximum representable
      timestamp — the header-drift tolerance window [now + tolerance]. A
      non-positive offset leaves the timestamp unchanged. Total. *)

  val equal : t -> t -> bool
  val compare : t -> t -> int
  val to_string : t -> string
end

(** A span of simulation time in milliseconds — timer delays and network
    latency. Distinct from {!Timestamp} because it is never hashed. *)
module Duration : sig
  type t

  val zero : t
  val of_ms : int -> t option
  val to_ms : t -> int
  val add : t -> t -> t

  val half : t -> t
  (** Truncating halving — Rust's [max_header_delay / 2] on the proposer's
      leader fast path. Total. *)

  val compare : t -> t -> int
end

(** The commit sequence number, used as the leader nonce. Rust packs it as
    [(epoch << 32) | round]; the split is recoverable, which the reputation
    schedule counter depends on. *)
module Sequence_number : sig
  type t

  val of_epoch_round : Epoch.t -> Round.t -> t
  val to_int64 : t -> int64
  val epoch : t -> Epoch.t
  val round : t -> Round.t
  val equal : t -> t -> bool
  val compare : t -> t -> int
end

(** A worker index within a validator (Rust [WorkerId = u16]). The current
    protocol runs a single worker per validator. *)
module Worker_id : sig
  type t

  val zero : t
  val of_int : int -> t option
  val to_int : t -> int
  val equal : t -> t -> bool
  val compare : t -> t -> int
end

(** A 20-byte execution-layer account address (fee recipient). *)
module Address : sig
  type t

  val length : int
  val of_bytes : string -> t option
  val to_bytes : t -> string
  val zero : t
  val equal : t -> t -> bool
  val compare : t -> t -> int
end
