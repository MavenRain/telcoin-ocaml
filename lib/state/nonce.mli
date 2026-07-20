(** An account nonce — the number of transactions an account has sent.

    Rust's account nonce is a [u64] that only ever increments. It is its own type
    so it can never be confused with a balance, a round or a block number, with a
    total saturating {!succ} whose maximum is unreachable in any real run. *)

type t

val zero : t
(** A fresh account's nonce. *)

val succ : t -> t
(** The nonce after sending one more transaction. Total (saturates at the maximum
    representable value). *)

val succ_checked : t -> t option
(** The nonce after one more transaction, or [None] if there is no such nonce
    because this one is already at the maximum.

    This is {!succ} with the saturation made visible instead of silent, and it
    exists because contract creation is the one caller for which the difference
    is a consensus rule rather than an unreachable corner: revm bumps the
    creator's nonce and abandons the creation when the bump would overflow
    ([revm-handler] [frame.rs:288-292]), pushing zero and returning the whole
    forwarded allowance. A creator that saturated instead would go on deriving
    the same address for every subsequent creation, so the failure has to be
    reportable even though no chain can reach it. *)

val of_int : int -> t option
(** A nonce from a non-negative [int], [None] for a negative one. *)

val to_int : t -> int
val equal : t -> t -> bool
val compare : t -> t -> int
val to_string : t -> string
