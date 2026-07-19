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

val of_int : int -> t option
(** A nonce from a non-negative [int], [None] for a negative one. *)

val to_int : t -> int
val equal : t -> t -> bool
val compare : t -> t -> int
val to_string : t -> string
