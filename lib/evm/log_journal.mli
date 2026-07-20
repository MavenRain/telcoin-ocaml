(** The logs a frame has emitted, in emission order.

    Held newest-first internally, because consing onto a persistent list is the
    only constant-time append; {!to_list} reverses. That direction is stated
    here rather than left to be inferred from a field's type, because "logs come
    out in the order they were emitted" is exactly the fact a reader assumes
    without checking and gets backwards. *)

type t

val empty : t
val append : t -> Log.t -> t

val to_list : t -> Log.t list
(** Oldest first: emission order. *)

val length : t -> int

val equal : t -> t -> bool
(** Order-sensitive and multiplicity-sensitive list equality.

    Do {e not} copy {!Access.equal}'s justification here. That one licenses
    content equality over a set, and it is sound precisely because nothing
    records {e when} or {e how often} an entry was touched. A journal records
    both, and both reach consensus through the receipt, which commits to the log
    list as a list. Two frames emitting the same two logs in opposite orders are
    different values. *)
