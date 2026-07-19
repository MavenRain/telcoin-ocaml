(** Non-empty lists.

    Several consensus collections are non-empty by protocol invariant: a
    header's parent set at a certified round carries a quorum, a committed
    sub-DAG always contains at least its leader. Encoding that in the type lets
    {!head} and {!last} be total, so the "cannot happen" branch never has to be
    written or trusted. *)

type 'a t

val singleton : 'a -> 'a t
val cons : 'a -> 'a list -> 'a t

val of_list : 'a list -> 'a t option
(** [None] exactly when the input is empty. *)

val to_list : 'a t -> 'a list

val head : 'a t -> 'a
(** Total: the first element always exists. *)

val last : 'a t -> 'a
(** Total: the last element always exists. *)

val length : 'a t -> int
(** Always [>= 1]. *)

val map : ('a -> 'b) -> 'a t -> 'b t
val iter : ('a -> unit) -> 'a t -> unit
val fold_left : ('acc -> 'a -> 'acc) -> 'acc -> 'a t -> 'acc

val append_list : 'a t -> 'a list -> 'a t
(** Extends a non-empty list; the result stays non-empty regardless of the
    appended tail. *)

val compare : ('a -> 'a -> int) -> 'a t -> 'a t -> int
val equal : ('a -> 'a -> bool) -> 'a t -> 'a t -> bool
