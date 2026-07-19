(** Rounds that can carry a leader.

    Bullshark elects a leader only on even rounds at or above 2. Making that a
    type rather than a runtime precondition turns [LeaderSchedule::leader] —
    which in Rust opens with [assert!(round % 2 == 0)] — into a total function,
    and deletes the [>= 2] guards inside [commit_leader]. A value of this type
    is a witness that leader election is well-defined. *)

type t

val of_round : Round.t -> t option
(** [Some] exactly when the round is even and [>= 2]. *)

val to_round : t -> Round.t

val schedule_index : t -> int
(** [round / 2 - 1]: the index, modulo committee size, of the elected leader in
    the id-sorted authority list. Always [>= 0] by the type's invariant. *)

val next : t -> t
(** The next leader round (two rounds later). *)

val equal : t -> t -> bool
val compare : t -> t -> int
