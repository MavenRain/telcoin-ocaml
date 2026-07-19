(** The uninhabited type — OCaml's [Void], Rust's [!].

    A value of this type cannot be constructed, so a function that claims to
    return one can never actually be called and a branch that binds one is dead
    code. It is the type-level statement {e this cannot happen}: {!Engine.Noop}
    sets its execution [error] to {!t}, so an engine that cannot fail says so in
    its signature rather than in a comment, and {!absurd} discharges the
    impossible error branch of its [result] without a partial function. *)

type t = |
(** No constructors: no value inhabits it. *)

val absurd : t -> 'a
(** Eliminate an impossible value: given a {!t} — which cannot exist — produce a
    value of any type. The counterpart of [Result.fold]'s [~error] argument when
    the error is uninhabited. Total; its body is unreachable. *)
