(** How many topics one [LOG] carries: the decoder's operand and the price's
    multiplier.

    Unlike {!Depth} and {!Opcode.Push_bytes} the constructors are exposed and
    there is no smart-constructor obligation, because the domain is not an
    interval of the integers with invalid inhabitants inside it. It is five
    things. Five constructors {e are} the bound, so {!Opcode.decode} needs no
    interval helper and {!Gas} cannot be handed an out-of-range count. *)

type t = Zero | One | Two | Three | Four

val of_int : int -> t option
(** [Some] on [[0, 4]] only. Used by the decoder, whose input is a code byte. *)

val to_int : t -> int
(** The multiplier the log price applies, and the offset from [0xa0] the byte
    encoding uses. *)

val all : t list
(** Ascending. Five elements. Tests fold over it so that a sixth arity, if one
    were ever added, could not be silently untested. *)

val equal : t -> t -> bool
