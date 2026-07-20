(** The three values EIP-2200's net gas metering compares: what a slot held at
    the start of the transaction, what it holds now, and what is being written.

    Net metering prices a write by what it does to the {e transaction's} net
    effect rather than to the current value, which is why the triple and not the
    pair is the unit here. It is the port of revm's [SStoreResult]; both the
    dynamic price ({!Gas.sstore_dynamic_cost}) and the refund
    ({!Gas.sstore_refund}) are total functions of it, so the two can never be
    derived from different views of the same write.

    {!original} is transaction-scoped, never frame-scoped. {!Effects.start} pins
    the pre-transaction world once and offers no way to move it, so a sub-frame
    built on the same {!Effects.t} nets against the transaction's original
    rather than its parent's current value. That is the EIP-2200 rule a port is
    most likely to get wrong, made here a consequence of a missing setter rather
    than a discipline about which snapshot to consult. *)

type word = Tn_state.U256.t

type t
(** One [SSTORE]'s three views of a slot. *)

val make : original:word -> present:word -> updated:word -> t
(** The triple. In execution it is reached only through {!Effects.plan_store},
    which is its sole caller; it is exposed because {!Gas} must price one
    without depending on {!Effects}, and because the tests walk EIP-2200's full
    case table directly. The cost of that exposure is named in §14. *)

val original : t -> word
(** The word the slot held before this transaction ran. *)

val present : t -> word
(** The word the slot holds now — after every earlier write in this
    transaction, including ones by other frames. *)

val updated : t -> word
(** The word this [SSTORE] is writing. *)

type change =
  | No_op
      (** [updated = present]. Nothing is written and nothing beyond the access
          is charged. *)
  | Fresh_set
      (** [original = present = 0] and [updated <> 0]: this write creates the
          slot and pays for creating it. *)
  | Fresh_reset
      (** [original = present <> 0] and [updated <> present]: this write is the
          first to disturb a slot the transaction found set. *)
  | Dirty
      (** [original <> present]: the transaction has already disturbed this slot
          and already paid, so further writes cost only the access. *)

val classify : t -> change
(** The EIP-2200 case, total and mutually exclusive.
    {!Gas.sstore_dynamic_cost} is an exhaustive match on it, which is the point:
    the dynamic charge really is four-way. The {e refund} is deliberately not
    expressed over this type — its branches cut across this partition, and
    forcing it into this shape would be a rewrite of the one formula in the gas
    schedule that is famously easy to get subtly wrong. See
    {!Gas.sstore_refund}. *)

val equal : t -> t -> bool
(** Componentwise equality of the three words. *)
