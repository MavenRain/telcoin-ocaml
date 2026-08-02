(** The [address_of] contract as a value: which execution address a seat's
    leader credit is paid to ({!Tn_types.Authority.execution_address}), keyed
    by the stable {!Tn_types.Authority_id.t}. It exists so the driver's
    attach call site spends a tested value rather than an anonymous closure
    (design patch P10).

    Totality caveat, inherited by every consumer: attach resolves every
    header author AND the leader unconditionally, so the book handed to a
    step must cover every author appearing in the committed sub-DAG, not
    merely the installed committee - a cross-epoch sub-DAG resolved against
    one epoch's book halts where telcoin skips (risk R6). {!union} is the
    tool for widening a book across an epoch change. *)

type t
(** A finite map from authority id to execution address. *)

val of_committee : Tn_types.Committee.t -> t
(** Every seat of the committee, mapped to its own execution address. *)

val union : t -> t -> t
(** [union newer older]. Monotone: the result answers every id either book
    answers, so widening never loses a seat. Left-biased: an id both books
    bind keeps [newer]'s address, matching the registry read-back at epoch
    entry superseding the previous epoch's committee. *)

val find : t -> Tn_types.Authority_id.t -> Tn_types.Units.Address.t option
(** The id's execution address, or [None] for an id no {!of_committee}
    committee contained. Total; never raises. *)
