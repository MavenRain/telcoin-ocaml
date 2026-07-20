(** EIP-1153 transient storage: the [(address, slot)] map [TSTORE] writes and
    [TLOAD] reads.

    Keyed by the pair, exactly as {!Access} keys its slot set, because a slot
    number alone names nothing and a slot-keyed implementation would be a
    cross-contract leak the day [CALL] lands.

    It lives here and not beside {!Tn_state.Storage} so that "a transient write
    leaked into the persistent world" is a bug the layering forbids rather than
    one a test has to catch: {!Tn_state.World_state} cannot see this module, so
    there is no function that could carry a value from one to the other.

    The representation is canonical in the same way {!Tn_state.Storage}'s is: a
    write of zero {e removes} the key. That is not an optimisation. EIP-1153
    gives [TLOAD] no way to distinguish a slot written zero from a slot never
    written, so if the two had distinct representations {!Effects.equal} would
    stop being exact the moment this map became one of its conjuncts, and two
    observably identical frames would compare unequal.

    There is no cold/warm axis and no {!Access.warmth} anywhere in this module.
    EIP-1153 places transient storage outside EIP-2929 entirely, and revm's
    [tload] and [tstore] never touch the access set. A warmth returned from here
    would be a price input for a surcharge that does not exist.

    Lifetime, which this module deliberately does not model: transient storage
    is cleared at the end of the {e transaction}, not of the frame, while a
    frame's revert must undo its transient writes. The second half is what this
    port gets for free, because the map rides inside {!Effects.t} and a reverted
    outcome structurally carries no effects. The first half is the transaction
    layer letting go of the whole {!Effects.t}, which is not a mechanism this
    chunk needs to build. *)

open Tn_types

type word = Tn_state.U256.t
type t

val empty : t

val get : t -> Units.Address.t -> slot:word -> word
(** Total: an unwritten slot reads zero, which is EIP-1153's rule and not a
    convenience, so this module has no error type. *)

val set : t -> Units.Address.t -> slot:word -> value:word -> t
(** A zero [value] removes the binding rather than storing a zero, which is what
    keeps the representation canonical. *)

val is_empty : t -> bool

val length : t -> int
(** How many slots are bound. For canonicity assertions and test printers; the
    interpreter never counts. *)

val bindings : t -> (Units.Address.t * word * word) list
(** Ascending by address then slot, mirroring {!Tn_state.Storage.bindings}.

    This exists so that canonicity is {e checkable}: [get] alone cannot tell a
    slot stored zero from a slot removed, which is precisely the confusion the
    canonical representation exists to prevent, so a test that asserts "every
    binding is nonzero" needs to enumerate. Execution never enumerates. *)

val equal : t -> t -> bool
