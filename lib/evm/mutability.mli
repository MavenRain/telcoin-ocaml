(** Whether the running frame may change anything outside itself.

    EIP-214 makes staticness a property of the frame, and three instructions
    must fail under it: [SSTORE], [TSTORE] and [LOG0]-[LOG4]. revm spells the
    rule [require_non_staticcall!] and puts it first in [sstore] and [log], and
    right after the Cancun hardfork check in [tstore], a gate this port does not
    reproduce because it targets a single fork.

    A [bool] on the environment would reproduce that and would leave three call
    sites each individually responsible for remembering to consult it. This port
    has already lost that bet once: {!Interpreter}'s [sstore] carried a comment
    saying the guard is absent because there is no static flag in this chunk. A
    guard whose omission compiles is a guard that gets omitted.

    So the check does not gate a write, it {e produces the argument the write
    demands}. {!permit} the type is abstract and constructorless; {!permit} the
    function is its sole producer and yields [None] in a static frame; and
    {!Effects.plan_store}, {!Effects.log} and {!Effects.transient_store} each
    take one. An instruction author who forgets the guard does not undercharge,
    he fails to compile.

    What this buys, stated exactly rather than gestured at. Three things are
    {e not} closed, and each is a test obligation rather than a claim:

    - The permit can be fabricated from a literal. [permit Mutable] is [Some]
      wherever it is written, including inside the very instruction bodies the
      permit disciplines. What the type closes is {e forgetting to consult} the
      mode, not lying about the answer. This is weaker than {!Access.warmth},
      which cannot be fabricated at all because it is derived from the access set
      the caller does not control, whereas {!permit}'s argument is a public
      two-constructor sum, so [permit Mutable] is a writable lie. The difference
      is that a warmth records something that happened, while a mutability is
      something the frame simply is. The static cross-product in the test suite
      is what pins the honest branch, and a mutation replacing the consultation
      with a literal is in the gate.
    - The caller still chooses what to report when the permit is [None].
    - The type cannot force the permit to be taken {e first}, before gas is
      charged or operands are popped. Ordering is pinned by allowance pairs in
      the tests.

    What this must NOT be extended to cover: EIP-214 also forbids a static frame
    from sending value. That rule belongs at the site where a sub-frame is
    built, which is where revm enforces it, so {!Env.Call.make} accepts a
    nonzero value under {!Static} today and the calls chunk is where it stops. *)

type t = Mutable | Static
(** Exposed, because a frame's mutability is a shape and not a capability:
    constructing [Static] is harmless, and a test needs to build both. The
    capability is {!permit}. *)

type permit
(** Permission to change substate, as a value. Abstract and constructorless, so
    the only way to name one is to call {!permit} on some mutability. *)

val permit : t -> permit option
(** [Some] exactly for {!Mutable}. The single gate in the port.

    Composed at the call site as
    [Mutability.permit (Env.Call.mutability (Env.call env))]. This module
    deliberately offers no [of_env]: {!Env.Call} stores a {!t}, so [Env] depends
    on this module, and a function here taking an [Env.t] would close a
    dependency cycle. *)

val is_static : t -> bool
(** For prose and for tests. Safe to expose precisely because it returns a
    [bool]: no write in {!Effects} accepts a [bool], so a caller cannot route
    one of these into a write in place of a permit. *)

val equal : t -> t -> bool
val to_string : t -> string
