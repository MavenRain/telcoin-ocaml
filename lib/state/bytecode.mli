(** An account's code: the bytes deployed at its address, and the Keccak-256 hash
    the state commits to.

    An account's code is immutable for as long as the account holds it: a
    contract is deployed once, by [CREATE] or at genesis, and thereafter its code
    only ever reads. So this is a value type with no mutators, only the two
    constructors {!empty} and {!of_string} and the readers below. It carries the
    bytes and nothing else; the {!hash} is {e derived} rather than stored, so
    there is no invariant that a hash matches its bytes to be maintained or
    broken. A stored hash would be the state root's concern, and the state root
    is still deferred.

    It lives in {!Tn_state}, beside {!Account}, rather than beside {!Tn_evm}'s
    {!Tn_evm.Data} because it is a field of an account and not a window into one.
    {!Tn_evm.Data} is calldata and copied-from code read through a
    zero-extension rule; this is the code an account {e holds}. The two never
    substitute for each other, and keeping them distinct types is what stops a
    caller handing account code where a calldata window is meant or the reverse.
    The interpreter bridges them: {!Account.code} hands out the bytes and the
    copying instruction wraps them in a {!Tn_evm.Data.t}.

    It is the one thing in {!Tn_state} that reaches into {!Tn_keccak}, and that
    placement is why {!Tn_keccak} is a leaf below both this library and
    {!Tn_evm}: the code hash is a fact fixed forever, not a link-time choice, so
    it names the concrete hash rather than the protocol-hash seam. *)

type t
(** Some bytes of code. Any byte string is one — code has no validity rule at
    this layer (jump-destination analysis is {!Tn_evm.Code}'s, and it treats
    every byte string as runnable) — so there is no smart constructor to fail. *)

val empty : t
(** No code. The code of an externally owned account and of an address the state
    holds no entry for; the value {!Account.empty} carries. Its {!hash} is
    [KECCAK_EMPTY], and {!is_empty} of it is [true]. *)

val of_string : string -> t
(** Admit a byte string as code. Total. *)

val to_string : t -> string
(** The code bytes, exactly as given. *)

val length : t -> int
(** The number of bytes — what [EXTCODESIZE] and [CODESIZE] report. *)

val is_empty : t -> bool
(** Whether there are no bytes. This is the third conjunct of {!Account.is_empty}
    and therefore of EIP-161 emptiness: an account is empty only if, among the
    rest, it holds no code. It is {e not} "the hash is [KECCAK_EMPTY]" spelled
    differently — those two agree here, but [is_empty] asks the question EIP-161
    asks (are there bytes) and reads the answer straight off the representation,
    without hashing. *)

val hash : t -> Tn_keccak.t
(** The Keccak-256 of the bytes. Derived on demand, never stored, so it cannot
    fall out of step with the code. The hash of {!empty} is [KECCAK_EMPTY]
    ({!Tn_keccak.empty}), because Keccak of the empty string is that constant.

    This is the digest [EXTCODEHASH] reports for an account that {e exists} —
    an account EIP-1052 does not fold to zero. The zero it reports for an account
    that does not exist is a bare word the interpreter produces, provably not a
    digest, and so is never confused with the [KECCAK_EMPTY] a real codeless
    account has. *)

val equal : t -> t -> bool
(** Byte equality. Exact as content equality: the representation is the bytes
    themselves, so no two distinct representations read alike. *)

val compare : t -> t -> int
