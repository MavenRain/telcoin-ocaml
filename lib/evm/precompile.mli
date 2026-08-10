open Tn_types

(** The Ethereum precompiled contracts, addressed by the low bytes of the callee
    address and reached through the CALL family. A precompile is not code on an
    account: {!Interpreter} intercepts a call whose target is one of these
    addresses and runs the built-in instead of entering a sub-frame, which is
    why the dispatch lives beside the interpreter rather than in the world state.

    Ground truth is [revm-precompile] at reth v1.11.3: the four
    Frontier/Homestead builtins, Berlin's repriced [MODEXP] (EIP-2565),
    Istanbul's [BLAKE2F] (EIP-152) and the three bn254 curve builtins [0x06],
    [0x07] and [0x08] at their Istanbul prices (EIP-1108). Every body here is
    in the BERLIN set, and revm folds [SpecId::SHANGHAI] straight into
    [PrecompileSpecId::BERLIN] ([src/lib.rs:441]), so Shanghai adds no
    precompile over Berlin and {!invoke} is INVARIANT across the port's whole
    fork subset: it takes no {!Spec.t} and needs none. The bn254 prices are the
    clearest case of that: the port's fork floor is Shanghai, well past
    Istanbul, so every expressible spec sees 150, 6_000 and 45_000 plus 34_000
    an element, and the pre-Istanbul 500, 40_000 and 100_000 plus 80_000 an
    element are unreachable and unwritten. What the later forks add is
    deferred rather than gated: Cancun's [0x0a] KZG point evaluation and
    Prague's [0x0b]-[0x11] BLS12-381 set are absent BODIES, missing at every
    level equally. That is a different debt from an activation gate, and adding
    a {!Spec.t} argument here would not pay any part of it. This comment long
    cited the pin as [32.0.0]; only [32.1.0] is vendored, and the line above
    was read from that (a patch bump, not diffed byte for byte).

    The result is reported abstractly so the interpreter can turn it into an
    outcome without knowing which precompile ran: a success carries its gas and
    output, a rejection carries neither because the call then forfeits the
    whole forwarded allowance. *)

type response =
  | Not_a_precompile
      (** No precompile lives at this address (either a plain account or one of
          the builtins this port has not reached yet, the KZG and BLS12-381
          ranges); the caller proceeds to the account's own code. *)
  | Succeeded of { gas_used : int; output : string }
      (** The precompile ran, spending [gas_used] of the forwarded allowance and
          returning [output]. [output] may be empty on a genuine success: a
          malformed [ECRECOVER] input recovers no key yet still returns
          successfully with empty output. That doctrine is [ECRECOVER]'s alone.
          The bn254 builtins never take it: a malformed point rejects. *)
  | Rejected
      (** The precompile refused the call: the forwarded gas did not cover its
          cost, or the input broke a structural rule the builtin enforces
          ([BLAKE2F]'s fixed framing, [MODEXP]'s length ceiling, a bn254
          coordinate at or above the field modulus or a point off the curve).
          This is an exceptional halt: the call returns zero, no output, and
          every unit of the forwarded allowance is consumed. *)

val invoke : Units.Address.t -> input:string -> gas_limit:int -> response
(** [invoke address ~input ~gas_limit] runs the precompile at [address] over
    [input] with [gas_limit] units forwarded, or answers {!Not_a_precompile}.

    Implemented: [ECRECOVER] (0x01), [SHA256] (0x02), [RIPEMD160] (0x03),
    [IDENTITY] (0x04), [MODEXP] (0x05), the three bn254 curve builtins ecAdd
    (0x06), ecMul (0x07) and ecPairing (0x08), and [BLAKE2F] (0x09). ecAdd and
    ecMul cost a flat 150 and 6_000 gas; ecPairing costs 45_000 plus 34_000 an
    element, priced on the element count the input length FLOORS to, so a
    trailing partial element is charged as though it were absent and refused
    afterwards. All three charge before the input is read, so an under-funded
    call is rejected whatever its bytes hold, and every other way they can fail
    (a coordinate at or above the field modulus, a point off its curve, a [G2]
    point outside the [r]-order subgroup, a length that is not a whole number of
    elements) is the same {!Rejected}. ecPairing answers a 32-byte word, one on
    a product of one and zero otherwise, and an element with either point at
    infinity is dropped before that product, so the empty input answers one.

    Still deferred: the KZG point evaluation (0x0a) and the BLS12-381 range
    (0x0b-0x11). Each reports {!Not_a_precompile}, so calling one runs the
    (empty) account code exactly as it did before this chunk, no better and no
    worse. *)
