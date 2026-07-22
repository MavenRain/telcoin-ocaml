open Tn_types

(** The Ethereum precompiled contracts, addressed by the low bytes of the callee
    address and reached through the CALL family. A precompile is not code on an
    account: {!Interpreter} intercepts a call whose target is one of these
    addresses and runs the built-in instead of entering a sub-frame, which is
    why the dispatch lives beside the interpreter rather than in the world state.

    Ground truth is [revm-precompile 32.0.0] at the Prague spec (reth v1.11.3):
    the four Frontier/Homestead builtins, Berlin's repriced [MODEXP] (EIP-2565)
    and Istanbul's [BLAKE2F] (EIP-152). The result is reported abstractly so the
    interpreter can turn it into an outcome without knowing which precompile ran:
    a success carries its gas and output, a rejection carries neither because the
    call then forfeits the whole forwarded allowance. *)

type response =
  | Not_a_precompile
      (** No precompile lives at this address (either a plain account or one of
          the curve/pairing builtins this chunk has not reached yet); the caller
          proceeds to the account's own code. *)
  | Succeeded of { gas_used : int; output : string }
      (** The precompile ran, spending [gas_used] of the forwarded allowance and
          returning [output]. [output] may be empty on a genuine success — a
          malformed [ECRECOVER] input recovers no key yet still returns
          successfully with empty output. *)
  | Rejected
      (** The precompile refused the call — the forwarded gas did not cover its
          cost, or the input broke a structural rule the builtin enforces
          ([BLAKE2F]'s fixed framing, [MODEXP]'s length ceiling). This is an
          exceptional halt: the call returns zero, no output, and every unit of
          the forwarded allowance is consumed. *)

val invoke : Units.Address.t -> input:string -> gas_limit:int -> response
(** [invoke address ~input ~gas_limit] runs the precompile at [address] over
    [input] with [gas_limit] units forwarded, or answers {!Not_a_precompile}.

    Implemented: [ECRECOVER] (0x01), [SHA256] (0x02), [RIPEMD160] (0x03),
    [IDENTITY] (0x04), [MODEXP] (0x05) and [BLAKE2F] (0x09). The elliptic-curve
    and pairing builtins — bn254 (0x06-0x08), the KZG point evaluation (0x0a) and
    the BLS12-381 range — are deferred to their own chunks and report
    {!Not_a_precompile}, so calling one runs the (empty) account code exactly as
    it did before this chunk, no better and no worse. *)
