(** The BLAKE2b compression function [F], as the [BLAKE2F] precompile (address
    [0x09]) exposes it (EIP-152, {{:https://datatracker.ietf.org/doc/html/rfc7693}
    RFC 7693} section 3.2).

    This is the bare mixing kernel: it takes an already-parsed state, message
    block, counter and final-block flag, and runs a caller-chosen number of
    rounds. The precompile's byte framing (the fixed 213-byte input, the
    little-endian word reads and the flag validation) lives in {!Precompile};
    keeping the kernel here lets it be exercised against the EIP-152 vectors on
    its own, in the units RFC 7693 states them (64-bit words), rather than only
    through the precompile's wrapper. *)

val compress :
  rounds:int ->
  h:int64 array ->
  m:int64 array ->
  t0:int64 ->
  t1:int64 ->
  final:bool ->
  int64 array
(** [compress ~rounds ~h ~m ~t0 ~t1 ~final] is the 8-word state after [rounds]
    applications of the round function, mixing the message block [m] into the
    state [h] under the 128-bit offset counter ([t0] low, [t1] high) and the
    final-block indicator [final].

    [h] must have length 8 and [m] length 16 (the {!Precompile} caller guarantees
    both from the 213-byte framing); indices outside those bounds are never
    read. Neither [h] nor [m] is mutated — the state is copied into a local
    working vector, so the result is a fresh array and [compress] is a pure
    function of its arguments. The round schedule wraps the ten permutation rows
    modulo ten, so [rounds] beyond ten (up to the [2^32 - 1] the precompile
    admits) is well defined and matches the reference. *)
