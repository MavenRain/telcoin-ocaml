(* The real implementation of the virtual [tn_crypto] library: BLAKE3
   digests (the in-repo pure-OCaml [Blake3], no opam blake3 dependency) and
   BLS12-381 min-signature aggregation over [bls12-381]/[bls12-381-signature].

   Every binding here is the real, final code: [Digest], [Public_key],
   [Secret_key], the [Signature]/[Aggregate] codecs, [sign]/[verify]
   (the shared pairing core at N=1) and [aggregate]/[verify_aggregate]
   (the same core at general N). No code path here raises. *)

(* DST_G1, byte-exact (ground truth F18): the min-sig ciphersuite tag used
   by every [hash_to_curve] call this file makes (the shared pairing core
   behind [verify]/[verify_aggregate]). [sign] delegates to
   [MinSig.Basic.sign], whose own private ciphersuite constant is
   byte-identical to this literal — but the two are typed independently, so
   the load-bearing proof they stay in sync is the stage-5 golden-vector
   gate (verify over a REAL Rust-produced pk/sig pair), not this comment
   (design notes sections 1 and 12). *)
let dst_g1 = Bytes.of_string "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"

module Digest = struct
  type t = string (* exactly 32 bytes, by construction *)

  let length = 32

  (* B256::ZERO, built from the width and never from a pre-image: the hash
     of the empty string is a different 32 bytes and is not a substitute. *)
  let zero = String.make length '\000'
  let hash s = Blake3.hash s
  let of_bytes s = if String.length s = length then Some s else None
  let to_bytes t = t

  (* Lowercase hex, no prefix. [Hex.of_string] encodes RAW bytes to a
     [`Hex _] payload and [Hex.show] unwraps that payload (hex.ml:191), so
     the design note's [Hex.show (`Hex t)] would have returned the raw
     bytes verbatim — corrected here to encode first. *)
  let to_hex t = Hex.show (Hex.of_string t)
  let equal = String.equal
  let compare = String.compare
end

module Public_key = struct
  type t = Bls12_381.G2.t
  (* on-curve + in-subgroup by construction ([of_compressed_bytes_opt]
     checks both), never infinity (filtered below) *)

  let to_bytes t = Bytes.to_string (Bls12_381.G2.to_compressed_bytes t)

  let of_bytes s =
    if String.length s <> Bls12_381.G2.compressed_size_in_bytes then None
    else
      Option.bind (Bls12_381.G2.of_compressed_bytes_opt (Bytes.of_string s))
        (fun p -> if Bls12_381.G2.is_zero p then None else Some p)

  let equal = Bls12_381.G2.eq
  let compare a b = String.compare (to_bytes a) (to_bytes b)
end

module Secret_key = struct
  type t = Bls12_381_signature.sk
  (* opaque; never extracted to Fr.t — avoids an unaudited byte bridge *)

  let derive seed =
    let seed_bytes =
      let buf = Buffer.create 8 in
      Buffer.add_int64_le buf seed;
      Buffer.contents buf
    in
    let ikm = Digest.hash ("tn-crypto-blst:secret-key-derive:" ^ seed_bytes) in
    (* [Digest.hash] always returns exactly [Digest.length] = 32 bytes:
       [generate_sk]'s ikm<32 raise is unreachable by construction here,
       not merely guarded. *)
    Bls12_381_signature.generate_sk ~key_info:Bytes.empty
      (Bytes.of_string ikm)

  let public_key sk =
    let pk_bytes =
      Bytes.to_string Bls12_381_signature.MinSig.(pk_to_bytes (derive_pk sk))
    in
    (* Fail-closed, not fail-open: [generate_sk]'s KeyGen contract
       (draft-04 s2.3) rejects/retries a zero scalar, so this decode is
       provably [Some] in practice. If a future opam version ever violates
       that, [G2.zero] is the inert fallback. This path never re-enters
       [Public_key.of_bytes], so its infinity filter cannot catch the
       fallback; what keeps it inert is [verify_core]'s own unconditional
       zero-pk rejection, which turns a degraded key into a [verify] that
       is always [false] — never a spurious accept. *)
    Option.value ~default:Bls12_381.G2.zero
      (Bls12_381.G2.of_compressed_bytes_opt (Bytes.of_string pk_bytes))
end

module Signature = struct
  type t = Bls12_381.G1.t

  let to_bytes t = Bytes.to_string (Bls12_381.G1.to_compressed_bytes t)

  let of_bytes s =
    if String.length s <> Bls12_381.G1.compressed_size_in_bytes then None
    else Bls12_381.G1.of_compressed_bytes_opt (Bytes.of_string s)
  (* deliberately NO is_zero filter: matches blst's own infinity-signature
     asymmetry *)

  let equal = Bls12_381.G1.eq
end

module Aggregate = struct
  type t = Bls12_381.G1.t
  (* one real curve point — never a list, unlike the stub *)

  let to_bytes t = Bytes.to_string (Bls12_381.G1.to_compressed_bytes t)

  let of_bytes s =
    if String.length s <> Bls12_381.G1.compressed_size_in_bytes then None
    else Bls12_381.G1.of_compressed_bytes_opt (Bytes.of_string s)

  let equal = Bls12_381.G1.eq
end

let sign sk msg =
  let sig_bytes =
    Bytes.to_string
      Bls12_381_signature.MinSig.(
        signature_to_bytes (Basic.sign sk (Bytes.of_string msg)))
  in
  (* Bridge from the opam package's abstract [MinSig.signature] to our
     [Signature.t = Bls12_381.G1.t] through the library's OWN canonical
     serialization, so this decode is provably [Some] in practice.
     Fail-closed, not fail-open: if a future opam version ever broke that
     round-trip, the inert [G1.zero] fallback would only ever FAIL [verify]
     against any real key downstream, never cause a spurious accept
     (design notes section 7). *)
  Option.value ~default:Bls12_381.G1.zero
    (Bls12_381.G1.of_compressed_bytes_opt (Bytes.of_string sig_bytes))

(* The one pairing routine, shared by [verify] (N=1) and
   [verify_aggregate] (N arbitrary), so [dst_g1] and the equation's
   sign/direction are stated exactly once. By bilinearity,
   [pairing_check terms] holds iff e(h, sum pk_i) = e(agg, g2) — the
   standard shared-message BLS aggregate-verify equation (design notes
   section 4). The [[] -> false] guard is unconditional and runs before
   [msg] is even hashed: without it, an empty-signer call would collapse to
   e(agg, g2) = 1, which the infinity-encoded aggregate satisfies. The
   zero-pk guard is just as unconditional: [Public_key.of_bytes] filters
   the infinity encoding, but [Secret_key.public_key]'s fail-closed
   fallback constructs a [Public_key.t] without ever passing through that
   filter, and e(P, zero) = 1 for every P — a zero pk against an
   infinity-encoded aggregate would otherwise collapse every term to 1 and
   accept ANY message. No [unsafe_*_of_bytes], no
   [MinSig.Basic.aggregate_verify] (raises on telcoin's own
   repeated-message shape), no private [core_aggregate_verify] anywhere. *)
let verify_core pks msg agg =
  match pks with
  | [] -> false
  | _ :: _ when List.exists Bls12_381.G2.is_zero pks -> false
  | _ :: _ ->
      let h = Bls12_381.G1.hash_to_curve (Bytes.of_string msg) dst_g1 in
      let terms =
        (Bls12_381.G1.negate agg, Bls12_381.G2.one)
        :: List.map (fun pk -> (h, pk)) pks
      in
      Bls12_381.Pairing.pairing_check terms

let verify pk msg sig_ = verify_core [ pk ] msg sig_

(* Point-sum aggregation (design notes section 4): fold [G1.add] from the
   group identity over the signatures AS GIVEN — no dedup, no reordering
   (G1 addition is commutative and associative, so order-irrelevance is a
   theorem, not code; the stage gate still tests it). Each element is
   in-subgroup by construction of [Signature.of_bytes]/[sign], so the sum
   is too — no per-element re-validation, matching blst's aggregate-then-
   check shape (ground truth F41). [aggregate []] is [G1.zero], whose
   compressed encoding is the 0xc0 infinity bytes — byte-compatible with
   Rust's empty-certificate default (ground truth F49) and the opam
   package's own empty fold (F50); downstream it can only ever be
   REJECTED, by [verify_core]'s empty-pks guard or by the pairing
   equation itself against any non-empty signer list. *)
let aggregate sigs = List.fold_left Bls12_381.G1.add Bls12_381.G1.zero sigs

(* The general-N face of [verify_core]: same [dst_g1], same equation, and
   the same unconditional [[] -> false] and zero-pk guards (design notes
   section 11 item 7 — the guards suffice where Rust needs three layers,
   because this file controls the entire call path with no library
   fallback of its own to also protect). Per-entry subgroup facts are
   carried by construction of the input types: each pk is in-subgroup
   ([Public_key.of_bytes]; infinity is re-rejected by [verify_core]'s
   zero-pk guard, which covers the one constructor that bypasses the
   codec filter — [Secret_key.public_key]'s fallback), the aggregate is in-subgroup
   ([Aggregate.of_bytes], which deliberately admits the infinity
   encoding — exactly why the guard's narrow [pks = [], agg = infinity]
   case is load-bearing, design notes section 4). Duplicate pks are kept
   AS GIVEN: [pk; pk] against a single [sig] rejects and against the
   doubled aggregate accepts — no dedup code exists to break that. *)
let verify_aggregate pks msg agg = verify_core pks msg agg
