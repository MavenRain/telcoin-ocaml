(* Deterministic, deliberately-forgeable crypto for the simulation slice.

   Design intent: exercise every protocol code path (sign, verify, aggregate,
   verify-aggregate, one-vote-per-authority, 2f+1 stake) with a real 32-byte
   hash but without a native BLS dependency. The digest is genuine (BLAKE2s-256
   via digestif, matching the 32-byte width of the production BLAKE3). The
   signature is structural — it simply records who signed what — so it is
   forgeable and MUST NOT be used outside simulation. Swapping in the real
   [tn_crypto_blst] implementation changes none of the protocol code that links
   against the virtual interface. *)

module H = Digestif.BLAKE2S

module Digest = struct
  type t = string (* exactly H.digest_size = 32 bytes, by construction *)

  let length = H.digest_size
  let hash s = H.to_raw_string (H.digest_string s)
  let of_bytes s = if String.length s = length then Some s else None
  let to_bytes t = t

  let to_hex t =
    String.concat ""
      (List.map
         (fun i -> Printf.sprintf "%02x" (Char.code t.[i]))
         (List.init (String.length t) Fun.id))

  let equal = String.equal
  let compare = String.compare
end

(* A public key in the stub is just the 32-byte hash of its seed; distinct
   seeds give distinct keys with overwhelming probability, which is all the
   committee ordering needs. *)
module Public_key = struct
  type t = string

  let to_bytes t = t
  let of_bytes s = if String.length s = 32 then Some s else None
  let equal = String.equal
  let compare = String.compare
end

module Secret_key = struct
  type t = { seed : int64; public : Public_key.t }

  let derive seed =
    let seed_bytes =
      let b = Bytes.create 8 in
      Bytes.set_int64_le b 0 seed;
      Bytes.to_string b
    in
    { seed; public = Digest.hash ("tn-stub-secret:" ^ seed_bytes) }

  let public_key t = t.public
end

(* A stub signature carries the signer's public key and the digest of the
   signed message. Verification checks both match — structurally sound for
   distinguishing signers and messages, cryptographically meaningless. *)
module Signature = struct
  type t = { signer : Public_key.t; msg_digest : Digest.t }

  let sep = "\x00" (* pk and digest are both fixed 32 bytes, but keep a
                      separator so the byte encoding is unambiguous *)

  let to_bytes { signer; msg_digest } = signer ^ sep ^ msg_digest

  let of_bytes s =
    if String.length s = 32 + 1 + 32 then
      Some { signer = String.sub s 0 32; msg_digest = String.sub s 33 32 }
    else None

  let equal a b =
    Public_key.equal a.signer b.signer && Digest.equal a.msg_digest b.msg_digest
end

module Aggregate = struct
  type t = Signature.t list

  (* Canonical byte form: signatures sorted by signer so the aggregate of a
     given signer set over a given message is unique regardless of collection
     order — mirroring the order-independence of a real BLS aggregate. *)
  let sorted (sigs : t) =
    List.sort
      (fun (a : Signature.t) b -> Public_key.compare a.signer b.signer)
      sigs

  let to_bytes sigs =
    String.concat "" (List.map Signature.to_bytes (sorted sigs))

  let of_bytes s =
    let unit = 65 in
    let n = String.length s in
    if n mod unit <> 0 then None
    else
      let rec go i acc =
        if i >= n then Some (List.rev acc)
        else
          match Signature.of_bytes (String.sub s i unit) with
          | Some sg -> go (i + unit) (sg :: acc)
          | None -> None
      in
      go 0 []

  let equal a b =
    List.equal Signature.equal (sorted a) (sorted b)
end

let sign (sk : Secret_key.t) msg =
  { Signature.signer = Secret_key.public_key sk; msg_digest = Digest.hash msg }

let verify pk msg (sg : Signature.t) =
  Public_key.equal sg.signer pk && Digest.equal sg.msg_digest (Digest.hash msg)

let aggregate sigs = sigs

let verify_aggregate pks msg (agg : Aggregate.t) =
  let want = Digest.hash msg in
  (* Every listed key must have contributed exactly the right signature, and no
     extra signatures may be present: the signer multiset equals the key
     multiset. *)
  let key_ok pk =
    List.exists
      (fun (s : Signature.t) ->
        Public_key.equal s.signer pk && Digest.equal s.msg_digest want)
      agg
  in
  List.length agg = List.length pks && List.for_all key_ok pks
