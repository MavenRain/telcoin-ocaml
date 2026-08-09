(* The id is the BARE hash of the compressed public key bytes, with no tag:
   Rust's [From<BlsPublicKey> for AuthorityIdentifier] is
   [blake3(pubkey.to_bytes())] (committee.rs:352-358). *)
type t = string

let zero = String.make 32 '\000'

let of_public_key pk =
  Tn_crypto.Digest.to_bytes
    (Tn_crypto.Digest.hash (Tn_crypto.Public_key.to_bytes pk))

let to_bytes t = t
let of_bytes s = if String.length s = Tn_crypto.Digest.length then Some s else None

let to_hex t =
  String.concat ""
    (List.map
       (fun i -> Printf.sprintf "%02x" (Char.code t.[i]))
       (List.init (String.length t) Fun.id))

let equal = String.equal
let compare = String.compare

module Map = Map.Make (String)
module Set = Set.Make (String)
