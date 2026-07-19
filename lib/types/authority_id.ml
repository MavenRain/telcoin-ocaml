(* The id is a domain-separated hash of the public key bytes, so it cannot be
   confused with a raw digest of anything else. *)
type t = string

let zero = String.make 32 '\000'
let domain = "tn-authority-id:"
let of_public_key pk =
  Tn_crypto.Digest.to_bytes
    (Tn_crypto.Digest.hash (domain ^ Tn_crypto.Public_key.to_bytes pk))

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
