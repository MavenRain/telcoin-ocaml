(* The bytes are the value: canonical on their own, so [equal] and [compare] are
   the string ones and the hash never needs storing beside them. *)
type t = string

let empty = ""
let of_string s = s
let to_string t = t
let length = String.length
let is_empty t = String.length t = 0

(* Derived, not stored. [Tn_keccak.digest] is total and hashes the empty string
   to [Tn_keccak.empty], so [hash empty] is [KECCAK_EMPTY] with no special case
   to keep in step. *)
let hash t = Tn_keccak.digest t
let equal = String.equal
let compare = String.compare
