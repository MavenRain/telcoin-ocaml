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

(* EIP-170's 0x6000 ([revm-primitives] [eip170.rs]) and EIP-3860's limit, which is
   defined as twice it ([eip3860.rs]) rather than as a number of its own. *)
let max_deployed_size = 0x6000
let max_initcode_size = 2 * max_deployed_size

type deployment_error = Reserved_prefix | Too_large of int

(* The two tests a creation's output must pass before it becomes code, in revm's
   order ([revm-handler] [frame.rs:281-296]): EIP-3541's reserved [0xEF] first,
   then EIP-170's size. The order is observable because the two produce different
   halts, and both produce a different one from the deposit charge that follows
   them, so it is written once here rather than at the call site. *)
let validate_deployment output =
  if String.length output > 0 && Char.code output.[0] = 0xef then Error Reserved_prefix
  else if String.length output > max_deployed_size then
    Error (Too_large (String.length output))
  else Ok ()
