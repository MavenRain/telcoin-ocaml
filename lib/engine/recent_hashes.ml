(* Newest first, capped at the depth limit: a hash further back than the limit
   can never be requested, so keeping it would only make two windows that
   answer every request alike compare unequal. *)
type t = Tn_keccak.t list

let cap hashes =
  List.filteri (fun i _ -> i < Tn_evm.Block_hashes.depth_limit) hashes

let of_genesis hash ~ancestors = cap (hash :: ancestors)
let push t hash = cap (hash :: t)
let window t = Tn_evm.Block_hashes.of_recent t
let depth t = List.length t
let to_list t = t
