(* Newest first, capped at the depth limit: a hash further back than the limit
   can never be requested, so keeping it would only make two windows that
   answer every request alike compare unequal.

   The newest entry is a FIELD rather than the head of a list, so "never
   empty" is a type fact and {!newest} is total without a head accessor, and
   {!ancestors} is a projection rather than a list taken apart. The observable
   surface is unchanged: [to_list] and [window] still see one newest-first
   list of at most [depth_limit] hashes. *)
type t = { newest : Tn_keccak.t; ancestors : Tn_keccak.t list }

(* An ancestor sits at combined position [i + 1], so the whole window - the
   newest plus what survives here - never passes the limit. *)
let cap ancestors =
  List.filteri (fun i _ -> i + 1 < Tn_evm.Block_hashes.depth_limit) ancestors

let of_genesis hash ~ancestors = { newest = hash; ancestors = cap ancestors }
let push t hash = { newest = hash; ancestors = cap (t.newest :: t.ancestors) }
let all t = t.newest :: t.ancestors
let window t = Tn_evm.Block_hashes.of_recent (all t)
let depth t = 1 + List.length t.ancestors
let newest t = t.newest
let ancestors t = t.ancestors
let to_list t = all t
