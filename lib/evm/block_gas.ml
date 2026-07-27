(* The block gas meter. The invariant [used <= limit] is established by [start]
   (zero used against a non-negative limit) and preserved by [charge_receipt],
   which is the only other producer and refuses the step that would break it. *)

type t = { limit : int; used : int }

let start ctx = { limit = Block_context.gas_limit ctx; used = 0 }
let limit t = t.limit
let used t = t.used

(* Non-negative by the invariant, so no [max 0] is needed and none is written:
   a clamp here would hide a broken invariant rather than uphold one. *)
let available t = t.limit - t.used

(* [Receipt.gas_used] is non-negative and the native [int] is 63-bit, so the sum
   cannot overflow before it can exceed a block gas limit. *)
let charge_receipt t receipt =
  let used = t.used + Receipt.gas_used receipt in
  if used > t.limit then None else Some { limit = t.limit; used }

let equal a b = a.limit = b.limit && a.used = b.used
