(* The depth is a native count, only ever built from [zero] by [succ], so it is
   always non-negative. *)
type t = int

let zero = 0
let succ t = t + 1

(* [CALL_STACK_LIMIT] ([revm] [primitives/constants.rs], imported at
   [revm-handler] [frame.rs:23]). The guard tests the child depth against it
   ([frame.rs:162-164], the comparison is [depth > 1024]), so [within_limit] is
   the negation of that strict [>], i.e. [<=]. *)
let call_stack_limit = 1024
let within_limit t = t <= call_stack_limit
let to_int t = t
