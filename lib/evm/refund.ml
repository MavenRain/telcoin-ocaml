(* A native [int], signed, with no invariant to protect — deliberately unlike
   [Gas.t], whose whole point is that it cannot go below zero. The counter is a
   distinct abstract type rather than a bare [int] so that no addition between a
   refund and an allowance can typecheck. *)
type t = int

let zero = 0
let add t contribution = t + contribution
let to_int t = t
let equal a b = Int.equal a b
