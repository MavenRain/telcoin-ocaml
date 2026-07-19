type t = Round.t

let of_round r =
  match Round.parity r with
  | Round.Odd -> None
  | Round.Even -> if Round.to_int r >= 2 then Some r else None

let to_round t = t
let schedule_index t = (Round.to_int t / 2) - 1

let next t =
  (* Two rounds on from an even round >= 2 is again even and >= 2, so the
     invariant is preserved without re-checking. *)
  Round.succ (Round.succ t)

let equal = Round.equal
let compare = Round.compare
