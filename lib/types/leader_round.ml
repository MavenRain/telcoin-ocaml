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

let prev t =
  (* An even round > 2 is >= 4, so two rounds back is even and >= 2 — the
     invariant holds and [of_round] accepts. Round 2 has no earlier leader. *)
  if Round.to_int t <= 2 then None else of_round (Round.sub_saturating t 2)

let equal = Round.equal
let compare = Round.compare
