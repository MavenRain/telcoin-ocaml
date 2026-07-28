(* IteratorRandom::choose_multiple (rand-0.9.2/src/seq/iterator.rs:244-268),
   the exact reservoir the pending-exit top-up consumes. The replacement draw
   random_range(..i + 1 + amount) is sample_single(0, i + 1 + amount), which
   is sample_single_inclusive(0, i + amount) (uniform_int.rs:152-168 and
   538-560), i.e. {!Std_rng.random_range_inclusive} with bound i + amount. *)

(* The first [min n (length l)] elements and the remainder; a negative [n]
   splits at zero. Hand-rolled so a negative amount is total rather than an
   exception. *)
let split_at n l =
  let rec go n acc rest =
    if n <= 0 then (List.rev acc, rest)
    else
      match rest with
      | [] -> (List.rev acc, [])
      | x :: tl -> go (n - 1) (x :: acc) tl
  in
  go n [] l

(* The reservoir with slot [k] replaced by [elem]: a gather, not a scatter. *)
let replace k elem = List.mapi (fun j x -> if j = k then elem else x)

let choose_multiple rng ~amount pool =
  let reservoir, rest = split_at amount pool in
  if List.length reservoir <> amount then
    (* The iterator was exhausted early (or the amount is negative, which
       has no Rust image): the whole list, no draws (iterator.rs:255,
       262-266). When the pool is short, [rest] is empty, so this arm and
       the fold below agree on consuming nothing; the guard is kept for
       structural fidelity to the crate. *)
    (reservoir, rng)
  else
    let chosen, rng, _ =
      List.fold_left
        (fun (res, rng, i) elem ->
          Result.fold
            ~ok:(fun (k, rng) ->
              let res = if k < amount then replace k elem res else res in
              (res, rng, i + 1))
            ~error:(fun (Std_rng.Negative_bound _) ->
              (* Unreachable: amount = length reservoir >= 0 and i >= 0, so
                 the bound is never negative. Advance without replacing. *)
              (res, rng, i + 1))
            (Std_rng.random_range_inclusive rng ~bound:(i + amount)))
        (reservoir, rng, 0) rest
    in
    (chosen, rng)
