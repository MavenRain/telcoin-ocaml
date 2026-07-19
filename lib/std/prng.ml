(* SplitMix64. The state is a 64-bit value advanced by a fixed odd increment
   (the golden-ratio constant); each output is a mix of the pre-advance state.
   All arithmetic is on Int64 so the wraparound matches the reference exactly
   regardless of the host's native int width. *)

type t = int64

let golden = 0x9e3779b97f4a7c15L

let of_seed s = s

let mix z =
  let z = Int64.mul (Int64.logxor z (Int64.shift_right_logical z 30)) 0xbf58476d1ce4e5b9L in
  let z = Int64.mul (Int64.logxor z (Int64.shift_right_logical z 27)) 0x94d049bb133111ebL in
  Int64.logxor z (Int64.shift_right_logical z 31)

let next_int64 state =
  let state' = Int64.add state golden in
  (mix state', state')

(* Uniform reduction into a range. The width is taken over Int64 to avoid
   overflow when hi - lo approaches max_int, then the raw draw is folded into
   [0, span) by unsigned remainder. A tiny modulo bias is acceptable for
   latency jitter and keeps the function total and allocation-free. *)
let int_in state ~lo ~hi =
  if hi <= lo then (lo, next_int64 state |> snd)
  else begin
    let span = Int64.add (Int64.sub (Int64.of_int hi) (Int64.of_int lo)) 1L in
    let raw, state' = next_int64 state in
    (* unsigned_rem keeps the sign bit from turning the draw negative *)
    let offset = Int64.to_int (Int64.unsigned_rem raw span) in
    (lo + offset, state')
  end

let split state =
  let a, state' = next_int64 state in
  let b, _ = next_int64 (Int64.add state' golden) in
  (of_seed a, of_seed b)
