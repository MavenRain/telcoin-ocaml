(* Stored as a host int constrained to the u32 range by of_int. OCaml's native
   int is 63-bit, so u32 values and all their sums used here fit without
   overflow; the range invariant is only re-imposed at the codec boundary. *)
type t = int

let u32_max = 0xffff_ffff
let genesis = 0
let of_int n = if n >= 0 && n <= u32_max then Some n else None
let to_int t = t
let succ t = if t >= u32_max then u32_max else t + 1
let pred t = if t <= 0 then None else Some (t - 1)

type parity = Even | Odd

let parity t = if t land 1 = 0 then Even else Odd
let sub_saturating t n = if n >= t then 0 else t - n
let equal = Int.equal
let compare = Int.compare
let to_string = string_of_int

module Map = Map.Make (Int)
module Set = Set.Make (Int)
