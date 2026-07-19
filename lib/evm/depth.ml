(* The sixteen stack depths [DUP] and [SWAP] can name. The representation is the
   one-based depth itself; [of_int] is the only way in, so a value of this type
   is always in range. *)
type t = int

let min_depth = 1
let max_depth = 16
let of_int n = if n >= min_depth && n <= max_depth then Some n else None
let to_int t = t
let all = List.init max_depth (fun i -> i + min_depth)
let equal = Int.equal
