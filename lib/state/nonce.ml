(* The count of transactions an account has sent — Rust [u64]. A native [int] is
   63-bit, far beyond any reachable nonce, and [succ] saturates rather than wrap. *)
type t = int

let zero = 0
let succ n = if n = max_int then n else n + 1
let of_int n = if n >= 0 then Some n else None
let to_int n = n
let equal = Int.equal
let compare = Int.compare
let to_string = string_of_int
