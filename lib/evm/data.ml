module U256 = Tn_state.U256

(* The bytes exactly as given. The zero extension past the end is a rule the
   readers below apply, never a materialised suffix, so every value has one
   representation and [equal] is exact. *)
type t = string

let empty = ""
let of_string s = s
let to_string t = t
let length t = String.length t

(* The source offset saturates rather than failing, and clamping it to the
   length is the same function: every offset at or past the end reads as all
   zeroes, so a word offset that will not fit in an [int] and one that is merely
   far too large are the same case. Clamping here is also what keeps
   [start + i] below [max_int] in the reader, so no index can wrap. *)
let start_of t offset =
  let len = String.length t in
  Option.fold ~none:len
    ~some:(fun o -> if o >= len then len else o)
    (U256.to_int offset)

(* [String.init] applies its function exactly on [0 .. length - 1], and the
   index into the source is range-checked, so no read can leave the source and
   every byte past the end is the zero the EVM specifies. [length] is the
   caller's precondition, as in [Memory.slice]: it is held to [Memory.max_extent]
   by the expansion the caller performs for the same length, NOT by the copy
   price, which is linear and stays affordable well past what [String.init] can
   serve. *)
let read t ~offset ~length =
  let start = start_of t offset in
  let len = String.length t in
  String.init length (fun i ->
      let j = start + i in
      if j < len then String.get t j else '\000')

(* [read] returns exactly 32 bytes and [of_be_bytes] accepts exactly that, so
   the default is unreachable. It is a default rather than an exception because
   the interface promises [CALLDATALOAD] a total function. *)
let word_at t offset =
  Option.value ~default:U256.zero (U256.of_be_bytes (read t ~offset ~length:32))

let equal a b = String.equal a b
