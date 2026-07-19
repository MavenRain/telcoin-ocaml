module W = Tn_state.U256

type word = W.t

(* The remaining allowance. [of_int] rejects a negative one and [charge] never
   spends past zero, so a value of this type is always non-negative. *)
type t = int

let of_int n = if n < 0 then None else Some n
let remaining t = t
let charge cost t = if cost < 0 || cost > t then None else Some (t - cost)

(* The named tiers of the schedule. *)
let zero = 0
let base = 2
let verylow = 3
let low = 5
let mid = 8
let high = 10
let jumpdest = 1

let static_cost = function
  (* The instructions that halt are free; all their cost, where they have any,
     is the memory they touch. *)
  | Opcode.Stop | Opcode.Return | Opcode.Revert | Opcode.Invalid -> zero
  | Opcode.Add | Opcode.Sub | Opcode.Lt | Opcode.Gt | Opcode.Slt | Opcode.Sgt
  | Opcode.Eq | Opcode.Iszero | Opcode.And | Opcode.Or | Opcode.Xor | Opcode.Not
  | Opcode.Byte | Opcode.Shl | Opcode.Shr | Opcode.Sar | Opcode.Mload
  | Opcode.Mstore | Opcode.Mstore8 | Opcode.Push _ | Opcode.Dup _
  | Opcode.Swap _ ->
      verylow
  | Opcode.Mul | Opcode.Div | Opcode.Sdiv | Opcode.Mod | Opcode.Smod
  | Opcode.Signextend ->
      low
  | Opcode.Addmod | Opcode.Mulmod | Opcode.Jump -> mid
  | Opcode.Exp | Opcode.Jumpi -> high
  | Opcode.Pop | Opcode.Pc | Opcode.Msize | Opcode.Gas | Opcode.Push0 -> base
  | Opcode.Jumpdest -> jumpdest

let exp_byte_cost = 50

(* The exponent's width in bytes: zero when it is zero, otherwise the distance
   from its most significant nonzero byte to the end of the word. Folding over
   the big-endian bytes and keeping the largest such distance finds it, since the
   most significant nonzero byte gives the largest. *)
let significant_bytes w =
  let source = W.to_be_bytes w in
  let width = String.length source in
  List.fold_left
    (fun acc i ->
      if Char.equal (String.get source i) '\000' then acc
      else Int.max acc (width - i))
    0
    (List.init width Fun.id)

let exp_cost exponent = exp_byte_cost * significant_bytes exponent

(* Multiplication and addition that refuse rather than wrap. Both arguments are
   non-negative everywhere they are used below. *)
let checked_mul a b =
  if a = 0 || b = 0 then Some 0 else if a > max_int / b then None else Some (a * b)

let checked_add a b = if a > max_int - b then None else Some (a + b)

let memory_word_cost = 3
let quadratic_divisor = 512

(* The total cost of [w] words, [3w + w^2/512], computed without ever forming a
   value that does not fit.

   The quadratic term is split as [w^2/512 = q*w + (r*w)/512] where [w = 512q + r]
   — exact, because [512*q*w] is divisible by the divisor — so the two products
   can be checked separately. Every [None] below is returned only after
   establishing that a factor of the true cost already exceeds [max_int]; the
   cost is therefore genuinely larger than any allowance, and the caller's
   treatment of [None] as out of gas is exact, not a conservative guess.

   (revm computes the same quantity in saturating [u64] arithmetic. The two
   agree on every memory size a frame could pay to reach; they can only differ
   above [2^53] words, which is some [2^58] bytes of memory.) *)
let memory_cost w =
  if w <= 0 then Some 0
  else
    let q = w / quadratic_divisor and r = w mod quadratic_divisor in
    Option.bind (checked_mul q w) (fun qw ->
        Option.bind (checked_mul r w) (fun rw ->
            Option.bind (checked_add qw (rw / quadratic_divisor))
              (fun quadratic ->
                Option.bind (checked_mul memory_word_cost w) (fun linear ->
                    checked_add linear quadratic))))

(* Memory is paid for once: growing to [next] costs the total for [next] less
   the total already paid for [current]. *)
let expansion_cost ~current ~next =
  if next <= current then Some 0
  else
    Option.bind (memory_cost next) (fun total ->
        Option.map (fun already_paid -> total - already_paid)
          (memory_cost current))
