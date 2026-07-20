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

(* [SELFBALANCE] costs 5, which is also the [LOW] tier's price. It is not a tier
   member: EIP-1884 priced it on its own at [instructions.rs:191], and the
   coincidence would quietly become a claim if [low] were reused for it. *)
let selfbalance = 5

(* Berlin's warm access price, and the static cost of [SLOAD] and [BALANCE] from
   Berlin on ([revm-context-interface] [cfg/gas.rs:100], overriding the table at
   [revm-interpreter] [instructions.rs:118-119]). *)
let warm_storage_read = 100

(* [KECCAK256]'s two prices ([cfg/gas.rs:50,52]). The word rate is 6 and is NOT
   the copy family's 3: an instruction that hashes memory pays for reaching the
   words (the memory curve's linear 3), and pays 6 for each word it absorbs.
   Three word prices exist in this schedule, two of which coincide at 3, and
   aliasing any pair would be a systematic mispricing no single test separates. *)
let keccak256 = 30
let keccak256_word = 6

(* The log prices ([cfg/gas.rs:44,46,48]). The base is the table entry every
   arity shares; the topic price is charged per topic in the body; the data
   price is per byte and not per word, which is the one place in the schedule
   where a memory-shaped quantity is not rounded up to a word. *)
let log_base = 375
let log_topic = 375
let log_data_byte = 8

let static_cost = function
  (* The instructions that halt are free; all their cost, where they have any,
     is the memory they touch. *)
  | Opcode.Stop | Opcode.Return | Opcode.Revert | Opcode.Invalid -> zero
  (* [SSTORE]'s table entry is zero, exactly as revm leaves it
     ([instructions.rs:201-203]): its 100 is charged inside [sstore_entry], after
     the EIP-2200 sentry, and charging it here would move that sentry by 100. *)
  | Opcode.Sstore -> zero
  | Opcode.Add | Opcode.Sub | Opcode.Lt | Opcode.Gt | Opcode.Slt | Opcode.Sgt
  | Opcode.Eq | Opcode.Iszero | Opcode.And | Opcode.Or | Opcode.Xor | Opcode.Not
  | Opcode.Byte | Opcode.Shl | Opcode.Shr | Opcode.Sar | Opcode.Mload
  | Opcode.Mstore | Opcode.Mstore8 | Opcode.Push _ | Opcode.Dup _ | Opcode.Swap _
  | Opcode.Calldataload | Opcode.Calldatacopy | Opcode.Codecopy | Opcode.Mcopy ->
      verylow
  | Opcode.Mul | Opcode.Div | Opcode.Sdiv | Opcode.Mod | Opcode.Smod
  | Opcode.Signextend ->
      low
  | Opcode.Addmod | Opcode.Mulmod | Opcode.Jump -> mid
  | Opcode.Exp | Opcode.Jumpi -> high
  | Opcode.Pop | Opcode.Pc | Opcode.Msize | Opcode.Gas | Opcode.Push0
  | Opcode.Address | Opcode.Origin | Opcode.Caller | Opcode.Callvalue
  | Opcode.Calldatasize | Opcode.Codesize | Opcode.Gasprice | Opcode.Coinbase
  | Opcode.Timestamp | Opcode.Number | Opcode.Prevrandao | Opcode.Gaslimit
  | Opcode.Chainid | Opcode.Basefee ->
      base
  | Opcode.Selfbalance -> selfbalance
  (* Berlin overrides, not tier members: EIP-2929 moved most of what [BALANCE]
     and [SLOAD] used to cost into the cold surcharge, leaving the warm 100 here
     ([instructions.rs:118-119]). *)
  | Opcode.Balance | Opcode.Sload -> warm_storage_read
  (* EIP-1153 gives both a flat warm-read price and no cold axis at all
     ([instructions.rs:210-211] writes the 100 as a literal). *)
  | Opcode.Tload | Opcode.Tstore -> warm_storage_read
  | Opcode.Keccak256 -> keccak256
  (* Uniform across the five arities: revm gives every [LOG] the same table
     entry [gas::LOG] ([instructions.rs:282-286]) and charges the per-topic 375
     in the body. Splitting it the other way would produce identical totals and
     an unpinnable ordering, so the table price stays the base alone. *)
  | Opcode.Log _ -> log_base
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

let call_stipend = 2300

(* The EIP-2929 surcharges, each the full cold price less the warm price the
   instruction's static cost already took. They are separate bindings from the
   [SSTORE] constants below even where the arithmetic looks similar; see
   [sstore_cold]. *)
let cold_sload = 2100
let cold_account_access = 2600
let cold_storage_additional = cold_sload - warm_storage_read
let cold_account_additional = cold_account_access - warm_storage_read

let storage_access_cost warmth =
  if Access.is_cold warmth then cold_storage_additional else 0

let account_access_cost warmth =
  if Access.is_cold warmth then cold_account_additional else 0

(* [COPY = 3] per word ([revm-context-interface] [cfg/gas.rs:54]). This is a
   different price from [memory_word_cost] above, which is also 3
   ([cfg/gas.rs:42]) — a copying instruction pays both, one for the words it
   moves and one for the words it makes the frame reach. Aliasing them would be
   a systematic undercharge that no single test could distinguish. *)
let copy_word_cost = 3
let word_bytes = 32

(* Words, rounded up, computed by dividing before counting the partial word, as
   [Memory.words_needed] does: adding 31 first would wrap for the last few
   lengths. The count is therefore at most [max_int / 32 + 1] and three times it
   is comfortably representable, which is why this returns an [int] and not an
   [int option]. *)
let words_of_length length =
  if length <= 0 then 0
  else (length / word_bytes) + if length mod word_bytes = 0 then 0 else 1

let copy_cost length = copy_word_cost * words_of_length length

(* [KECCAK256]'s dynamic half: 6 per word of input, over the same rounding rule
   the copy family uses and at a different rate. Sharing the rule and separating
   the rate is the whole point of the split — the rounding is one fact, as
   revm's [num_words] is, while [copy_word_cost] and [keccak256_word] are two
   prices that must be free to differ.

   Returns an [int] rather than an option for [copy_cost]'s reason: the word
   count is at most [max_int / 32 + 1] and six times it is representable. *)
let keccak_word_cost length = keccak256_word * words_of_length length

(* A log's dynamic half: 375 per topic plus 8 per byte of data.

   Unlike the two above this is checked, because the per-byte rate is applied to
   a length rather than to a word count, so the product is eight times larger
   than anything [copy_cost] forms and a length near [max_int / 8] would wrap. A
   [None] means the true price exceeds [max_int], which no allowance can meet,
   so the caller's treatment of it as out of gas is exact. *)
let log_dynamic_cost ~topics ~length =
  Option.bind (checked_mul log_data_byte (Int.max 0 length)) (fun data ->
      Option.bind (checked_mul log_topic (Topic_count.to_int topics))
        (fun topic -> checked_add topic data))

type sstore_entry_error = Reentrancy_sentry | Insufficient

(* EIP-2200's sentry, then the static charge, in that order and inseparably.
   revm tests the allowance at [instructions/host.rs:237-244] and charges at
   [:246-249]; the comparison is [<=], so an allowance of exactly 2300 halts.

   [Insufficient] is unreachable as written — the sentry has already established
   that more than 2300 units remain, and the charge is 100 — but the charge is
   still consulted rather than assumed, so this stays correct if either constant
   ever moves. *)
let sstore_entry t =
  if t <= call_stipend then Error Reentrancy_sentry
  else Option.to_result ~none:Insufficient (charge warm_storage_read t)

(* [SSTORE]'s cold surcharge is [cold_storage_cost], which Berlin sets to
   [COLD_SLOAD_COST] itself ([cfg/gas_params.rs:437] wired at [:274]) — 2100, not
   the 2000 [SLOAD] adds. The two differ by exactly the static charge each
   instruction has already paid. Deriving one from the other, or sharing a
   binding, is the mistake this comment exists to prevent. *)
let sstore_cold = cold_sload

(* [SSTORE_SET] and [WARM_SSTORE_RESET], each less the warm 100 already taken by
   [sstore_entry] ([cfg/gas_params.rs:277-280]). [WARM_SSTORE_RESET] is itself
   [SSTORE_RESET - COLD_SLOAD_COST = 5000 - 2100 = 2900] ([cfg/gas.rs:102]). *)
let sstore_set = 20000 - warm_storage_read
let warm_sstore_reset = 5000 - cold_sload
let sstore_reset = warm_sstore_reset - warm_storage_read

(* EIP-3529's replacement for the old clearing schedule:
   [WARM_SSTORE_RESET + ACCESS_LIST_STORAGE_KEY] ([cfg/gas_params.rs:296-297]). *)
let access_list_storage_key = 1900
let clearing_refund = warm_sstore_reset + access_list_storage_key

(* The set and reset refunds are the same two numbers the write paid
   ([cfg/gas_params.rs:281-284]), credited back when the write restores the slot
   to what the transaction started with. *)
let set_refund = sstore_set
let reset_refund = sstore_reset

(* [cfg/gas_params.rs:433-451]. The cold term and the change term are ADDITIVE: a
   cold fresh set pays both. *)
let sstore_dynamic_cost warmth write =
  let cold = if Access.is_cold warmth then sstore_cold else 0 in
  let change =
    match Sstore_state.classify write with
    | Sstore_state.No_op -> 0 (* new = present: no change term *)
    | Sstore_state.Dirty -> 0 (* original <> present: already paid *)
    | Sstore_state.Fresh_set -> sstore_set (* 19900, gas_params.rs:442-445 *)
    | Sstore_state.Fresh_reset -> sstore_reset (* 2800, gas_params.rs:446-449 *)
  in
  cold + change

(* [cfg/gas_params.rs:456-506], Istanbul-and-later. Do NOT restructure into an
   if/else chain: [claw] and [restore] are independent additive terms and a
   single [SSTORE] can hit both. The first two tests, by contrast, really do
   return. *)
let sstore_refund write =
  let original = Sstore_state.original write
  and present = Sstore_state.present write
  and updated = Sstore_state.updated write in
  if W.equal updated present then 0 (* :469-471 EARLY *)
  else if W.equal original present && W.is_zero updated then
    clearing_refund (* :475-477 EARLY, +4800 *)
  else
    let claw =
      (* :481-491 *)
      if W.is_zero original then 0
      else if W.is_zero present then -clearing_refund (* :483-485 -4800 *)
      else if W.is_zero updated then clearing_refund (* :487-489 +4800 *)
      else 0
    in
    let restore =
      (* :494-504 *)
      if W.equal original updated then
        if W.is_zero original then set_refund (* :496-498 19900 *)
        else reset_refund (* :500-502 2800 *)
      else 0
    in
    claw + restore
