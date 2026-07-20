(* Tests for the host seam: the instructions that read and write the world, and
   the pricing that EIP-2929 and EIP-2200 attach to them.

   The seam is where this port is most exposed. Every other instruction is a
   function of the stack and memory, so a wrong answer is a wrong number in a
   place a unit test looks at. Here a wrong answer is usually a {e missing}
   charge, and a missing charge is invisible to any test that measures a
   difference: an [SLOAD] arm that performs the lookup, warms the slot, pushes
   the value and forgets [Gas.charge] returns the right word, leaves the right
   world, and undercharges by 2000 on every cold access. Two runs of it differ by
   exactly what a correct implementation's two runs differ by. Only the absolute
   figure is wrong.

   So every gas assertion in this file is an absolute total against a number
   computed by hand from the schedule and written into the comment above it:
   2105, 105, 2605, 112, 17, 22106, 20006, 2906. Not one of them is stated as a
   delta, and the two places where a delta would read more naturally — the
   SELFBALANCE warming and the MCOPY mirror — assert both absolutes instead and
   say in the comment which of the two would move under the bug being ruled out.
   Where a decomposition of one of those totals is also worth stating, it is
   compared against the MEASURED spend and never against the sum that produced
   it: [check int "which is 22106" 22106 (3 + 3 + 100 + 2100 + 19_900)] compares
   two literals, runs no implementation code, and would pass with the interpreter
   deleted. {!measure_sstore} returns the measurement so it does not have to.

   A second hazard, distinct from the missing charge and just as quiet: a field
   read from the wrong place. The fourteen flat context instructions are one line
   each, and while every field of the fixture was [U256.zero] — as it was — the
   TIMESTAMP and NUMBER arms could be exchanged, or GASPRICE with CALLVALUE, or
   CALLER with ORIGIN, without a single case in the tree noticing. Every field
   here therefore holds a different, recognisable value and [caller] is not
   [origin], so that {!test_flat_context_opcodes} can name the arm that is wrong.

   Five batches.

   First, the unit boundaries of the three modules the seam introduced:
   {!Storage}'s canonical zero, {!World_state}'s pruning rule, and {!Access}'s
   warmth witness — together with the EIP-2930 access list's one flattening,
   {!Env.Tx.declared_warm}, whose product has to reach the pricing for a declared
   slot's first touch to be warm. These are small and they are here rather than
   only in [test_state.ml] because the pruning hazard — an [SSTORE] into a
   zero-nonce zero-balance account being erased by a state-clearing rule that
   never looked at storage — is a host-seam bug that happens to live in a state
   module.

   Second, whole programs with their gas computed by hand, returning their result
   through memory, in the idiom [test_interpreter.ml] already uses — beginning
   with the fourteen context instructions, which push a field and stop.

   Third, the [SSTORE] matrix: the four-way EIP-2200 classification crossed with
   cold and warm, each cell asserted with its total cost {e and} its refund. Two
   of the sixteen nominal cells are unreachable from a single frame and say so.

   Fourth, the orderings that are invisible except at one point: the EIP-2200
   sentry at exactly 2300 and at 2301, the pop that happens before it, the
   zero-length copy that returns before its destination is converted, and
   MCOPY's source conversion, which happens after the destination's and so is
   reachable only with a nonzero length.

   Fifth, randomised properties. Each is checked against an oracle that shares no
   code with the implementation: a flat [Bytes] buffer for memory, [Bytes.blit]
   (memmove by specification) for [MCOPY], a naive padded string reader for
   {!Data}, a [logand] mask for {!Address_word}, and — for the one formula in the
   schedule that is famously easy to get subtly wrong — a transcription of
   revm's [sstore_dynamic_gas] and [sstore_refund] made directly from the Rust,
   line by line, into {!Oracle} below. That transcription deliberately keeps
   revm's shape, including the two branches that return and the two that
   accumulate, because a restatement that tidied them would agree with a
   restatement of the implementation that had tidied them the same way and the
   property would prove nothing.

   Every property here reads what the run PRODUCED. That is not a stylistic
   preference: {!Interpreter.run} is a pure function, so any conjunct inspecting
   the [Effects.t] the caller passed IN is true by the type of [run] and survives
   every possible mutation. The reverting property was written that way once and
   was constant-true because of it — see {!revert_is_a_no_op}, which now carries
   the account.

   The qcheck driver is pinned to a fixed [Random.State], as in the other
   suites, so the sampled cases and the verdict replay. *)

module U256 = Tn_state.U256
module Account = Tn_state.Account
module Address_word = Tn_state.Address_word
module Nonce = Tn_state.Nonce
module Storage = Tn_state.Storage
module World_state = Tn_state.World_state
module Units = Tn_types.Units
module Access = Tn_evm.Access
module Code = Tn_evm.Code
module Data = Tn_evm.Data
module Effects = Tn_evm.Effects
module Env = Tn_evm.Env
module Mutability = Tn_evm.Mutability
module Log = Tn_evm.Log
module Log_journal = Tn_evm.Log_journal
module Topic_count = Tn_evm.Topic_count
module Transient = Tn_evm.Transient
module Keccak = Tn_keccak
module Gas = Tn_evm.Gas
module Interpreter = Tn_evm.Interpreter
module Memory = Tn_evm.Memory
module Opcode = Tn_evm.Opcode
module Refund = Tn_evm.Refund
module Sstore_state = Tn_evm.Sstore_state

let get = function Some x -> x | None -> Alcotest.fail "expected Some"

(* The permit for a mutability, for the two unit tests that call an Effects
   write directly rather than through a program. Going through {!Mutability.permit}
   rather than fabricating one is not ceremony: there is no other way to obtain
   the value, which is the property the type exists for. *)
let get_permit mutability =
  match Mutability.permit mutability with
  | Some permit -> permit
  | None -> Alcotest.fail "expected a mutable frame to yield a permit"
let u n = get (U256.of_int n)
let hex s = get (U256.of_hex s)
let gas_of n = get (Gas.of_int n)
let width_of n = get (Opcode.Push_bytes.of_int n)

let u256 =
  Alcotest.testable (fun ppf w -> Format.pp_print_string ppf (U256.to_hex w)) U256.equal

let address_of n =
  get
    (Units.Address.of_bytes
       (String.make (Units.Address.length - 1) '\000' ^ String.make 1 (Char.chr n)))

(* The addresses this file names. [self] is the call target, which is the
   account [SLOAD], [SSTORE] and [SELFBALANCE] all reach — there is no
   delegatecall yet, so the code address and the storage address coincide.

   [caller] is deliberately NOT [origin]. With the two equal — as this fixture
   had them — the [CALLER] and [ORIGIN] arms of the dispatch table are
   interchangeable and no test in the tree notices. *)
let self = address_of 0x02
let origin = address_of 0x01
let caller = address_of 0x0c
let coinbase = address_of 0xc0
let other = address_of 0xab

(* Every field of the environment gets a DIFFERENT, recognisable value, and that
   is the whole point of these constants rather than any property of the numbers
   themselves.

   The fixture used to set timestamp, number, prevrandao, gas_limit, basefee,
   chain_id, gas_price and the call value all to [U256.zero], and [caller] to
   [origin]. Under that fixture the fourteen flat context instructions push
   indistinguishable words: swapping the TIMESTAMP and NUMBER arms of
   {!Interpreter.execute}, or BASEFEE with GASLIMIT, or CHAINID with PREVRANDAO,
   or GASPRICE with CALLVALUE, or CALLER with ORIGIN, passes the entire suite.
   Distinct values are what make {!test_flat_context_opcodes} below able to name
   the opcode that is wrong.

   [prevrandao] is a full-width word rather than a small integer so that a
   truncating route to it — the twelve-byte mask {!Address_word.of_word}
   applies, say — would change the answer rather than pass through. *)
let timestamp = u 1_700_000_000
let block_number = u 19_000_000
let prevrandao = hex "9f3c1e07d2b4a6580c19ae7f4d3b2610fe58c4a90b7d2e13c6a5f08b1d4e7290"
let gas_limit = u 30_000_000
let basefee = u 7_000_000_000
let chain_id = u 2_017
let gas_price = u 12_000_000_000
let call_value = u 1_000_000_000_000_000_000

let base_block =
  Env.Block.make ~coinbase ~timestamp ~number:block_number ~prevrandao ~gas_limit
    ~basefee ~chain_id

let base_tx = Env.Tx.make ~origin ~gas_price ~access_list:[]

let env_with_mutability mutability data =
  Env.make ~block:base_block ~tx:base_tx
    ~call:(Env.Call.make ~target:self ~caller ~value:call_value ~data ~mutability)

let env_with_data data = env_with_mutability Mutability.Mutable data
let base_env = env_with_data Data.empty

(* A frame entered by [STATICCALL]. Nothing in this chunk builds one — the calls
   chunk does — so the static column of the cross product below is reached only
   by constructing it here, which is exactly why the guard is worth having
   before its caller exists. *)
let static_env = env_with_mutability Mutability.Static Data.empty

(* ---------- warmth witnesses ----------

   {!Access.warmth} is abstract with no constructor: the only way to obtain one
   is to touch something. That is the whole point of the type — a price cannot be
   computed for a lookup that did not happen — and it means even a unit test of
   {!Gas.sstore_dynamic_cost} has to go through a touch to name its argument. *)

let cold_witness = fst (Access.touch_slot Access.empty self U256.zero)

let warm_witness =
  fst (Access.touch_slot (snd (Access.touch_slot Access.empty self U256.zero)) self U256.zero)

(* ---------- a miniature assembler ---------- *)

let byte b = String.make 1 (Char.chr b)
let op o = byte (Opcode.to_byte o)
let push1 n = op (Opcode.Push (width_of 1)) ^ byte n
let push32 w = op (Opcode.Push (width_of 32)) ^ U256.to_be_bytes w

let push20 address =
  op (Opcode.Push (width_of 20)) ^ Units.Address.to_bytes address

let asm parts = Code.of_string (String.concat "" parts)

(* Store the top of the stack at memory zero and return those 32 bytes: the
   epilogue that makes a program's result observable from outside the frame. Its
   cost is PUSH1 3, MSTORE 3, PUSH1 3, PUSH1 3, RETURN 0, plus 3 for the first
   word of memory when the program has not already paid for it. *)
let return_top = [ push1 0x00; op Opcode.Mstore; push1 0x20; push1 0x00; op Opcode.Return ]
let return_top_cost = 3 + 6 + 3 + 3 + 0
let return_top_cost_paid = return_top_cost - 3

(* The three bytes that end a run successfully, and the no-op that stands in for
   them. Used by the reverting property below, which has to be able to say that a
   run did NOT halt successfully — impossible while the random tail can contain a
   STOP of its own. *)
let halting_bytes = List.map Opcode.to_byte [ Opcode.Stop; Opcode.Return; Opcode.Revert ]
let jumpdest_byte = Char.chr (Opcode.to_byte Opcode.Jumpdest)

(* Thirty-two JUMPDEST bytes, which is what makes a trailing epilogue reachable
   whatever the code before it ends with. A PUSH32 as the last byte of that code
   advances the program counter thirty-two bytes past itself; with no padding
   that walks clean over a five-byte epilogue and off the end of the code, which
   halts as an implicit STOP. Thirty-two is exactly the widest immediate, so the
   counter lands at worst on the epilogue's first byte. Pinned deterministically
   in {!test_revert_discards_everything}. *)
let revert_padding = String.make 32 jumpdest_byte

(* ---------- running, and reading an outcome ---------- *)

let empty_effects = Effects.start ~world:World_state.empty ~access:Access.empty

let run ?(env = base_env) ?(effects = empty_effects) code gas =
  Interpreter.run ~env ~code ~gas:(gas_of gas) ~effects

let remaining_of = function
  | Interpreter.Stopped { gas_left; _ } -> Gas.remaining gas_left
  | Interpreter.Returned { gas_left; _ } -> Gas.remaining gas_left
  | Interpreter.Reverted { gas_left; _ } -> Gas.remaining gas_left
  | Interpreter.Failed error ->
      Alcotest.fail
        ("expected a halt carrying gas, got " ^ Interpreter.error_to_string error)

let effects_of = function
  | Interpreter.Stopped { effects; _ } -> Some effects
  | Interpreter.Returned { effects; _ } -> Some effects
  | Interpreter.Reverted _ -> None
  | Interpreter.Failed _ -> None

let effects_or_fail outcome =
  match effects_of outcome with
  | Some effects -> effects
  | None -> Alcotest.fail "expected an outcome carrying effects"

(* Everything a run makes reachable to its caller, read off the OUTCOME.

   This exists because the obvious way to test "a reverting frame changes
   nothing" does not test anything. {!Interpreter.run} is a pure function of its
   arguments, so the [Effects.t] the caller passed IN cannot have changed however
   the implementation behaves; an assertion that inspects that value is true by
   the type of [run] and would survive any mutation whatsoever. The escape route
   that has to be closed runs the other way — out through the returned value —
   and only the outcome witnesses it.

   Today the [Reverted] constructor has no [effects] field, so a reverting frame
   whose effects escape has to come back as a DIFFERENT constructor. That is
   exactly the shape this returns [Some] for. Should [Reverted] ever gain such a
   field, this function is the one place that has to learn about it, and the
   callers below keep working. *)
let reachable_effects = function
  | Interpreter.Stopped { effects; _ } -> Some effects
  | Interpreter.Returned { effects; _ } -> Some effects
  | Interpreter.Reverted _ -> None
  | Interpreter.Failed _ -> None

(* Whether the outcome is one of the two halts that hand effects back. Asserted
   directly rather than inferred from {!reachable_effects}, because it is the
   constructor itself that carries the claim: a frame that executed REVERT must
   not report a successful halt, whatever it puts in it. *)
let halted_successfully outcome =
  match outcome with
  | Interpreter.Stopped _ | Interpreter.Returned _ -> true
  | Interpreter.Reverted _ | Interpreter.Failed _ -> false

let output_of = function
  | Interpreter.Returned { output; _ } -> output
  | Interpreter.Reverted { output; _ } -> output
  | Interpreter.Stopped _ -> Alcotest.fail "expected an outcome carrying output"
  | Interpreter.Failed error ->
      Alcotest.fail
        ("expected an outcome carrying output, got " ^ Interpreter.error_to_string error)

let error_of = function
  | Interpreter.Failed error -> Interpreter.error_to_string error
  | Interpreter.Stopped _ -> "stopped"
  | Interpreter.Returned _ -> "returned"
  | Interpreter.Reverted _ -> "reverted"

(* Every gas assertion in this file goes through here, and it takes the total
   rather than a difference on purpose — see the header. *)
let allowance = 1_000_000

let check_total msg expected outcome =
  Alcotest.(check int) msg expected (allowance - remaining_of outcome)

let check_error msg expected outcome =
  Alcotest.(check string) msg (Interpreter.error_to_string expected) (error_of outcome)

let check_refund msg expected effects =
  Alcotest.(check int) msg expected (Refund.to_int (Effects.refund effects))

(* ---------- 1. unit boundaries ---------- *)

let test_storage_canonical_zero () =
  (* Writing zero to an unwritten slot writes nothing at all: the map is not
     merely equal to empty, it holds no binding, which is what makes
     {!Storage.is_empty} a constant-time test and {!Storage.equal} exact. *)
  let written = Storage.set Storage.empty (u 7) U256.zero in
  Alcotest.(check bool) "a zero write leaves the map empty" true
    (Storage.equal written Storage.empty);
  Alcotest.(check bool) "and is_empty agrees" true (Storage.is_empty written);
  Alcotest.(check int) "with no bindings at all" 0 (List.length (Storage.bindings written));
  (* Write then clear is the identity, not a slot holding zero. *)
  let round_trip = Storage.set (Storage.set Storage.empty (u 7) (u 42)) (u 7) U256.zero in
  Alcotest.(check bool) "write then clear returns to empty" true
    (Storage.equal round_trip Storage.empty);
  Alcotest.(check int) "and drops the binding" 0 (List.length (Storage.bindings round_trip));
  (* An unwritten slot reads zero — the totality [SLOAD] is promised. *)
  Alcotest.(check u256) "an unwritten slot reads zero" U256.zero
    (Storage.get Storage.empty (u 999))

let test_pruning_hazard () =
  (* The hazard, asserted directly. This account has zero nonce and zero balance,
     so the EIP-161 emptiness predicate is true of it, and a [set_account] that
     pruned on {!Account.is_empty} would silently discard the write. *)
  let world = World_state.set_storage World_state.empty self (u 3) (u 9) in
  Alcotest.(check u256) "an SSTORE into a zero-nonce zero-balance account survives" (u 9)
    (World_state.storage world self (u 3));
  let account = World_state.account world self in
  Alcotest.(check bool) "the account is EIP-161 empty" true (Account.is_empty account);
  Alcotest.(check bool) "and yet not absent" false (Account.is_absent account);
  (* Clearing the slot again returns the state to exactly where it started, and
     the address is missing from the listing at both ends rather than present
     with an empty account — canonicity, so that [equal] is semantic. *)
  let cleared = World_state.set_storage world self (u 3) U256.zero in
  Alcotest.(check bool) "clearing the slot restores the original state" true
    (World_state.equal cleared World_state.empty);
  Alcotest.(check int) "the address is not listed before the write" 0
    (List.length (World_state.accounts World_state.empty));
  Alcotest.(check int) "nor after clearing it" 0 (List.length (World_state.accounts cleared));
  Alcotest.(check int) "though it is listed while the slot is set" 1
    (List.length (World_state.accounts world));
  (* Two states differing in one slot are not equal, so the assertion above is
     not vacuously true of everything. *)
  Alcotest.(check bool) "a differing slot compares unequal" false
    (World_state.equal world (World_state.set_storage World_state.empty self (u 3) (u 10)))

let test_remove_account_drops_both_halves () =
  let world =
    World_state.set_storage
      (World_state.set_account World_state.empty self
         (Account.make ~nonce:Nonce.zero ~balance:(u 500)))
      self (u 3) (u 9)
  in
  let removed = World_state.remove_account world self in
  Alcotest.(check u256) "the balance is gone" U256.zero (World_state.balance removed self);
  Alcotest.(check u256) "and so is the storage" U256.zero
    (World_state.storage removed self (u 3));
  Alcotest.(check bool) "removing the only account empties the state" true
    (World_state.equal removed World_state.empty)

let test_access_warmth () =
  (* The first touch is cold and the second is not — and the witness for each is
     built by the same call that records it, so the test and the record cannot
     disagree. *)
  let warmth, once = Access.touch_slot Access.empty self (u 1) in
  Alcotest.(check bool) "the first touch of a slot is cold" true (Access.is_cold warmth);
  let warmth, _ = Access.touch_slot once self (u 1) in
  Alcotest.(check bool) "the second is warm" false (Access.is_cold warmth);
  (* The key is the pair. Warming (a, k) says nothing about (b, k). *)
  let warmth, _ = Access.touch_slot once other (u 1) in
  Alcotest.(check bool) "the same slot of another account is still cold" true
    (Access.is_cold warmth);
  Alcotest.(check bool) "and one account's slot is not the other's" false
    (Access.mem_slot once other (u 1));
  Alcotest.(check bool) "while its own is recorded" true (Access.mem_slot once self (u 1));
  (* An account and a slot are separate sets: touching a slot does not warm the
     account it belongs to. *)
  Alcotest.(check bool) "touching a slot does not warm its account" false
    (Access.mem_account once self);
  (* The witnesses the pricing tests below use really are what they claim. *)
  Alcotest.(check bool) "the cold witness is cold" true (Access.is_cold cold_witness);
  Alcotest.(check bool) "the warm witness is not" false (Access.is_cold warm_witness)

let test_selfbalance_warms_the_account () =
  (* The settled dispute, pinned at the seam rather than only in the gas figure.
     revm reaches SELFBALANCE's value through [Host::balance], whose default
     implementation loads through the journal and whose [is_cold] the instruction
     discards ([instructions/host.rs:42-48] into [context-interface]
     [host.rs:140-144]). The account is marked; the surcharge is not charged. *)
  let world = World_state.of_alloc [ (self, u 77) ] in
  let before = Effects.start ~world ~access:Access.empty in
  Alcotest.(check bool) "the executing account starts cold" false
    (Access.mem_account (Effects.access before) self);
  let value, after = Effects.self_balance before self in
  Alcotest.(check u256) "the balance reads back" (u 77) value;
  Alcotest.(check bool) "and the account is now warm" true
    (Access.mem_account (Effects.access after) self)

(* The EIP-2930 access list as it comes off the wire — slots grouped under their
   address — and the flattening that turns it into what {!Access.of_transaction}
   consumes. The port has exactly one such flatten, {!Env.Tx.declared_warm}, and
   this is where it is pinned.

   Two layers, and they catch different things. The structural assertions
   localise a wrong conversion — dropping the bare-address entry and keying a
   slot under the wrong account each fail a differently-named check, which is
   what makes a failure here readable. The gas figures at the end are the
   end-to-end claim the structural ones cannot make: that the set so produced
   actually reaches the pricing and makes the FIRST touch warm. It is the
   contrast that carries it, 105 against the 2105 and 2605 the same two programs
   cost from [Access.empty]; a set that never arrived would produce the cold
   figure in both columns. *)
let test_declared_access_list () =
  (* [other] lists no slots at all. EIP-2930 charges ACCESS_LIST_ADDRESS_COST for
     such an entry, so it warms the account and is not an entry to skip. *)
  let declared = [ (self, [ U256.zero; u 7 ]); (other, []) ] in
  let tx = Env.Tx.make ~origin ~gas_price ~access_list:declared in
  let addresses, slots = Env.Tx.declared_warm tx in
  Alcotest.(check int) "every entry's address is declared, slots or not" 2
    (List.length addresses);
  Alcotest.(check bool) "including the one that listed no slots" true
    (List.exists (Units.Address.equal other) addresses);
  Alcotest.(check int) "and the grouped slots are flattened one per pair" 2
    (List.length slots);
  Alcotest.(check bool) "each under the account that declared it" true
    (List.for_all (fun (addr, _) -> Units.Address.equal addr self) slots);
  (* Total on the empty list, which is what a transaction with no access list
     presents and the case a partial conversion would raise on. *)
  let empty_addresses, empty_slots =
    Env.Tx.declared_warm (Env.Tx.make ~origin ~gas_price ~access_list:[])
  in
  Alcotest.(check int) "an absent access list declares no addresses" 0
    (List.length empty_addresses);
  Alcotest.(check int) "and no slots" 0 (List.length empty_slots);
  (* The two components fit {!Access.of_transaction}'s two arguments with no
     reshaping, which is the property the return type was chosen for. *)
  let access = Access.of_transaction ~addresses ~slots in
  Alcotest.(check bool) "the declared account is warm" true (Access.mem_account access self);
  Alcotest.(check bool) "the slotless entry's account is warm too" true
    (Access.mem_account access other);
  Alcotest.(check bool) "the declared slots are warm" true
    (Access.mem_slot access self U256.zero && Access.mem_slot access self (u 7));
  (* And not vacuously: a slot nobody declared, and the same slot number under
     another account, are both still cold. *)
  Alcotest.(check bool) "an undeclared slot is not" false (Access.mem_slot access self (u 8));
  Alcotest.(check bool) "nor the same slot under another account" false
    (Access.mem_slot access other U256.zero);
  Alcotest.(check bool) "and an account nobody named is cold" false
    (Access.mem_account access coinbase);
  (* The figure. PUSH1 3, SLOAD (100 static, no surcharge), POP 2, STOP 0 — 105,
     not the 2105 the same program costs from [Access.empty]. A conversion that
     lost the slot would produce 2105 here and pass everything above. *)
  let effects = Effects.start ~world:World_state.empty ~access in
  let reading = asm [ push1 0x00; op Opcode.Sload; op Opcode.Pop; op Opcode.Stop ] in
  check_total "a declared slot's first SLOAD is warm at 105" 105
    (run ~effects reading allowance);
  (* The bare-address entry priced the same way: PUSH20 3, BALANCE 100, POP 2. *)
  let weighing = asm [ push20 other; op Opcode.Balance; op Opcode.Pop; op Opcode.Stop ] in
  check_total "a declared bare address's first BALANCE is warm at 105" 105
    (run ~effects weighing allowance);
  (* The contrast that makes both figures statements about the access list: the
     same two programs from an empty set pay the full cold price. *)
  let cold = Effects.start ~world:World_state.empty ~access:Access.empty in
  check_total "and without the declaration the SLOAD is cold at 2105" 2105
    (run ~effects:cold reading allowance);
  check_total "and the BALANCE cold at 2605" 2605 (run ~effects:cold weighing allowance)

(* ---------- 2. whole programs, gas computed by hand ---------- *)

(* The slot [self] holds when a program starts. Because {!Effects.start} pins
   EIP-2200's [original] to the world it is handed, this is both [original] and
   [present] at the first [SSTORE] of every program below. *)
let world_with_slot value = World_state.set_storage World_state.empty self (u 0) (u value)

let warm_slot_access = Access.of_transaction ~addresses:[] ~slots:[ (self, U256.zero) ]

(* The fourteen instructions that push one field of the environment and stop.
   They are the cheapest thing in the seam to get wrong and were, until this
   case, named by no test at all: every one of them is a single line of the
   dispatch table reading a single accessor, and nothing downstream would notice
   two of those lines exchanged.

   Each row asserts the word AND the absolute total. The total is the same 17 for
   all fourteen — [base] 2 for the instruction, then the epilogue's 15 — so it is
   not what separates them; the word is. The fixture above gives every field a
   different value precisely so that it can.

   The two derived sizes are the exceptions to "a field": CODESIZE is the length
   of the program actually assembled here and CALLDATASIZE the length of the
   input handed to it, so both are computed from the same values the run was
   given rather than written as literals that could drift. They differ from each
   other (9 against 5), which is what makes them non-interchangeable too. *)
let test_flat_context_opcodes () =
  let calldata = "\x0a\x0b\x0c\x0d\x0e" in
  let env = env_with_data (Data.of_string calldata) in
  let address_word = Address_word.to_word in
  List.iter
    (fun (name, opcode, expected) ->
      let code = asm ([ op opcode ] @ return_top) in
      let outcome = run ~env code allowance in
      Alcotest.(check string)
        (name ^ " pushes its own field")
        (U256.to_be_bytes (expected code))
        (output_of outcome);
      (* 2 for the instruction plus the 15 the epilogue costs from cold memory. *)
      check_total (name ^ " costs 17 in all") 17 outcome)
    [
      (* The call context. *)
      ("ADDRESS", Opcode.Address, fun _ -> address_word self);
      ("CALLER", Opcode.Caller, fun _ -> address_word caller);
      ("CALLVALUE", Opcode.Callvalue, fun _ -> call_value);
      ("CALLDATASIZE", Opcode.Calldatasize, fun _ -> u (String.length calldata));
      ("CODESIZE", Opcode.Codesize, fun code -> u (Code.length code));
      (* The transaction. *)
      ("ORIGIN", Opcode.Origin, fun _ -> address_word origin);
      ("GASPRICE", Opcode.Gasprice, fun _ -> gas_price);
      (* The block. *)
      ("COINBASE", Opcode.Coinbase, fun _ -> address_word coinbase);
      ("TIMESTAMP", Opcode.Timestamp, fun _ -> timestamp);
      ("NUMBER", Opcode.Number, fun _ -> block_number);
      ("PREVRANDAO", Opcode.Prevrandao, fun _ -> prevrandao);
      ("GASLIMIT", Opcode.Gaslimit, fun _ -> gas_limit);
      ("CHAINID", Opcode.Chainid, fun _ -> chain_id);
      ("BASEFEE", Opcode.Basefee, fun _ -> basefee);
    ];
  (* And the fourteen expected words really are fourteen different words, so the
     rows above cannot be satisfied by an implementation that pushed one constant
     for all of them. The two sizes are included: 5 and 9 are distinct from each
     other and from every field. *)
  let expected_words =
    [
      address_word self; address_word caller; call_value; u 5; u 9;
      address_word origin; gas_price; address_word coinbase; timestamp;
      block_number; prevrandao; gas_limit; chain_id; basefee;
    ]
  in
  Alcotest.(check int) "the fourteen expected words are pairwise distinct" 14
    (List.length (List.sort_uniq U256.compare expected_words))

let test_sload_cold_and_warm () =
  (* PUSH1 3, SLOAD (100 static + 2000 cold surcharge), POP 2, STOP 0. The 2000
     is [cold_storage_additional_cost] — COLD_SLOAD_COST less the warm 100 — and
     is NOT the 2100 that SSTORE adds. *)
  let code = asm [ push1 0x00; op Opcode.Sload; op Opcode.Pop; op Opcode.Stop ] in
  check_total "a cold SLOAD costs 2105 in all" 2105 (run code allowance);
  (* Pre-warmed by the transaction's access list, the surcharge is simply absent:
     3 + (100 + 0) + 2 + 0. An arm that looked the slot up and forgot to charge
     would produce this number in BOTH cases, which is why the pair is asserted
     absolutely and never as the difference between them. *)
  let warm = Effects.start ~world:World_state.empty ~access:warm_slot_access in
  check_total "a pre-warmed SLOAD costs 105" 105 (run ~effects:warm code allowance);
  (* Two reads of the same slot: the first pays the surcharge, the second does
     not, so the total is 2210 and not 4210 or 210. *)
  let twice =
    asm
      [
        push1 0x00; op Opcode.Sload; op Opcode.Pop;
        push1 0x00; op Opcode.Sload; op Opcode.Pop;
        op Opcode.Stop;
      ]
  in
  check_total "the second read of a slot is warm" 2210 (run twice allowance)

let test_sload_reads_the_world () =
  (* The value really comes from the world state, not from a zero default that
     happens to be right in the tests above. *)
  let code = asm ([ push1 0x00; op Opcode.Sload ] @ return_top) in
  let effects = Effects.start ~world:(world_with_slot 0x2a) ~access:Access.empty in
  let outcome = run ~effects code allowance in
  Alcotest.(check string) "SLOAD pushes what the world holds"
    (U256.to_be_bytes (u 0x2a)) (output_of outcome);
  (* 3 + (100 + 2000) + return_top *)
  check_total "and the read is still priced at 2105 plus the epilogue"
    (3 + 2100 + return_top_cost) outcome

let test_balance_cold_and_warm () =
  (* PUSH20 3, BALANCE (100 static + 2500 cold surcharge), POP 2, STOP 0. *)
  let code = asm [ push20 other; op Opcode.Balance; op Opcode.Pop; op Opcode.Stop ] in
  check_total "a cold BALANCE costs 2605 in all" 2605 (run code allowance);
  let warm =
    Effects.start ~world:World_state.empty
      ~access:(Access.of_transaction ~addresses:[ other ] ~slots:[])
  in
  check_total "a pre-warmed BALANCE costs 105" 105 (run ~effects:warm code allowance);
  (* And the value is the account's, read through the top-twelve-bytes
     truncation that {!Address_word.of_word} performs. *)
  let code = asm ([ push20 other; op Opcode.Balance ] @ return_top) in
  let effects = Effects.start ~world:(World_state.of_alloc [ (other, u 4096) ]) ~access:Access.empty in
  Alcotest.(check string) "BALANCE pushes the account's balance"
    (U256.to_be_bytes (u 4096))
    (output_of (run ~effects code allowance))

let test_selfbalance_then_balance () =
  (* The warming is worth 2500 and this is where it shows. SELFBALANCE 5,
     POP 2, PUSH20 3, BALANCE (100 + 0 — the account is already warm), POP 2,
     STOP 0. *)
  let code =
    asm
      [
        op Opcode.Selfbalance; op Opcode.Pop;
        push20 self; op Opcode.Balance; op Opcode.Pop;
        op Opcode.Stop;
      ]
  in
  check_total "SELFBALANCE leaves the account warm for BALANCE" 112 (run code allowance);
  (* Without the SELFBALANCE prefix the same BALANCE pays the full cold price.
     Both absolutes are asserted: under a port that failed to warm, the first
     figure would be 2612 and this one would be unchanged, so the pair says which
     of the two moved. *)
  let bare = asm [ push20 self; op Opcode.Balance; op Opcode.Pop; op Opcode.Stop ] in
  check_total "and without it the same BALANCE is cold" 2605 (run bare allowance);
  (* SELFBALANCE alone charges its flat 5 and nothing else, from a cold start. *)
  let alone = asm [ op Opcode.Selfbalance; op Opcode.Pop; op Opcode.Stop ] in
  check_total "SELFBALANCE alone is 5 flat" 7 (run alone allowance)

let test_calldatacopy () =
  let calldata = "\x11\x22\x33" in
  let env = env_with_data (Data.of_string calldata) in
  (* PUSH1 3, PUSH1 3, PUSH1 3, CALLDATACOPY (3 static + copy_cost 5 = 3 + one
     word of expansion = 3), STOP 0. The copy price and the expansion price are
     both 3-per-word and are two different charges; this program pays both. *)
  let code =
    asm
      [
        push1 0x05; push1 0x00; push1 0x00; op Opcode.Calldatacopy; op Opcode.Stop;
      ]
  in
  check_total "a five-byte CALLDATACOPY costs 18" 18 (run ~env code allowance);
  (* The same copy, returning the word it wrote: three calldata bytes then two
     zeroes, then the rest of the word untouched. The epilogue adds PUSH1 3,
     PUSH1 3, RETURN 0 with no further expansion. *)
  let observed =
    asm
      [
        push1 0x05; push1 0x00; push1 0x00; op Opcode.Calldatacopy;
        push1 0x20; push1 0x00; op Opcode.Return;
      ]
  in
  let outcome = run ~env observed allowance in
  check_total "and 24 with the return" 24 outcome;
  Alcotest.(check string) "the calldata lands zero-extended"
    (calldata ^ String.make 29 '\000')
    (output_of outcome);
  (* Reading past the end of the calldata pads with zeroes rather than failing,
     and the price is by the length asked for, not the length available: 33 bytes
     from empty calldata is copy_cost 6 and two words of expansion. *)
  let past_the_end =
    asm [ push1 33; push1 0x00; push1 0x00; op Opcode.Calldatacopy; op Opcode.Stop ]
  in
  check_total "33 bytes from empty calldata costs 24" 24 (run past_the_end allowance);
  let with_msize =
    asm
      ([ push1 33; push1 0x00; push1 0x00; op Opcode.Calldatacopy; op Opcode.Msize ]
      @ return_top)
  in
  let outcome = run with_msize allowance in
  Alcotest.(check string) "and MSIZE reports the two words it reached"
    (U256.to_be_bytes (u 64)) (output_of outcome);
  check_total "at 24 plus MSIZE plus the epilogue"
    (24 + 2 + return_top_cost_paid)
    outcome

let test_codecopy () =
  (* CODECOPY reads the running code through the same window type, so the same
     price applies and the same zero-extension past the end. *)
  let code =
    asm
      [
        push1 0x04; push1 0x00; push1 0x00; op Opcode.Codecopy;
        push1 0x20; push1 0x00; op Opcode.Return;
      ]
  in
  let outcome = run code allowance in
  (* 3 + 3 + 3 + (3 + copy_cost 4 = 3 + expansion 3) + 3 + 3 + 0 *)
  check_total "a four-byte CODECOPY costs 24" 24 outcome;
  Alcotest.(check string) "and copies the program's own first four bytes"
    (String.sub (String.concat "" [ push1 0x04; push1 0x00 ]) 0 4 ^ String.make 28 '\000')
    (output_of outcome)

let test_calldataload_past_the_end () =
  let env = env_with_data (Data.of_string "\x11\x22\x33") in
  (* One byte in: the window slides and pads. *)
  let at n = asm ([ push1 n; op Opcode.Calldataload ] @ return_top) in
  Alcotest.(check string) "a partial word is zero-extended"
    ("\x22\x33" ^ String.make 30 '\000')
    (output_of (run ~env (at 1) allowance));
  (* Exactly at the end, and past it: zeros, and no error. *)
  Alcotest.(check string) "at the end of the calldata it is all zeroes"
    (String.make 32 '\000')
    (output_of (run ~env (at 3) allowance));
  Alcotest.(check string) "past the end too" (String.make 32 '\000')
    (output_of (run ~env (at 200) allowance));
  (* And at an offset no [int] could hold. The source offset SATURATES; it is the
     destination offsets that refuse. Hardening this into an error would halt
     valid mainnet transactions. *)
  let enormous = asm ([ push32 U256.max_value; op Opcode.Calldataload ] @ return_top) in
  let outcome = run ~env enormous allowance in
  Alcotest.(check string) "and at a saturating-huge offset" (String.make 32 '\000')
    (output_of outcome);
  check_total "which costs the same as any other CALLDATALOAD"
    (3 + 3 + return_top_cost) outcome

let test_mcopy_moves_bytes () =
  (* Seed memory from calldata, move it forward by sixteen bytes, return the
     first word. MCOPY's source is memory, so it is converted and can fail — but
     after the destination, and it reads through the expansion this very
     instruction paid for. *)
  let env = env_with_data (Data.of_string "\x01\x02\x03\x04") in
  let code =
    asm
      [
        push1 0x04; push1 0x00; push1 0x00; op Opcode.Calldatacopy;
        push1 0x04; push1 0x00; push1 0x10; op Opcode.Mcopy;
        push1 0x20; push1 0x00; op Opcode.Return;
      ]
  in
  Alcotest.(check string) "MCOPY moves the bytes to the destination"
    ("\x01\x02\x03\x04" ^ String.make 12 '\000' ^ "\x01\x02\x03\x04" ^ String.make 12 '\000')
    (output_of (run ~env code allowance))

(* ---------- 3. the SSTORE matrix ---------- *)

(* [PUSH1 value; PUSH1 slot; SSTORE; STOP]: 3 + 3 + (100 from the entry +
   whatever the write costs) + 0. The 100 is inside [Gas.sstore_entry] and not in
   [Gas.static_cost], which returns zero for SSTORE so that the EIP-2200 sentry
   reads an allowance the dispatch loop has not touched. *)
let sstore_program values =
  asm
    (List.concat_map (fun v -> [ push1 v; push1 0x00; op Opcode.Sstore ]) values
    @ [ op Opcode.Stop ])

(* Asserts the three figures and RETURNS the total the machine actually spent, so
   that a caller wanting to assert the closed form of a decomposition can compare
   it against the MEASUREMENT rather than against itself. [check int "which is
   22106" 22106 (3 + 3 + 100 + 2100 + 19_900)] exercises no implementation code
   at all — it is two literals and the OCaml compiler's arithmetic, and it would
   still pass with the whole interpreter deleted. *)
let measure_sstore name ~original ~warm ~writes ~total ~refund ~final =
  let world =
    if original = 0 then World_state.empty else world_with_slot original
  in
  let access = if warm then warm_slot_access else Access.empty in
  let outcome = run ~effects:(Effects.start ~world ~access) (sstore_program writes) allowance in
  check_total (name ^ ": total") total outcome;
  let effects = effects_or_fail outcome in
  check_refund (name ^ ": refund") refund effects;
  Alcotest.(check u256)
    (name ^ ": the slot afterwards") (u final)
    (World_state.storage (Effects.world effects) self U256.zero);
  allowance - remaining_of outcome

let check_sstore name ~original ~warm ~writes ~total ~refund ~final =
  ignore (measure_sstore name ~original ~warm ~writes ~total ~refund ~final : int)

let test_sstore_fresh_set () =
  (* original = present = 0, updated <> 0. The dynamic charge is the cold 2100
     plus SSTORE_SET less the warm 100, and the two terms are additive. *)
  let cold =
    measure_sstore "cold fresh set" ~original:0 ~warm:false ~writes:[ 1 ]
      ~total:(3 + 3 + 100 + 2100 + 19_900) ~refund:0 ~final:1
  in
  (* The closed form against the MACHINE, not against the sum that produced it.
     Written as [check int "which is 22106" 22106 (3 + 3 + ...)] this compared one
     literal with another and would have passed with no interpreter at all. *)
  Alcotest.(check int) "which is 22106, as the machine spends it" 22106 cold;
  let warm =
    measure_sstore "warm fresh set" ~original:0 ~warm:true ~writes:[ 1 ]
      ~total:(3 + 3 + 100 + 19_900) ~refund:0 ~final:1
  in
  Alcotest.(check int) "and 20006 pre-warmed" 20006 warm;
  (* The 2100 the pair differs by is the cold surcharge, stated once as the
     difference of two measurements. *)
  Alcotest.(check int) "the two differ by exactly the cold surcharge" 2100 (cold - warm)

let test_sstore_fresh_reset () =
  (* original = present <> 0 and the write disturbs it. 2800 is WARM_SSTORE_RESET
     less the warm 100. Clearing to zero also earns the 4800 clearing refund;
     overwriting with another nonzero earns nothing. *)
  let warm_clear =
    measure_sstore "warm clear of an untouched slot" ~original:1 ~warm:true ~writes:[ 0 ]
      ~total:(3 + 3 + 100 + 2800) ~refund:4800 ~final:0
  in
  Alcotest.(check int) "which is 2906, as the machine spends it" 2906 warm_clear;
  check_sstore "cold clear of an untouched slot" ~original:1 ~warm:false ~writes:[ 0 ]
    ~total:(3 + 3 + 100 + 2100 + 2800) ~refund:4800 ~final:0;
  check_sstore "cold overwrite with another nonzero" ~original:1 ~warm:false ~writes:[ 2 ]
    ~total:(3 + 3 + 100 + 2100 + 2800) ~refund:0 ~final:2;
  check_sstore "warm overwrite with another nonzero" ~original:1 ~warm:true ~writes:[ 2 ]
    ~total:(3 + 3 + 100 + 2800) ~refund:0 ~final:2

let test_sstore_no_op () =
  (* updated = present. Nothing is written and nothing beyond the access is
     charged — but the access itself is charged, so a cold no-op is not free. *)
  check_sstore "cold no-op on an unset slot" ~original:0 ~warm:false ~writes:[ 0 ]
    ~total:(3 + 3 + 100 + 2100) ~refund:0 ~final:0;
  check_sstore "warm no-op on an unset slot" ~original:0 ~warm:true ~writes:[ 0 ]
    ~total:(3 + 3 + 100) ~refund:0 ~final:0;
  check_sstore "cold no-op on a set slot" ~original:1 ~warm:false ~writes:[ 1 ]
    ~total:(3 + 3 + 100 + 2100) ~refund:0 ~final:1;
  check_sstore "warm no-op on a set slot" ~original:1 ~warm:true ~writes:[ 1 ]
    ~total:(3 + 3 + 100) ~refund:0 ~final:1

let test_sstore_dirty () =
  (* original <> present: the transaction has already paid to disturb the slot,
     so further writes cost only the access.

     Every dirty cell is necessarily WARM, because the write that made the slot
     dirty warmed it. The cold-dirty cells of the sixteen-cell matrix are not
     reachable from a single frame at all; they are covered instead by the
     exhaustive table against the oracle below, which prices the triple
     directly. *)
  check_sstore "set then dirty-overwrite" ~original:0 ~warm:false ~writes:[ 1; 2 ]
    ~total:(3 + 3 + 100 + 2100 + 19_900 + (3 + 3 + 100))
    ~refund:0 ~final:2;
  check_sstore "reset then dirty-overwrite" ~original:1 ~warm:false ~writes:[ 2; 3 ]
    ~total:(3 + 3 + 100 + 2100 + 2800 + (3 + 3 + 100))
    ~refund:0 ~final:3;
  (* Restoring the slot to what the transaction found refunds what the reset
     cost. This is the accumulating arm of the refund, and it is the only test
     that reaches [sstore_reset_refund]. *)
  check_sstore "reset then restore the original" ~original:1 ~warm:false ~writes:[ 2; 1 ]
    ~total:(3 + 3 + 100 + 2100 + 2800 + (3 + 3 + 100))
    ~refund:2800 ~final:1;
  (* And restoring a slot the transaction found unset refunds what creating it
     cost — the [sstore_set_refund] arm, 19900. *)
  check_sstore "set then clear back to the original" ~original:0 ~warm:false ~writes:[ 1; 0 ]
    ~total:(3 + 3 + 100 + 2100 + 19_900 + (3 + 3 + 100))
    ~refund:19_900 ~final:0

let test_sstore_negative_refund () =
  (* The negative branch: original nonzero, present zero, updated nonzero claws
     back the 4800 that the clearing write was credited ([gas_params.rs:483-485]).

     Two programs make it visible. The first clears and stops, banking +4800. The
     second clears and then writes a nonzero, and ends at exactly zero — so the
     second write contributed -4800 and nothing else.

     Note what this pair also establishes: within a SINGLE frame the running
     counter can never actually go negative, because the negative branch requires
     [present = 0] with [original <> 0], and at frame start those coincide. Some
     earlier write in the same frame must have cleared the slot, and that write
     was credited the same 4800. The counter is signed for the per-write term,
     which really is negative, and for the day CALL makes a frame able to hand
     back a counter it did not start. *)
  check_sstore "clearing an untouched slot banks 4800" ~original:1 ~warm:false ~writes:[ 0 ]
    ~total:(3 + 3 + 100 + 2100 + 2800) ~refund:4800 ~final:0;
  check_sstore "and rewriting it claws the 4800 straight back" ~original:1 ~warm:false
    ~writes:[ 0; 3 ]
    ~total:(3 + 3 + 100 + 2100 + 2800 + (3 + 3 + 100))
    ~refund:0 ~final:3;
  (* The term itself, priced directly, so the cancellation above cannot be a pair
     of compensating zeroes. *)
  Alcotest.(check int) "the term in isolation is -4800" (-4800)
    (Gas.sstore_refund
       (Sstore_state.make ~original:(u 1) ~present:U256.zero ~updated:(u 3)));
  (* A dirty write is free of the change term but not of the cold surcharge —
     the cell no program can reach. *)
  Alcotest.(check int) "a cold dirty write still pays the 2100 surcharge" 2100
    (Gas.sstore_dynamic_cost cold_witness
       (Sstore_state.make ~original:(u 1) ~present:(u 2) ~updated:(u 3)));
  Alcotest.(check int) "and a warm one pays nothing" 0
    (Gas.sstore_dynamic_cost warm_witness
       (Sstore_state.make ~original:(u 1) ~present:(u 2) ~updated:(u 3)))

let test_sstore_constants_are_not_shared () =
  (* Trap 8. SSTORE's cold surcharge is COLD_SLOAD_COST itself; SLOAD's is that
     constant less the warm 100 it has already paid. They differ by exactly 100
     and both remain plausible numbers if swapped, so both are asserted here
     against literals rather than against each other. *)
  Alcotest.(check int) "SLOAD's cold surcharge is 2000" 2000
    (Gas.storage_access_cost cold_witness);
  Alcotest.(check int) "SSTORE's is 2100"
    2100
    (Gas.sstore_dynamic_cost cold_witness
       (Sstore_state.make ~original:U256.zero ~present:U256.zero ~updated:U256.zero));
  Alcotest.(check int) "BALANCE's is 2500" 2500 (Gas.account_access_cost cold_witness);
  Alcotest.(check int) "and warm is nothing in all three" 0
    (Gas.storage_access_cost warm_witness
    + Gas.account_access_cost warm_witness
    + Gas.sstore_dynamic_cost warm_witness
        (Sstore_state.make ~original:U256.zero ~present:U256.zero ~updated:U256.zero));
  Alcotest.(check int) "SSTORE's table entry is zero" 0 (Gas.static_cost Opcode.Sstore);
  Alcotest.(check int) "SLOAD's and BALANCE's are the warm 100" 200
    (Gas.static_cost Opcode.Sload + Gas.static_cost Opcode.Balance)

(* ---------- 4. orderings visible at exactly one point ---------- *)

let test_reentrancy_sentry_boundary () =
  (* [PUSH1 1; PUSH1 0; SSTORE]. Six units go to the two pushes and SSTORE's own
     table entry is zero, so an allowance of 2306 leaves the sentry looking at
     exactly 2300.

     The comparison is [<=] ([instructions/host.rs:238]), so exactly 2300 is
     refused — and refused CATEGORICALLY, not for want of gas: at 2306 the frame
     is nowhere near able to afford the 22000 the write costs, and yet the error
     is distinguishable from the one it gets at 2307. *)
  let code = sstore_program [ 1 ] in
  check_error "exactly 2300 remaining trips the sentry" Interpreter.Reentrancy_sentry
    (run code 2306);
  (* One more unit and the sentry passes; the write is then charged for and
     cannot be paid. Different error, one unit apart. This is the pair that pins
     the [<=], and it is also what would break if [static_cost Sstore] were 100:
     the boundary would move to 2406. *)
  check_error "2301 remaining passes it and then runs out" Interpreter.Out_of_gas
    (run code 2307);
  (* Far below the boundary is still the sentry, not out-of-gas: the refusal does
     not depend on the shortfall. *)
  check_error "well below the boundary is still the sentry" Interpreter.Reentrancy_sentry
    (run code 200);
  (* And well above it, the write goes through. *)
  check_total "well above it the write succeeds" 22106 (run code allowance)

let test_pop_precedes_the_sentry () =
  (* One operand instead of two, with exactly 2300 remaining when SSTORE
     dispatches. revm pops first ([host.rs:230]) and tests the sentry after
     ([:237]), so this is a stack underflow. Reversing the two lines is invisible
     on every other program in this file. *)
  let one_operand = asm [ push1 0x00; op Opcode.Sstore; op Opcode.Stop ] in
  check_error "an underflow at the sentry boundary reports the underflow"
    Interpreter.Stack_underflow (run one_operand 2303);
  (* And with plenty of gas it is the same underflow, so the error above is not
     an artefact of the tight allowance. *)
  check_error "and reports it with room to spare" Interpreter.Stack_underflow
    (run one_operand allowance)

let test_zero_length_copy_at_a_wild_destination () =
  (* The copy family charges [copy_cost] BEFORE converting the destination, and
     returns on a zero length BEFORE converting it. So a zero-length copy to an
     offset no [int] could hold succeeds, expands nothing, and leaves MSIZE at 0.

     PUSH1 3, PUSH1 3, PUSH32 3, CALLDATACOPY 3 (copy_cost 0 = 0), MSIZE 2, then
     the epilogue, which is the first thing in the program to touch memory. *)
  let nothing_at_the_end opcode =
    asm ([ push1 0x00; push1 0x00; push32 U256.max_value; op opcode; op Opcode.Msize ] @ return_top)
  in
  List.iter
    (fun (name, opcode) ->
      let outcome = run (nothing_at_the_end opcode) allowance in
      Alcotest.(check string)
        (name ^ ": a zero-length copy expands nothing")
        (U256.to_be_bytes U256.zero) (output_of outcome);
      check_total
        (name ^ ": and costs only its own price")
        (3 + 3 + 3 + 3 + 2 + return_top_cost)
        outcome)
    [ ("CALLDATACOPY", Opcode.Calldatacopy); ("CODECOPY", Opcode.Codecopy);
      ("MCOPY", Opcode.Mcopy) ];
  (* MCOPY's SOURCE is converted too, and also only after the zero-length return,
     so an impossible source with zero length is equally fine. *)
  let wild_source =
    asm
      ([ push1 0x00; push32 U256.max_value; push32 U256.max_value; op Opcode.Mcopy;
         op Opcode.Msize ]
      @ return_top)
  in
  Alcotest.(check string) "MCOPY: an impossible source with zero length is fine"
    (U256.to_be_bytes U256.zero)
    (output_of (run wild_source allowance));
  (* One byte instead of none, at the same DESTINATION, is refused. This controls
     for the destination rule and for that alone: CALLDATACOPY has no source
     offset to convert — its source is a {!Data.t} read at a saturating word — so
     it says nothing whatever about MCOPY's [extent_of_word source]. The comment
     here used to claim it did. *)
  let one_byte =
    asm [ push1 0x01; push1 0x00; push32 U256.max_value; op Opcode.Calldatacopy; op Opcode.Stop ]
  in
  check_error "one byte to the same destination is refused" Interpreter.Offset_too_large
    (run one_byte allowance);
  (* The control the branch above actually needs, and the only test in the file
     that drives MCOPY's source conversion to a refusal: an impossible SOURCE with
     a nonzero length, at a destination that is perfectly fine. Delete
     [extent_of_word source] from [mcopy] and this is the case that fails — under
     the zero-length pair above it is unreachable, because the zero-length return
     happens first.

     Pushed len, src, dst, so the popped order is dst (0, representable), src
     (max_value, not), len (1, nonzero). *)
  let wild_source_one_byte =
    asm [ push1 0x01; push32 U256.max_value; push1 0x00; op Opcode.Mcopy; op Opcode.Stop ]
  in
  check_error "MCOPY: an impossible source with a nonzero length is refused"
    Interpreter.Offset_too_large (run wild_source_one_byte allowance);
  (* And the mirror, so the refusal above is about the source and not about the
     pair: the same length and the same wild word in the DESTINATION position is
     refused too, while the same program with both offsets representable
     succeeds. *)
  let wild_dest_one_byte =
    asm [ push1 0x01; push1 0x00; push32 U256.max_value; op Opcode.Mcopy; op Opcode.Stop ]
  in
  check_error "MCOPY: an impossible destination with a nonzero length is refused"
    Interpreter.Offset_too_large (run wild_dest_one_byte allowance);
  let both_fine = asm [ push1 0x01; push1 0x00; push1 0x00; op Opcode.Mcopy; op Opcode.Stop ] in
  Alcotest.(check string) "MCOPY: and with both representable it simply runs" "stopped"
    (error_of (run both_fine allowance))

let test_mcopy_expands_at_the_maximum () =
  (* Trap 6. The expansion covers [max dst src], because the source MCOPY reads
     must exist. A dst-only implementation prices the first of these at 27 and
     the second — its mirror — at 18, and passes every test built from a single
     MCOPY that copies forward.

     Each figure: PUSH1 3 x3, MCOPY 3 static + copy_cost 32 = 3, then the
     expansion. Reaching [96, 128) is four words, and memory_cost 4 is
     3*4 + 4*4/512 = 12. Reaching [0, 32) is one word, and memory_cost 1 is 3. *)
  let mcopy ~dst ~src ~len =
    asm [ push1 len; push1 src; push1 dst; op Opcode.Mcopy; op Opcode.Stop ]
  in
  check_total "copying forward to offset 96 reaches four words" 27
    (run (mcopy ~dst:96 ~src:0 ~len:32) allowance);
  check_total "and copying BACKWARD from offset 96 reaches the same four" 27
    (run (mcopy ~dst:0 ~src:96 ~len:32) allowance);
  (* The symmetric case costs less, so the two figures above are not simply a
     constant the test would accept from any implementation. *)
  check_total "while a copy that stays in the first word is 18" 18
    (run (mcopy ~dst:0 ~src:0 ~len:32) allowance)

let test_revert_discards_everything () =
  (* A program that writes storage, warms a slot and earns a refund, then
     reverts. The outcome carries no effects — there is no field to read them
     from — and the caller's own value is untouched.

     The write is a clear of an untouched nonzero slot, so under a leak all three
     components would be observable: the world would hold zero, the slot would be
     warm, and the refund would be 4800. *)
  let world = world_with_slot 1 in
  let before = Effects.start ~world ~access:Access.empty in
  let body = [ push1 0x00; push1 0x00; op Opcode.Sstore ] in
  (* First, the same program ending in STOP, to show the effects really are there
     to be lost. *)
  let kept = effects_or_fail (run ~effects:before (asm (body @ [ op Opcode.Stop ])) allowance) in
  Alcotest.(check u256) "the write lands when the program stops" U256.zero
    (World_state.storage (Effects.world kept) self U256.zero);
  check_refund "and the refund is earned" 4800 kept;
  Alcotest.(check bool) "and the slot is warm" true
    (Access.mem_slot (Effects.access kept) self U256.zero);
  Alcotest.(check bool) "so the effects differ from the ones passed in" false
    (Effects.equal kept before);
  (* Now the reverting version.

     Every assertion from here on reads the OUTCOME. The four that used to stand
     here read [before] instead — the caller's own input — and so were true of
     every possible implementation: [run] is pure, so the value passed in is the
     value still held, and no mutation to the REVERT arm could have moved any of
     them. *)
  let reverting = asm (body @ [ push1 0x00; push1 0x00; op Opcode.Revert ]) in
  let outcome = run ~effects:before reverting allowance in
  Alcotest.(check string) "the program reverts" "reverted" (error_of outcome);
  Alcotest.(check bool) "so it does not report a successful halt" false
    (halted_successfully outcome);
  Alcotest.(check bool) "and makes no effects reachable at all" true
    (Option.is_none (reachable_effects outcome));
  (* The three components, read from whatever the outcome exposes. When it
     exposes nothing these fall back on the caller's own value and are trivially
     true — the assertion above is what carries the weight there — but under a
     leak they read the ESCAPED effects, and the program was chosen so that all
     three would then differ: the world would hold zero, the refund 4800, and the
     slot would be warm. *)
  let exposed = Option.value (reachable_effects outcome) ~default:before in
  Alcotest.(check u256) "no world with the slot cleared is reachable" (u 1)
    (World_state.storage (Effects.world exposed) self U256.zero);
  check_refund "no refund is reachable" 0 exposed;
  Alcotest.(check bool) "and no warm set holding the slot is reachable" false
    (Access.mem_slot (Effects.access exposed) self U256.zero);
  Alcotest.(check bool) "nothing reachable differs from what was passed in" true
    (Effects.equal exposed before);
  (* That [exposed] is not vacuously [before]: the STOP version of the same
     program does make effects reachable, and they differ in all three
     components. So the assertions above are facts about reverting. *)
  Alcotest.(check bool) "the stopping version does expose effects" true
    (Option.is_some (reachable_effects (run ~effects:before (asm (body @ [ op Opcode.Stop ])) allowance)));
  Alcotest.(check bool) "and they differ from the caller's" false (Effects.equal kept before);
  (* Revert is not a discount: the gas the discarded work cost is still spent.
     3 + 3 + (100 + 2100 + 2800) + 3 + 3 + 0. *)
  check_total "and the reverted work was still paid for" (3 + 3 + 100 + 2100 + 2800 + 6)
    outcome;
  (* The assumption the randomised version of this rests on, pinned here rather
     than left as a remark in its comment. The property appends {!revert_padding}
     between the random tail and the REVERT epilogue; this is the worst case that
     padding exists for, and the pair shows it is not decorative.

     A bare PUSH32 opcode as the last byte of the tail advances the program
     counter thirty-two bytes. Unpadded, that clears the whole five-byte epilogue
     and runs off the end of the code, which halts as an implicit STOP and hands
     the effects back — honestly, but the run never reverted, and a property
     asserting "this did not halt successfully" would fail for a reason that has
     nothing to do with the leak it is hunting. Padded, the counter lands on the
     epilogue and the frame reverts as intended. *)
  let epilogue = [ push1 0x00; push1 0x00; op Opcode.Revert ] in
  let trailing_push = op (Opcode.Push (width_of 32)) in
  let unpadded = asm (body @ [ trailing_push ] @ epilogue) in
  Alcotest.(check string) "an unpadded trailing PUSH32 skips the epilogue entirely" "stopped"
    (error_of (run ~effects:before unpadded allowance));
  Alcotest.(check bool) "and so hands the effects back" true
    (Option.is_some (reachable_effects (run ~effects:before unpadded allowance)));
  let padded = asm (body @ [ trailing_push; revert_padding ] @ epilogue) in
  Alcotest.(check string) "while the padded form reaches the REVERT" "reverted"
    (error_of (run ~effects:before padded allowance));
  Alcotest.(check bool) "and makes nothing reachable" true
    (Option.is_none (reachable_effects (run ~effects:before padded allowance)))

let test_sstore_termination_under_a_loop () =
  (* [SSTORE] is the one instruction the dispatch loop does not charge for, so a
     loop dominated by it is the shape most exposed to the hole that zero table
     entry opens:

       0: JUMPDEST   1
       1: PUSH1 0    3   (value)
       3: PUSH1 0    3   (slot)
       5: SSTORE     100 + 2100 the first time round, 100 thereafter
       6: PUSH1 0    3   (destination)
       8: JUMP       8

     It halts — and it halts on the SENTRY, not out of gas, which is worth
     pinning in its own right. Once fewer than 2301 units remain, EIP-2200
     refuses every further [SSTORE] outright, so a storage-writing loop can never
     burn its last 2300 units and can never be the program that reaches an
     allowance of zero.

     Be clear about what this does and does not guard. It does not prove the
     100-unit charge happens: the eighteen units the surrounding instructions
     cost would terminate this loop on their own. The charge is guarded by the
     straight-line matrix above, where every total is absolute and a missing 100
     moves a figure. What this guards is the driver — that an SSTORE-heavy
     program returns at all — and a regression in that would hang the suite
     rather than fail it, which is the honest description and the strongest
     available short of instrumenting [drive]'s step count. *)
  let sstore_loop =
    asm
      [
        op Opcode.Jumpdest; push1 0x00; push1 0x00; op Opcode.Sstore; push1 0x00;
        op Opcode.Jump;
      ]
  in
  check_error "an SSTORE loop halts at the sentry rather than running forever"
    Interpreter.Reentrancy_sentry (run sstore_loop 100_000);
  check_error "and from a much smaller allowance too" Interpreter.Reentrancy_sentry
    (run sstore_loop 10_000);
  check_error "and from one already below the boundary" Interpreter.Reentrancy_sentry
    (run sstore_loop 2_500);
  (* The contrast: the same loop with no [SSTORE] in it halts at zero, on the
     dispatch loop's own charge. That is what makes the three results above a
     statement about the sentry and not about looping in general. *)
  let bare_loop = asm [ op Opcode.Jumpdest; push1 0x00; op Opcode.Jump ] in
  check_error "a loop with no SSTORE runs out of gas instead" Interpreter.Out_of_gas
    (run bare_loop 100_000)

(* ---------- 5. properties ---------- *)

(* An independent transcription of revm's SSTORE pricing, made from
   [revm-context-interface-14.0.0/src/cfg/gas_params.rs] lines 433-451 and
   456-506 at Berlin and London, with the constants resolved from
   [cfg/gas.rs:63,65,90,93,100,102] through the table at [gas_params.rs:268-297].

   This is an oracle and not a restatement: it is written from the Rust rather
   than from [Gas], it keeps revm's control flow rather than the four-way
   classification the implementation matches on, and its two accumulating
   branches are two independent [if]s summed exactly as revm has them. If it were
   tidied into an if/else chain it would agree with an implementation that had
   been tidied the same way, and the property below would be a tautology. *)
module Oracle = struct
  let sstore_set = 20_000
  let sstore_reset = 5_000
  let cold_sload_cost = 2_100
  let warm_storage_read_cost = 100
  let access_list_storage_key = 1_900
  let warm_sstore_reset = sstore_reset - cold_sload_cost
  let cold_storage_cost = cold_sload_cost
  let sstore_set_without_load_cost = sstore_set - warm_storage_read_cost
  let sstore_reset_without_cold_load_cost = warm_sstore_reset - warm_storage_read_cost
  let sstore_set_refund = sstore_set_without_load_cost
  let sstore_reset_refund = sstore_reset_without_cold_load_cost
  let sstore_clearing_slot_refund = warm_sstore_reset + access_list_storage_key

  (* [gas_params.rs:433-451]. *)
  let dynamic_cost ~is_cold ~original ~present ~updated =
    let gas = if is_cold then cold_storage_cost else 0 in
    let new_values_changes_present = not (U256.equal updated present) in
    let is_original_eq_present = U256.equal original present in
    if new_values_changes_present && is_original_eq_present then
      gas
      + (if U256.equal original U256.zero then sstore_set_without_load_cost
         else sstore_reset_without_cold_load_cost)
    else gas

  (* [gas_params.rs:456-506]. The first two tests return; the last two
     accumulate into one total and are independent of each other. *)
  let refund ~original ~present ~updated =
    if U256.equal updated present then 0
    else if U256.equal original present && U256.equal updated U256.zero then
      sstore_clearing_slot_refund
    else
      let clearing =
        if not (U256.equal original U256.zero) then
          if U256.equal present U256.zero then -sstore_clearing_slot_refund
          else if U256.equal updated U256.zero then sstore_clearing_slot_refund
          else 0
        else 0
      in
      let restoring =
        if U256.equal original updated then
          if U256.equal original U256.zero then sstore_set_refund else sstore_reset_refund
        else 0
      in
      clearing + restoring
end

(* The 54 rows the spec asks for: three values each for original, present and
   updated, crossed with cold and warm. Every combination is checked, including
   the ones no single frame can reach. *)
let test_sstore_against_the_oracle () =
  let words = [ U256.zero; u 1; u 2 ] in
  List.iter
    (fun is_cold ->
      List.iter
        (fun original ->
          List.iter
            (fun present ->
              List.iter
                (fun updated ->
                  let triple = Sstore_state.make ~original ~present ~updated in
                  let witness = if is_cold then cold_witness else warm_witness in
                  let label =
                    Printf.sprintf "%s o=%s p=%s n=%s"
                      (if is_cold then "cold" else "warm")
                      (U256.to_hex original) (U256.to_hex present) (U256.to_hex updated)
                  in
                  Alcotest.(check int)
                    (label ^ ": dynamic cost")
                    (Oracle.dynamic_cost ~is_cold ~original ~present ~updated)
                    (Gas.sstore_dynamic_cost witness triple);
                  Alcotest.(check int)
                    (label ^ ": refund")
                    (Oracle.refund ~original ~present ~updated)
                    (Gas.sstore_refund triple))
                words)
            words)
        words)
    [ true; false ];
  (* The oracle is not vacuous: it produces all four dynamic charges and a
     negative refund somewhere in that table. *)
  Alcotest.(check int) "the oracle really does reach -4800" (-4800)
    (Oracle.refund ~original:(u 1) ~present:U256.zero ~updated:(u 2));
  Alcotest.(check int) "and 19900" 19_900
    (Oracle.dynamic_cost ~is_cold:false ~original:U256.zero ~present:U256.zero ~updated:(u 1))

let mk ~salt ~count name arb fn =
  Alcotest.test_case name `Slow (fun () ->
      QCheck.Test.check_exn
        ~rand:(Random.State.make [| 0x5eed_5; salt |])
        (QCheck.Test.make ~count ~name arb fn))

let gen_word =
  let open QCheck.Gen in
  let edges = [ U256.zero; U256.one; U256.max_value; U256.two_pow 255; u 2; u 255 ] in
  let random_bytes =
    map
      (fun s -> get (U256.of_be_bytes s))
      (string_size ~gen:(map Char.chr (int_range 0 255)) (return 32))
  in
  int_range 0 4 >>= fun k ->
  if k < 2 then oneof_list edges
  else if k < 3 then map (fun n -> u n) (int_range 0 3)
  else random_bytes

let hex3 (a, b, c) =
  Printf.sprintf "%s %s %s" (U256.to_hex a) (U256.to_hex b) (U256.to_hex c)

let arb_triple = QCheck.make ~print:hex3 QCheck.Gen.(triple gen_word gen_word gen_word)
let arb_word = QCheck.make ~print:U256.to_hex gen_word

(* Random bytecode, biased so that the host instructions and SSTORE in
   particular actually appear: uniform bytes reach 0x55 once in 256. *)
let host_bytes =
  List.map Opcode.to_byte
    [ Opcode.Sload; Opcode.Sstore; Opcode.Balance; Opcode.Selfbalance;
      Opcode.Calldataload; Opcode.Calldatacopy; Opcode.Codecopy; Opcode.Mcopy;
      Opcode.Keccak256; Opcode.Tload; Opcode.Tstore; Opcode.Log Topic_count.One ]

let gen_host_code =
  let open QCheck.Gen in
  let one =
    int_range 0 2 >>= fun k ->
    if k < 1 then oneof_list (List.map Char.chr host_bytes)
    else map Char.chr (int_range 0 255)
  in
  string_size ~gen:one (int_range 0 40)

let print_code s =
  String.concat ""
    (List.init (String.length s) (fun i -> Printf.sprintf "%02x" (Char.code (String.get s i))))

let arb_host_code = QCheck.make ~print:print_code gen_host_code

let arb_host_code_and_gas =
  QCheck.make
    ~print:(fun (s, g) -> Printf.sprintf "%s @ %d" (print_code s) g)
    QCheck.Gen.(pair gen_host_code (int_range 0 60_000))

(* --- storage canonicity --- *)

(* Writing a value and then clearing it leaves the map exactly where clearing it
   directly would: the intermediate binding is erased, not zeroed. Checked over a
   random prior state so it is not only true of [empty]. *)
let storage_canonicity (k, v, w) =
  let prior = Storage.set (Storage.set Storage.empty (u 3) w) (u 5) v in
  let via_write = Storage.set (Storage.set prior k v) k U256.zero in
  let direct = Storage.set prior k U256.zero in
  Storage.equal via_write direct
  && List.for_all (fun (_, value) -> not (U256.is_zero value)) (Storage.bindings via_write)
  && U256.is_zero (Storage.get via_write k)

(* The same at the world-state level: two routes to one logical state compare
   equal, and the equality is not vacuous because the readings are compared
   pointwise as well. *)
let world_canonicity (a, b, c) =
  let slots = [ (u 0, a); (u 1, b); (u 2, c) ] in
  let forwards =
    List.fold_left (fun w (k, v) -> World_state.set_storage w self k v) World_state.empty slots
  in
  let backwards =
    List.fold_left
      (fun w (k, v) -> World_state.set_storage w self k v)
      (List.fold_left
         (fun w (k, _) -> World_state.set_storage w self k (u 0xff))
         World_state.empty slots)
      slots
  in
  World_state.equal forwards backwards
  && List.for_all
       (fun (k, v) ->
         U256.equal (World_state.storage forwards self k) v
         && U256.equal (World_state.storage backwards self k) v)
       slots

(* --- the SSTORE pricing, against the oracle, over random words --- *)

let sstore_matches_oracle is_cold (original, present, updated) =
  let triple = Sstore_state.make ~original ~present ~updated in
  let witness = if is_cold then cold_witness else warm_witness in
  Int.equal
    (Gas.sstore_dynamic_cost witness triple)
    (Oracle.dynamic_cost ~is_cold ~original ~present ~updated)
  && Int.equal (Gas.sstore_refund triple) (Oracle.refund ~original ~present ~updated)

(* --- copy_cost --- *)

let copy_cost_is_three_per_word n = Int.equal (Gas.copy_cost n) (3 * ((n + 31) / 32))

let arb_length =
  QCheck.make ~print:string_of_int
    QCheck.Gen.(oneof [ int_range 0 200; int_range 0 100_000; int_range 0 10_000_000 ])

(* --- Memory.store_bytes against a flat buffer --- *)

let buffer_size = 512

let store_bytes_matches_a_flat_buffer (offset, content) =
  let offset = offset mod (buffer_size - String.length content - 1) in
  let reference = Bytes.make buffer_size '\000' in
  Bytes.blit_string content 0 reference offset (String.length content);
  let memory = Memory.store_bytes Memory.empty ~offset content in
  String.equal
    (Memory.slice memory ~offset:0 ~length:buffer_size)
    (Bytes.to_string reference)

let arb_offset_and_content =
  QCheck.make
    ~print:(fun (o, s) -> Printf.sprintf "%d %s" o (print_code s))
    QCheck.Gen.(
      pair (int_range 0 (buffer_size - 1))
        (string_size ~gen:(map Char.chr (int_range 0 255)) (int_range 0 64)))

(* --- MCOPY against Bytes.blit, which is memmove by specification --- *)

let mcopy_window = 160

let mcopy_is_memmove (dst, src, len, seed) =
  (* Seed memory from the calldata, move a range, return the window. The
     generated offsets are deliberately overlapping in both directions. *)
  let env = env_with_data (Data.of_string seed) in
  let code =
    asm
      [
        push1 (String.length seed); push1 0x00; push1 0x00; op Opcode.Calldatacopy;
        push1 len; push1 src; push1 dst; op Opcode.Mcopy;
        push1 mcopy_window; push1 0x00; op Opcode.Return;
      ]
  in
  let reference = Bytes.make (mcopy_window + 128) '\000' in
  Bytes.blit_string seed 0 reference 0 (String.length seed);
  Bytes.blit reference src reference dst len;
  match run ~env code allowance with
  | Interpreter.Returned { output; _ } ->
      String.equal output (Bytes.sub_string reference 0 mcopy_window)
  | Interpreter.Stopped _ | Interpreter.Reverted _ | Interpreter.Failed _ -> false

let arb_mcopy =
  QCheck.make
    ~print:(fun (d, s, l, seed) -> Printf.sprintf "dst=%d src=%d len=%d %s" d s l (print_code seed))
    QCheck.Gen.(
      int_range 0 64 >>= fun dst ->
      int_range 0 64 >>= fun src ->
      int_range 0 64 >>= fun len ->
      map (fun seed -> (dst, src, len, seed))
        (string_size ~gen:(map Char.chr (int_range 1 255)) (int_range 0 64)))

(* --- MCOPY's expansion is symmetric in dst and src --- *)

(* The property that catches a [dst]-only expansion and nothing else does: the
   same copy in the two orientations must cost the same, because both must reach
   [max dst src]. Under [dst] alone the orientation with the larger source is
   cheaper by exactly the expansion it skipped. *)
let mcopy_expansion_is_symmetric (a, b, len) =
  let mcopy ~dst ~src =
    asm [ push1 len; push1 src; push1 dst; op Opcode.Mcopy; op Opcode.Stop ]
  in
  let cost ~dst ~src = remaining_of (run (mcopy ~dst ~src) allowance) in
  Int.equal (cost ~dst:a ~src:b) (cost ~dst:b ~src:a)

let arb_mirror =
  QCheck.make
    ~print:(fun (a, b, l) -> Printf.sprintf "%d %d %d" a b l)
    QCheck.Gen.(triple (int_range 0 200) (int_range 0 200) (int_range 0 64))

(* --- Data.read against a naive padded reader --- *)

let naive_read source ~offset ~length =
  let available = String.length source in
  let start =
    match U256.to_int offset with
    | Some o when o >= 0 && o <= available -> o
    | Some _ -> available
    | None -> available
  in
  String.init length (fun i ->
      if start + i < available then String.get source (start + i) else '\000')

let data_read_matches_the_naive_reader (source, offset, length) =
  String.equal
    (Data.read (Data.of_string source) ~offset ~length)
    (naive_read source ~offset ~length)

let arb_data_read =
  QCheck.make
    ~print:(fun (s, o, l) -> Printf.sprintf "%s @ %s x %d" (print_code s) (U256.to_hex o) l)
    QCheck.Gen.(
      triple
        (string_size ~gen:(map Char.chr (int_range 0 255)) (int_range 0 40))
        (oneof [ map (fun n -> u n) (int_range 0 48); gen_word ])
        (int_range 0 48))

(* --- Address_word truncates exactly the top twelve bytes --- *)

let address_mask = U256.sub (U256.two_pow 160) U256.one

let address_word_masks w =
  U256.equal (Address_word.to_word (Address_word.of_word w)) (U256.logand w address_mask)
  && U256.equal
       (Address_word.to_word (Address_word.of_word (Address_word.to_word (Address_word.of_word w))))
       (U256.logand w address_mask)

(* --- random bytecode cannot raise, invent gas, or reach an unreachable world --- *)

let seeded_world =
  World_state.set_storage
    (World_state.of_alloc [ (self, u 1_000); (other, u 5) ])
    self (u 0) (u 7)

let accounts_besides address world =
  List.filter (fun (a, _) -> not (Units.Address.equal a address)) (World_state.accounts world)

let random_code_is_sound (source, allowed) =
  let effects = Effects.start ~world:seeded_world ~access:Access.empty in
  let outcome = run ~effects (Code.of_string source) allowed in
  let gas_is_sane =
    match outcome with
    | Interpreter.Failed _ -> true
    | Interpreter.Stopped { gas_left; _ }
    | Interpreter.Returned { gas_left; _ }
    | Interpreter.Reverted { gas_left; _ } ->
        let left = Gas.remaining gas_left in
        left >= 0 && left <= allowed
  in
  (* SSTORE is the only writer OF THE WORLD, and it always names the executing
     account, so no other account can have moved. The result world is therefore
     reachable from the input by writes to [self] alone.

     TSTORE and LOG also write, but they write substate this conjunct does not
     constrain: neither can reach {!World_state} at all, since {!Transient} and
     {!Log_journal} live in [tn_evm] and the world state cannot see them. That
     is the layering argument, not an omission. *)
  let world_is_reachable =
    match effects_of outcome with
    | None -> true
    | Some effects ->
        List.equal
          (fun (a, x) (b, y) -> Units.Address.equal a b && Account.equal x y)
          (accounts_besides self seeded_world)
          (accounts_besides self (Effects.world effects))
        && U256.equal
             (World_state.balance (Effects.world effects) self)
             (World_state.balance seeded_world self)
  in
  gas_is_sane && world_is_reachable

(* --- a reverting run leaves the caller exactly where it was --- *)

(* Random bytecode with every successful-halt byte removed. STOP, RETURN and
   REVERT become JUMPDEST, which is a priced no-op and cannot end a run.

   The substitution is what gives the property something to assert. With the raw
   generator a tail containing a STOP halts the frame legitimately, effects and
   all, so "the outcome is not a successful halt" would be false for honest
   reasons and the property could only ever say "IF it reverted, then …" — which
   a leak that changes the constructor satisfies vacuously. With the halts gone,
   the appended REVERT is the only exit that is not a failure, so the constructor
   itself becomes assertable.

   A byte is replaced wherever it appears, including inside a PUSH immediate.
   That shifts the distribution and takes nothing away: an immediate byte is
   never executed, so no reachable halt survives the substitution either way. *)
let gen_unhalting_code =
  QCheck.Gen.map
    (String.map (fun c -> if List.mem (Char.code c) halting_bytes then jumpdest_byte else c))
    gen_host_code

let arb_unhalting_code = QCheck.make ~print:print_code gen_unhalting_code

(* A frame that executed REVERT must make nothing reachable to its caller.

   The previous version of this property was constant-true and a verifier proved
   it: patching the REVERT arm to return [Stopped { gas_left; effects }] —
   carrying the world with the slot cleared, the slot warm and the refund 4800,
   i.e. every effect of a reverted frame escaping — left all 300 samples passing.
   Every conjunct read [before], which a pure [run] cannot touch, and the one
   remaining conjunct held by the definition of the test file's own helper.

   So all three conjuncts below read the OUTCOME:

   - it must not be a successful halt. The prologue's SSTORE always runs and the
     tail can no longer halt, so [Reverted] or [Failed] are the only honest
     answers, and the constructor-swapping leak lands squarely on this.
   - nothing may be reachable through it, by {!reachable_effects}.
   - and whatever IS reachable — the caller's own value when nothing is — must
     hold the slot at 1, no refund and a cold slot. Under the leak this reads the
     escaped effects and all three differ.

   Note what is being tested is still a structural claim: effects are a value the
   run threads rather than a journal to unwind, so there is no undo step to
   forget. The property now fails if that structure is broken, which is the part
   it previously did not do.

   How much of the sample carries that weight, counted rather than assumed: of
   the 300 samples at this seed, 29 reach the REVERT and 271 fail before it, on a
   stack underflow or an undecodable byte or the allowance. The 271 are the weak
   half — [Failed] carries no effects and structurally cannot — so it is the 29
   that could catch a leak, and they do: the constructor-swapping patch described
   above fails this property. The deterministic case in
   {!test_revert_discards_everything} remains the sharper of the two.

   The figure is 29 and not the 30 recorded before this chunk, because
   {!host_bytes} grew when the hash, the logs and transient storage landed and
   that reshuffles the corpus drawn at this seed. It is recounted here rather
   than left to drift: a stale count reads as evidence while being none. *)
let revert_is_a_no_op source =
  let world = world_with_slot 1 in
  let before = Effects.start ~world ~access:Access.empty in
  let code =
    Code.of_string
      (String.concat ""
         [ push1 0x00; push1 0x00; op Opcode.Sstore; source; revert_padding; push1 0x00;
           push1 0x00; op Opcode.Revert ])
  in
  let outcome = run ~effects:before code allowance in
  let exposed = Option.value (reachable_effects outcome) ~default:before in
  (not (halted_successfully outcome))
  && Option.is_none (reachable_effects outcome)
  && Effects.equal exposed before
  && U256.equal (World_state.storage (Effects.world exposed) self U256.zero) (u 1)
  && Int.equal (Refund.to_int (Effects.refund exposed)) 0
  && not (Access.mem_slot (Effects.access exposed) self U256.zero)

(* --- termination under SSTORE --- *)

(* Random bytecode rich in SSTORE, at random allowances, must return. It cannot
   be asserted that it returns "within N steps" without instrumenting the driver;
   what is asserted is that it returns at all and never reports more gas than it
   was given. The deterministic loop test above is the sharper of the two. *)
let terminates_and_accounts (source, allowed) =
  let effects = Effects.start ~world:seeded_world ~access:Access.empty in
  match run ~effects (Code.of_string source) allowed with
  | Interpreter.Failed _ -> true
  | Interpreter.Stopped { gas_left; _ }
  | Interpreter.Returned { gas_left; _ }
  | Interpreter.Reverted { gas_left; _ } ->
      Gas.remaining gas_left <= allowed

let prop_cases =
  [
    mk ~salt:1 ~count:300 "storage canonicity" arb_triple storage_canonicity;
    mk ~salt:2 ~count:200 "world-state canonicity" arb_triple world_canonicity;
    mk ~salt:3 ~count:500 "cold SSTORE pricing matches the revm oracle" arb_triple
      (sstore_matches_oracle true);
    mk ~salt:4 ~count:500 "warm SSTORE pricing matches the revm oracle" arb_triple
      (sstore_matches_oracle false);
    mk ~salt:5 ~count:300 "copy_cost is three per word" arb_length copy_cost_is_three_per_word;
    mk ~salt:6 ~count:300 "store_bytes matches a flat buffer" arb_offset_and_content
      store_bytes_matches_a_flat_buffer;
    mk ~salt:7 ~count:300 "MCOPY is memmove" arb_mcopy mcopy_is_memmove;
    mk ~salt:8 ~count:200 "MCOPY expansion is symmetric in dst and src" arb_mirror
      mcopy_expansion_is_symmetric;
    mk ~salt:9 ~count:300 "Data.read matches a naive padded reader" arb_data_read
      data_read_matches_the_naive_reader;
    mk ~salt:10 ~count:300 "Address_word clears exactly the top twelve bytes" arb_word
      address_word_masks;
    mk ~salt:11 ~count:300 "random bytecode reaches only a writable world"
      arb_host_code_and_gas random_code_is_sound;
    mk ~salt:12 ~count:300 "a reverting run makes nothing reachable" arb_unhalting_code
      revert_is_a_no_op;
    mk ~salt:13 ~count:300 "termination under SSTORE" arb_host_code_and_gas
      terminates_and_accounts;
  ]

(* ---------- 6. the hash, the logs and transient storage ---------- *)

(* KECCAK256 over 32 bytes of memory, with the total hand-computed.

   PUSH1 3, PUSH1 3, MSTORE 3 and the first word of memory 3 puts a known word at
   offset 0. Then PUSH1 3, PUSH1 3 for the length and offset, KECCAK256's static
   30, its 6 for the one word it absorbs, and no further expansion because the
   word is already paid for. The epilogue then re-stores and returns. *)
let test_keccak256_of_a_word () =
  let subject = hex "00000000000000000000000000000000000000000000000000000000000000ff" in
  let outcome =
    run
      (asm
         ([ push32 subject; push1 0x00; op Opcode.Mstore; push1 0x20; push1 0x00;
            op Opcode.Keccak256 ]
         @ return_top))
      allowance
  in
  Alcotest.(check string) "the hash of the stored word"
    (Keccak.to_hex (Keccak.digest (U256.to_be_bytes subject)))
    (U256.to_hex (get (U256.of_be_bytes (output_of outcome))));
  check_total "PUSH32 3, PUSH1 3, MSTORE 3, memory 3, PUSH1 6, KECCAK256 30, word 6, epilogue"
    (3 + 3 + 3 + 3 + 6 + 30 + 6 + return_top_cost_paid)
    outcome

(* The word rate is SIX and not the copy family's three. Two lengths whose word
   counts differ by one must differ by exactly six, and the absolute totals are
   asserted so that an implementation charging three fails both rather than
   neither. *)
let test_keccak256_word_rate () =
  let hash_of_length length =
    run
      (asm [ push1 length; push1 0x00; op Opcode.Keccak256; op Opcode.Pop; op Opcode.Stop ])
      allowance
  in
  let one_word = allowance - remaining_of (hash_of_length 0x20) in
  let two_words = allowance - remaining_of (hash_of_length 0x40) in
  (* PUSH1 3, PUSH1 3, KECCAK256 30, one word 6, memory for one word 3, POP 2. *)
  Alcotest.(check int) "one word costs 47" (3 + 3 + 30 + 6 + 3 + 2) one_word;
  (* The second word costs 6 to absorb and 3 more of curve. *)
  Alcotest.(check int) "two words cost 56" (3 + 3 + 30 + 12 + 6 + 2) two_words;
  Alcotest.(check int) "the marginal word is six plus three of curve" 9
    (two_words - one_word)

(* A zero-length hash pushes KECCAK_EMPTY, and does so without ever converting
   the offset: 2^255 is not a reachable memory offset, so an implementation that
   converted it first would report Offset_too_large. It also expands nothing,
   which the total pins by containing no memory term at all. *)
let test_keccak256_zero_length_ignores_the_offset () =
  let outcome =
    run
      (asm
         ([ push1 0x00; push32 (U256.two_pow 255); op Opcode.Keccak256 ] @ return_top))
      allowance
  in
  Alcotest.(check string) "the empty hash" (Keccak.to_hex Keccak.empty)
    (U256.to_hex (get (U256.of_be_bytes (output_of outcome))));
  check_total "PUSH1 3, PUSH32 3, KECCAK256 30, no words, no expansion, epilogue"
    (3 + 3 + 30 + return_top_cost)
    outcome

(* LOG1 over 32 bytes: 375 base, 375 for the one topic, 8 per byte for 32 bytes,
   plus the memory the window forces. The absolute total is what separates a
   correct implementation from one that prices topics or data at the wrong rate,
   since every wrong rate still produces a plausible-looking number. *)
let test_log1_price_and_journal () =
  let topic = u 0xbeef in
  let outcome =
    run
      (asm
         [ push32 (u 0x1234); push1 0x00; op Opcode.Mstore; push32 topic; push1 0x20;
           push1 0x00; op (Opcode.Log Topic_count.One); op Opcode.Stop ])
      allowance
  in
  check_total "PUSH32 3, PUSH1 3, MSTORE 3, memory 3, PUSH32 3, PUSH1 6, LOG1 375+375+256"
    (3 + 3 + 3 + 3 + 3 + 6 + 375 + 375 + (8 * 32))
    outcome;
  let entries = Log_journal.to_list (Effects.logs (effects_or_fail outcome)) in
  Alcotest.(check int) "one entry was journalled" 1 (List.length entries);
  let entry = List.hd entries in
  Alcotest.(check bool) "it names the executing account" true
    (Units.Address.equal (Log.address entry) self);
  Alcotest.(check (list string)) "it carries its one topic" [ U256.to_hex topic ]
    (List.map U256.to_hex (Log.Topics.to_list (Log.topics entry)));
  Alcotest.(check string) "and the memory window as data"
    (U256.to_be_bytes (u 0x1234))
    (Log.data entry)

(* The base price and the per-topic price are pinned SEPARATELY, at arities where
   they do not sum to the same number. At arity 1 a base of 400 and a topic of
   350 total 750 exactly as 375 and 375 do, so LOG1 alone cannot tell the split
   apart. LOG0 pins the base with no topic term at all, and LOG2 pins the topic
   given that base, so the two together fix both constants. *)
let test_log_price_by_arity () =
  let cost body = allowance - remaining_of (run (asm (body @ [ op Opcode.Stop ])) allowance) in
  (* LOG0, no data: PUSH1 3, PUSH1 3, base 375. *)
  Alcotest.(check int) "LOG0 is base alone" (3 + 3 + 375)
    (cost [ push1 0x00; push1 0x00; op (Opcode.Log Topic_count.Zero) ]);
  (* LOG2, no data: PUSH1 x4 12, base 375, two topics 750. *)
  Alcotest.(check int) "LOG2 is base plus two topics" (12 + 375 + 750)
    (cost
       [ push1 0x01; push1 0x02; push1 0x00; push1 0x00; op (Opcode.Log Topic_count.Two) ])

(* Each arity pops exactly its own topics, bounded from BOTH sides.

   Conjunct (a): with exactly 5 - n words left beneath, a following POP sequence
   of that length succeeds and one more underflows. Conjunct (a) alone would
   pass against a LOG3 that popped four topics and discarded one, which is why
   the underflow half is here: it pins that no EXTRA word was consumed, while
   the successful half pins that no word was left behind. *)
let test_log_arity_pops_exactly () =
  let markers = [ 0x11; 0x22; 0x33; 0x44 ] in
  let probe arity ~extra_pops =
    (* Four marker words, then the log's length and offset. The log consumes the
       offset, the length and n markers, leaving 4 - n markers. *)
    run
      (asm
         (List.map push1 markers
         @ [ push1 0x00; push1 0x00; op (Opcode.Log arity) ]
         @ List.init extra_pops (fun _ -> op Opcode.Pop)
         @ [ op Opcode.Stop ]))
      allowance
  in
  List.iter
    (fun arity ->
      let n = Topic_count.to_int arity in
      let label = Printf.sprintf "LOG%d" n in
      Alcotest.(check string)
        (label ^ " leaves exactly " ^ string_of_int (4 - n) ^ " words")
        "stopped"
        (error_of (probe arity ~extra_pops:(4 - n)));
      check_error (label ^ " left no more than that") Interpreter.Stack_underflow
        (probe arity ~extra_pops:(5 - n)))
    Topic_count.all

(* The topics are popped AFTER the gas charge and after the expansion, which is
   revm's order and is observable through WHICH error a doomed program reports.

   Both programs below would underflow if the topics were popped first. Neither
   does, because something else refuses earlier: the first cannot pay the
   1500-unit topic charge, and the second names an offset no memory can reach.
   An implementation that hoisted Topics.collect would report Stack_underflow
   for both, so this pair is the whole evidence for the ordering. *)
let test_log_topics_pop_after_the_charge () =
  check_error "the gas charge precedes the topic pops" Interpreter.Out_of_gas
    (Interpreter.run ~env:base_env
       ~code:(asm [ push1 0x00; push1 0x00; op (Opcode.Log Topic_count.Four) ])
       ~gas:(gas_of 500) ~effects:empty_effects);
  check_error "and so does the offset conversion" Interpreter.Offset_too_large
    (run
       (asm [ push1 0x20; push32 (U256.two_pow 255); op (Opcode.Log Topic_count.One) ])
       allowance)

(* A zero-length log at an unreachable offset is valid and expands nothing,
   exactly as a zero-length return is. *)
let test_log_zero_length_ignores_the_offset () =
  let outcome =
    run
      (asm
         [ push32 (u 0xaa); push1 0x00; push32 (U256.two_pow 255);
           op (Opcode.Log Topic_count.One); op Opcode.Stop ])
      allowance
  in
  check_total "PUSH32 3, PUSH1 3, PUSH32 3, LOG1 375+375, no data, no expansion"
    (3 + 3 + 3 + 375 + 375)
    outcome;
  let entry = List.hd (Log_journal.to_list (Effects.logs (effects_or_fail outcome))) in
  Alcotest.(check int) "the entry carries no data" 0 (String.length (Log.data entry))

(* The journal is a list and not a set: order and multiplicity both reach
   consensus through the receipt. Two identical logs are two entries.

   The emitted sequence must not be a palindrome, or "oldest first" and "newest
   first" agree and the assertion pins nothing. An earlier version of this case
   emitted 1, 2, 1 and a mutation dropping the reversal in {!Log_journal.to_list}
   survived it. The repeated 2 keeps the multiplicity half of the claim while
   1, 2, 2, 3 stays asymmetric. *)
let test_log_journal_is_ordered_and_counts () =
  let emit topic = [ push1 topic; push1 0x00; push1 0x00; op (Opcode.Log Topic_count.One) ] in
  let emitted = [ 0x01; 0x02; 0x02; 0x03 ] in
  let outcome =
    run (asm (List.concat_map emit emitted @ [ op Opcode.Stop ])) allowance
  in
  let topics_of entry = List.map U256.to_hex (Log.Topics.to_list (Log.topics entry)) in
  Alcotest.(check bool) "the fixture is asymmetric, so order is observable" false
    (List.equal Int.equal emitted (List.rev emitted));
  Alcotest.(check (list (list string))) "four entries, in emission order"
    (List.map (fun topic -> [ U256.to_hex (u topic) ]) emitted)
    (List.map topics_of (Log_journal.to_list (Effects.logs (effects_or_fail outcome))))

(* TSTORE then TLOAD round-trips, at a flat 100 each and with no cold surcharge
   on either: the second read of the same slot costs exactly what the first did,
   which is what "outside EIP-2929" means in gas terms. *)
let test_transient_round_trip () =
  let outcome =
    run
      (asm
         ([ push1 0x2a; push1 0x07; op Opcode.Tstore; push1 0x07; op Opcode.Tload;
            op Opcode.Pop; push1 0x07; op Opcode.Tload ]
         @ return_top))
      allowance
  in
  Alcotest.(check string) "the value written comes back"
    (U256.to_hex (u 0x2a))
    (U256.to_hex (get (U256.of_be_bytes (output_of outcome))));
  check_total "PUSH1 x4 12, TSTORE 100, TLOAD 100, POP 2, TLOAD 100, epilogue"
    (3 + 3 + 100 + 3 + 100 + 2 + 3 + 100 + return_top_cost)
    outcome;
  (* Observed through the OUTCOME's effects at a specific address, not just
     through the program's own TLOAD. The program round-trips whichever account
     the interpreter keys by, so it cannot see whether that account is the
     executing one or the caller; only an Effects read at a named address can.
     [self] and [caller] are distinct fixtures, so routing the key through the
     caller — the cross-contract transient leak CALL would expose — flips this. *)
  let effects = effects_or_fail outcome in
  Alcotest.(check string) "the write lands under the executing account"
    (U256.to_hex (u 0x2a))
    (U256.to_hex (Effects.transient_load effects self ~slot:(u 7)));
  Alcotest.(check bool) "and not under the caller"
    true
    (U256.is_zero (Effects.transient_load effects caller ~slot:(u 7)))

(* An unwritten transient slot reads zero, and a slot written zero is
   indistinguishable from one never written — EIP-1153 offers no way to tell
   them apart, so the representation must not either. *)
let test_transient_zero_is_canonical () =
  let effects =
    Effects.transient_store empty_effects (get_permit Mutability.Mutable) self ~slot:(u 7)
      ~value:U256.zero
  in
  Alcotest.(check bool) "a zero write leaves no binding" true
    (Transient.is_empty (Effects.transient effects));
  Alcotest.(check int) "and nothing to enumerate" 0
    (Transient.length (Effects.transient effects));
  Alcotest.(check bool) "an unwritten slot reads zero" true
    (U256.is_zero (Effects.transient_load empty_effects self ~slot:(u 7)))

(* Transient storage is keyed by the PAIR. A write under one account is
   invisible to another at the same slot number, which is the cross-contract
   leak the day CALL lands. *)
let test_transient_is_keyed_by_the_pair () =
  let permit = get_permit Mutability.Mutable in
  (* Both halves of the key are exercised symmetrically: the same slot under a
     different account, and a different slot under the same account. Varying only
     the address would pass against a key that dropped the slot component (every
     slot of a contract aliasing to one cell), which is exactly the collapse a
     mutation of the comparator produces. *)
  let effects =
    Effects.transient_store
      (Effects.transient_store empty_effects permit self ~slot:(u 7) ~value:(u 99))
      permit self ~slot:(u 8) ~value:(u 42)
  in
  Alcotest.(check string) "slot 7 under self reads its own value" (U256.to_hex (u 99))
    (U256.to_hex (Effects.transient_load effects self ~slot:(u 7)));
  Alcotest.(check string) "slot 8 under self reads independently" (U256.to_hex (u 42))
    (U256.to_hex (Effects.transient_load effects self ~slot:(u 8)));
  Alcotest.(check bool) "another account at slot 7 does not see it" true
    (U256.is_zero (Effects.transient_load effects other ~slot:(u 7)));
  Alcotest.(check int) "two distinct slots are two bindings" 2
    (Transient.length (Effects.transient effects));
  Alcotest.(check bool) "every binding is nonzero" true
    (List.for_all
       (fun (_address, _slot, value) -> not (U256.is_zero value))
       (Transient.bindings (Effects.transient effects)))

(* A transient write cannot reach the persistent world. This is layering rather
   than behaviour — World_state cannot see Transient — but the run is worth
   asserting because it is the claim a reader wants checked. *)
let test_transient_does_not_touch_the_world () =
  let outcome =
    run (asm [ push1 0x2a; push1 0x07; op Opcode.Tstore; op Opcode.Stop ]) allowance
  in
  Alcotest.(check bool) "the world is untouched" true
    (World_state.equal World_state.empty (Effects.world (effects_or_fail outcome)))

(* The static cross product: every substate write refuses in a static frame and
   succeeds in a mutable one. The mutable column is not decoration — it is what
   proves the static column is failing for the right reason rather than because
   the programs are broken. *)
let test_static_frame_refuses_every_write () =
  let programs =
    [ ("SSTORE", [ push1 0x01; push1 0x07; op Opcode.Sstore ]);
      ("TSTORE", [ push1 0x01; push1 0x07; op Opcode.Tstore ]);
      ("LOG0", [ push1 0x00; push1 0x00; op (Opcode.Log Topic_count.Zero) ]);
      ("LOG1", [ push1 0x01; push1 0x00; push1 0x00; op (Opcode.Log Topic_count.One) ]);
      ("LOG4",
       [ push1 0x01; push1 0x02; push1 0x03; push1 0x04; push1 0x00; push1 0x00;
         op (Opcode.Log Topic_count.Four) ]) ]
  in
  List.iter
    (fun (label, body) ->
      let code = asm (body @ [ op Opcode.Stop ]) in
      check_error (label ^ " is refused in a static frame") Interpreter.Static_state_change
        (run ~env:static_env code allowance);
      Alcotest.(check string) (label ^ " succeeds in a mutable one") "stopped"
        (error_of (run ~env:base_env code allowance)))
    programs

(* The guard is FIRST: it precedes the pops and it precedes the charge. A static
   frame with an empty stack reports the static violation rather than the
   underflow it would report if the operands were taken first, and a static
   frame that could not pay reports it rather than running out of gas. *)
let test_static_guard_precedes_everything () =
  (* The fixture really is a static frame, read through the accessor rather than
     assumed, and a mutable one really is not. This also exercises
     {!Mutability.is_static}, whose only caller is here. *)
  Alcotest.(check bool) "the static fixture is static" true
    (Mutability.is_static (Env.Call.mutability (Env.call static_env)));
  Alcotest.(check bool) "the base fixture is not" false
    (Mutability.is_static (Env.Call.mutability (Env.call base_env)));
  check_error "the guard precedes the pops" Interpreter.Static_state_change
    (run ~env:static_env (asm [ op Opcode.Sstore ]) allowance);
  (* TSTORE separately, because its guard sits after a hardfork check in revm and
     is the one whose reordering no other case here would catch. *)
  check_error "for TSTORE, on an empty stack" Interpreter.Static_state_change
    (run ~env:static_env (asm [ op Opcode.Tstore ]) allowance);
  check_error "for a log too" Interpreter.Static_state_change
    (run ~env:static_env (asm [ op (Opcode.Log Topic_count.Four) ]) allowance);
  check_error "and it precedes the charge" Interpreter.Static_state_change
    (Interpreter.run ~env:static_env
       ~code:(asm [ push1 0x00; push1 0x00; op (Opcode.Log Topic_count.Four) ])
       ~gas:(gas_of 500) ~effects:empty_effects)

(* A revert discards the logs and the transient writes with no code to do it,
   because both ride inside the Effects.t that Reverted structurally does not
   carry. Asserted through the OUTCOME, for the reason {!reachable_effects}
   documents: inspecting the value passed in would be true by the type of run. *)
let test_revert_discards_logs_and_transient () =
  let body =
    [ push1 0x2a; push1 0x07; op Opcode.Tstore; push1 0x01; push1 0x00; push1 0x00;
      op (Opcode.Log Topic_count.One) ]
  in
  let reverted = run (asm (body @ [ push1 0x00; push1 0x00; op Opcode.Revert ])) allowance in
  let stopped = run (asm (body @ [ op Opcode.Stop ])) allowance in
  Alcotest.(check bool) "the reverting run reaches no effects at all" true
    (Option.is_none (reachable_effects reverted));
  Alcotest.(check bool) "the reverting run did not report success" false
    (halted_successfully reverted);
  (* And the same body without the REVERT really did produce both, so the
     assertion above is about the revert and not about an inert program. *)
  let effects = effects_or_fail stopped in
  Alcotest.(check int) "the stopping run journalled its log" 1
    (Log_journal.length (Effects.logs effects));
  Alcotest.(check int) "and kept its transient write" 1
    (Transient.length (Effects.transient effects))

(* Topic_count and Log.Topics are two five-way sums that could drift apart. The
   round trip over every arity is the only thing holding them together.

   The pop source yields 0, 1, 2, 3 in pop order, and the payload is asserted as
   a whole rather than by length, so the ORDER is pinned and not just the count:
   [collect]'s docstring promises "first pop first, which is topic order", and
   reversing any of the T2/T3/T4 arms would produce 3, 2, 1, 0 here. A reversed
   order is a wrong receipt and a wrong logs bloom, and a length check is blind
   to it. *)
let test_topic_arity_round_trip () =
  List.iter
    (fun arity ->
      let n = Topic_count.to_int arity in
      let collected = Log.Topics.collect arity ~pop:(fun k -> Ok (u k, k + 1)) 0 in
      match collected with
      | Error _ -> Alcotest.fail "collecting from an infinite source cannot fail"
      | Ok (topics, consumed) ->
          Alcotest.(check int) (Printf.sprintf "LOG%d pops its own count" n) n consumed;
          Alcotest.(check int) "and the shape reports the same arity" n
            (Topic_count.to_int (Log.Topics.arity topics));
          Alcotest.(check (list string)) "the topics come back in pop order, first pop first"
            (List.init n (fun i -> U256.to_hex (u i)))
            (List.map U256.to_hex (Log.Topics.to_list topics)))
    Topic_count.all

(* An end-to-end LOG4 with four pairwise-distinct, non-palindromic topics, so the
   journalled entry witnesses the order through the whole interpreter rather than
   through {!Log.Topics.collect} in isolation. Pushed 0x44, 0x33, 0x22, 0x11, so
   the last pushed (0x11) is the top of stack and must come back as topic0. *)
let test_log4_topic_order_end_to_end () =
  let outcome =
    run
      (asm
         [ push1 0x44; push1 0x33; push1 0x22; push1 0x11; push1 0x00; push1 0x00;
           op (Opcode.Log Topic_count.Four); op Opcode.Stop ])
      allowance
  in
  let entry = List.hd (Log_journal.to_list (Effects.logs (effects_or_fail outcome))) in
  Alcotest.(check (list string)) "topic0 is the top of stack"
    (List.map U256.to_hex [ u 0x11; u 0x22; u 0x33; u 0x44 ])
    (List.map U256.to_hex (Log.Topics.to_list (Log.topics entry)))

(* Log_journal.equal, and through it Log.equal and Topics.equal, are load-bearing
   because {!Effects.equal} folds the journal in and the revert and frame-boundary
   properties compare whole effects. A length-only journal equality would satisfy
   every one of those while an entry's address, topics or data was corrupted, so
   the chain is pinned directly here. *)
let test_log_journal_equality () =
  let entry topic = Log.make ~address:self ~topics:(Log.Topics.T1 (u topic)) ~data:"" in
  let ab = Log_journal.append (Log_journal.append Log_journal.empty (entry 1)) (entry 2) in
  let ba = Log_journal.append (Log_journal.append Log_journal.empty (entry 2)) (entry 1) in
  let ab' = Log_journal.append (Log_journal.append Log_journal.empty (entry 1)) (entry 2) in
  let one_topic_off =
    Log_journal.append (Log_journal.append Log_journal.empty (entry 1)) (entry 3)
  in
  Alcotest.(check bool) "same entries, opposite order, are unequal" false (Log_journal.equal ab ba);
  Alcotest.(check bool) "a single differing topic is unequal" false
    (Log_journal.equal ab one_topic_off);
  Alcotest.(check bool) "identical journals are equal" true (Log_journal.equal ab ab');
  Alcotest.(check bool) "differing lengths are unequal" false
    (Log_journal.equal ab (Log_journal.append ab (entry 9)))

(* The five LOG bytes decode to the five arities and back. *)
let test_log_opcode_round_trip () =
  List.iter
    (fun arity ->
      let byte_value = Opcode.to_byte (Opcode.Log arity) in
      Alcotest.(check int)
        (Printf.sprintf "LOG%d is 0xa%d" (Topic_count.to_int arity)
           (Topic_count.to_int arity))
        (0xa0 + Topic_count.to_int arity)
        byte_value;
      Alcotest.(check bool) "and decodes back to itself" true
        (match Opcode.decode byte_value with
        | Some (Opcode.Log decoded) -> Topic_count.equal decoded arity
        | Some _ | None -> false))
    Topic_count.all;
  Alcotest.(check bool) "0xa5 is not a log" true
    (Option.is_none (Opcode.decode 0xa5))

let () =
  Alcotest.run "tn_evm_host_seam"
    [
      ( "storage",
        [
          Alcotest.test_case "the canonical zero" `Quick test_storage_canonical_zero;
        ] );
      ( "pruning",
        [
          Alcotest.test_case "a write into an empty account survives" `Quick test_pruning_hazard;
          Alcotest.test_case "removing an account drops its storage too" `Quick
            test_remove_account_drops_both_halves;
        ] );
      ( "access",
        [
          Alcotest.test_case "cold once, warm after" `Quick test_access_warmth;
          Alcotest.test_case "SELFBALANCE marks the account warm" `Quick
            test_selfbalance_warms_the_account;
          Alcotest.test_case "a declared access list warms what it names" `Quick
            test_declared_access_list;
        ] );
      ( "programs",
        [
          Alcotest.test_case "the fourteen flat context opcodes" `Quick
            test_flat_context_opcodes;
          Alcotest.test_case "SLOAD cold and warm" `Quick test_sload_cold_and_warm;
          Alcotest.test_case "SLOAD reads the world" `Quick test_sload_reads_the_world;
          Alcotest.test_case "BALANCE cold and warm" `Quick test_balance_cold_and_warm;
          Alcotest.test_case "SELFBALANCE then BALANCE" `Quick test_selfbalance_then_balance;
          Alcotest.test_case "CALLDATACOPY" `Quick test_calldatacopy;
          Alcotest.test_case "CODECOPY" `Quick test_codecopy;
          Alcotest.test_case "CALLDATALOAD past the end" `Quick test_calldataload_past_the_end;
          Alcotest.test_case "MCOPY moves bytes" `Quick test_mcopy_moves_bytes;
        ] );
      ( "sstore matrix",
        [
          Alcotest.test_case "a fresh set" `Quick test_sstore_fresh_set;
          Alcotest.test_case "a fresh reset" `Quick test_sstore_fresh_reset;
          Alcotest.test_case "a no-op" `Quick test_sstore_no_op;
          Alcotest.test_case "a dirty slot" `Quick test_sstore_dirty;
          Alcotest.test_case "the negative refund" `Quick test_sstore_negative_refund;
          Alcotest.test_case "2000, 2100 and 2500 are three constants" `Quick
            test_sstore_constants_are_not_shared;
          Alcotest.test_case "the whole table against the revm oracle" `Quick
            test_sstore_against_the_oracle;
        ] );
      ( "orderings",
        [
          Alcotest.test_case "the EIP-2200 sentry at 2300 and 2301" `Quick
            test_reentrancy_sentry_boundary;
          Alcotest.test_case "the pop precedes the sentry" `Quick test_pop_precedes_the_sentry;
          Alcotest.test_case "a zero-length copy at a wild destination" `Quick
            test_zero_length_copy_at_a_wild_destination;
          Alcotest.test_case "MCOPY expands at max(dst, src)" `Quick
            test_mcopy_expands_at_the_maximum;
          Alcotest.test_case "a revert discards everything" `Quick test_revert_discards_everything;
          Alcotest.test_case "an SSTORE loop terminates" `Quick test_sstore_termination_under_a_loop;
        ] );
      ( "keccak256",
        [
          Alcotest.test_case "the hash of a stored word" `Quick test_keccak256_of_a_word;
          Alcotest.test_case "six per word, not three" `Quick test_keccak256_word_rate;
          Alcotest.test_case "a zero length ignores the offset" `Quick
            test_keccak256_zero_length_ignores_the_offset;
        ] );
      ( "logs",
        [
          Alcotest.test_case "LOG1 prices and journals" `Quick test_log1_price_and_journal;
          Alcotest.test_case "base and per-topic are pinned separately" `Quick
            test_log_price_by_arity;
          Alcotest.test_case "each arity pops exactly its topics" `Quick
            test_log_arity_pops_exactly;
          Alcotest.test_case "the topics pop after the charge" `Quick
            test_log_topics_pop_after_the_charge;
          Alcotest.test_case "a zero length ignores the offset" `Quick
            test_log_zero_length_ignores_the_offset;
          Alcotest.test_case "the journal is ordered and counts" `Quick
            test_log_journal_is_ordered_and_counts;
          Alcotest.test_case "the arities round-trip in topic order" `Quick
            test_topic_arity_round_trip;
          Alcotest.test_case "LOG4 topic order end to end" `Quick
            test_log4_topic_order_end_to_end;
          Alcotest.test_case "the journal equality is order and content sensitive" `Quick
            test_log_journal_equality;
          Alcotest.test_case "the five bytes round-trip" `Quick test_log_opcode_round_trip;
        ] );
      ( "transient storage",
        [
          Alcotest.test_case "TSTORE then TLOAD" `Quick test_transient_round_trip;
          Alcotest.test_case "a zero write is canonical" `Quick
            test_transient_zero_is_canonical;
          Alcotest.test_case "keyed by the pair" `Quick test_transient_is_keyed_by_the_pair;
          Alcotest.test_case "it never reaches the world" `Quick
            test_transient_does_not_touch_the_world;
        ] );
      ( "static frames",
        [
          Alcotest.test_case "every write is refused" `Quick
            test_static_frame_refuses_every_write;
          Alcotest.test_case "the guard is first" `Quick test_static_guard_precedes_everything;
          Alcotest.test_case "a revert discards logs and transient writes" `Quick
            test_revert_discards_logs_and_transient;
        ] );
      ("properties", prop_cases);
    ]
