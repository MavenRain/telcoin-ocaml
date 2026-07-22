module W = Tn_state.U256
module Address_word = Tn_state.Address_word
module Account = Tn_state.Account

type error =
  | Out_of_gas
  | Stack_underflow
  | Stack_overflow
  | Invalid_jump
  | Invalid_opcode of int
  | Offset_too_large
  | Reentrancy_sentry
  | Static_state_change
  | Out_of_offset
  | Call_not_allowed_inside_static
  | Initcode_too_large
  | Balance_overflow

let error_to_string = function
  | Out_of_gas -> "out of gas"
  | Stack_underflow -> "stack underflow"
  | Stack_overflow -> "stack overflow"
  | Invalid_jump -> "invalid jump destination"
  | Invalid_opcode byte -> Printf.sprintf "invalid opcode 0x%02x" byte
  | Offset_too_large -> "memory offset or length too large"
  | Reentrancy_sentry -> "storage write refused on a call stipend"
  | Static_state_change -> "state change in a static frame"
  | Out_of_offset -> "return-data read past the end of the buffer"
  | Call_not_allowed_inside_static -> "value-bearing call from a static frame"
  | Initcode_too_large -> "init code longer than the EIP-3860 limit"
  | Balance_overflow -> "balance overflow past 2^256"

type outcome =
  | Stopped of { gas_left : Gas.t; effects : Effects.t }
  | Returned of { output : string; gas_left : Gas.t; effects : Effects.t }
  | Reverted of { output : string; gas_left : Gas.t }
  | Failed of error

let outcome_to_string = function
  | Stopped { gas_left; effects = _ } ->
      Printf.sprintf "stopped, gas left %d" (Gas.remaining gas_left)
  | Returned { output; gas_left; effects = _ } ->
      Printf.sprintf "returned %d bytes, gas left %d" (String.length output)
        (Gas.remaining gas_left)
  | Reverted { output; gas_left } ->
      Printf.sprintf "reverted with %d bytes, gas left %d" (String.length output)
        (Gas.remaining gas_left)
  | Failed error -> Printf.sprintf "failed: %s" (error_to_string error)

(* The frame's whole state: where execution is, the three resources it spends,
   and what it has done outside itself so far. [Env.t] is deliberately not here —
   it is fixed for the whole run, so it travels beside the machine as an argument
   exactly as [Code.t] does, and an instruction body structurally cannot alter
   it. *)
type machine = {
  pc : int;
  stack : Stack.t;
  memory : Memory.t;
  gas : Gas.t;
  effects : Effects.t;
  (* The buffer the most recent sub-call returned. Like [memory] it evolves step
     to step — every call replaces it and [RETURNDATASIZE]/[RETURNDATACOPY] read
     it — so it lives here rather than beside the machine as [Env]/[Code] do. A
     fresh frame starts with it empty. *)
  return_data : Return_data.t;
}

(* One step either produces the next state or ends the run. *)
type transition = Continue of machine | Halt of outcome

let word_bytes = String.length (W.to_be_bytes W.zero)

(* A native count as a word. Every count converted here — a program counter, a
   memory size, a remaining allowance — is non-negative, so the conversion always
   succeeds and the default is unreachable. *)
let word_of_int n = Option.value ~default:W.zero (W.of_int n)

(* The least significant byte of a word, which is all [MSTORE8] keeps. The index
   is read from the representation rather than written as a literal. *)
let low_byte w =
  let source = W.to_be_bytes w in
  Char.code (String.get source (String.length source - 1))

let stack_error = function
  | Stack.Underflow -> Stack_underflow
  | Stack.Overflow -> Stack_overflow

let stack_result r = Result.map_error stack_error r

(* A memory offset or length as a native count. A word too large to be one names
   memory no allowance could pay to reach. *)
let extent_of_word w =
  Option.fold ~none:(Error Offset_too_large) ~some:(fun n -> Ok n) (W.to_int w)

(* A word as a native offset that {e saturates} rather than failing: a word past
   [max_int] becomes [max_int]. This is revm's [as_usize_saturated!]
   ([instructions/system.rs:199]), the rule the {e source} offset of
   [RETURNDATACOPY] obeys — an enormous source offset is not an error, it simply
   places the read past the buffer and the strict bounds check refuses it there.
   The destination offset and the length, by contrast, go through
   {!extent_of_word} and can halt. *)
let saturating_int w = Option.value ~default:max_int (W.to_int w)

(* Instruction bodies below work in [(machine, error) result]; this projects that
   into a transition. *)
let transition = Result.fold ~ok:(fun m -> Continue m) ~error:(fun e -> Halt (Failed e))

(* Charge for reaching [offset .. offset + length) and expand to cover it. The
   frame pays only for the words it has not already paid for, so this is the
   difference between the two totals; a zero length reaches nothing and costs
   nothing. *)
let reach m ~offset ~length =
  Option.fold ~none:(Error Offset_too_large)
    ~some:(fun needed ->
      Option.fold ~none:(Error Out_of_gas)
        ~some:(fun cost ->
          Option.fold ~none:(Error Out_of_gas)
            ~some:(fun gas -> Ok (Memory.expand m.memory needed, gas))
            (Gas.charge cost m.gas))
        (Gas.expansion_cost ~current:(Memory.words m.memory) ~next:needed))
    (Memory.words_needed ~offset ~length)

(* The stack-only instructions. Operand order follows the opcode: the word popped
   first is the first argument, which is the order {!Alu} takes them in. *)
let stack_step m result =
  transition (Result.map (fun stack -> { m with stack; pc = m.pc + 1 }) result)

let unary f m =
  stack_step m
    (stack_result (Result.bind (Stack.pop m.stack) (fun (a, s) -> Stack.push (f a) s)))

let binary f m =
  stack_step m
    (stack_result
       (Result.bind (Stack.pop2 m.stack) (fun (a, b, s) -> Stack.push (f a b) s)))

let ternary f m =
  stack_step m
    (stack_result
       (Result.bind (Stack.pop3 m.stack) (fun (a, b, c, s) ->
            Stack.push (f a b c) s)))

let push_value w m = stack_step m (stack_result (Stack.push w m.stack))
let discard m = stack_step m (stack_result (Result.map snd (Stack.pop m.stack)))

let with_stack f m = stack_step m (stack_result (f m.stack))

(* [EXP] is the one arithmetic instruction with a price beyond its fixed one: it
   pays per byte of its exponent, charged once the exponent is on hand. *)
let exponentiate m =
  transition
    (Result.bind (stack_result (Stack.pop2 m.stack)) (fun (base, exponent, stack) ->
         Option.fold ~none:(Error Out_of_gas)
           ~some:(fun gas ->
             Result.map
               (fun stack -> { m with stack; gas; pc = m.pc + 1 })
               (stack_result (Stack.push (Alu.exp base exponent) stack)))
           (Gas.charge (Gas.exp_cost exponent) m.gas)))

let mload m =
  transition
    (Result.bind (stack_result (Stack.pop m.stack)) (fun (offset_word, stack) ->
         Result.bind (extent_of_word offset_word) (fun offset ->
             Result.bind (reach m ~offset ~length:word_bytes)
               (fun (memory, gas) ->
                 Result.map
                   (fun stack -> { m with pc = m.pc + 1; stack; memory; gas })
                   (stack_result
                      (Stack.push (Memory.load_word memory offset) stack))))))

(* [MSTORE] and [MSTORE8] differ only in how much they reach and what they write,
   so they share everything else. *)
let mstore ~length ~write m =
  transition
    (Result.bind (stack_result (Stack.pop2 m.stack))
       (fun (offset_word, value, stack) ->
         Result.bind (extent_of_word offset_word) (fun offset ->
             Result.map
               (fun (memory, gas) ->
                 {
                   m with
                   pc = m.pc + 1;
                   stack;
                   memory = write memory offset value;
                   gas;
                 })
               (reach m ~offset ~length))))

(* A jump lands only on a [JUMPDEST] instruction. A destination too large to be
   an offset cannot be one, so it fails the same way rather than as an arithmetic
   error — which is also how revm reports it. *)
let jump_to code m destination =
  Option.fold ~none:(Halt (Failed Invalid_jump))
    ~some:(fun offset ->
      if Code.is_valid_jumpdest code offset then Continue { m with pc = offset }
      else Halt (Failed Invalid_jump))
    (W.to_int destination)

let jump code m =
  Result.fold
    ~ok:(fun (destination, stack) -> jump_to code { m with stack } destination)
    ~error:(fun e -> Halt (Failed e))
    (stack_result (Stack.pop m.stack))

(* [JUMPI] takes the branch on any nonzero condition, not only on one. A
   condition of zero consumes both operands and falls through without looking at
   the destination at all — so an invalid destination that is never jumped to is
   not an error. *)
let jumpi code m =
  Result.fold
    ~ok:(fun (destination, condition, stack) ->
      let m = { m with stack } in
      if W.is_zero condition then Continue { m with pc = m.pc + 1 }
      else jump_to code m destination)
    ~error:(fun e -> Halt (Failed e))
    (stack_result (Stack.pop2 m.stack))

(* The immediate of a [PUSH] is the bytes following the opcode, right-aligned in
   the word. Reading past the end of the code yields zeros, so an immediate the
   code cuts short is zero-extended — the behaviour revm gets by padding the
   code itself. *)
let push_immediate code width m =
  let immediate =
    String.init width (fun i -> Char.chr (Code.byte_at code (m.pc + 1 + i)))
  in
  let value =
    Option.value ~default:W.zero
      (W.of_be_bytes (String.make (word_bytes - width) '\000' ^ immediate))
  in
  transition
    (Result.map
       (fun stack -> { m with stack; pc = m.pc + 1 + width })
       (stack_result (Stack.push value m.stack)))

let charged cost gas =
  Option.fold ~none:(Error Out_of_gas) ~some:(fun gas -> Ok gas) (Gas.charge cost gas)

(* Read the window [offset .. offset + length) as bytes, in the exact order revm
   reads one. Four instructions want it: [RETURN] and [REVERT] hand it back,
   [KECCAK256] hashes it and [LOG] journals it, and all four are written from
   this one function so the order below is one fact rather than four copies.

   The order is the whole content, and every step of it is observable through
   which error a failing program reports:

   1. Convert the LENGTH. A length no native integer can hold is
      [Offset_too_large] before anything is charged or read.
   2. Charge [price] — the caller's dynamic half, which is nothing for a return,
      six per word for a hash and 375-per-topic-plus-8-per-byte for a log. This
      happens BEFORE the zero-length branch and before any expansion, so a frame
      that cannot afford the dynamic price reports [Out_of_gas] having never
      looked at the offset.
   3. Zero length short-circuits with the empty string. The offset is NEVER
      converted and memory is NOT expanded, so an enormous offset with a zero
      length succeeds. This is not a convenience: revm's [len == 0] arm returns
      before its [as_usize_or_fail!] on the offset, so a program that returns
      zero bytes from [2^255] is valid there and must be valid here.
   4. Only then convert the offset and pay the expansion.

   Note what is deliberately NOT here: popping the operands. [KECCAK256] takes
   its two from the stack while [LOG] takes two and then more afterwards, and
   folding the pops in would have forced a shape that could not express the
   second. *)
let reach_data m ~offset_word ~length_word ~price =
  Result.bind (extent_of_word length_word) (fun length ->
      Result.bind (price length m.gas) (fun gas ->
          if length = 0 then Ok ("", m.memory, gas)
          else
            Result.bind (extent_of_word offset_word) (fun offset ->
                Result.map
                  (fun (memory, gas) ->
                    (Memory.slice memory ~offset ~length, memory, gas))
                  (reach { m with gas } ~offset ~length))))

(* A return or a revert is that window with no dynamic price of its own, handed
   to the outcome constructor. *)
let halt_with_output build m =
  Result.fold ~ok:Fun.id ~error:(fun e -> Halt (Failed e))
    (Result.bind (stack_result (Stack.pop2 m.stack))
       (fun (offset_word, length_word, _stack) ->
         Result.map
           (fun (output, _memory, gas) -> Halt (build output gas))
           (reach_data m ~offset_word ~length_word ~price:(fun _length gas -> Ok gas))))

(* ---------- the context instructions ---------- *)

(* The fourteen 2-gas context opcodes differ only in which field of the
   environment they name, so each is one projection. Nothing here can fail: the
   value is already a word or becomes one totally, and the only error a push can
   raise is the overflow [push_value] already reports. *)
let env_word project env m = push_value (project env) m

(* ---------- the copy family ---------- *)

(* What the shared prologue of [CALLDATACOPY], [CODECOPY] and [MCOPY] decided.
   revm's [copy_cost_and_memory_resize] returns an [Option<usize>] whose [None]
   means {e either} "zero length, nothing to do" ([instructions/system.rs:258-260])
   {e or} "out of gas, the interpreter is already halted" (the [gas!] at [:257]).
   Its callers cannot tell the two apart and do not need to, because both lead to
   a bare [return] out of a function that has already recorded the halt. Here one
   continues and the other halts, so mirroring the option would be a real bug —
   an unaffordable copy would fall through as a successful no-op. Hence three
   cases and not two.

   [Copy_to] carries the operands the prologue popped as well as the destination
   it converted, because the tail of each instruction needs them and the prologue
   is the only thing that has them. *)
type copy_plan =
  | Copy_nothing of machine
      (* Zero length. The per-word cost (zero words, zero gas) has been charged,
         the destination offset was NEVER converted, and memory is NOT expanded —
         so an enormous destination with zero length succeeds. That is the same
         rule [Memory.words_needed] already states for RETURN and REVERT, and the
         rule revm reaches by returning before the [as_usize_or_fail] on the
         memory offset ([instructions/system.rs:258-261]). *)
  | Copy_to of { machine : machine; dest : int; source : W.t; length : int }
  | Copy_failed of error

(* Steps 1 to 5 of the order fixed by [instructions/system.rs:83,164,250-265] and
   [instructions/memory.rs:57-81], shared by all three instructions:

   1. pop the three operands — destination, source, length, in that order for
      every member of the family;
   2. length word to a native count, else [Offset_too_large];
   3. charge [Gas.copy_cost], BEFORE any offset conversion and before expansion,
      so that a barely affordable copy reports out of gas and not a bad offset;
   4. a zero length returns here, without converting the destination;
   5. destination word to a native count, else [Offset_too_large].

   The source offset is left a word on purpose. It saturates rather than failing
   ([system.rs:92,174]), so an out-of-range source reads zeros and is not an
   error — the opposite of the rule the destination obeys one line above. *)
let plan_copy m =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Copy_failed e)
    (Result.bind (stack_result (Stack.pop3 m.stack))
       (fun (dest_word, source, length_word, stack) ->
         Result.bind (extent_of_word length_word) (fun length ->
             Option.fold ~none:(Error Out_of_gas)
               ~some:(fun gas ->
                 let charged = { m with stack; gas } in
                 if length = 0 then Ok (Copy_nothing charged)
                 else
                   Result.map
                     (fun dest -> Copy_to { machine = charged; dest; source; length })
                     (extent_of_word dest_word))
               (Gas.charge (Gas.copy_cost length) m.gas))))

(* Steps 7 and 8: pay to reach [reach_at .. reach_at + length) and write. [bytes]
   is handed the {e expanded} memory, which matters only for [MCOPY], whose
   source may lie in the words this expansion just created. *)
let finish_copy machine ~dest ~length ~reach_at ~bytes =
  transition
    (Result.map
       (fun (memory, gas) ->
         {
           machine with
           pc = machine.pc + 1;
           memory = Memory.store_bytes memory ~offset:dest (bytes memory);
           gas;
         })
       (reach machine ~offset:reach_at ~length))

(* [CALLDATACOPY] and [CODECOPY]: the source is a {!Data.t} read at a saturating
   word offset, and the expansion is paid at the destination alone
   ([system.rs:262]). *)
let copy_from_data data m =
  match plan_copy m with
  | Copy_failed error -> Halt (Failed error)
  | Copy_nothing machine -> Continue { machine with pc = machine.pc + 1 }
  | Copy_to { machine; dest; source; length } ->
      finish_copy machine ~dest ~length ~reach_at:dest ~bytes:(fun _memory ->
          Data.read data ~offset:source ~length)

(* [MCOPY]. Two things separate it from the pair above. Its source offset is a
   memory offset, so it {e is} converted and can fail — after the destination
   ([memory.rs:71-72]) and so only once the destination has already been ruled
   good. And it expands to cover [max dst src], not [dst] ([memory.rs:74-79]):
   the source it reads must exist, and a copy whose source lies beyond the
   current end of memory is reading zeros the frame has to pay for. Expanding at
   [dst] alone passes every gas test built from a single [MCOPY] and undercharges
   exactly when [src > dst]. *)
let mcopy m =
  match plan_copy m with
  | Copy_failed error -> Halt (Failed error)
  | Copy_nothing machine -> Continue { machine with pc = machine.pc + 1 }
  | Copy_to { machine; dest; source; length } ->
      Result.fold
        ~error:(fun e -> Halt (Failed e))
        ~ok:(fun src ->
          finish_copy machine ~dest ~length
            ~reach_at:(Int.max dest src)
            ~bytes:(fun memory -> Memory.slice memory ~offset:src ~length))
        (extent_of_word source)

(* ---------- the world instructions ---------- *)

(* The account whose code is running: the storage [SLOAD] and [SSTORE] address
   and the balance [SELFBALANCE] reads. There is no delegatecall yet, so the
   code address and the storage address are the same account and this is the
   only place either is named. *)
let executing env = Env.Call.target (Env.call env)

(* [BALANCE] and [SLOAD] have one shape: look the value up, charge the EIP-2929
   surcharge that same lookup's warmth prices, then push. The charge is not
   optional and cannot be skipped by accident here, but it could be by omission —
   an arm that pushes [Effects.loaded] without charging compiles cleanly and
   undercharges by 2000 on every cold [SLOAD], which is why the tests assert
   absolute costs and not differences. *)
let load_and_charge ~surcharge ~load m =
  Option.fold ~none:(Error Out_of_gas)
    ~some:(fun gas ->
      Result.map
        (fun stack ->
          { m with pc = m.pc + 1; stack; gas; effects = Effects.warmed load })
        (stack_result (Stack.push (Effects.loaded load) m.stack)))
    (Gas.charge (surcharge (Effects.warmth load)) m.gas)

(* The address is the low twenty bytes of the popped word and the top twelve are
   discarded, not rejected — [Address::from_word] truncates, and an [option] here
   would halt valid mainnet transactions. See {!Address_word}. Note this takes no
   environment: [BALANCE] names its account, unlike [SELFBALANCE]. *)
let balance m =
  transition
    (Result.bind (stack_result (Stack.pop m.stack)) (fun (word, stack) ->
         load_and_charge ~surcharge:Gas.account_access_cost
           ~load:(Effects.balance m.effects (Address_word.of_word word))
           { m with stack }))

let sload env m =
  transition
    (Result.bind (stack_result (Stack.pop m.stack)) (fun (slot, stack) ->
         load_and_charge ~surcharge:Gas.storage_access_cost
           ~load:(Effects.storage m.effects (executing env) ~slot)
           { m with stack }))

(* [SELFBALANCE] pays its flat 5 in the dispatch loop and nothing else, ever. It
   nevertheless {e warms} the account, because revm reaches the value through
   [Host::balance], whose default implementation loads through the journal and
   whose [is_cold] the instruction discards ([instructions/host.rs:42-48] →
   [revm-context-interface] [host.rs:140-144]). {!Effects.self_balance} returns
   no warmth, so there is no witness to hand a price and the surcharge is not
   merely unwritten but unwritable. *)
let selfbalance env m =
  let value, effects = Effects.self_balance m.effects (executing env) in
  push_value value { m with effects }

(* EIP-214, as an argument rather than as a branch someone must remember to
   write. The three instructions that change substate — [SSTORE], [TSTORE] and
   [LOG] — each demand a {!Mutability.permit}, and this is the only thing in the
   port that produces one. An arm that forgets it does not undercharge or
   over-permit, it fails to compile. *)
let permitted env =
  Option.fold ~none:(Error Static_state_change) ~some:(fun permit -> Ok permit)
    (Mutability.permit (Env.Call.mutability (Env.call env)))

(* A digest as a word. {!Tn_keccak.length} is 32, which is exactly the width
   [of_be_bytes] accepts, so the default is unreachable — the same shape, and
   the same justification, as [word_of_int]. *)
let word_of_digest digest =
  Option.value ~default:W.zero (W.of_be_bytes (Tn_keccak.to_bytes digest))

(* ---------- the external-code readers ---------- *)

(* [EXTCODESIZE] and [EXTCODEHASH] share [BALANCE]'s shape — warm the named
   account, charge the EIP-2929 surcharge that same touch's warmth prices, push a
   word — but for the word: [BALANCE] pushes the value loaded, these push a
   function of the account loaded (its code length, or its EIP-1052 code hash).
   So [load_and_charge]'s direct push does not fit, and this projects the account
   first. The surcharge is [account_access_cost], exactly [BALANCE]'s. *)
let account_projection ~project ~load m =
  Option.fold ~none:(Error Out_of_gas)
    ~some:(fun gas ->
      Result.map
        (fun stack ->
          { m with pc = m.pc + 1; stack; gas; effects = Effects.warmed load })
        (stack_result (Stack.push (project (Effects.loaded load)) m.stack)))
    (Gas.charge (Gas.account_access_cost (Effects.warmth load)) m.gas)

let extcodesize m =
  transition
    (Result.bind (stack_result (Stack.pop m.stack)) (fun (word, stack) ->
         account_projection
           ~project:(fun account -> word_of_int (Account.code_length account))
           ~load:(Effects.ext_account m.effects (Address_word.of_word word))
           { m with stack }))

(* EIP-1052 ([instructions/host.rs:77-104]) and its one subtlety: an account that
   is [is_empty] — EIP-161's zero nonce, zero balance and no code — has a code
   hash of ZERO, and this is NOT [KECCAK_EMPTY]. A codeless account that
   nonetheless exists, one with a balance say, is not [is_empty], so it reports
   its real code hash, which for empty code IS [KECCAK_EMPTY]. Only an account
   that does not exist reports zero. That zero is a bare word produced here, never
   a digest, so it can never be confused with the [KECCAK_EMPTY] of a real
   codeless account — the distinction {!Tn_keccak} has no constructor to blur. *)
let extcodehash m =
  transition
    (Result.bind (stack_result (Stack.pop m.stack)) (fun (word, stack) ->
         account_projection
           ~project:(fun account ->
             if Account.is_empty account then W.zero
             else word_of_digest (Account.code_hash account))
           ~load:(Effects.ext_account m.effects (Address_word.of_word word))
           { m with stack }))

(* Warm the target account and charge its EIP-2929 surcharge, returning the
   loaded account (its code is [EXTCODECOPY]'s source) alongside the machine that
   has paid. Charged AFTER whatever the copy prologue and any expansion took,
   because revm's [berlin_load_account!] ([instructions/host.rs:140-141]) sits
   after both the copy [gas!] and the resize — and it runs even for a zero
   length, so the caller pays this on the empty copy too. *)
let charge_ext_account machine address =
  let load = Effects.ext_account machine.effects address in
  Option.fold ~none:(Error Out_of_gas)
    ~some:(fun gas ->
      Ok (Effects.loaded load, { machine with gas; effects = Effects.warmed load }))
    (Gas.charge (Gas.account_access_cost (Effects.warmth load)) machine.gas)

(* [EXTCODECOPY] ([instructions/host.rs:106-158]). The copy family with two
   differences from [CODECOPY]: the source is ANOTHER account's code, reached
   through the host seam so the read warms it, and the account surcharge falls
   after the copy price and the expansion rather than not at all. The address is
   the first word popped, above the three the copy prologue takes. revm's order:

     base 100 (dispatch) -> copy price -> expansion (only if len>0)
       -> account 2500-if-cold -> write.

   The account is warmed and its surcharge paid EVEN for a zero length, where the
   frame-local copies do nothing: [berlin_load_account!] is after the
   [if len != 0] resize, so a zero-length [EXTCODECOPY] still warms and still pays
   the cold surcharge. That is why [Copy_nothing] here charges the account rather
   than continuing at once. *)
let extcodecopy m =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Halt (Failed e))
    (Result.bind (stack_result (Stack.pop m.stack)) (fun (address_word, stack) ->
         let address = Address_word.of_word address_word in
         match plan_copy { m with stack } with
         | Copy_failed error -> Error error
         | Copy_nothing machine ->
             Result.map
               (fun (_account, machine) ->
                 Continue { machine with pc = machine.pc + 1 })
               (charge_ext_account machine address)
         | Copy_to { machine; dest; source; length } ->
             Result.bind (reach machine ~offset:dest ~length) (fun (memory, gas) ->
                 Result.map
                   (fun (account, machine) ->
                     Continue
                       {
                         machine with
                         pc = machine.pc + 1;
                         memory =
                           Memory.store_bytes machine.memory ~offset:dest
                             (Data.read
                                (Data.of_string (Account.code account))
                                ~offset:source ~length);
                       })
                   (charge_ext_account { machine with gas; memory } address))))

(* [KECCAK256] ([instructions/system.rs:14-34]). The static 30 is the table's;
   the six per word is charged inside [reach_data], before the zero-length
   branch, which is where revm charges it.

   A zero-length hash pushes {!Tn_keccak.empty} rather than hashing the empty
   slice it did not read. The two are the same word, and going through the
   constant is what keeps the promise that memory is never touched: this arm
   reaches no memory at all, so an enormous offset with a zero length is a valid
   [KECCAK_EMPTY] and not an [Offset_too_large]. *)
let keccak256 m =
  transition
    (Result.bind (stack_result (Stack.pop2 m.stack))
       (fun (offset_word, length_word, stack) ->
         Result.bind
           (reach_data m ~offset_word ~length_word ~price:(fun length gas ->
                charged (Gas.keccak_word_cost length) gas))
           (fun (bytes, memory, gas) ->
             let digest =
               if String.length bytes = 0 then Tn_keccak.empty else Tn_keccak.digest bytes
             in
             Result.map
               (fun stack -> { m with pc = m.pc + 1; stack; memory; gas })
               (stack_result (Stack.push (word_of_digest digest) stack)))))

(* [LOG0]-[LOG4] ([instructions/host.rs:313-347]), in revm's order, which is not
   the order a reader expects:

   1. The static guard FIRST, before a single pop, so a static frame reports
      [Static_state_change] even when the stack could not have supplied the
      operands.
   2. Pop the offset and the length; convert the length; charge
      375-per-topic-plus-8-per-byte; expand.
   3. Pop the TOPICS LAST, after all of that.

   Step 3 is the trap. The topics are popped after the gas and after the
   expansion, so a [LOG4] on a short stack with too small an allowance reports
   [Out_of_gas] and not [Stack_underflow]: the price of a log does not depend on
   whether its topics are actually there. Moving [Topics.collect] earlier would
   be invisible on every program except that one, which is why the test suite
   pins it with an allowance pair rather than trusting the comment. *)
let log arity env m =
  let ( let* ) = Result.bind in
  transition
    (let* permit = permitted env in
     let* offset_word, length_word, stack = stack_result (Stack.pop2 m.stack) in
     let* data, memory, gas =
       reach_data m ~offset_word ~length_word ~price:(fun length gas ->
           Option.fold ~none:(Error Out_of_gas)
             ~some:(fun cost -> charged cost gas)
             (Gas.log_dynamic_cost ~topics:arity ~length))
     in
     let* topics, stack =
       Log.Topics.collect arity ~pop:(fun stack -> stack_result (Stack.pop stack)) stack
     in
     let entry = Log.make ~address:(executing env) ~topics ~data in
     (* Every field of the machine but the return-data buffer is named here, so
        there is a partial [m with]: a log moves the stack, memory, gas and
        effects at once, and leaves the buffer of the last sub-call untouched. *)
     Ok
       {
         m with
         pc = m.pc + 1;
         stack;
         memory;
         gas;
         effects = Effects.log m.effects permit entry;
       })

(* [TLOAD] ([instructions/host.rs:302-311]): a flat 100 from the table, a total
   read, and no warmth — EIP-1153 puts transient storage outside EIP-2929, so
   there is no surcharge and nothing to price one from. No static guard: a read
   changes nothing, and revm's [tload] carries no [require_non_staticcall]. *)
let tload env m =
  transition
    (Result.bind (stack_result (Stack.pop m.stack)) (fun (slot, stack) ->
         Result.map
           (fun stack -> { m with pc = m.pc + 1; stack })
           (stack_result
              (Stack.push (Effects.transient_load m.effects (executing env) ~slot) stack))))

(* [TSTORE] ([instructions/host.rs:290-300]): the guard first (revm puts
   [require_non_staticcall] at :294, the statement after the Cancun hardfork
   check this port has no counterpart for), then a flat 100 from the table and a
   write. There is no plan-and-commit split as [SSTORE] has, because the price
   depends on nothing that has to be looked up first, and no refund, because
   EIP-1153 gives transient storage none. *)
let tstore env m =
  transition
    (Result.bind (permitted env) (fun permit ->
         Result.map
           (fun (slot, value, stack) ->
             {
               m with
               pc = m.pc + 1;
               stack;
               effects =
                 Effects.transient_store m.effects permit (executing env) ~slot ~value;
             })
           (stack_result (Stack.pop2 m.stack))))

let sstore_error = function
  | Gas.Reentrancy_sentry -> Reentrancy_sentry
  | Gas.Insufficient -> Out_of_gas

(* [SSTORE], in revm's exact order ([instructions/host.rs:228-288]).

   1. [require_non_staticcall] (:229), which here is [permitted] producing the
      {!Mutability.permit} that [Effects.plan_store] demands. It is first, before
      the pops, so a static frame reports [Static_state_change] even when the
      stack could not have supplied the operands.
   2. Pop both operands (:230). This is why a two-deep underflow on a
      2300-unit allowance reports [Stack_underflow] and not [Reentrancy_sentry];
      swapping the two lines is invisible on every program except that one.
   3. [Gas.sstore_entry]: the EIP-2200 sentry against the UNDECREMENTED allowance
      (:237-244, and the comparison is [<=], so exactly 2300 halts), then the
      static 100 (:246-249). The two are fused into one function so the order is
      not expressible wrongly, and [Gas.static_cost Sstore] is zero so the
      dispatch loop has taken nothing from the allowance the sentry reads.
   4. [Effects.plan_store] reads [original] from the pre-transaction world and
      [present] from the current one, and records the slot's warmth (:251-267).
      The write is not applied.
   5. Charge the dynamic cost of that same triple (:272-279). On failure the
      whole [Effects.t] is dropped, which un-warms the slot — free here, because
      [Failed] carries no effects to drop it from.
   6. [Effects.commit_store] applies the write and accrues the refund
      (:282-287), which are one function so neither can happen without the other.

   revm's skip-the-database-read short-circuits (:252-260) are deliberately not
   ported: with no database behind the world state they are outcome-equivalent,
   and re-adding them would add a branch with nothing observable on either
   side. *)
let sstore env m =
  transition
    (Result.bind (permitted env) (fun permit ->
    Result.bind (stack_result (Stack.pop2 m.stack)) (fun (slot, value, stack) ->
         Result.bind
           (Result.map_error sstore_error (Gas.sstore_entry m.gas))
           (fun entered ->
             let planned =
               Effects.plan_store m.effects permit (executing env) ~slot ~value
             in
             Option.fold ~none:(Error Out_of_gas)
               ~some:(fun gas ->
                 Ok
                   {
                     m with
                     pc = m.pc + 1;
                     stack;
                     gas;
                     effects = Effects.commit_store planned;
                   })
               (Gas.charge
                  (Gas.sstore_dynamic_cost (Effects.warmth planned)
                     (Effects.loaded planned))
                  entered)))))

(* ---------- the return-data readers ---------- *)

(* [RETURNDATACOPY] ([instructions/system.rs:193-233]) in revm's exact order, the
   mirror image of the copy family's [Data] read:

   1. pop [dest; source; length];
   2. convert the LENGTH ([as_usize_or_fail], [Offset_too_large] if it will not
      fit) and SATURATE the source offset ([as_usize_saturated]);
   3. the STRICT bounds check {!Return_data.read}, BEFORE any gas — a window whose
      end passes the buffer is [Out_of_offset], never a zero-fill;
   4. only then charge {!Gas.copy_cost_verylow} (the VERYLOW base plus per-word),
      which a zero length still pays;
   5. for a nonzero length, convert the destination, pay its expansion and write;
      a zero length reaches no memory, so an enormous destination succeeds. *)
let returndatacopy m =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Halt (Failed e))
    (let ( let* ) = Result.bind in
     let* dest_word, source_word, length_word, stack = stack_result (Stack.pop3 m.stack) in
     let* length = extent_of_word length_word in
     let source = saturating_int source_word in
     let* bytes =
       Option.fold ~none:(Error Out_of_offset) ~some:(fun b -> Ok b)
         (Return_data.read m.return_data ~offset:source ~length)
     in
     let* gas = charged (Gas.copy_cost_verylow length) m.gas in
     let m = { m with stack; gas } in
     if length = 0 then Ok (Continue { m with pc = m.pc + 1 })
     else
       let* dest = extent_of_word dest_word in
       let* memory, gas = reach m ~offset:dest ~length in
       Ok
         (Continue
            {
              m with
              pc = m.pc + 1;
              memory = Memory.store_bytes memory ~offset:dest bytes;
              gas;
            }))

(* ---------- the sub-frame message calls ---------- *)

(* [get_memory_input_and_out_ranges] ([call_helpers.rs:22-49]): pop the input and
   output windows [in_off; in_len; out_off; out_len] and charge the expansion to
   reach the input window then the output window. A zero-length window touches no
   memory and leaves its offset unconverted, so an enormous offset with a zero
   length is not an error. *)
(* [BLOCKHASH] ([instructions/host.rs:186-216]). Its whole price is the table's
   20, which the dispatch loop has already taken — revm's body carries a
   commented-out [gas!] at [host.rs:189] for exactly that reason. Every request
   outside the window reads zero, and {!Block_hashes.lookup} is where the four
   ways of being outside it are one rule. *)
let blockhash env m =
  unary
    (fun requested ->
      Block_hashes.lookup
        (Env.Block.hashes (Env.block env))
        ~current:(Env.Block.number (Env.block env))
        ~requested)
    m

(* [SELFDESTRUCT] ([instructions/host.rs:387-426]) in revm's order, which is
   observable at three points:

   1. the EIP-214 ban comes first, before the pop, so a static frame halts on the
      ban and not on an empty stack;
   2. the static 5000 is charged before the beneficiary is looked up, so a frame
      that cannot afford even that never warms it;
   3. the two surcharges are charged after that lookup, because both are
      functions of what it found — and the plan is applied only once they are
      paid, which is {!Effects.plan_destruction} and {!Effects.commit_destruction}
      being two functions.

   It halts like [STOP]: revm's [InstructionResult::SelfDestruct] is in the
   success class, so the frame's effects survive and its remaining gas goes back
   to the caller. There is no refund — EIP-3529 removed it, and [host.rs:414-421]
   records one only below London. *)
let selfdestruct env m =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Halt (Failed e))
    (let ( let* ) = Result.bind in
     let* permit = permitted env in
     let* beneficiary_word, stack = stack_result (Stack.pop m.stack) in
     let m = { m with stack } in
     let* gas = charged Gas.selfdestruct_base m.gas in
     let plan =
       Effects.plan_destruction m.effects ~address:(executing env)
         ~beneficiary:(Address_word.of_word beneficiary_word)
     in
     let planned = Effects.loaded plan in
     let* gas =
       charged
         (Gas.selfdestruct_dynamic (Effects.warmth plan)
            ~had_value:(Destruction.had_value planned)
            ~beneficiary_exists:(Destruction.beneficiary_exists planned))
         gas
     in
     Ok
       (Option.fold
          ~none:(Halt (Failed Balance_overflow))
          ~some:(fun effects -> Halt (Stopped { gas_left = gas; effects }))
          (Effects.commit_destruction plan permit)))

let reach_window m ~offset_word ~length_word =
  let ( let* ) = Result.bind in
  let* length = extent_of_word length_word in
  if length = 0 then Ok (m, 0, length)
  else
    let* offset = extent_of_word offset_word in
    let* memory, gas = reach m ~offset ~length in
    Ok ({ m with memory; gas }, offset, length)

let mem_windows m =
  let ( let* ) = Result.bind in
  let* in_off_w, in_len_w, stack = stack_result (Stack.pop2 m.stack) in
  let* out_off_w, out_len_w, stack = stack_result (Stack.pop2 stack) in
  let m = { m with stack } in
  let* m, in_off, in_len = reach_window m ~offset_word:in_off_w ~length_word:in_len_w in
  let* m, out_off, out_len = reach_window m ~offset_word:out_off_w ~length_word:out_len_w in
  Ok (m, in_off, in_len, out_off, out_len)

(* The ok and revert classes both copy the child's output head into the caller's
   output window and hand its leftover gas back; they differ only in the flag
   pushed (1 for ok, 0 for revert) and whose effects survive. The write is
   [min out_len |output|] bytes at [out_off] with NO zero-fill of the rest of the
   window ([frame.rs:481-484]); the window was already reached in {!mem_windows},
   so this reach charges nothing. *)
let finish_written base ~out_off ~out_len ~output ~gas ~effects ~pushed =
  let return_data = Return_data.of_string output in
  let target_len = Int.min out_len (String.length output) in
  transition
    (let ( let* ) = Result.bind in
     let* memory, gas = reach { base with gas } ~offset:out_off ~length:target_len in
     let memory =
       Memory.store_bytes memory ~offset:out_off (String.sub output 0 target_len)
     in
     let* stack = stack_result (Stack.push pushed base.stack) in
     Ok { pc = base.pc + 1; stack; memory; gas; effects; return_data })

(* A call that pushes zero and copies no output: the child halted exceptionally,
   or a frame-entry guard refused it before it ran. The caller keeps its own
   memory and effects (no child write, no value transfer survives) and clears the
   buffer; the gas is whatever the caller hands back — nothing for a [Failed]
   child, the full forwarded amount for a guard. *)
let push_zero base ~gas =
  transition
    (Result.map
       (fun stack ->
         { base with pc = base.pc + 1; stack; gas; return_data = Return_data.empty })
       (stack_result (Stack.push W.zero base.stack)))

(* revm's ok / revert / error classification of a returned sub-frame
   ([frame.rs:462,479-486]). [base] is the caller having paid every charge, its
   effects still the PRE-transfer parent effects, so a dropped child (revert or
   halt) leaves them and the warming intact while an ok child's effects are
   adopted whole (transfer, writes, warmings and the refund counter within). *)
let merge_call base ~out_off ~out_len ~outcome =
  match outcome with
  | Stopped { gas_left; effects } ->
      finish_written base ~out_off ~out_len ~output:"" ~effects ~pushed:W.one
        ~gas:(Gas.give_back (Gas.remaining gas_left) base.gas)
  | Returned { output; gas_left; effects } ->
      finish_written base ~out_off ~out_len ~output ~effects ~pushed:W.one
        ~gas:(Gas.give_back (Gas.remaining gas_left) base.gas)
  | Reverted { output; gas_left } ->
      finish_written base ~out_off ~out_len ~output ~effects:base.effects ~pushed:W.zero
        ~gas:(Gas.give_back (Gas.remaining gas_left) base.gas)
  | Failed _ -> push_zero base ~gas:base.gas

(* The end of a successful creation frame ([revm-handler] [frame.rs:535-593]):
   what the init code returned becomes the account's code, if it may and if the
   frame can pay for it.

   Three ways to fail, and all three are alike in the caller: the state the frame
   built is dropped, zero is pushed and NOT one unit of the forwarded allowance
   comes back, because all three are errors rather than reverts.

   1. EIP-3541, output beginning with the reserved [0xEF];
   2. EIP-170, output past {!Tn_state.Bytecode.max_deployed_size};
   3. EIP-2 point 3, a frame that cannot pay 200 per byte for its own code. That
      one is the reason the charge is here and not in the frame: a creation that
      returns code it cannot afford deploys nothing at all rather than a shorter
      contract.

   An init code that merely [STOP]s returns no bytes, passes all three, pays
   nothing, and deploys an account with empty code — which is a successful
   creation, not a failed one. It is a plain [let] rather than a member of the
   frame-recursion group below: like {!merge_call} it spawns no sub-frame, so it
   sits beside that function, and [create_op] reaches it by backward reference. *)
let deposit_code base ~created ~permit ~warmed ~output ~gas_left ~effects =
  Result.fold
    ~ok:Fun.id
    ~error:(fun () -> push_zero { base with effects = warmed } ~gas:base.gas)
    (let ( let* ) = Result.bind in
     let* () =
       Result.map_error (fun _ -> ()) (Tn_state.Bytecode.validate_deployment output)
     in
     let* paid =
       Option.to_result ~none:()
         (Gas.charge (Gas.code_deposit_cost (String.length output)) gas_left)
     in
     Ok
       (transition
          (Result.map
             (fun stack ->
               {
                 base with
                 pc = base.pc + 1;
                 stack;
                 effects = Effects.deploy_code effects permit created output;
                 gas = Gas.give_back (Gas.remaining paid) base.gas;
                 return_data = Return_data.empty;
               })
             (stack_result (Stack.push (Address_word.to_word created) base.stack)))))

(* Merging a finished creation frame into its caller ([revm-handler]
   [frame.rs:493-527]). It differs from {!merge_call} on every axis, which is why
   it is a separate function rather than a flag on that one:

   - what is pushed is the created address, not a one;
   - nothing is copied into an output window, because a creation has none;
   - the return-data buffer stays EMPTY on success. The deployed code is not
     return data, and [RETURNDATASIZE] after a successful [CREATE] reads zero
     ([frame.rs:497-505] populates the buffer only for an exact [Revert]);
   - a revert hands its leftover gas back AND leaves its output in the buffer,
     which is the only way a creation ever fills it.

   Like {!deposit_code} it spawns no sub-frame, so it is a plain [let] beside
   {!merge_call} rather than a member of the frame-recursion group below. *)
let merge_creation base ~created ~permit ~warmed ~outcome =
  match outcome with
  | Stopped { gas_left; effects } ->
      deposit_code base ~created ~permit ~warmed ~output:"" ~gas_left ~effects
  | Returned { output; gas_left; effects } ->
      deposit_code base ~created ~permit ~warmed ~output ~gas_left ~effects
  | Reverted { output; gas_left } ->
      transition
        (Result.map
           (fun stack ->
             {
               base with
               pc = base.pc + 1;
               stack;
               effects = warmed;
               gas = Gas.give_back (Gas.remaining gas_left) base.gas;
               return_data = Return_data.of_string output;
             })
           (stack_result (Stack.push W.zero base.stack)))
  | Failed _ -> push_zero { base with effects = warmed } ~gas:base.gas

let rec execute env code depth m = function
  | Opcode.Stop -> Halt (Stopped { gas_left = m.gas; effects = m.effects })
  | Opcode.Add -> binary Alu.add m
  | Opcode.Mul -> binary Alu.mul m
  | Opcode.Sub -> binary Alu.sub m
  | Opcode.Div -> binary Alu.div m
  | Opcode.Sdiv -> binary Alu.sdiv m
  | Opcode.Mod -> binary Alu.modulo m
  | Opcode.Smod -> binary Alu.smod m
  | Opcode.Addmod -> ternary Alu.addmod m
  | Opcode.Mulmod -> ternary Alu.mulmod m
  | Opcode.Exp -> exponentiate m
  | Opcode.Signextend -> binary Alu.signextend m
  | Opcode.Lt -> binary Alu.lt m
  | Opcode.Gt -> binary Alu.gt m
  | Opcode.Slt -> binary Alu.slt m
  | Opcode.Sgt -> binary Alu.sgt m
  | Opcode.Eq -> binary Alu.eq m
  | Opcode.Iszero -> unary Alu.iszero m
  | Opcode.And -> binary Alu.logand m
  | Opcode.Or -> binary Alu.logor m
  | Opcode.Xor -> binary Alu.logxor m
  | Opcode.Not -> unary Alu.lognot m
  | Opcode.Byte -> binary Alu.byte m
  | Opcode.Shl -> binary Alu.shl m
  | Opcode.Shr -> binary Alu.shr m
  | Opcode.Sar -> binary Alu.sar m
  | Opcode.Pop -> discard m
  | Opcode.Mload -> mload m
  | Opcode.Mstore ->
      mstore ~length:word_bytes
        ~write:(fun memory offset value -> Memory.store_word memory offset value)
        m
  | Opcode.Mstore8 ->
      mstore ~length:1
        ~write:(fun memory offset value ->
          Memory.store_byte memory offset (low_byte value))
        m
  | Opcode.Jump -> jump code m
  | Opcode.Jumpi -> jumpi code m
  (* [PC] reports the offset of the [PC] instruction itself. *)
  | Opcode.Pc -> push_value (word_of_int m.pc) m
  | Opcode.Msize -> push_value (word_of_int (Memory.size_bytes m.memory)) m
  (* [GAS] reports what is left after its own cost has been charged, which the
     dispatch loop has already done. *)
  | Opcode.Gas -> push_value (word_of_int (Gas.remaining m.gas)) m
  | Opcode.Jumpdest -> Continue { m with pc = m.pc + 1 }
  | Opcode.Push0 -> push_value W.zero m
  | Opcode.Push width -> push_immediate code (Opcode.Push_bytes.to_int width) m
  | Opcode.Dup depth -> with_stack (Stack.dup depth) m
  | Opcode.Swap depth -> with_stack (Stack.swap depth) m
  | Opcode.Return ->
      halt_with_output
        (fun output gas_left -> Returned { output; gas_left; effects = m.effects })
        m
  | Opcode.Revert ->
      halt_with_output (fun output gas_left -> Reverted { output; gas_left }) m
  | Opcode.Invalid -> Halt (Failed (Invalid_opcode (Opcode.to_byte Opcode.Invalid)))
  (* The call context. *)
  | Opcode.Address ->
      env_word (fun env -> Address_word.to_word (executing env)) env m
  | Opcode.Caller ->
      env_word
        (fun env -> Address_word.to_word (Env.Call.caller (Env.call env)))
        env m
  | Opcode.Callvalue -> env_word (fun env -> Env.Call.value (Env.call env)) env m
  (* [CALLDATALOAD]'s offset saturates: a word past the end of the input reads
     thirty-two zero bytes rather than halting ([system.rs:92]). *)
  | Opcode.Calldataload ->
      unary (fun offset -> Data.word_at (Env.Call.data (Env.call env)) offset) m
  | Opcode.Calldatasize ->
      env_word
        (fun env -> word_of_int (Data.length (Env.Call.data (Env.call env))))
        env m
  | Opcode.Calldatacopy -> copy_from_data (Env.Call.data (Env.call env)) m
  (* [CODESIZE] and [CODECOPY] see the frame's own code, and see it unpadded:
     [Code.length] is what was given, while [Code.byte_at] past the end reads
     [STOP]. The window {!Code.window} exposes carries the same zero-extension
     rule, so a copy that runs off the end pads with zeros exactly as revm's
     padded bytecode does. *)
  | Opcode.Codesize -> env_word (fun _env -> word_of_int (Code.length code)) env m
  | Opcode.Codecopy -> copy_from_data (Code.window code) m
  (* The external-code readers name their account by a popped word, not the
     environment, so like [BALANCE] they take no [env]. *)
  | Opcode.Extcodesize -> extcodesize m
  | Opcode.Extcodecopy -> extcodecopy m
  | Opcode.Extcodehash -> extcodehash m
  | Opcode.Selfbalance -> selfbalance env m
  (* The transaction. [ORIGIN] is the signer, never the immediate caller; they
     coincide only in the top-level frame. *)
  | Opcode.Origin ->
      env_word
        (fun env -> Address_word.to_word (Env.Tx.origin (Env.tx env)))
        env m
  | Opcode.Gasprice -> env_word (fun env -> Env.Tx.gas_price (Env.tx env)) env m
  (* The block. *)
  | Opcode.Coinbase ->
      env_word
        (fun env -> Address_word.to_word (Env.Block.coinbase (Env.block env)))
        env m
  | Opcode.Timestamp ->
      env_word (fun env -> Env.Block.timestamp (Env.block env)) env m
  | Opcode.Number -> env_word (fun env -> Env.Block.number (Env.block env)) env m
  | Opcode.Prevrandao ->
      env_word (fun env -> Env.Block.prevrandao (Env.block env)) env m
  | Opcode.Gaslimit ->
      env_word (fun env -> Env.Block.gas_limit (Env.block env)) env m
  | Opcode.Chainid ->
      env_word (fun env -> Env.Block.chain_id (Env.block env)) env m
  | Opcode.Basefee -> env_word (fun env -> Env.Block.basefee (Env.block env)) env m
  (* The world. *)
  | Opcode.Balance -> balance m
  | Opcode.Sload -> sload env m
  | Opcode.Sstore -> sstore env m
  | Opcode.Mcopy -> mcopy m
  | Opcode.Keccak256 -> keccak256 m
  | Opcode.Tload -> tload env m
  | Opcode.Tstore -> tstore env m
  | Opcode.Log arity -> log arity env m
  (* The return-data readers. [RETURNDATASIZE] pushes the buffer's length for a
     flat 2; [RETURNDATACOPY] copies a strictly-bounded window of it. *)
  | Opcode.Returndatasize ->
      push_value (word_of_int (Return_data.size m.return_data)) m
  | Opcode.Returndatacopy -> returndatacopy m
  (* The sub-frame message calls. Each opens a second frame at the callee's code
     and threads [depth] one deeper. *)
  | Opcode.Call -> call_op env code depth m
  | Opcode.Callcode -> callcode_op env code depth m
  | Opcode.Delegatecall -> delegatecall_op env code depth m
  | Opcode.Staticcall -> staticcall_op env code depth m
  (* The creations open a sub-frame at code they were handed rather than at code
     an account already holds, and deploy what it returns. *)
  | Opcode.Create -> create_op env code depth m ~salted:false
  | Opcode.Create2 -> create_op env code depth m ~salted:true
  (* Neither of these opens a frame: [SELFDESTRUCT] ends one and [BLOCKHASH]
     reads the chain behind this block. *)
  | Opcode.Selfdestruct -> selfdestruct env m
  | Opcode.Blockhash -> blockhash env m

(* One instruction: decode the byte at the program counter, charge the fixed
   price before running it — so an instruction that then fails on its operands
   has still paid, as in revm — and dispatch. A byte naming no instruction halts
   the machine; so does an allowance that cannot pay for one. *)
and step env code depth m =
  let byte = Code.byte_at code m.pc in
  Option.fold ~none:(Halt (Failed (Invalid_opcode byte)))
    ~some:(fun op ->
      Option.fold ~none:(Halt (Failed Out_of_gas))
        ~some:(fun gas -> execute env code depth { m with gas } op)
        (Gas.charge (Gas.static_cost op) m.gas))
    (Opcode.decode byte)

(* The dispatch loop. Every instruction that continues costs at least one unit of
   gas, so the allowance strictly decreases with each step and the recursion
   terminates on every program.

   [SSTORE] is the one instruction whose table price is zero, so this loop takes
   nothing from it — by design, so that EIP-2200's sentry reads an undecremented
   allowance. The decrease is restored inside [sstore], which charges 100 through
   [Gas.sstore_entry] before it can reach [Continue]. The invariant therefore
   still holds of every path, but it holds because of that body rather than
   because of this loop, and nothing in the types would notice an edit that broke
   it. *)
and drive env code depth m =
  match step env code depth m with
  | Continue next -> drive env code depth next
  | Halt outcome -> outcome

(* Enter a sub-frame: a fresh machine at offset zero, empty stack and memory, an
   empty return-data buffer, running [code] at [depth] against [gas] and the
   effects it was handed. The seam every call opcode bottoms out in — and the one
   {!run} is a special case of, with [depth = zero]. Never re-[start]s the
   effects, so EIP-2200's [original] stays the pre-transaction value across the
   nesting (see {!Effects}). *)
and run_subframe ~env ~code ~gas ~effects ~depth =
  drive env code depth
    {
      pc = 0;
      stack = Stack.empty;
      memory = Memory.empty;
      gas;
      effects;
      return_data = Return_data.empty;
    }

(* The body every call opcode shares, in revm's exact charge order
   ([contract.rs], [call_helpers.rs], [frame.rs]). [m] here has the fixed
   operands (gas limit, address, and value for the value-bearing calls) already
   popped; the four variants differ only in the arguments they pass:

   - [transfer_value] drives {!Gas.call_value_cost}, the stipend and the transfer:
     the popped value for [CALL]/[CALLCODE], zero for [DELEGATECALL]/[STATICCALL].
   - [child_value] is the [CALLVALUE] the sub-frame reads: the popped value, the
     parent's apparent value for [DELEGATECALL], or zero for [STATICCALL].
   - [sub_target] is the storage context and the value's destination: the callee
     for [CALL]/[STATICCALL], the caller itself for [CALLCODE]/[DELEGATECALL].
   - [is_plain_call] gates the new-account cost to [CALL] alone. *)
and do_call env code depth m ~requested ~to_addr ~child_value ~transfer_value
    ~is_plain_call ~sub_target ~sub_caller ~mutability =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Halt (Failed e))
    (let ( let* ) = Result.bind in
     (* 4. input and output memory windows, charged input then output. *)
     let* m, in_off, in_len, out_off, out_len = mem_windows m in
     (* 5. warm the target in the parent effects and charge the account access;
        the warming lands here, before the transfer branches, so a reverting
        child leaves [to_addr] warm. *)
     let load = Effects.ext_account m.effects to_addr in
     let callee_account = Effects.loaded load in
     let m = { m with effects = Effects.warmed load } in
     let* gas = charged (Gas.account_access_cost (Effects.warmth load)) m.gas in
     (* 6. the value-transfer cost, zero unless value moves. *)
     let* gas = charged (Gas.call_value_cost transfer_value) gas in
     (* 7. the new-account cost: only [CALL], only to an [is_empty] callee that
        receives value. *)
     let* gas =
       charged
         (if is_plain_call && Account.is_empty callee_account then
            Gas.new_account_cost ~value:transfer_value
          else 0)
         gas
     in
     (* 8. the EIP-150 cap on what is left, charged, plus the stipend on top. *)
     let cg = Gas.call_gas ~requested ~remaining:gas ~value:transfer_value in
     let* gas = charged cg.Gas.charge gas in
     let forwarded = cg.Gas.forwarded in
     let base = { m with gas } in
     let refuse () = push_zero base ~gas:(Gas.give_back (Gas.remaining forwarded) base.gas) in
     (* 9. depth guard; 10-11 the transfer, whose [None] (sender underflow or
        recipient overflow) is the balance guard. Every refusal hands back the
        whole forwarded gas and runs no child. *)
     let self_target = Env.Call.target (Env.call env) in
     let sub_effects =
       if W.is_zero transfer_value then Some base.effects
       else
         Effects.transfer base.effects ~from:self_target ~to_:sub_target
           ~value:transfer_value
     in
     if not (Call_depth.within_limit (Call_depth.succ depth)) then Ok (refuse ())
     else
       Ok
         (Option.fold ~none:(refuse ())
            ~some:(fun sub_effects ->
              (* 12. run the callee: a precompiled contract at [to_addr], or the
                 account's own code in a sub-frame. The precompile is dispatched
                 on the code address, so [DELEGATECALL]/[CALLCODE] to a builtin
                 reach it too, and its success carries the post-transfer
                 [sub_effects] unchanged (a precompile touches no world state
                 beyond the value move already folded in). A precompile that
                 rejects is an exceptional halt: the whole forwarded allowance is
                 forfeit, exactly as {!merge_call} treats a [Failed] child. *)
              let calldata = Memory.slice base.memory ~offset:in_off ~length:in_len in
              let outcome =
                match
                  Precompile.invoke to_addr ~input:calldata
                    ~gas_limit:(Gas.remaining forwarded)
                with
                | Precompile.Succeeded { gas_used; output } ->
                    Option.fold ~none:(Failed Out_of_gas)
                      ~some:(fun gas_left ->
                        Returned { output; gas_left; effects = sub_effects })
                      (Gas.charge gas_used forwarded)
                | Precompile.Rejected -> Failed Out_of_gas
                | Precompile.Not_a_precompile ->
                    let callee_code = Code.of_string (Account.code callee_account) in
                    let sub_call =
                      Env.Call.make ~target:sub_target ~caller:sub_caller
                        ~value:child_value ~data:(Data.of_string calldata) ~mutability
                    in
                    run_subframe ~env:(Env.with_call env sub_call) ~code:callee_code
                      ~gas:forwarded ~effects:sub_effects
                      ~depth:(Call_depth.succ depth)
              in
              (* 13. merge the outcome into the caller. *)
              merge_call base ~out_off ~out_len ~outcome)
            sub_effects))

(* [CALL] ([contract.rs:122-164]): pop gas, address and value; the EIP-214 static
   guard (value in a static frame halts, before the window pops); then the shared
   body, with the callee as both storage context and value destination. *)
and call_op env code depth m =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Halt (Failed e))
    (let ( let* ) = Result.bind in
     let* requested, stack = stack_result (Stack.pop m.stack) in
     let* to_word, stack = stack_result (Stack.pop stack) in
     let* value, stack = stack_result (Stack.pop stack) in
     let parent_mut = Env.Call.mutability (Env.call env) in
     if Mutability.is_static parent_mut && not (W.is_zero value) then
       Ok (Halt (Failed Call_not_allowed_inside_static))
     else
       let to_addr = Address_word.of_word to_word in
       let self_target = Env.Call.target (Env.call env) in
       Ok
         (do_call env code depth { m with stack } ~requested ~to_addr
            ~child_value:value ~transfer_value:value ~is_plain_call:true
            ~sub_target:to_addr ~sub_caller:self_target ~mutability:parent_mut))

(* [CALLCODE] ([contract.rs:173-208]): like [CALL] but the callee's code runs in
   the caller's OWN storage, so the sub-frame target and both transfer parties are
   the executing account. No EIP-214 guard (exempt) and no new-account cost. *)
and callcode_op env code depth m =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Halt (Failed e))
    (let ( let* ) = Result.bind in
     let* requested, stack = stack_result (Stack.pop m.stack) in
     let* to_word, stack = stack_result (Stack.pop stack) in
     let* value, stack = stack_result (Stack.pop stack) in
     let to_addr = Address_word.of_word to_word in
     let parent_mut = Env.Call.mutability (Env.call env) in
     let self_target = Env.Call.target (Env.call env) in
     Ok
       (do_call env code depth { m with stack } ~requested ~to_addr
          ~child_value:value ~transfer_value:value ~is_plain_call:false
          ~sub_target:self_target ~sub_caller:self_target ~mutability:parent_mut))

(* [DELEGATECALL] ([contract.rs:217-252]): no value word. The callee's code runs
   in the caller's storage with the caller's own [CALLER] and [CALLVALUE]
   preserved (the apparent value), and no value moves. *)
and delegatecall_op env code depth m =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Halt (Failed e))
    (let ( let* ) = Result.bind in
     let* requested, stack = stack_result (Stack.pop m.stack) in
     let* to_word, stack = stack_result (Stack.pop stack) in
     let to_addr = Address_word.of_word to_word in
     let self_target = Env.Call.target (Env.call env) in
     let self_caller = Env.Call.caller (Env.call env) in
     let self_value = Env.Call.value (Env.call env) in
     let parent_mut = Env.Call.mutability (Env.call env) in
     Ok
       (do_call env code depth { m with stack } ~requested ~to_addr
          ~child_value:self_value ~transfer_value:W.zero ~is_plain_call:false
          ~sub_target:self_target ~sub_caller:self_caller ~mutability:parent_mut))

(* [STATICCALL] ([contract.rs:261-296]): no value word. The child is forced
   {!Mutability.Static}, moves no value, and runs in the callee's storage as
   [CALL] does. *)
and staticcall_op env code depth m =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Halt (Failed e))
    (let ( let* ) = Result.bind in
     let* requested, stack = stack_result (Stack.pop m.stack) in
     let* to_word, stack = stack_result (Stack.pop stack) in
     let to_addr = Address_word.of_word to_word in
     let self_target = Env.Call.target (Env.call env) in
     Ok
       (do_call env code depth { m with stack } ~requested ~to_addr
          ~child_value:W.zero ~transfer_value:W.zero ~is_plain_call:false
          ~sub_target:to_addr ~sub_caller:self_target ~mutability:Mutability.Static))

(* [CREATE] ([contract.rs:22-106]) and [CREATE2] (the same function under
   [IS_CREATE2]), together with the frame lifecycle revm keeps in its handler
   ([revm-handler] [frame.rs:262-346] going in, [:535-593] coming out).

   The two differ in three places and nowhere else: [CREATE2] pops a salt, pays
   6 per word to hash the init code, and derives its address from that hash
   instead of from the creator's nonce.

   The order below is revm's, and almost every step of it is observable:

   1. the EIP-214 ban, before any pop;
   2. pop value, offset and length;
   3. EIP-3860, but only when the length is nonzero: the limit is checked against
      the length BEFORE the meter is charged and before any memory is touched, so
      an over-long request halts without paying for the expansion it asked for. A
      zero length reads no memory and never converts its offset, so an enormous
      offset with a zero length is not an error — the same rule the copy family
      and the call windows follow;
   4. [CREATE2] pops its salt only now, AFTER the memory work, which is why a
      [CREATE2] with a doomed length halts on the length rather than on a missing
      salt;
   5. the 32000 base, plus [CREATE2]'s hash cost;
   6. the EIP-150 ceiling, charged whole. A creation has no requested-gas operand
      and gets no stipend, so all of what the ceiling allows goes to the frame.

   Then the frame-entry guards, in revm's order, which is what decides both what
   the creator keeps and what it is charged:

   7. depth, 8. the creator's balance, 9. the nonce bump. All three refuse by
      pushing zero and handing the whole forwarded allowance back, because revm
      classifies [CallTooDeep] and [OutOfFunds] as {e reverts} and a nonce
      overflow as an ordinary [Return] with no address ([frame.rs:275-292]);
   10. derive the address from the nonce the creator had BEFORE step 9;
   11. warm it, then test it for a collision. A collision burns the whole
       forwarded allowance instead of returning it, because [CreateCollision] is
       an {e error} ([revm-handler] [frame.rs:316] and the merge at [:514]), and
       this is the one refusal that costs the caller everything;
   12. create the account and move the endowment.

   Two things a failed creation leaves behind, and they are not an oversight:
   the creator's bumped nonce and the warmth of the created address. revm makes
   both before the checkpoint that a failure reverts to ([frame.rs:290,306] are
   above [inner.rs:399]), so neither is undone by any outcome. Here that falls
   out of which value is threaded on: every refusal from step 11 onward carries
   [warmed], the effects after the bump and the warming, and never [base]. *)
and create_op env code depth m ~salted =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Halt (Failed e))
    (let ( let* ) = Result.bind in
     let* permit = permitted env in
     let* value, stack = stack_result (Stack.pop m.stack) in
     let* offset_word, length_word, stack = stack_result (Stack.pop2 stack) in
     let m = { m with stack } in
     let* length = extent_of_word length_word in
     let* m, init_code =
       if length = 0 then Ok (m, "")
       else if length > Tn_state.Bytecode.max_initcode_size then Error Initcode_too_large
       else
         let* gas = charged (Gas.initcode_cost length) m.gas in
         let* offset = extent_of_word offset_word in
         let* memory, gas = reach { m with gas } ~offset ~length in
         Ok ({ m with memory; gas }, Memory.slice memory ~offset ~length)
     in
     let* salt, m =
       if salted then
         Result.map
           (fun (salt, stack) -> (salt, { m with stack }))
           (stack_result (Stack.pop m.stack))
       else Ok (W.zero, m)
     in
     let* gas = charged (Gas.create_cost ~salted length) m.gas in
     let cg = Gas.create_gas gas in
     let* gas = charged cg.Gas.charge gas in
     let forwarded = cg.Gas.forwarded in
     let base = { m with gas } in
     let creator = executing env in
     (* The creator is read whole and warmed, one lookup for the two fields the
        creation needs: the balance for step 8, the nonce for step 10. *)
     let creator_account, effects = Effects.self_account base.effects creator in
     let base = { base with effects } in
     (* Refusing with the allowance handed back, and refusing with it burned. The
        difference between them is the whole of revm's revert-versus-error
        classification for a creation that never ran. *)
     let refund_all effects =
       push_zero { base with effects }
         ~gas:(Gas.give_back (Gas.remaining forwarded) base.gas)
     in
     let burn effects = push_zero { base with effects } ~gas:base.gas in
     if not (Call_depth.within_limit (Call_depth.succ depth)) then Ok (refund_all base.effects)
     else if W.compare (Account.balance creator_account) value < 0 then
       Ok (refund_all base.effects)
     else
       Ok
         (Option.fold ~none:(refund_all base.effects)
            ~some:(fun bumped ->
              let created =
                Contract_address.derive ~creator
                  (if salted then Contract_address.From_salt { salt; init_code }
                   else Contract_address.From_nonce (Account.nonce creator_account))
              in
              let load = Effects.ext_account bumped created in
              let warmed = Effects.warmed load in
              if Account.is_occupied (Effects.loaded load) then burn warmed
              else
                (* A [None] here can only be the recipient overflow: the sender
                   underflow was ruled out at step 8. revm classifies that
                   overflow as an error, so it burns rather than refunds. *)
                Option.fold ~none:(burn warmed)
                  ~some:(fun child_effects ->
                    merge_creation base ~created ~permit ~warmed
                      ~outcome:
                        (run_subframe
                           ~env:
                             (Env.with_call env
                                (Env.Call.make ~target:created ~caller:creator ~value
                                   ~data:Data.empty
                                   ~mutability:(Env.Call.mutability (Env.call env))))
                           ~code:(Code.of_string init_code) ~gas:forwarded
                           ~effects:child_effects ~depth:(Call_depth.succ depth)))
                  (Effects.begin_creation warmed permit ~creator ~created ~value))
            (Effects.bump_nonce base.effects creator)))

let run ~env ~code ~gas ~effects =
  run_subframe ~env ~code ~gas ~effects ~depth:Call_depth.zero
