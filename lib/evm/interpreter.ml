module W = Tn_state.U256
module Address_word = Tn_state.Address_word

type error =
  | Out_of_gas
  | Stack_underflow
  | Stack_overflow
  | Invalid_jump
  | Invalid_opcode of int
  | Offset_too_large
  | Reentrancy_sentry

let error_to_string = function
  | Out_of_gas -> "out of gas"
  | Stack_underflow -> "stack underflow"
  | Stack_overflow -> "stack overflow"
  | Invalid_jump -> "invalid jump destination"
  | Invalid_opcode byte -> Printf.sprintf "invalid opcode 0x%02x" byte
  | Offset_too_large -> "memory offset or length too large"
  | Reentrancy_sentry -> "storage write refused on a call stipend"

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

(* [RETURN] and [REVERT] hand back a slice of memory, paying for whatever of it
   the frame had not already reached. A zero-length output touches no memory, so
   its offset is never even examined — an enormous offset with a zero length is a
   perfectly good empty return. *)
let halt_with_output build m =
  Result.fold ~ok:Fun.id ~error:(fun e -> Halt (Failed e))
    (Result.bind (stack_result (Stack.pop2 m.stack))
       (fun (offset_word, length_word, _stack) ->
         Result.bind (extent_of_word length_word) (fun length ->
             if length = 0 then Ok (Halt (build "" m.gas))
             else
               Result.bind (extent_of_word offset_word) (fun offset ->
                   Result.map
                     (fun (memory, gas) ->
                       Halt (build (Memory.slice memory ~offset ~length) gas))
                     (reach m ~offset ~length)))))

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

let sstore_error = function
  | Gas.Reentrancy_sentry -> Reentrancy_sentry
  | Gas.Insufficient -> Out_of_gas

(* [SSTORE], in revm's exact order ([instructions/host.rs:228-288]).

   1. [require_non_staticcall] — absent, because there is no static flag in this
      chunk (:229). It arrives with STATICCALL.
   2. Pop both operands FIRST (:230). This is why a two-deep underflow on a
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
    (Result.bind (stack_result (Stack.pop2 m.stack)) (fun (slot, value, stack) ->
         Result.bind
           (Result.map_error sstore_error (Gas.sstore_entry m.gas))
           (fun entered ->
             let planned =
               Effects.plan_store m.effects (executing env) ~slot ~value
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
                  entered))))

let execute env code m = function
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

(* One instruction: decode the byte at the program counter, charge the fixed
   price before running it — so an instruction that then fails on its operands
   has still paid, as in revm — and dispatch. A byte naming no instruction halts
   the machine; so does an allowance that cannot pay for one. *)
let step env code m =
  let byte = Code.byte_at code m.pc in
  Option.fold ~none:(Halt (Failed (Invalid_opcode byte)))
    ~some:(fun op ->
      Option.fold ~none:(Halt (Failed Out_of_gas))
        ~some:(fun gas -> execute env code { m with gas } op)
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
let rec drive env code m =
  match step env code m with
  | Continue next -> drive env code next
  | Halt outcome -> outcome

let run ~env ~code ~gas ~effects =
  drive env code
    { pc = 0; stack = Stack.empty; memory = Memory.empty; gas; effects }
