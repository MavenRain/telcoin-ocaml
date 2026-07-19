module W = Tn_state.U256

type error =
  | Out_of_gas
  | Stack_underflow
  | Stack_overflow
  | Invalid_jump
  | Invalid_opcode of int
  | Offset_too_large

let error_to_string = function
  | Out_of_gas -> "out of gas"
  | Stack_underflow -> "stack underflow"
  | Stack_overflow -> "stack overflow"
  | Invalid_jump -> "invalid jump destination"
  | Invalid_opcode byte -> Printf.sprintf "invalid opcode 0x%02x" byte
  | Offset_too_large -> "memory offset or length too large"

type outcome =
  | Stopped of { gas_left : Gas.t }
  | Returned of { output : string; gas_left : Gas.t }
  | Reverted of { output : string; gas_left : Gas.t }
  | Failed of error

let outcome_to_string = function
  | Stopped { gas_left } -> Printf.sprintf "stopped, gas left %d" (Gas.remaining gas_left)
  | Returned { output; gas_left } ->
      Printf.sprintf "returned %d bytes, gas left %d" (String.length output)
        (Gas.remaining gas_left)
  | Reverted { output; gas_left } ->
      Printf.sprintf "reverted with %d bytes, gas left %d" (String.length output)
        (Gas.remaining gas_left)
  | Failed error -> Printf.sprintf "failed: %s" (error_to_string error)

(* The frame's whole state: where execution is, and the three resources it
   spends. Everything else an instruction could want belongs to a chunk that is
   not written yet. *)
type machine = {
  pc : int;
  stack : Stack.t;
  memory : Memory.t;
  gas : Gas.t;
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
                   (fun stack -> { pc = m.pc + 1; stack; memory; gas })
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
                 { pc = m.pc + 1; stack; memory = write memory offset value; gas })
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

let execute code m = function
  | Opcode.Stop -> Halt (Stopped { gas_left = m.gas })
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
      halt_with_output (fun output gas_left -> Returned { output; gas_left }) m
  | Opcode.Revert ->
      halt_with_output (fun output gas_left -> Reverted { output; gas_left }) m
  | Opcode.Invalid -> Halt (Failed (Invalid_opcode (Opcode.to_byte Opcode.Invalid)))

(* One instruction: decode the byte at the program counter, charge the fixed
   price before running it — so an instruction that then fails on its operands
   has still paid, as in revm — and dispatch. A byte naming no instruction halts
   the machine; so does an allowance that cannot pay for one. *)
let step code m =
  let byte = Code.byte_at code m.pc in
  Option.fold ~none:(Halt (Failed (Invalid_opcode byte)))
    ~some:(fun op ->
      Option.fold ~none:(Halt (Failed Out_of_gas))
        ~some:(fun gas -> execute code { m with gas } op)
        (Gas.charge (Gas.static_cost op) m.gas))
    (Opcode.decode byte)

(* The dispatch loop. Every instruction that continues costs at least one unit of
   gas, so the allowance strictly decreases with each step and the recursion
   terminates on every program. *)
let rec drive code m =
  match step code m with
  | Continue next -> drive code next
  | Halt outcome -> outcome

let run ~code ~gas =
  drive code { pc = 0; stack = Stack.empty; memory = Memory.empty; gas }
