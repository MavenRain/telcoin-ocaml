(* Tests for the EVM interpreter machine: the operand stack, byte-addressed
   memory and its expansion pricing, the gas schedule, jump-destination analysis,
   and the dispatch loop that folds them through bytecode.

   Three batches. First, unit tests of each component in isolation, where the
   boundaries live — the stack at 1024 words, memory rounding a partial word up,
   the quadratic term of the expansion cost, a [JUMPDEST] byte hiding inside push
   data. Second, whole programs run end to end with their gas cost computed by
   hand from the schedule, so a wrong price for any single instruction fails a
   test rather than quietly changing what a contract costs; each program returns
   its result through memory, which is the only thing an outside observer of a
   frame can see. Third, randomised properties: that the interpreter's wiring of
   each opcode agrees with the {!Alu} the opcode dispatches to, that decoding
   round-trips over every byte, that the termination argument the loop relies on
   actually holds of the schedule, and that no random bytecode can make the
   machine raise. The qcheck driver is pinned to a fixed [Random.State] so the
   sampled cases — and the verdict — replay. *)

module U256 = Tn_state.U256
module World_state = Tn_state.World_state
module Units = Tn_types.Units
module Access = Tn_evm.Access
module Alu = Tn_evm.Alu
module Code = Tn_evm.Code
module Data = Tn_evm.Data
module Depth = Tn_evm.Depth
module Effects = Tn_evm.Effects
module Env = Tn_evm.Env
module Gas = Tn_evm.Gas
module Interpreter = Tn_evm.Interpreter
module Memory = Tn_evm.Memory
module Opcode = Tn_evm.Opcode
module Refund = Tn_evm.Refund
module Stack = Tn_evm.Stack

let get = function Some x -> x | None -> Alcotest.fail "expected Some"
let u n = get (U256.of_int n)
let hex s = get (U256.of_hex s)
let gas_of n = get (Gas.of_int n)
let depth_of n = get (Depth.of_int n)
let width_of n = get (Opcode.Push_bytes.of_int n)

(* The interpreter takes a context and an effects accumulator. Nothing in this
   file exercises either — the host seam has its own suite — so the world and the
   access set are empty and the programs below neither read the context nor touch
   the world.

   The environment is nevertheless built from DISTINCT, nonzero values rather
   than the zeros it used to hold, and the reason is exactly that nothing here
   should be able to tell. Every gas figure and every expected output in this file
   is computed on the assumption that no program reads the context; with the
   fixture all zeros that assumption was untestable, because a program that DID
   read a field would push the same zero as one that read nothing. Nonzero
   discriminating values turn the assumption into something the suite checks:
   were any figure below secretly reading a field, it would move the moment these
   constants did.

   The constants deliberately differ from the ones [test_host_seam.ml] uses. The
   two files are separate executables with separate fixtures, and disagreeing
   values mean a figure accidentally hardcoded from one cannot pass in the other.
   That file is where the fields are asserted; here they are only required to be
   invisible.

   Passing [Access.empty] is a deliberately unreal starting point (a real
   transaction pre-warms the target, the origin and the coinbase), and it is
   harmless precisely because no program here contains an instruction that could
   observe it. *)
let address_of n =
  get (Units.Address.of_bytes (String.make (Units.Address.length - 1) '\000' ^ String.make 1 (Char.chr n)))

let base_env =
  Env.make
    ~block:
      (Env.Block.make ~coinbase:(address_of 0xc0) ~timestamp:(u 1_600_000_000)
         ~number:(u 15_500_000)
         ~prevrandao:
           (hex "4b7e19a2c05d38f61ea4907c2d5b8e3f016ca94d7b2e58301fc6a9d4e07b3521")
         ~gas_limit:(u 25_000_000) ~basefee:(u 3_500_000_000)
         ~chain_id:(u 4_321))
    ~tx:
      (Env.Tx.make ~origin:(address_of 0x01) ~gas_price:(u 9_000_000_000)
         ~access_list:[])
    ~call:
      (Env.Call.make ~target:(address_of 0x02) ~caller:(address_of 0x0c)
         ~value:(u 500_000_000_000_000_000) ~data:Data.empty)

let base_effects = Effects.start ~world:World_state.empty ~access:Access.empty

let u256 =
  Alcotest.testable (fun ppf w -> Format.pp_print_string ppf (U256.to_hex w)) U256.equal

(* ---------- a miniature assembler ---------- *)

let byte b = String.make 1 (Char.chr b)
let op o = byte (Opcode.to_byte o)
let push1 n = op (Opcode.Push (width_of 1)) ^ byte n
let push2 hi lo = op (Opcode.Push (width_of 2)) ^ byte hi ^ byte lo
let push32 w = op (Opcode.Push (width_of 32)) ^ U256.to_be_bytes w
let asm parts = Code.of_string (String.concat "" parts)

(* An outcome projected to comparable data: the kind of halt, the output bytes,
   the gas left (which a failure does not have, so it reads as [-1] — a value no
   successful halt can produce), and the effects it carries, if the constructor
   has any. Comparing projections needs no case analysis across constructors.

   The fourth component is not decoration. The expected values below all name
   [effects = base_effects], and while this projection dropped the field those
   were dead text: they READ like assertions, and every one of them would have
   held with any effects whatever in the outcome. A dead expectation is worse
   than an absent one, because it advertises a check that is not happening. So
   the field is compared, and the twelve [check_outcome] cases now genuinely
   assert that a program which touches no storage hands its effects back
   untouched. *)
let view = function
  | Interpreter.Stopped { gas_left; effects } ->
      ("stopped", "", Gas.remaining gas_left, Some effects)
  | Interpreter.Returned { output; gas_left; effects } ->
      ("returned", output, Gas.remaining gas_left, Some effects)
  | Interpreter.Reverted { output; gas_left } ->
      ("reverted", output, Gas.remaining gas_left, None)
  | Interpreter.Failed error -> (Interpreter.error_to_string error, "", -1, None)

(* Enough of an [Effects.t] to read a mismatch from the failure message. The
   refund and the account count are the two components a stray write moves. *)
let pp_effects ppf = function
  | None -> Format.pp_print_string ppf "no effects"
  | Some effects ->
      Format.fprintf ppf "refund=%d accounts=%d"
        (Refund.to_int (Effects.refund effects))
        (List.length (World_state.accounts (Effects.world effects)))

let pp_outcome ppf outcome =
  let kind, output, gas_left, effects = view outcome in
  Format.fprintf ppf "%s [%s] gas=%d %a" kind
    (String.concat ""
       (List.init (String.length output) (fun i ->
            Printf.sprintf "%02x" (Char.code (String.get output i)))))
    gas_left pp_effects effects

let outcome =
  Alcotest.testable pp_outcome (fun a b ->
      let ka, oa, ga, ea = view a and kb, ob, gb, eb = view b in
      String.equal ka kb && String.equal oa ob && Int.equal ga gb
      && Option.equal Effects.equal ea eb)

let check_outcome msg expected actual = Alcotest.(check outcome) msg expected actual

(* ---------- stack ---------- *)

let ok = function Ok x -> x | Error _ -> Alcotest.fail "expected Ok"

let test_stack_push_pop () =
  let s = ok (Stack.push (u 7) Stack.empty) in
  Alcotest.(check int) "one word deep" 1 (Stack.depth s);
  let w, s = ok (Stack.pop s) in
  Alcotest.(check u256) "the word comes back" (u 7) w;
  Alcotest.(check int) "empty again" 0 (Stack.depth s);
  Alcotest.(check bool) "popping empty underflows" true
    (Result.is_error (Stack.pop Stack.empty))

let test_stack_limit () =
  (* Exactly [limit] words fit; the next push is refused and the stack is
     unchanged, never 1025 words deep. *)
  let full =
    List.fold_left (fun s i -> ok (Stack.push (u i) s)) Stack.empty
      (List.init Stack.limit (fun i -> i))
  in
  Alcotest.(check int) "full at the limit" 1024 (Stack.depth full);
  Alcotest.(check bool) "one more overflows" true
    (Result.is_error (Stack.push U256.zero full));
  let one_short = snd (ok (Stack.pop full)) in
  Alcotest.(check bool) "one below the limit still accepts" true
    (Result.is_ok (Stack.push U256.zero one_short))

let test_stack_dup () =
  (* [DUP2] copies the second word from the top; the top is unchanged and the
     stack is one deeper. *)
  let s = ok (Stack.push (u 2) (ok (Stack.push (u 1) Stack.empty))) in
  let duped = ok (Stack.dup (depth_of 2) s) in
  Alcotest.(check (list u256))
    "dup2 copies the deeper word to the top" [ u 1; u 2; u 1 ]
    (Stack.to_list duped);
  Alcotest.(check bool) "dup deeper than the stack underflows" true
    (Result.is_error (Stack.dup (depth_of 3) s));
  Alcotest.(check bool) "dup1 of one word is fine" true
    (Result.is_ok (Stack.dup (depth_of 1) (ok (Stack.push (u 9) Stack.empty))))

let test_stack_swap () =
  let s =
    ok (Stack.push (u 3) (ok (Stack.push (u 2) (ok (Stack.push (u 1) Stack.empty)))))
  in
  Alcotest.(check (list u256))
    "swap1 exchanges the top two" [ u 2; u 3; u 1 ]
    (Stack.to_list (ok (Stack.swap (depth_of 1) s)));
  Alcotest.(check (list u256))
    "swap2 exchanges the top with the third" [ u 1; u 2; u 3 ]
    (Stack.to_list (ok (Stack.swap (depth_of 2) s)));
  Alcotest.(check int) "the depth is unchanged" 3
    (Stack.depth (ok (Stack.swap (depth_of 2) s)));
  Alcotest.(check bool) "swap past the bottom underflows" true
    (Result.is_error (Stack.swap (depth_of 3) s))

(* ---------- memory ---------- *)

let test_memory_words_needed () =
  let needed offset length = Memory.words_needed ~offset ~length in
  Alcotest.(check (option int)) "a word at zero" (Some 1) (needed 0 32);
  Alcotest.(check (option int)) "one byte at zero still a word" (Some 1) (needed 0 1);
  Alcotest.(check (option int)) "a byte at 31 stays in the first word" (Some 1) (needed 31 1);
  Alcotest.(check (option int)) "a byte at 32 needs a second" (Some 2) (needed 32 1);
  Alcotest.(check (option int)) "a word at 1 straddles two" (Some 2) (needed 1 32);
  (* A zero length touches nothing, whatever the offset — the rule [RETURN] and
     [REVERT] rely on to accept an enormous offset with no output. *)
  Alcotest.(check (option int)) "zero length needs nothing" (Some 0) (needed 0 0);
  Alcotest.(check (option int)) "zero length at a huge offset too" (Some 0)
    (needed max_int 0);
  Alcotest.(check (option int)) "an unrepresentable extent is refused" None
    (needed max_int 1);
  (* Everything past [Memory.max_extent] is refused outright rather than priced.
     These extents used to be admitted and left to the gas curve, which made them
     payable up to roughly 1.55e12 bytes and let a copy drive the interpreter into
     an allocation instead of an outcome. *)
  List.iter
    (fun (offset, length) ->
      Alcotest.(check (option int))
        (Printf.sprintf "extent %d+%d is past the bound" offset length)
        None (needed offset length))
    [
      (max_int - 32, 32);
      (max_int - 40, 32);
      (max_int - 31, 1);
      (max_int - 1, 1);
      (0, max_int - 10);
      (0, max_int);
      (Memory.max_extent, 1);
      (1, Memory.max_extent);
      (Memory.max_extent / 2, (Memory.max_extent / 2) + 1);
    ]
  ;
  (* The bound itself is reachable, and rounding an extent up to whole words at
     the boundary must not overflow: a negative count would read downstream as
     "no expansion needed" and hand out that memory for free. *)
  Alcotest.(check (option int)) "the bound itself is admitted"
    (Some (Memory.max_extent / 32))
    (needed (Memory.max_extent - 32) 32);
  Alcotest.(check bool) "an extent at the bound rounds up positively" true
    (Option.fold ~none:false ~some:(fun w -> w > 0) (needed (Memory.max_extent - 1) 1))

let test_memory_read_write () =
  let m = Memory.store_word Memory.empty 0 (u 0x1234) in
  Alcotest.(check u256) "a word reads back" (u 0x1234) (Memory.load_word m 0);
  Alcotest.(check u256) "untouched memory is zero" U256.zero (Memory.load_word m 32);
  (* A byte written at an offset is the most significant byte of the word read
     from that offset. *)
  let b = Memory.store_byte Memory.empty 0 0xff in
  Alcotest.(check u256)
    "mstore8 writes the top byte of the word at that offset"
    (hex ("ff" ^ String.make 62 '0'))
    (Memory.load_word b 0);
  Alcotest.(check string) "a slice is zero-filled past what was written"
    "\x12\x00\x00" (Memory.slice (Memory.store_byte Memory.empty 5 0x12) ~offset:5 ~length:3);
  (* The representation is canonical: writing zeros is writing nothing. *)
  Alcotest.(check bool) "writing a zero word leaves memory equal to empty" true
    (Memory.equal (Memory.expand Memory.empty 1)
       (Memory.expand (Memory.store_word Memory.empty 0 U256.zero) 1))

let test_memory_size () =
  Alcotest.(check int) "empty memory is empty" 0 (Memory.size_bytes Memory.empty);
  (* Expansion rounds up to whole words, so a single byte makes MSIZE 32. *)
  Alcotest.(check int) "one byte expands to a word" 32
    (Memory.size_bytes (Memory.expand Memory.empty 1));
  Alcotest.(check int) "expansion never shrinks" 64
    (Memory.size_bytes (Memory.expand (Memory.expand Memory.empty 2) 1))

(* ---------- gas ---------- *)

let test_gas_memory_cost () =
  let cost w = Gas.memory_cost w in
  Alcotest.(check (option int)) "nothing costs nothing" (Some 0) (cost 0);
  Alcotest.(check (option int)) "one word" (Some 3) (cost 1);
  Alcotest.(check (option int)) "two words" (Some 6) (cost 2);
  (* The quadratic term only starts to bite at 512 words: 3*512 + 512^2/512. *)
  Alcotest.(check (option int)) "512 words" (Some (1536 + 512)) (cost 512);
  Alcotest.(check (option int)) "1024 words" (Some (3072 + 2048)) (cost 1024);
  (* Below 512 words the quadratic term is a genuine truncated division, not zero:
     100 words is 300 + 10000/512 = 300 + 19. *)
  Alcotest.(check (option int)) "100 words" (Some (300 + 19)) (cost 100);
  (* A memory no allowance could pay for is refused rather than wrapped. *)
  Alcotest.(check (option int)) "an unpayable memory is refused" None (cost max_int);
  (* No words is free, and so is a count below zero — which no caller produces,
     since the only source of one refuses to return a negative. *)
  Alcotest.(check (option int)) "a negative count is free" (Some 0) (cost (-1))

let test_gas_expansion () =
  Alcotest.(check (option int)) "growing from one word to three"
    (Some (Gas.memory_cost 3 |> get |> fun c -> c - get (Gas.memory_cost 1)))
    (Gas.expansion_cost ~current:1 ~next:3);
  Alcotest.(check (option int)) "already paid for" (Some 0)
    (Gas.expansion_cost ~current:3 ~next:3);
  Alcotest.(check (option int)) "shrinking is free" (Some 0)
    (Gas.expansion_cost ~current:5 ~next:2)

let test_gas_exp_cost () =
  Alcotest.(check int) "a zero exponent has no byte" 0 (Gas.exp_cost U256.zero);
  Alcotest.(check int) "a one-byte exponent" 50 (Gas.exp_cost (u 255));
  Alcotest.(check int) "a two-byte exponent" 100 (Gas.exp_cost (u 256));
  Alcotest.(check int) "a full-width exponent" (50 * 32) (Gas.exp_cost U256.max_value)

let test_gas_static_cost () =
  Alcotest.(check int) "add is verylow" 3 (Gas.static_cost Opcode.Add);
  Alcotest.(check int) "mul is low" 5 (Gas.static_cost Opcode.Mul);
  Alcotest.(check int) "addmod is mid" 8 (Gas.static_cost Opcode.Addmod);
  Alcotest.(check int) "jump is mid" 8 (Gas.static_cost Opcode.Jump);
  Alcotest.(check int) "jumpi is high" 10 (Gas.static_cost Opcode.Jumpi);
  Alcotest.(check int) "jumpdest is one" 1 (Gas.static_cost Opcode.Jumpdest);
  Alcotest.(check int) "pop is base" 2 (Gas.static_cost Opcode.Pop);
  Alcotest.(check int) "push0 is base" 2 (Gas.static_cost Opcode.Push0);
  Alcotest.(check int) "push1 is verylow" 3 (Gas.static_cost (Opcode.Push (width_of 1)));
  Alcotest.(check int) "dup16 is verylow" 3 (Gas.static_cost (Opcode.Dup (depth_of 16)));
  Alcotest.(check int) "stop is free" 0 (Gas.static_cost Opcode.Stop)

(* ---------- code analysis ---------- *)

let test_code_jumpdests () =
  (* A real [JUMPDEST] is found; the identical byte inside a [PUSH] immediate is
     not, because the analysis steps over the immediate. *)
  let real = Code.of_string (String.concat "" [ push1 0; op Opcode.Jumpdest; op Opcode.Stop ]) in
  Alcotest.(check (list int)) "a genuine destination" [ 2 ] (Code.jumpdests real);
  let hidden = Code.of_string (String.concat "" [ push1 (Opcode.to_byte Opcode.Jumpdest) ]) in
  Alcotest.(check (list int)) "one hidden in push data is not a destination" []
    (Code.jumpdests hidden);
  (* A truncated trailing push takes its immediate from past the end, so the
     analysis simply ends. *)
  let truncated = Code.of_string (op (Opcode.Push (width_of 32)) ^ String.make 3 '\x5b') in
  Alcotest.(check (list int)) "push data past the end is still push data" []
    (Code.jumpdests truncated)

let test_code_bytes () =
  let code = Code.of_string (push1 0x2a) in
  Alcotest.(check int) "length is what was given" 2 (Code.length code);
  Alcotest.(check int) "the immediate byte" 0x2a (Code.byte_at code 1);
  (* Past either end the code reads as STOP, which is what makes a program
     counter that walks off the end halt rather than fault. *)
  Alcotest.(check int) "past the end is stop" 0 (Code.byte_at code 2);
  Alcotest.(check int) "far past the end is stop" 0 (Code.byte_at code 1_000);
  Alcotest.(check int) "before the start is stop" 0 (Code.byte_at code (-1))

(* ---------- whole programs, with gas computed from the schedule ---------- *)

let run code gas =
  Interpreter.run ~env:base_env ~code ~gas:(gas_of gas) ~effects:base_effects
let word_output w = U256.to_be_bytes w

(* Store the top of the stack at memory zero and return those 32 bytes: the
   epilogue every program below uses to make its result observable. *)
let return_top = [ push1 0x00; op Opcode.Mstore; push1 0x20; push1 0x00; op Opcode.Return ]

(* Its cost: PUSH1 3, MSTORE 3 + 3 for the first word of memory, PUSH1 3,
   PUSH1 3, RETURN 0 (the word is already paid for). *)
let return_top_cost = 3 + 6 + 3 + 3 + 0

let test_program_add () =
  let code = asm ([ push1 2; push1 3; op Opcode.Add ] @ return_top) in
  let spent = 3 + 3 + 3 + return_top_cost in
  check_outcome "two and three make five"
    (Interpreter.Returned { effects = base_effects; output = word_output (u 5); gas_left = gas_of (1_000 - spent) })
    (run code 1_000)

let test_program_empty () =
  check_outcome "empty code stops having spent nothing"
    (Interpreter.Stopped { effects = base_effects; gas_left = gas_of 100 })
    (run (Code.of_string "") 100);
  (* Walking off the end of the code is the same halt as an explicit STOP. *)
  check_outcome "a program counter off the end stops"
    (Interpreter.Stopped { effects = base_effects; gas_left = gas_of 97 })
    (run (asm [ push1 1 ]) 100)

let test_program_memory_expansion () =
  (* Writing at offset 32 reaches two words and pays for both at once. *)
  let code = asm [ push1 0x00; push1 0x20; op Opcode.Mstore ] in
  let spent = 3 + 3 + (3 + 6) in
  check_outcome "a store at the second word pays for two"
    (Interpreter.Stopped { effects = base_effects; gas_left = gas_of (1_000 - spent) })
    (run code 1_000);
  (* And a second store inside what is already paid for adds nothing. *)
  let twice =
    asm [ push1 0x00; push1 0x20; op Opcode.Mstore; push1 0x00; push1 0x00; op Opcode.Mstore ]
  in
  check_outcome "a store inside paid-for memory expands nothing"
    (Interpreter.Stopped { effects = base_effects; gas_left = gas_of (1_000 - spent - 3 - 3 - 3) })
    (run twice 1_000)

let test_program_msize () =
  (* A single byte written at zero makes MSIZE report a whole word. *)
  let code =
    asm ([ push1 0xff; push1 0x00; op Opcode.Mstore8; op Opcode.Msize ] @ return_top)
  in
  (* The byte store has already paid for the first word, so the epilogue's own
     store expands nothing and costs only its fixed price — [return_top_cost]
     less the 3 it usually pays for that first word. *)
  let spent = 3 + 3 + (3 + 3) + 2 + (return_top_cost - 3) in
  check_outcome "msize rounds a partial word up"
    (Interpreter.Returned { effects = base_effects; output = word_output (u 32); gas_left = gas_of (1_000 - spent) })
    (run code 1_000)

let test_program_pc () =
  (* PC reports the offset of the PC instruction itself, not the next byte. *)
  let code =
    asm
      [
        op Opcode.Pc;    (* 0: pushes 0 *)
        push1 0x00;      (* 1 *)
        op Opcode.Mstore;(* 3 *)
        op Opcode.Pc;    (* 4: pushes 4 *)
        push1 0x20;      (* 5 *)
        op Opcode.Mstore;(* 7 *)
        push1 0x40;      (* 8 *)
        push1 0x00;      (* 10 *)
        op Opcode.Return;(* 12 *)
      ]
  in
  let spent = 2 + 3 + (3 + 3) + 2 + 3 + (3 + 3) + 3 + 3 + 0 in
  check_outcome "pc is the offset of the pc instruction"
    (Interpreter.Returned
       { effects = base_effects;
         output = word_output U256.zero ^ word_output (u 4);
         gas_left = gas_of (1_000 - spent);
       })
    (run code 1_000)

let test_program_gas () =
  (* GAS reports what is left once its own price has been paid. *)
  let code = asm ([ op Opcode.Gas ] @ return_top) in
  let spent = 2 + return_top_cost in
  check_outcome "gas reports the balance after its own cost"
    (Interpreter.Returned
       { effects = base_effects; output = word_output (u (1_000 - 2)); gas_left = gas_of (1_000 - spent) })
    (run code 1_000)

let test_program_jump () =
  let code =
    asm
      [
        push1 0x05;        (* 0 *)
        op Opcode.Jump;    (* 2 *)
        op Opcode.Invalid; (* 3, skipped *)
        op Opcode.Invalid; (* 4, skipped *)
        op Opcode.Jumpdest;(* 5 *)
        op Opcode.Stop;    (* 6 *)
      ]
  in
  check_outcome "a jump lands on the jumpdest and skips what is between"
    (Interpreter.Stopped { effects = base_effects; gas_left = gas_of (1_000 - 3 - 8 - 1) })
    (run code 1_000)

let test_program_jump_invalid () =
  (* The destination byte is a 0x5b, but it is the immediate of a PUSH1, so it is
     not an instruction and cannot be jumped to. *)
  let code =
    asm
      [
        push1 0x04;                                (* 0 *)
        op Opcode.Jump;                            (* 2 *)
        push1 (Opcode.to_byte Opcode.Jumpdest);    (* 3, its immediate is at 4 *)
        op Opcode.Stop;                            (* 5 *)
      ]
  in
  check_outcome "a jump into push data is invalid"
    (Interpreter.Failed Interpreter.Invalid_jump)
    (run code 1_000);
  check_outcome "a jump past the end of the code is invalid"
    (Interpreter.Failed Interpreter.Invalid_jump)
    (run (asm [ push1 0xff; op Opcode.Jump ]) 1_000);
  (* A destination too large to be an offset at all fails the same way. *)
  check_outcome "an enormous destination is invalid"
    (Interpreter.Failed Interpreter.Invalid_jump)
    (run (asm [ push32 U256.max_value; op Opcode.Jump ]) 1_000)

let test_program_jumpi () =
  (* A zero condition falls through without looking at the destination, so an
     impossible destination is not an error when the branch is not taken. *)
  let not_taken = asm [ push1 0x00; push1 0xff; op Opcode.Jumpi; op Opcode.Stop ] in
  check_outcome "a zero condition falls through and never checks the destination"
    (Interpreter.Stopped { effects = base_effects; gas_left = gas_of (1_000 - 3 - 3 - 10) })
    (run not_taken 1_000);
  (* Any nonzero condition takes the branch — not only one. *)
  let taken =
    asm
      [
        push1 0x02;         (* 0: a condition that is neither zero nor one *)
        push1 0x07;         (* 2 *)
        op Opcode.Jumpi;    (* 4 *)
        op Opcode.Invalid;  (* 5 *)
        op Opcode.Invalid;  (* 6 *)
        op Opcode.Jumpdest; (* 7 *)
        op Opcode.Stop;     (* 8 *)
      ]
  in
  check_outcome "any nonzero condition branches"
    (Interpreter.Stopped { effects = base_effects; gas_left = gas_of (1_000 - 3 - 3 - 10 - 1) })
    (run taken 1_000);
  check_outcome "a taken branch to an invalid destination fails"
    (Interpreter.Failed Interpreter.Invalid_jump)
    (run (asm [ push1 0x01; push1 0xff; op Opcode.Jumpi ]) 1_000)

let test_program_push_immediate () =
  (* The immediate bytes are the value's low-order bytes, zero-extended to the
     word. *)
  let code = asm ([ push2 0x01 0x00 ] @ return_top) in
  check_outcome "a two-byte immediate is big-endian in the low bytes"
    (Interpreter.Returned
       { effects = base_effects; output = word_output (u 256); gas_left = gas_of (1_000 - 3 - return_top_cost) })
    (run code 1_000);
  (* An immediate the code cuts short reads its missing bytes as zero and the
     program counter lands past the end, which halts. *)
  let truncated = Code.of_string (op (Opcode.Push (width_of 2)) ^ byte 0x01) in
  check_outcome "a truncated immediate is zero-extended and then stops"
    (Interpreter.Stopped { effects = base_effects; gas_left = gas_of (1_000 - 3) })
    (run truncated 1_000)

let test_program_mload () =
  (* Write a word, read it back from the same offset, and return what was read,
     so the output proves the load saw what the store wrote. *)
  let code =
    asm
      [
        push1 0x42; push1 0x00; op Opcode.Mstore;  (* 0..32 := 0x42 *)
        push1 0x00; op Opcode.Mload;               (* push 0..32 *)
        push1 0x20; op Opcode.Mstore;              (* 32..64 := it *)
        push1 0x20; push1 0x20; op Opcode.Return;  (* return 32..64 *)
      ]
  in
  let spent = 3 + 3 + (3 + 3) + 3 + 3 + 3 + (3 + 3) + 3 + 3 + 0 in
  check_outcome "a load reads back what was stored"
    (Interpreter.Returned
       { effects = base_effects; output = word_output (u 0x42); gas_left = gas_of (1_000 - spent) })
    (run code 1_000);
  (* A load of memory that was never written reads zero, and pays to reach it. *)
  let unwritten = asm ([ push1 0x00; op Opcode.Mload ] @ return_top) in
  let unwritten_spent = 3 + (3 + 3) + (return_top_cost - 3) in
  check_outcome "a load of untouched memory reads zero and pays for the word"
    (Interpreter.Returned
       { effects = base_effects; output = word_output U256.zero; gas_left = gas_of (1_000 - unwritten_spent) })
    (run unwritten 1_000)

let test_program_unary_and_pop () =
  (* The single-operand dispatch path, and the two instructions that use it. *)
  let iszero = asm ([ push1 0x00; op Opcode.Iszero ] @ return_top) in
  check_outcome "iszero of zero is one"
    (Interpreter.Returned
       { effects = base_effects; output = word_output U256.one; gas_left = gas_of (1_000 - 3 - 3 - return_top_cost) })
    (run iszero 1_000);
  let complement = asm ([ push1 0x00; op Opcode.Not ] @ return_top) in
  check_outcome "not of zero is every bit set"
    (Interpreter.Returned
       { effects = base_effects;
         output = word_output U256.max_value;
         gas_left = gas_of (1_000 - 3 - 3 - return_top_cost);
       })
    (run complement 1_000);
  (* POP discards the top word, uncovering the one beneath. *)
  let popped = asm ([ push1 0xaa; push1 0xbb; op Opcode.Pop ] @ return_top) in
  check_outcome "pop uncovers the word beneath"
    (Interpreter.Returned
       { effects = base_effects;
         output = word_output (u 0xaa);
         gas_left = gas_of (1_000 - 3 - 3 - 2 - return_top_cost);
       })
    (run popped 1_000);
  (* PUSH0 pushes a zero word and carries no immediate. *)
  let zero = asm ([ op Opcode.Push0 ] @ return_top) in
  check_outcome "push0 pushes zero"
    (Interpreter.Returned
       { effects = base_effects; output = word_output U256.zero; gas_left = gas_of (1_000 - 2 - return_top_cost) })
    (run zero 1_000)

let test_program_extent_at_the_limit () =
  (* An offset near the top of the representable range must halt, not quietly
     store for the price of the instruction alone. Rounding the extent up to whole
     words used to wrap negative here, which read as "no expansion needed": the
     store succeeded for 3 gas and MSIZE still reported zero.

     The halt is [Offset_too_large] and not [Out_of_gas] because these extents now
     fail [Memory.words_needed]'s [Memory.max_extent] test before any price is
     computed — the refusal does not consult the allowance at all. *)
  let near_limit = get (U256.of_int (max_int - 40)) in
  let storing = asm [ push1 0x00; push32 near_limit; op Opcode.Mstore ] in
  check_outcome "a store at the representable limit is refused"
    (Interpreter.Failed Interpreter.Offset_too_large)
    (run storing 1_000);
  let loading = asm [ push32 near_limit; op Opcode.Mload ] in
  check_outcome "a load there is refused too"
    (Interpreter.Failed Interpreter.Offset_too_large)
    (run loading 1_000);
  (* And the same for a length rather than an offset, which additionally used to
     reach the output slice and raise out of the interpreter. *)
  let returning =
    asm [ push32 (get (U256.of_int (max_int - 10))); push1 0x00; op Opcode.Return ]
  in
  check_outcome "a return of a length at the limit is refused"
    (Interpreter.Failed Interpreter.Offset_too_large)
    (run returning 1_000);
  (* The reproducer from the finding. A copy length below the old [max_int] guard
     is payable, because the copy price is LINEAR — three per word — so no
     allowance short of the extent bound stops it reaching the byte producer,
     which then builds the string. [Memory.max_extent] is what refuses it now.

     The whole copy family goes through the same [plan_copy] and the same [reach],
     so all three are driven here rather than only the one the finding happened to
     name. MCOPY additionally reads its source through [Memory.slice].

     The wall clock is part of the assertion, and it is the only part that can
     speak to the defect's actual symptom. Under the bug this program does not
     produce a wrong answer to compare against — it attempts a 1.55-terabyte
     allocation, so the suite hangs or dies rather than failing. The bound is
     deliberately enormous: the correct answer takes microseconds, and anything
     here measured in seconds is the bug. *)
  let huge_length = get (U256.of_int 1_550_000_000_000) in
  let unpayable_allowance = 4_582_405_380_957_031_300 in
  let started = Sys.time () in
  List.iter
    (fun (name, opcode) ->
      let copying =
        asm [ push32 huge_length; op Opcode.Push0; op Opcode.Push0; op opcode; op Opcode.Stop ]
      in
      check_outcome
        (name ^ ": a copy length no allowance can reach is refused, not allocated")
        (Interpreter.Failed Interpreter.Offset_too_large)
        (run copying unpayable_allowance))
    [ ("CALLDATACOPY", Opcode.Calldatacopy); ("CODECOPY", Opcode.Codecopy);
      ("MCOPY", Opcode.Mcopy) ];
  Alcotest.(check bool) "and all three answer at once rather than allocating" true
    (Sys.time () -. started < 5.0);
  (* The same length as a RETURN, which reaches the output slice rather than the
     copy path, and the same length as a plain expansion. *)
  let returning_huge = asm [ push32 huge_length; op Opcode.Push0; op Opcode.Return ] in
  check_outcome "a return of that length is refused too"
    (Interpreter.Failed Interpreter.Offset_too_large)
    (run returning_huge unpayable_allowance);
  let storing_huge = asm [ op Opcode.Push0; push32 huge_length; op Opcode.Mstore ] in
  check_outcome "and a store at that offset"
    (Interpreter.Failed Interpreter.Offset_too_large)
    (run storing_huge unpayable_allowance);
  (* The bound is a bound and not a blanket refusal: an extent just inside it is
     still admitted and still priced, so it fails for want of gas rather than on
     the offset rule. This is what says [max_extent] did not simply break the
     copy family. *)
  let just_inside =
    asm
      [ push32 (get (U256.of_int (Memory.max_extent - 32)));
        op Opcode.Push0; op Opcode.Push0; op Opcode.Calldatacopy; op Opcode.Stop ]
  in
  check_outcome "a length just inside the bound is priced, not refused"
    (Interpreter.Failed Interpreter.Out_of_gas)
    (run just_inside 1_000_000)

let test_program_dup_swap () =
  let dup = asm ([ push1 0xaa; push1 0xbb; op (Opcode.Dup (depth_of 2)) ] @ return_top) in
  check_outcome "dup2 brings the deeper word to the top"
    (Interpreter.Returned
       { effects = base_effects;
         output = word_output (u 0xaa);
         gas_left = gas_of (1_000 - 3 - 3 - 3 - return_top_cost);
       })
    (run dup 1_000);
  let swap = asm ([ push1 0xaa; push1 0xbb; op (Opcode.Swap (depth_of 1)) ] @ return_top) in
  check_outcome "swap1 exchanges the top two"
    (Interpreter.Returned
       { effects = base_effects;
         output = word_output (u 0xaa);
         gas_left = gas_of (1_000 - 3 - 3 - 3 - return_top_cost);
       })
    (run swap 1_000)

let test_program_revert () =
  let code = asm ([ push1 0x42 ] @ return_top) in
  let reverting =
    asm [ push1 0x42; push1 0x00; op Opcode.Mstore; push1 0x20; push1 0x00; op Opcode.Revert ]
  in
  let spent = 3 + return_top_cost in
  check_outcome "return hands back the slice"
    (Interpreter.Returned
       { effects = base_effects; output = word_output (u 0x42); gas_left = gas_of (1_000 - spent) })
    (run code 1_000);
  (* A revert keeps both its output and its unspent gas. *)
  check_outcome "revert hands back the slice and keeps its gas"
    (Interpreter.Reverted
       { output = word_output (u 0x42); gas_left = gas_of (1_000 - spent) })
    (run reverting 1_000)

let test_program_zero_length_return () =
  (* A zero-length return touches no memory, so its offset is never examined —
     even an offset larger than any addressable memory is fine, and nothing is
     charged for expansion. *)
  let code = asm [ push1 0x00; push32 U256.max_value; op Opcode.Return ] in
  check_outcome "a zero-length return ignores an enormous offset"
    (Interpreter.Returned { effects = base_effects; output = ""; gas_left = gas_of (1_000 - 3 - 3) })
    (run code 1_000);
  (* With a nonzero length that same offset cannot be paid for. *)
  let paying = asm [ push1 0x20; push32 U256.max_value; op Opcode.Return ] in
  check_outcome "a nonzero length at that offset cannot be paid for"
    (Interpreter.Failed Interpreter.Offset_too_large)
    (run paying 1_000)

let test_program_exp_cost () =
  (* EXP pays ten plus fifty per byte of its exponent. *)
  let code = asm [ push2 0x01 0x00; push1 0x03; op Opcode.Exp ] in
  check_outcome "exp charges per byte of the exponent"
    (Interpreter.Stopped { effects = base_effects; gas_left = gas_of (10_000 - 3 - 3 - (10 + 100)) })
    (run code 10_000);
  let one_byte = asm [ push1 0xff; push1 0x03; op Opcode.Exp ] in
  check_outcome "a one-byte exponent costs fifty"
    (Interpreter.Stopped { effects = base_effects; gas_left = gas_of (10_000 - 3 - 3 - (10 + 50)) })
    (run one_byte 10_000);
  let zero = asm [ push1 0x00; push1 0x03; op Opcode.Exp ] in
  check_outcome "a zero exponent has no dynamic cost"
    (Interpreter.Stopped { effects = base_effects; gas_left = gas_of (10_000 - 3 - 3 - 10) })
    (run zero 10_000)

let test_program_out_of_gas () =
  check_outcome "an instruction that cannot be paid for halts"
    (Interpreter.Failed Interpreter.Out_of_gas)
    (run (asm [ push1 1 ]) 2);
  (* A loop is bounded by its fuel and nothing else: this program jumps to itself
     forever, and terminates only because gas runs out. *)
  let forever = asm [ op Opcode.Jumpdest; push1 0x00; op Opcode.Jump ] in
  check_outcome "an unbounded loop terminates out of gas"
    (Interpreter.Failed Interpreter.Out_of_gas)
    (run forever 10_000);
  (* Memory too expensive to reach is the same halt. The offset stays well inside
     [Memory.max_extent] on purpose: past that the halt is [Offset_too_large], and
     this case is about the gas curve refusing an extent it is willing to price.
     Sixteen mebibytes costs some 538 million units. *)
  let expensive = asm [ push1 0x00; push32 (U256.two_pow 24); op Opcode.Mstore ] in
  check_outcome "memory beyond the allowance halts out of gas"
    (Interpreter.Failed Interpreter.Out_of_gas)
    (run expensive 1_000)

let test_program_stack_errors () =
  check_outcome "an instruction with no operands underflows"
    (Interpreter.Failed Interpreter.Stack_underflow)
    (run (asm [ op Opcode.Add ]) 1_000);
  (* Exactly 1024 words fit; the next push halts the machine. *)
  let overflowing = asm (List.init (Stack.limit + 1) (fun _ -> push1 0x00)) in
  check_outcome "pushing past the limit overflows"
    (Interpreter.Failed Interpreter.Stack_overflow)
    (run overflowing 100_000);
  let exactly_full = asm (List.init Stack.limit (fun _ -> push1 0x00)) in
  check_outcome "exactly the limit is fine"
    (Interpreter.Stopped { effects = base_effects; gas_left = gas_of (100_000 - (3 * Stack.limit)) })
    (run exactly_full 100_000)

let test_program_invalid_opcode () =
  check_outcome "an unassigned byte halts"
    (Interpreter.Failed (Interpreter.Invalid_opcode 0x0c))
    (run (Code.of_string (byte 0x0c)) 1_000);
  check_outcome "the designated invalid instruction halts"
    (Interpreter.Failed (Interpreter.Invalid_opcode 0xfe))
    (run (asm [ op Opcode.Invalid ]) 1_000);
  (* An opcode deferred to a later chunk is refused rather than silently doing
     something else. 0x54 (SLOAD) used to stand here and now decodes, which is
     the whole point of the host seam; 0x20 is KECCAK256, deferred with the rest
     of this port's crypto, and 0xf1 is CALL, which needs a second frame. *)
  check_outcome "a deferred hash instruction halts"
    (Interpreter.Failed (Interpreter.Invalid_opcode 0x20))
    (run (Code.of_string (byte 0x20)) 1_000);
  check_outcome "a deferred call instruction halts"
    (Interpreter.Failed (Interpreter.Invalid_opcode 0xf1))
    (run (Code.of_string (byte 0xf1)) 1_000)

(* ---------- randomised properties ---------- *)

let gen_word =
  let open QCheck.Gen in
  let edges =
    [ U256.zero; U256.one; U256.max_value; U256.two_pow 255; U256.two_pow 128; u 2; u 255; u 256 ]
  in
  let random_bytes =
    map
      (fun s -> get (U256.of_be_bytes s))
      (string_size ~gen:(map Char.chr (int_range 0 255)) (return 32))
  in
  let small = map (fun n -> u n) (int_range 0 100_000) in
  int_range 0 8 >>= fun k ->
  if k < 2 then oneof_list edges else if k < 4 then small else random_bytes

let h1 = U256.to_hex

let mk ~salt ~count name arb fn =
  Alcotest.test_case name `Slow (fun () ->
      QCheck.Test.check_exn
        ~rand:(Random.State.make [| 0x5eed_e; salt |])
        (QCheck.Test.make ~count ~name arb fn))

(* Every byte either decodes to an instruction that encodes back to it, or does
   not decode at all — the encoding is injective and total on what it accepts. *)
let test_opcode_roundtrip () =
  List.iter
    (fun b ->
      Option.fold ~none:()
        ~some:(fun decoded ->
          Alcotest.(check int) (Printf.sprintf "0x%02x round-trips" b) b
            (Opcode.to_byte decoded))
        (Opcode.decode b))
    (List.init 256 (fun i -> i));
  Alcotest.(check (option int)) "a byte outside the range decodes to nothing" None
    (Option.map Opcode.to_byte (Opcode.decode 256));
  (* The families are contiguous and complete. *)
  Alcotest.(check int) "push1 is 0x60" 0x60 (Opcode.to_byte (Opcode.Push (width_of 1)));
  Alcotest.(check int) "push32 is 0x7f" 0x7f (Opcode.to_byte (Opcode.Push (width_of 32)));
  Alcotest.(check int) "dup1 is 0x80" 0x80 (Opcode.to_byte (Opcode.Dup (depth_of 1)));
  Alcotest.(check int) "swap16 is 0x9f" 0x9f (Opcode.to_byte (Opcode.Swap (depth_of 16)))

(* The dispatch loop terminates because every instruction that lets execution
   continue costs at least one unit of gas. That is a property of the schedule,
   so check it against the schedule: the only free instructions are the four that
   halt — and [SSTORE].

   [SSTORE]'s table entry is zero on purpose, exactly as revm leaves it
   ([instructions.rs:201-203]), so that EIP-2200's sentry reads an allowance the
   dispatch loop has not decremented. It is the one instruction whose decrease is
   restored by its own body rather than by the loop: [Gas.sstore_entry] takes 100
   before any path can continue. Listing it here as an exemption rather than
   weakening the check keeps the hole visible and countable — one instruction,
   named, with its guarantee written down. The property that the body really does
   charge belongs to the host-seam suite, which runs [SSTORE] programs. *)
let test_termination_invariant () =
  List.iter
    (fun b ->
      Option.fold ~none:()
        ~some:(fun decoded ->
          let free = Gas.static_cost decoded = 0 in
          let halts =
            List.exists (Opcode.equal decoded)
              [ Opcode.Stop; Opcode.Return; Opcode.Revert; Opcode.Invalid ]
          in
          let charges_in_its_body = Opcode.equal decoded Opcode.Sstore in
          Alcotest.(check bool)
            (Printf.sprintf "%s is free only if it halts" (Opcode.to_string decoded))
            true
            ((not free) || halts || charges_in_its_body))
        (Opcode.decode b))
    (List.init 256 (fun i -> i))

(* The immediate width every PUSH declares matches the byte range it occupies, so
   the program counter and the jump analysis step over exactly the right data. *)
let test_immediate_widths () =
  List.iter
    (fun width ->
      let opcode = Opcode.Push (width_of width) in
      Alcotest.(check int)
        (Printf.sprintf "push%d carries %d bytes" width width)
        width
        (Opcode.immediate_bytes opcode))
    (List.init 32 (fun i -> i + 1));
  Alcotest.(check int) "push0 carries none" 0 (Opcode.immediate_bytes Opcode.Push0);
  Alcotest.(check int) "add carries none" 0 (Opcode.immediate_bytes Opcode.Add)

(* Run a two-operand opcode through the machine and compare with the ALU it
   dispatches to. The first word pushed sits deeper, so the opcode's first
   argument — the word popped first — is the second one pushed. *)
let binary_program opcode a b =
  asm ([ push32 a; push32 b; op opcode ] @ return_top)

let ternary_program opcode a b c =
  asm ([ push32 a; push32 b; push32 c; op opcode ] @ return_top)

let returned_word outcome_value =
  match outcome_value with
  | Interpreter.Returned { output; _ } -> U256.of_be_bytes output
  | Interpreter.Stopped _ | Interpreter.Reverted _ | Interpreter.Failed _ -> None

let arb2 =
  QCheck.make
    ~print:(fun (a, b) -> Printf.sprintf "%s %s" (h1 a) (h1 b))
    QCheck.Gen.(pair gen_word gen_word)

let arb3 =
  QCheck.make
    ~print:(fun (a, b, c) -> Printf.sprintf "%s %s %s" (h1 a) (h1 b) (h1 c))
    QCheck.Gen.(triple gen_word gen_word gen_word)

let binary_agrees opcode alu (a, b) =
  Option.fold ~none:false
    ~some:(fun w -> U256.equal w (alu b a))
    (returned_word (run (binary_program opcode a b) 100_000))

let ternary_agrees opcode alu (a, b, c) =
  Option.fold ~none:false
    ~some:(fun w -> U256.equal w (alu c b a))
    (returned_word (run (ternary_program opcode a b c) 100_000))

(* Random bytecode must never make the machine raise, loop forever, or report
   more gas left than it started with. *)
let arb_code =
  QCheck.make
    ~print:(fun s ->
      String.concat ""
        (List.init (String.length s) (fun i -> Printf.sprintf "%02x" (Char.code (String.get s i)))))
    QCheck.Gen.(
      string_size ~gen:(map Char.chr (int_range 0 255)) (int_range 0 48))

let arb_words = QCheck.make ~print:(fun (a, b) -> Printf.sprintf "%d %d" a b)
    QCheck.Gen.(pair (int_range 0 5_000) (int_range 0 5_000))

(* Word counts spanning the whole range, so the sampling straddles the point
   where the exact cost stops being representable rather than staying safely
   below it. *)
let arb_word_count =
  QCheck.make ~print:string_of_int
    QCheck.Gen.(
      oneof
        [
          int_range 0 5_000;
          int_range 0 100_000_000;
          int_range 0 max_int;
          map (fun k -> max_int / (k + 1)) (int_range 0 64);
          (* Powers of two up to [2^61]; [1 lsl 62] is already negative in a
             63-bit int, and a negative count is not a word count. *)
          map (fun k -> 1 lsl k) (int_range 0 61);
        ])

(* Bytecode that cannot observe its own allowance: the GAS instruction is the
   only one that can, so replacing it makes a run's behaviour independent of how
   much gas it was given (beyond having enough). *)
let arb_code_no_gas =
  QCheck.make
    ~print:(fun s ->
      String.concat ""
        (List.init (String.length s) (fun i -> Printf.sprintf "%02x" (Char.code (String.get s i)))))
    QCheck.Gen.(
      string_size
        ~gen:
          (map
             (fun c -> if Char.code c = Opcode.to_byte Opcode.Gas then '\x00' else c)
             (map Char.chr (int_range 0 255)))
        (int_range 0 48))

let prop_cases =
  [
    mk ~salt:1 ~count:200 "add" arb2 (binary_agrees Opcode.Add Alu.add);
    mk ~salt:2 ~count:200 "mul" arb2 (binary_agrees Opcode.Mul Alu.mul);
    mk ~salt:3 ~count:200 "sub" arb2 (binary_agrees Opcode.Sub Alu.sub);
    mk ~salt:4 ~count:200 "div" arb2 (binary_agrees Opcode.Div Alu.div);
    mk ~salt:5 ~count:200 "sdiv" arb2 (binary_agrees Opcode.Sdiv Alu.sdiv);
    mk ~salt:6 ~count:200 "mod" arb2 (binary_agrees Opcode.Mod Alu.modulo);
    mk ~salt:7 ~count:200 "smod" arb2 (binary_agrees Opcode.Smod Alu.smod);
    mk ~salt:8 ~count:100 "exp" arb2 (binary_agrees Opcode.Exp Alu.exp);
    mk ~salt:9 ~count:200 "signextend" arb2 (binary_agrees Opcode.Signextend Alu.signextend);
    mk ~salt:10 ~count:200 "lt" arb2 (binary_agrees Opcode.Lt Alu.lt);
    mk ~salt:11 ~count:200 "gt" arb2 (binary_agrees Opcode.Gt Alu.gt);
    mk ~salt:12 ~count:200 "slt" arb2 (binary_agrees Opcode.Slt Alu.slt);
    mk ~salt:13 ~count:200 "sgt" arb2 (binary_agrees Opcode.Sgt Alu.sgt);
    mk ~salt:14 ~count:200 "eq" arb2 (binary_agrees Opcode.Eq Alu.eq);
    mk ~salt:15 ~count:200 "and" arb2 (binary_agrees Opcode.And Alu.logand);
    mk ~salt:16 ~count:200 "or" arb2 (binary_agrees Opcode.Or Alu.logor);
    mk ~salt:17 ~count:200 "xor" arb2 (binary_agrees Opcode.Xor Alu.logxor);
    mk ~salt:18 ~count:200 "byte" arb2 (binary_agrees Opcode.Byte Alu.byte);
    mk ~salt:19 ~count:200 "shl" arb2 (binary_agrees Opcode.Shl Alu.shl);
    mk ~salt:20 ~count:200 "shr" arb2 (binary_agrees Opcode.Shr Alu.shr);
    mk ~salt:21 ~count:200 "sar" arb2 (binary_agrees Opcode.Sar Alu.sar);
    mk ~salt:22 ~count:150 "addmod" arb3 (ternary_agrees Opcode.Addmod Alu.addmod);
    mk ~salt:23 ~count:150 "mulmod" arb3 (ternary_agrees Opcode.Mulmod Alu.mulmod);
    (* Whatever the bytecode, the machine halts and never invents gas. *)
    mk ~salt:24 ~count:400 "arbitrary bytecode halts without raising" arb_code (fun s ->
        let limit = 20_000 in
        let _, _, gas_left, _ = view (run (Code.of_string s) limit) in
        gas_left <= limit);
    (* The memory curve against an arbitrary-precision oracle that shares none of
       its code. This is what pins the .mli's claim that the native-int
       computation is EXACT and that [None] means the true cost really exceeds
       any representable allowance — not merely that it was inconvenient to
       compute. *)
    mk ~salt:25 ~count:500 "the memory curve matches an exact oracle" arb_word_count
      (fun w ->
        let z = Z.of_int w in
        let exact =
          Z.add (Z.mul (Z.of_int 3) z) (Z.div (Z.mul z z) (Z.of_int 512))
        in
        Option.fold
          ~none:(Z.gt exact (Z.of_int max_int))
          ~some:(fun cost -> Z.equal (Z.of_int cost) exact)
          (Gas.memory_cost w));
    (* And expansion is the difference of two such totals — checked against the
       oracle rather than against the implementation it restates. *)
    mk ~salt:26 ~count:400 "expansion is the difference of two exact totals" arb_words
      (fun (a, b) ->
        let low = Int.min a b and high = Int.max a b in
        let exact n =
          let z = Z.of_int n in
          Z.add (Z.mul (Z.of_int 3) z) (Z.div (Z.mul z z) (Z.of_int 512))
        in
        Option.fold ~none:false
          ~some:(fun cost -> Z.equal (Z.of_int cost) (Z.sub (exact high) (exact low)))
          (Gas.expansion_cost ~current:low ~next:high));
    (* Every offset the analysis reports really holds a JUMPDEST instruction. *)
    mk ~salt:29 ~count:300 "reported destinations are jumpdest bytes" arb_code (fun s ->
        let code = Code.of_string s in
        List.for_all
          (fun offset -> Code.byte_at code offset = Opcode.to_byte Opcode.Jumpdest)
          (Code.jumpdests code));
    (* The word-to-native conversion the interpreter converts offsets with agrees
       with its inverse. *)
    mk ~salt:27 ~count:300 "to_int inverts of_int"
      (QCheck.make ~print:string_of_int QCheck.Gen.(int_range 0 max_int))
      (fun n -> Option.equal Int.equal (Some n) (U256.to_int (u n)));
    (* A word above the native range has no offset, which is what makes an
       unpayable memory reference a halt rather than a wrapped small offset. The
       generator straddles the boundary itself — [max_int] is [2^62 - 1], so the
       whole octave from [2^62] up must be refused, not only the powers of two
       above [2^63]. *)
    mk ~salt:28 ~count:400 "a word past the native range has no offset"
      (QCheck.make ~print:h1
         QCheck.Gen.(
           oneof
             [
               map (fun k -> U256.two_pow (62 + k)) (int_range 0 193);
               map (fun r -> U256.add (U256.two_pow 62) (u r)) (int_range 0 100_000);
               return U256.max_value;
             ]))
      (fun w -> Option.is_none (U256.to_int w));
    (* Bytecode that cannot read its own allowance behaves identically however
       much it is given, spending exactly the same amount — so the extra gas comes
       back untouched. A run that only failed for want of gas is exempt, since
       more gas legitimately changes what it does. *)
    mk ~salt:30 ~count:300 "extra gas changes only the balance" arb_code_no_gas (fun s ->
        let code = Code.of_string s in
        let base = 20_000 in
        let extra = 777 in
        let lean = view (run code base) and rich = view (run code (base + extra)) in
        let kind_lean, output_lean, gas_lean, effects_lean = lean in
        let kind_rich, output_rich, gas_rich, effects_rich = rich in
        String.equal kind_lean (Interpreter.error_to_string Interpreter.Out_of_gas)
        || String.equal kind_lean kind_rich
           && String.equal output_lean output_rich
           && Option.equal Effects.equal effects_lean effects_rich
           && (gas_lean < 0 || Int.equal gas_rich (gas_lean + extra)));
  ]

let () =
  Alcotest.run "tn_evm_interpreter"
    [
      ( "stack",
        [
          Alcotest.test_case "push and pop" `Quick test_stack_push_pop;
          Alcotest.test_case "the 1024-word limit" `Quick test_stack_limit;
          Alcotest.test_case "duplication" `Quick test_stack_dup;
          Alcotest.test_case "exchange" `Quick test_stack_swap;
        ] );
      ( "memory",
        [
          Alcotest.test_case "words needed to reach an extent" `Quick test_memory_words_needed;
          Alcotest.test_case "reading and writing" `Quick test_memory_read_write;
          Alcotest.test_case "expanded size" `Quick test_memory_size;
        ] );
      ( "gas",
        [
          Alcotest.test_case "the memory cost curve" `Quick test_gas_memory_cost;
          Alcotest.test_case "expansion is a difference" `Quick test_gas_expansion;
          Alcotest.test_case "exponentiation by exponent size" `Quick test_gas_exp_cost;
          Alcotest.test_case "the static schedule" `Quick test_gas_static_cost;
        ] );
      ( "code analysis",
        [
          Alcotest.test_case "jump destinations skip push data" `Quick test_code_jumpdests;
          Alcotest.test_case "reading past the code" `Quick test_code_bytes;
        ] );
      ( "programs",
        [
          Alcotest.test_case "arithmetic and return" `Quick test_program_add;
          Alcotest.test_case "empty code and running off the end" `Quick test_program_empty;
          Alcotest.test_case "memory expansion is paid once" `Quick test_program_memory_expansion;
          Alcotest.test_case "msize after a byte store" `Quick test_program_msize;
          Alcotest.test_case "pc reports its own offset" `Quick test_program_pc;
          Alcotest.test_case "gas reports the remaining balance" `Quick test_program_gas;
          Alcotest.test_case "jumping to a jumpdest" `Quick test_program_jump;
          Alcotest.test_case "invalid jump destinations" `Quick test_program_jump_invalid;
          Alcotest.test_case "conditional jumps" `Quick test_program_jumpi;
          Alcotest.test_case "push immediates" `Quick test_program_push_immediate;
          Alcotest.test_case "loading from memory" `Quick test_program_mload;
          Alcotest.test_case "single-operand instructions and pop" `Quick
            test_program_unary_and_pop;
          Alcotest.test_case "extents at the representable limit" `Quick
            test_program_extent_at_the_limit;
          Alcotest.test_case "duplication and exchange" `Quick test_program_dup_swap;
          Alcotest.test_case "return and revert" `Quick test_program_revert;
          Alcotest.test_case "a zero-length return" `Quick test_program_zero_length_return;
          Alcotest.test_case "exponentiation is priced by exponent" `Quick test_program_exp_cost;
          Alcotest.test_case "running out of gas" `Quick test_program_out_of_gas;
          Alcotest.test_case "stack underflow and overflow" `Quick test_program_stack_errors;
          Alcotest.test_case "invalid and deferred opcodes" `Quick test_program_invalid_opcode;
        ] );
      ( "encoding",
        [
          Alcotest.test_case "every byte round-trips" `Quick test_opcode_roundtrip;
          Alcotest.test_case "only halting instructions are free" `Quick test_termination_invariant;
          Alcotest.test_case "immediate widths" `Quick test_immediate_widths;
        ] );
      ("machine vs alu", prop_cases);
    ]
