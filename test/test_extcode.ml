(* The external-code readers: [EXTCODESIZE], [EXTCODEHASH] and [EXTCODECOPY], and
   the code-on-account migration beneath them. Absolute gas throughout, never
   differences — an arm that looked an account up and forgot to charge its cold
   surcharge produces the warm number in both the cold and warm case, and only an
   absolute assertion separates them. The EIP-1052 cases are pinned three ways
   apart (a contract, a codeless-but-existing account, an absent one) because the
   whole subtlety is that they give three different answers. *)

module U256 = Tn_state.U256
module Account = Tn_state.Account
module Bytecode = Tn_state.Bytecode
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
module Keccak = Tn_keccak
module Gas = Tn_evm.Gas
module Interpreter = Tn_evm.Interpreter
module Memory = Tn_evm.Memory
module Opcode = Tn_evm.Opcode

let get = function Some x -> x | None -> Alcotest.fail "expected Some"
let u n = get (U256.of_int n)
let gas_of n = get (Gas.of_int n)
let width_of n = get (Opcode.Push_bytes.of_int n)
let nonce_of n = get (Nonce.of_int n)

let address_of n =
  get
    (Units.Address.of_bytes
       (String.make (Units.Address.length - 1) '\000' ^ String.make 1 (Char.chr n)))

(* ---------- the miniature assembler ---------- *)

let byte b = String.make 1 (Char.chr b)
let op o = byte (Opcode.to_byte o)
let push1 n = op (Opcode.Push (width_of 1)) ^ byte n
let push20 address = op (Opcode.Push (width_of 20)) ^ Units.Address.to_bytes address
let push32 w = op (Opcode.Push (width_of 32)) ^ U256.to_be_bytes w
let asm parts = Code.of_string (String.concat "" parts)

(* Move the word on top of the stack into memory and return it, so a pushed value
   becomes an observable thirty-two-byte output. Costs [3 + (3 + 3 expansion) + 3
   + 3 + 0], the MSTORE reaching the first word from nothing. *)
let return_top = [ push1 0x00; op Opcode.Mstore; push1 0x20; push1 0x00; op Opcode.Return ]

(* ---------- the accounts under test ---------- *)

let contract = address_of 0xab
let contract_code = "\x60\x2a\x60\x00\x52\x60\x20" (* seven arbitrary bytes *)
let eoa = address_of 0x0e (* exists via a balance, has no code *)
let nonce_only = address_of 0x0d (* exists via a nonzero nonce alone, no balance, no code *)
let absent = address_of 0x0f (* no entry at all *)

let world =
  let deployed =
    Account.with_code (Account.make ~nonce:(nonce_of 1) ~balance:U256.zero) contract_code
  in
  let funded = Account.make ~nonce:Nonce.zero ~balance:(u 500) in
  let has_nonced = Account.make ~nonce:(nonce_of 7) ~balance:U256.zero in
  World_state.set_account
    (World_state.set_account
       (World_state.set_account World_state.empty contract deployed)
       eoa funded)
    nonce_only has_nonced

let base_env =
  Env.make
    ~block:
      (Env.Block.make ~coinbase:(address_of 0xc0) ~timestamp:(u 1_600_000_000)
         ~number:(u 15_500_000) ~prevrandao:U256.zero ~gas_limit:(u 25_000_000)
         ~basefee:(u 7) ~chain_id:(u 2017))
    ~tx:(Env.Tx.make ~origin:(address_of 0x01) ~gas_price:(u 9) ~access_list:[])
    ~call:
      (Env.Call.make ~target:(address_of 0x02) ~caller:(address_of 0x0c)
         ~value:U256.zero ~data:Data.empty ~mutability:Mutability.Mutable)

let cold_effects = Effects.start ~world ~access:Access.empty

let warm_effects_of address =
  Effects.start ~world ~access:(Access.of_transaction ~addresses:[ address ] ~slots:[])

let allowance = 1_000_000

let run ?(effects = cold_effects) code =
  Interpreter.run ~env:base_env ~code ~gas:(gas_of allowance) ~effects

let remaining_of = function
  | Interpreter.Stopped { gas_left; _ } -> Gas.remaining gas_left
  | Interpreter.Returned { gas_left; _ } -> Gas.remaining gas_left
  | Interpreter.Reverted { gas_left; _ } -> Gas.remaining gas_left
  | Interpreter.Failed error ->
      Alcotest.fail
        ("expected a halt carrying gas, got " ^ Interpreter.error_to_string error)

let output_of = function
  | Interpreter.Returned { output; _ } -> output
  | Interpreter.Reverted { output; _ } -> output
  | Interpreter.Stopped _ -> Alcotest.fail "expected an outcome carrying output"
  | Interpreter.Failed error ->
      Alcotest.fail
        ("expected an outcome carrying output, got " ^ Interpreter.error_to_string error)

let check_total msg expected outcome =
  Alcotest.(check int) msg expected (allowance - remaining_of outcome)

let check_output msg expected outcome =
  Alcotest.(check string) msg expected (output_of outcome)

(* ---------- EXTCODESIZE ---------- *)

let test_extcodesize_value () =
  (* PUSH20, EXTCODESIZE, then return the pushed word. The size is the code's
     byte length, seven here. *)
  let code = asm ([ push20 contract; op Opcode.Extcodesize ] @ return_top) in
  check_output "EXTCODESIZE pushes the code length"
    (U256.to_be_bytes (u (String.length contract_code)))
    (run code);
  (* A codeless account and an absent one both report zero. *)
  let of_addr a = asm ([ push20 a; op Opcode.Extcodesize ] @ return_top) in
  check_output "a codeless account has size zero"
    (U256.to_be_bytes U256.zero) (run (of_addr eoa));
  check_output "an absent account has size zero"
    (U256.to_be_bytes U256.zero) (run (of_addr absent))

let test_extcodesize_gas () =
  (* PUSH20 3, EXTCODESIZE (100 static + 2500 cold surcharge), POP 2, STOP 0 —
     the same shape and the same numbers as BALANCE. *)
  let code = asm [ push20 contract; op Opcode.Extcodesize; op Opcode.Pop; op Opcode.Stop ] in
  check_total "a cold EXTCODESIZE costs 2605 in all" 2605 (run code);
  check_total "a pre-warmed EXTCODESIZE costs 105" 105
    (run ~effects:(warm_effects_of contract) code)

(* ---------- EXTCODEHASH ---------- *)

let test_extcodehash_three_ways () =
  let of_addr a = asm ([ push20 a; op Opcode.Extcodehash ] @ return_top) in
  (* A deployed contract reports the Keccak-256 of its code. *)
  check_output "EXTCODEHASH of a contract is the hash of its code"
    (Keccak.to_bytes (Keccak.digest contract_code)) (run (of_addr contract));
  (* An account that EXISTS but holds no code reports KECCAK_EMPTY — NOT zero.
     This is the EIP-1052 line: emptiness, not codelessness, is what folds to
     zero, and a funded EOA is not empty. Swapping this arm to zero would pass
     the absent case below and only fail here. *)
  check_output "EXTCODEHASH of a codeless-but-funded account is KECCAK_EMPTY"
    (Keccak.to_bytes Keccak.empty) (run (of_addr eoa));
  (* And an account made non-empty by its NONCE alone — zero balance, no code —
     is likewise KECCAK_EMPTY and not zero: emptiness is all three of nonce,
     balance and code. This pins the nonce conjunct EXTCODEHASH now leans on;
     dropping it from Account.is_empty would fold this account to zero and still
     pass every other case in this suite (the funded EOA above separates only the
     balance conjunct). *)
  check_output "EXTCODEHASH of a nonce-only account is KECCAK_EMPTY"
    (Keccak.to_bytes Keccak.empty) (run (of_addr nonce_only));
  (* An account with no entry is empty, and EIP-1052 folds it to zero, which is a
     bare word and never the KECCAK_EMPTY above. *)
  check_output "EXTCODEHASH of an absent account is zero"
    (U256.to_be_bytes U256.zero) (run (of_addr absent))

let test_extcodehash_gas () =
  let code = asm [ push20 contract; op Opcode.Extcodehash; op Opcode.Pop; op Opcode.Stop ] in
  check_total "a cold EXTCODEHASH costs 2605 in all" 2605 (run code);
  check_total "a pre-warmed EXTCODEHASH costs 105" 105
    (run ~effects:(warm_effects_of contract) code)

(* ---------- EXTCODECOPY ---------- *)

(* Stack order for EXTCODECOPY is address on top, then the destination, the code
   offset and the length, so they are pushed in reverse: length, code offset,
   destination, address. *)
let extcodecopy ~len ~code_off ~dest address =
  [ push1 len; push1 code_off; push1 dest; push20 address; op Opcode.Extcodecopy ]

let test_extcodecopy_value () =
  (* Copy the whole seven-byte code to offset zero and return the first word:
     the code, then zeroes to fill the word. *)
  let code =
    asm (extcodecopy ~len:(String.length contract_code) ~code_off:0x00 ~dest:0x00 contract
        @ [ push1 0x20; push1 0x00; op Opcode.Return ])
  in
  check_output "EXTCODECOPY lands the code zero-extended"
    (contract_code ^ String.make (32 - String.length contract_code) '\000')
    (run code);
  (* A code offset at or past the end reads zeroes, the source saturation rule
     [Data] already obeys for CALLDATACOPY and CODECOPY. *)
  let past =
    asm (extcodecopy ~len:0x04 ~code_off:0x20 ~dest:0x00 contract
        @ [ push1 0x20; push1 0x00; op Opcode.Return ])
  in
  check_output "a code offset past the end reads zeroes"
    (String.make 32 '\000') (run past)

let test_extcodecopy_gas () =
  (* PUSH1 x4 (12), EXTCODECOPY (100 static + copy_cost 3 + one word of expansion
     3 + 2500 cold surcharge), STOP 0. Only the static 100 and the account
     surcharge separate this from CALLDATACOPY. *)
  let code = asm (extcodecopy ~len:0x05 ~code_off:0x00 ~dest:0x00 contract @ [ op Opcode.Stop ]) in
  check_total "a cold five-byte EXTCODECOPY costs 2618" 2618 (run code);
  check_total "a pre-warmed five-byte EXTCODECOPY costs 118" 118
    (run ~effects:(warm_effects_of contract) code)

let test_extcodecopy_zero_length_still_warms () =
  (* A zero-length EXTCODECOPY writes nothing and pays no copy or expansion, but
     it STILL warms the account and pays the cold surcharge — revm's
     berlin_load_account! sits after the resize guard and runs regardless. So the
     cold total is 2612 (12 + 100 + 2500) and the warm 112 (12 + 100). If the
     zero-length arm short-circuited before the account access, both would be 112,
     which is exactly the mutation this pins. *)
  let code = asm (extcodecopy ~len:0x00 ~code_off:0x00 ~dest:0x00 contract @ [ op Opcode.Stop ]) in
  check_total "a cold zero-length EXTCODECOPY still pays the surcharge" 2612 (run code);
  check_total "a warm zero-length EXTCODECOPY pays only the base" 112
    (run ~effects:(warm_effects_of contract) code)

let test_extcodecopy_high_dest () =
  (* Copy the whole code to a NON-ZERO destination, so the expansion is more than
     the single word every other test reaches, and the bytes land where asked.
     Return [0x20, 0x40): the code, then zeroes to fill the word. *)
  let n = String.length contract_code in
  let code =
    asm
      (extcodecopy ~len:n ~code_off:0x00 ~dest:0x20 contract
      @ [ push1 0x20; push1 0x20; op Opcode.Return ])
  in
  check_output "EXTCODECOPY writes at a high destination"
    (contract_code ^ String.make (32 - n) '\000') (run code);
  (* And MSIZE reports the two words the copy reached: the window [0x20, 0x27)
     rounds up to sixty-four bytes, so a copy to a high offset really did expand. *)
  let with_msize =
    asm
      (extcodecopy ~len:n ~code_off:0x00 ~dest:0x20 contract
      @ [ op Opcode.Msize ] @ return_top)
  in
  check_output "and MSIZE sees the expansion" (U256.to_be_bytes (u 64)) (run with_msize)

let test_extcodecopy_overlength_and_saturating_offset () =
  let n = String.length contract_code in
  (* A copy longer than the code: the price is by the length ASKED for, not the
     bytes available, and everything past the code is zero. Forty bytes is two
     words of copy and two of expansion, so 100 + 6 + 6 + 2500 cold plus the four
     pushes and the return: 2630. *)
  let over =
    asm
      (extcodecopy ~len:0x28 ~code_off:0x00 ~dest:0x00 contract
      @ [ push1 0x40; push1 0x00; op Opcode.Return ])
  in
  check_output "an over-length EXTCODECOPY zero-fills past the code"
    (contract_code ^ String.make (0x40 - n) '\000') (run over);
  check_total "and is charged on the length asked for" 2630 (run over);
  (* A code offset of 2^256-1 saturates to reading nothing but zeroes — the
     source-offset rule Data already applies to CALLDATACOPY and CODECOPY, so a
     wild code offset is not an error, it copies zeroes. *)
  let huge =
    asm
      [
        push1 0x04; push32 U256.max_value; push1 0x00; push20 contract;
        op Opcode.Extcodecopy; push1 0x20; push1 0x00; op Opcode.Return;
      ]
  in
  check_output "a saturating code offset reads zeroes" (String.make 32 '\000') (run huge)

(* ---------- the shared warm set ---------- *)

let test_readers_share_the_warm_set () =
  (* EXTCODESIZE then EXTCODEHASH of one address: the first touch pays 2500, the
     second is warm. 3 + 2600 + 2 + 3 + 100 + 2 + 0 = 2710. *)
  let code =
    asm
      [
        push20 contract; op Opcode.Extcodesize; op Opcode.Pop;
        push20 contract; op Opcode.Extcodehash; op Opcode.Pop;
        op Opcode.Stop;
      ]
  in
  check_total "the second reader of an address is warm" 2710 (run code);
  (* And the warm set is the SAME one BALANCE grows: a cold BALANCE leaves the
     following EXTCODESIZE warm. *)
  let mixed =
    asm
      [
        push20 contract; op Opcode.Balance; op Opcode.Pop;
        push20 contract; op Opcode.Extcodesize; op Opcode.Pop;
        op Opcode.Stop;
      ]
  in
  check_total "EXTCODESIZE is warm after BALANCE of the same address" 2710 (run mixed)

(* ---------- the opcodes decode and round-trip ---------- *)

let test_opcode_round_trip () =
  let round op expected_byte =
    Alcotest.(check int) (Opcode.to_string op ^ " encodes") expected_byte (Opcode.to_byte op);
    Alcotest.(check bool)
      (Opcode.to_string op ^ " decodes back")
      true
      (match Opcode.decode expected_byte with Some d -> Opcode.equal d op | None -> false)
  in
  round Opcode.Extcodesize 0x3b;
  round Opcode.Extcodecopy 0x3c;
  round Opcode.Extcodehash 0x3f;
  (* None of them carries an immediate. *)
  List.iter
    (fun op -> Alcotest.(check int) "no immediate" 0 (Opcode.immediate_bytes op))
    [ Opcode.Extcodesize; Opcode.Extcodecopy; Opcode.Extcodehash ]

(* ---------- the code-on-account migration ---------- *)

let test_bytecode_basics () =
  Alcotest.(check int) "empty is zero length" 0 (Bytecode.length Bytecode.empty);
  Alcotest.(check bool) "empty is empty" true (Bytecode.is_empty Bytecode.empty);
  Alcotest.(check bool)
    "the hash of empty is KECCAK_EMPTY" true
    (Keccak.equal (Bytecode.hash Bytecode.empty) Keccak.empty);
  let code = Bytecode.of_string contract_code in
  Alcotest.(check int) "length is the byte count" (String.length contract_code) (Bytecode.length code);
  Alcotest.(check bool) "nonempty code is not empty" false (Bytecode.is_empty code);
  Alcotest.(check bool)
    "the hash matches keccak of the bytes" true
    (Keccak.equal (Bytecode.hash code) (Keccak.digest contract_code))

let test_account_code_and_emptiness () =
  let contract_acct =
    Account.with_code (Account.make ~nonce:Nonce.zero ~balance:U256.zero) contract_code
  in
  Alcotest.(check int) "code_length reports the bytes" (String.length contract_code)
    (Account.code_length contract_acct);
  Alcotest.(check string) "code returns the bytes" contract_code (Account.code contract_acct);
  (* An account whose only content is code — zero nonce, zero balance — is NOT
     EIP-161 empty: code is the third conjunct, now present. Dropping it would
     make this true again. *)
  Alcotest.(check bool) "code alone makes an account non-empty" false
    (Account.is_empty contract_acct);
  Alcotest.(check bool) "a codeless zero account is still empty" true
    (Account.is_empty Account.empty)

let test_a_code_only_account_is_kept () =
  (* is_absent is is_empty and empty storage; a zero-nonce zero-balance account
     that carries code is not is_empty, so it is not is_absent, so set_account
     keeps it rather than pruning it, and equal sees the code. *)
  let acct =
    Account.with_code (Account.make ~nonce:Nonce.zero ~balance:U256.zero) contract_code
  in
  Alcotest.(check bool) "a code-only account is not absent" false (Account.is_absent acct);
  let st = World_state.set_account World_state.empty contract acct in
  Alcotest.(check bool) "so the world keeps it" false
    (World_state.equal st World_state.empty);
  Alcotest.(check string) "and reads its code back" contract_code
    (Account.code (World_state.account st contract))

let () =
  Alcotest.run "tn_evm_extcode"
    [
      ( "extcodesize",
        [
          Alcotest.test_case "the pushed size" `Quick test_extcodesize_value;
          Alcotest.test_case "cold and warm gas" `Quick test_extcodesize_gas;
        ] );
      ( "extcodehash",
        [
          Alcotest.test_case "contract, codeless, absent" `Quick test_extcodehash_three_ways;
          Alcotest.test_case "cold and warm gas" `Quick test_extcodehash_gas;
        ] );
      ( "extcodecopy",
        [
          Alcotest.test_case "the copied bytes" `Quick test_extcodecopy_value;
          Alcotest.test_case "cold and warm gas" `Quick test_extcodecopy_gas;
          Alcotest.test_case "a zero length still warms" `Quick
            test_extcodecopy_zero_length_still_warms;
          Alcotest.test_case "a high destination and MSIZE" `Quick
            test_extcodecopy_high_dest;
          Alcotest.test_case "over-length and a saturating offset" `Quick
            test_extcodecopy_overlength_and_saturating_offset;
        ] );
      ( "warm set",
        [
          Alcotest.test_case "the readers share it, and with BALANCE" `Quick
            test_readers_share_the_warm_set;
        ] );
      ( "opcodes",
        [ Alcotest.test_case "decode and round-trip" `Quick test_opcode_round_trip ] );
      ( "code on account",
        [
          Alcotest.test_case "bytecode basics" `Quick test_bytecode_basics;
          Alcotest.test_case "code and EIP-161 emptiness" `Quick
            test_account_code_and_emptiness;
          Alcotest.test_case "a code-only account is kept" `Quick
            test_a_code_only_account_is_kept;
        ] );
    ]
