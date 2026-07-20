(* Contract creation and account destruction: CREATE, CREATE2, SELFDESTRUCT and
   BLOCKHASH. Faithful to revm 32.0.0 at Prague.

   The address derivations are pinned against oracles this port did not produce.
   The seven [CREATE2] cases are EIP-1014's own published vectors, reproduced
   verbatim; the [CREATE] cases were computed with an independent Keccak-256
   implementation (Python's pycryptodome) that was first shown to reproduce all
   seven of those EIP vectors, so the RLP nonce encoding is checked against a
   witness outside this tree rather than against itself. They cover the four
   shapes the nonce encoding has: zero as the empty string, a bare byte below
   [0x80], the [0x81]-prefixed byte at [0x80] and above, and a multi-byte
   integer. *)

module U256 = Tn_state.U256
module Nonce = Tn_state.Nonce
module Units = Tn_types.Units
module Contract_address = Tn_evm.Contract_address

let get = function Some x -> x | None -> Alcotest.fail "expected Some"
let nonce_of n = get (Nonce.of_int n)

(* A twenty-byte address from its hex, and a hex rendering of one, so that the
   published vectors can be written and compared exactly as they are published. *)
let unhex hex =
  String.init
    (String.length hex / 2)
    (fun i -> Char.chr (int_of_string ("0x" ^ String.sub hex (2 * i) 2)))

let address_of_hex hex = get (Units.Address.of_bytes (unhex hex))

let hex_of_address address =
  String.concat ""
    (List.map
       (fun c -> Printf.sprintf "%02x" (Char.code c))
       (List.of_seq (String.to_seq (Units.Address.to_bytes address))))

let check_address ~expected actual =
  Alcotest.(check string) "created address" (String.lowercase_ascii expected) (hex_of_address actual)

(* ---------- CREATE2: EIP-1014's published vectors ---------- *)

let create2 ~creator ~salt ~init_code =
  Contract_address.derive
    ~creator:(address_of_hex creator)
    (Contract_address.From_salt
       { salt = get (U256.of_be_bytes (unhex salt)); init_code = unhex init_code })

let eip1014_vectors =
  [
    ( "0000000000000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000000",
      "00",
      "4D1A2e2bB4F88F0250f26Ffff098B0b30B26BF38" );
    ( "deadbeef00000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000000",
      "00",
      "B928f69Bb1D91Cd65274e3c79d8986362984fDA3" );
    ( "deadbeef00000000000000000000000000000000",
      "000000000000000000000000feed000000000000000000000000000000000000",
      "00",
      "D04116cDd17beBE565EB2422F2497E06cC1C9833" );
    ( "0000000000000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000000",
      "deadbeef",
      "70f2b2914A2a4b783FaEFb75f459A580616Fcb5e" );
    ( "00000000000000000000000000000000deadbeef",
      "00000000000000000000000000000000000000000000000000000000cafebabe",
      "deadbeef",
      "60f3f640a8508fC6a86d45DF051962668E1e8AC7" );
    ( "00000000000000000000000000000000deadbeef",
      "00000000000000000000000000000000000000000000000000000000cafebabe",
      "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
      "1d8bfDC5D46DC4f61D6b6115972536eBE6A8854C" );
    ( "0000000000000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000000",
      "",
      "E33C0C7F7df4809055C3ebA6c09CFe4BaF1BD9e0" );
  ]

let test_create2_eip1014_vectors () =
  List.iter
    (fun (creator, salt, init_code, expected) ->
      check_address ~expected (create2 ~creator ~salt ~init_code))
    eip1014_vectors

(* ---------- CREATE: the RLP nonce encoding ---------- *)

let create_at ~creator ~nonce =
  Contract_address.derive
    ~creator:(address_of_hex creator)
    (Contract_address.From_nonce (nonce_of nonce))

(* Two creators against the four encoding shapes. The zero creator is included
   because it is the one whose RLP payload a mistake in the address item would
   still leave well formed. *)
let create_vectors =
  [
    ("6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0", 0, "cd234a471b72ba2f1ccf0a70fcaba648a5eecd8d");
    ("6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0", 1, "343c43a37d37dff08ae8c4a11544c718abb4fcf8");
    ("6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0", 127, "06d9a77f5e4b311bae8d559db9cdb4df94104aa0");
    ("6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0", 128, "08e190dcb7b73f5fcdabb43e102215c83659a76d");
    ("6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0", 255, "3ef7c1a519e4b4431e317d7839340e3139b03c65");
    ("6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0", 256, "3837c1ae70354f670550c746580199ac6a73cb0a");
    ("6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0", 65535, "65260eecff4edebabe134f76f1f39a91defde56c");
    ("0000000000000000000000000000000000000000", 0, "bd770416a3345f91e4b34576cb804a576fa48eb1");
    ("0000000000000000000000000000000000000000", 127, "5a1bfc20f2037f3e54d367a70957a5327130cea5");
    ("0000000000000000000000000000000000000000", 128, "c1784bd8a0ffebd60d0bc7099dcd811b57f30bc4");
    ("0000000000000000000000000000000000000000", 256, "1183a5a83c1fa113618603abc4509077ec672699");
    ("deadbeef00000000000000000000000000000000", 0, "f2048c36a5536fea3bc71d49ed59f2c65c546eea");
    ("deadbeef00000000000000000000000000000000", 128, "2297787b25b800d655071345a1d3a7951404b50c");
  ]

let test_create_nonce_vectors () =
  List.iter
    (fun (creator, nonce, expected) -> check_address ~expected (create_at ~creator ~nonce))
    create_vectors

(* The nonce is the only thing separating two creations by one account, so a
   derivation that ignored it — or that encoded every nonce the same way — would
   deploy every contract of a creator to one address. *)
let test_create_nonce_changes_address () =
  let creator = "6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0" in
  let addresses = List.map (fun nonce -> hex_of_address (create_at ~creator ~nonce)) [ 0; 1; 2; 127; 128; 129 ] in
  Alcotest.(check int)
    "six nonces, six distinct addresses" 6
    (List.length (List.sort_uniq String.compare addresses))

(* The salt and the init code are independent inputs to EIP-1014: changing
   either alone must move the address. *)
let test_create2_salt_and_code_independent () =
  let creator = "00000000000000000000000000000000deadbeef" in
  let base = create2 ~creator ~salt:(String.make 64 '0') ~init_code:"deadbeef" in
  let other_salt =
    create2 ~creator ~salt:(String.make 63 '0' ^ "1") ~init_code:"deadbeef"
  in
  let other_code = create2 ~creator ~salt:(String.make 64 '0') ~init_code:"deadbeff" in
  Alcotest.(check bool) "a different salt moves it" false (hex_of_address base = hex_of_address other_salt);
  Alcotest.(check bool) "a different init code moves it" false (hex_of_address base = hex_of_address other_code)

(* ========================================================================== *)
(* The opcode suite: CREATE, CREATE2, SELFDESTRUCT and BLOCKHASH run end to    *)
(* end. test_calls.ml conventions throughout: a miniature assembler, a world   *)
(* seeded by fold over set_account, absolute hand-computed gas asserted as      *)
(* literals with the derivation in a comment, programs ending in a cost-free    *)
(* STOP where a spend is measured, and every failure class asserted on both     *)
(* what it pushes and the exact gas it leaves so a regression that flips a      *)
(* class fails here.                                                            *)
(* ========================================================================== *)

module Account = Tn_state.Account
module Storage = Tn_state.Storage
module World_state = Tn_state.World_state
module Bytecode = Tn_state.Bytecode
module Address_word = Tn_state.Address_word
module Access = Tn_evm.Access
module Call_depth = Tn_evm.Call_depth
module Code = Tn_evm.Code
module Data = Tn_evm.Data
module Effects = Tn_evm.Effects
module Env = Tn_evm.Env
module Gas = Tn_evm.Gas
module Interpreter = Tn_evm.Interpreter
module Lifecycle = Tn_evm.Lifecycle
module Mutability = Tn_evm.Mutability
module Opcode = Tn_evm.Opcode
module Refund = Tn_evm.Refund
module Block_hashes = Tn_evm.Block_hashes
module Keccak = Tn_keccak

let u n = get (U256.of_int n)
let gas_of n = get (Gas.of_int n)
let width_of n = get (Opcode.Push_bytes.of_int n)

let address_of n =
  get
    (Units.Address.of_bytes
       (String.make (Units.Address.length - 1) '\000' ^ String.make 1 (Char.chr n)))

(* 2^n as a full word, 0 <= n <= 255: a single bit set in the big-endian bytes. *)
let pow2 n =
  let byte_index = 31 - (n / 8) in
  get
    (U256.of_be_bytes
       (String.init 32 (fun i -> if i = byte_index then Char.chr (1 lsl (n mod 8)) else '\000')))

(* ---------- the miniature assembler ---------- *)

let byte b = String.make 1 (Char.chr b)
let op o = byte (Opcode.to_byte o)
let push1 n = op (Opcode.Push (width_of 1)) ^ byte n
let push20 address = op (Opcode.Push (width_of 20)) ^ Units.Address.to_bytes address
let push32 w = op (Opcode.Push (width_of 32)) ^ U256.to_be_bytes w
let asm parts = Code.of_string (String.concat "" parts)
let bytes_of parts = String.concat "" parts
let store_at off = [ push1 off; op Opcode.Mstore ]
let return_range ~off ~len = [ push1 len; push1 off; op Opcode.Return ]

(* CREATE pops value, then (offset, len); pushed in reverse so value ends on top. *)
let emit_create ~value ~offset ~len =
  [ push32 len; push32 offset; push32 value; op Opcode.Create ]

(* CREATE2 pops the salt LAST, after the memory work, so it sits below len. *)
let emit_create2 ~value ~offset ~len ~salt =
  [ push32 salt; push32 len; push32 offset; push32 value; op Opcode.Create2 ]

(* Lay a <= 32-byte init code into memory word 0 (big-endian, high bytes first),
   then CREATE reads it from offset 0. The prelude PUSH32/PUSH1 0/MSTORE costs 12
   and reaches word 0, so the CREATE's own expansion is nothing. *)
let word_of_prefix bytes =
  get (U256.of_be_bytes (bytes ^ String.make (32 - String.length bytes) '\000'))

let store_initcode bytes = [ push32 (word_of_prefix bytes); push1 0x00; op Opcode.Mstore ]

(* ---------- init codes the child frames run ---------- *)

(* A single STOP byte: the shortest init code, an empty deploy. *)
let ic_stop = "\x00"

(* Returns one untouched (zero) byte: PUSH1 1, PUSH1 0, RETURN. *)
let ic_return_one_zero = bytes_of [ push1 0x01; push1 0x00; op Opcode.Return ]

(* Returns 32 untouched (zero) bytes: PUSH1 0x20, PUSH1 0, RETURN. *)
let ic_return_word = bytes_of [ push1 0x20; push1 0x00; op Opcode.Return ]

(* Returns one 0xEF byte, the EIP-3541 reserved prefix. *)
let ic_return_ef =
  bytes_of
    [ push1 0xEF; push1 0x00; op Opcode.Mstore8; push1 0x01; push1 0x00; op Opcode.Return ]

(* Returns 24577 zero bytes, one over the EIP-170 ceiling; the child pays its own
   expansion. PUSH3 0x006001 (24577), PUSH1 0, RETURN. *)
let ic_return_over_170 =
  bytes_of [ (op (Opcode.Push (width_of 3)) ^ "\x00\x60\x01"); push1 0x00; op Opcode.Return ]

(* Returns exactly 24576 zero bytes, the EIP-170 ceiling itself. *)
let ic_return_at_170 =
  bytes_of [ (op (Opcode.Push (width_of 3)) ^ "\x00\x60\x00"); push1 0x00; op Opcode.Return ]

(* Reverts four (zero) bytes: PUSH1 4, PUSH1 0, REVERT. *)
let ic_revert_four = bytes_of [ push1 0x04; push1 0x00; op Opcode.Revert ]

(* SLOADs slot 1 and returns it as the 32-byte deployed code. Over a created
   account this must read zero. *)
let ic_sload_slot1 =
  bytes_of
    [
      push1 0x01; op Opcode.Sload; push1 0x00; op Opcode.Mstore; push1 0x20;
      push1 0x00; op Opcode.Return;
    ]

(* SSTOREs 7 to slot 1, then STOPs: an empty deploy that wrote storage. *)
let ic_sstore_slot1 = bytes_of [ push1 0x07; push1 0x01; op Opcode.Sstore; op Opcode.Stop ]

(* ADDRESS, SELFDESTRUCT: the created account destroys itself to itself. *)
let ic_address_selfdestruct = bytes_of [ op Opcode.Address; op Opcode.Selfdestruct ]

let ic_selfdestruct_to addr = bytes_of [ push20 addr; op Opcode.Selfdestruct ]

(* ---------- the executing account and the world ---------- *)

let self = address_of 0x01
let beneficiary = address_of 0xbe
let arbitrary_code = "\x60\x00\x00" (* PUSH1 0 STOP: nonempty, never executed here *)

let self_acct ~nonce ~balance = Account.make ~nonce:(nonce_of nonce) ~balance:(u balance)

let world_seed pairs =
  List.fold_left
    (fun w (address, account) -> World_state.set_account w address account)
    World_state.empty pairs

let block_of ?(number = u 1000) ?(hashes = Block_hashes.empty) () =
  Env.Block.make ~coinbase:(address_of 0xc0) ~timestamp:(u 1_600_000_000) ~number
    ~prevrandao:U256.zero ~gas_limit:(u 25_000_000) ~basefee:(u 7) ~chain_id:(u 2017)
    ~hashes

let env_of ?(mutability = Mutability.Mutable) ?number ?hashes () =
  Env.make
    ~block:(block_of ?number ?hashes ())
    ~tx:(Env.Tx.make ~origin:(address_of 0x09) ~gas_price:(u 9) ~access_list:[])
    ~call:
      (Env.Call.make ~target:self ~caller:(address_of 0xaa) ~value:U256.zero
         ~data:Data.empty ~mutability)

let cold world = Effects.start ~world ~access:Access.empty
let warm world addresses = Effects.start ~world ~access:(Access.of_transaction ~addresses ~slots:[])

let run ~env ~effects ?(gas = 50_000_000) parts =
  Interpreter.run ~env ~code:(asm parts) ~gas:(gas_of gas) ~effects

let depth_of_n n =
  List.fold_left (fun d _ -> Call_depth.succ d) Call_depth.zero (List.init n (fun _ -> ()))

let run_sub ~env ~effects ~depth ?(gas = 50_000_000) parts =
  Interpreter.run_subframe ~env ~code:(asm parts) ~gas:(gas_of gas) ~effects
    ~depth:(depth_of_n depth)

let derive_nonce ~creator n =
  Contract_address.derive ~creator (Contract_address.From_nonce (nonce_of n))

let derive_salt ~creator ~salt ~init_code =
  Contract_address.derive ~creator (Contract_address.From_salt { salt; init_code })

(* ---------- projections of an outcome ---------- *)

let output_of = function
  | Interpreter.Returned { output; _ } | Interpreter.Reverted { output; _ } -> output
  | Interpreter.Stopped _ -> Alcotest.fail "expected an outcome carrying output, got stop"
  | Interpreter.Failed e ->
      Alcotest.fail ("expected output, got failure: " ^ Interpreter.error_to_string e)

let effects_of = function
  | Interpreter.Stopped { effects; _ } | Interpreter.Returned { effects; _ } -> effects
  | Interpreter.Reverted _ -> Alcotest.fail "expected effects, got a top-level revert"
  | Interpreter.Failed e ->
      Alcotest.fail ("expected effects, got failure: " ^ Interpreter.error_to_string e)

let remaining_of = function
  | Interpreter.Stopped { gas_left; _ }
  | Interpreter.Returned { gas_left; _ }
  | Interpreter.Reverted { gas_left; _ } ->
      Gas.remaining gas_left
  | Interpreter.Failed e ->
      Alcotest.fail ("expected a halt carrying gas, got " ^ Interpreter.error_to_string e)

let spend_of ~allowance outcome = allowance - remaining_of outcome
let world_of outcome = Effects.world (effects_of outcome)
let account_at outcome address = World_state.account (world_of outcome) address
let balance_at outcome address = World_state.balance (world_of outcome) address
let storage_at outcome address slot = World_state.storage (world_of outcome) address (u slot)
let destroyed_of outcome = Lifecycle.destroyed (Effects.lifecycle (effects_of outcome))
let refund_of outcome = Refund.to_int (Effects.refund (effects_of outcome))
let warm_at outcome address = Access.mem_account (Effects.access (effects_of outcome)) address
let nonce_at outcome address = Nonce.to_int (Account.nonce (account_at outcome address))

let word_at output i = get (U256.of_be_bytes (String.sub output (i * 32) 32))
let check_word msg expected output i = Alcotest.(check bool) msg true (U256.equal expected (word_at output i))

let is_failed_with expected = function
  | Interpreter.Failed e -> e = expected
  | _ -> false

(* A CREATE program (ending right after the opcode) run two ways: once with a STOP
   appended so the exact spend is measured against [allowance], once with the
   pushed word extracted so it can be read. The first is the gas pin, the second
   the pushed-word pin. *)
let stop_run ~env ~effects ~allowance prog = run ~env ~effects ~gas:allowance (prog @ [ op Opcode.Stop ])

let pushed_word ~env ~effects ~allowance prog =
  word_at (output_of (run ~env ~effects ~gas:allowance (prog @ store_at 0x00 @ return_range ~off:0x00 ~len:0x20))) 0

(* ======================= create ======================= *)

let test_create_empty_initcode_gas () =
  (* PUSH len 0, offset 0, value 0, CREATE, STOP. len 0 skips the 3860 meter and
     the expansion; the empty child STOPs for free; the whole forward returns and
     the deposit is 0. spend = 3 + 3 + 3 + 32000 = 32009. *)
  let world = world_seed [ (self, self_acct ~nonce:0 ~balance:1_000_000) ] in
  let effects = cold world in
  let env = env_of () in
  let prog = emit_create ~value:U256.zero ~offset:U256.zero ~len:U256.zero in
  let stop = stop_run ~env ~effects ~allowance:50_000_000 prog in
  Alcotest.(check int) "an empty CREATE spends the flat 32000 plus three pushes" 32009
    (spend_of ~allowance:50_000_000 stop);
  let created = derive_nonce ~creator:self 0 in
  Alcotest.(check int) "the created account is at nonce one" 1 (nonce_at stop created);
  (* The pushed word is the derived address, and RETURNDATASIZE after a success is
     zero, the CREATE buffer staying empty. *)
  let observed =
    output_of
      (run ~env ~effects
         (prog @ [ op Opcode.Returndatasize ] @ store_at 0x00 @ store_at 0x20
        @ return_range ~off:0x00 ~len:0x40))
  in
  check_word "RETURNDATASIZE after a successful CREATE is zero" U256.zero observed 0;
  check_word "CREATE pushes the derived address" (Address_word.to_word created) observed 1

let test_create_len_zero_huge_offset_succeeds () =
  (* An enormous offset with a zero length is not an error: the offset conversion
     and the expansion are both skipped, so spend is the same flat 32009. *)
  let world = world_seed [ (self, self_acct ~nonce:0 ~balance:1_000_000) ] in
  let effects = cold world in
  let env = env_of () in
  let prog = emit_create ~value:U256.zero ~offset:(pow2 255) ~len:U256.zero in
  Alcotest.(check int) "a zero length ignores an absurd offset" 32009
    (spend_of ~allowance:50_000_000 (stop_run ~env ~effects ~allowance:50_000_000 prog))

let test_create_pushes_pre_increment_address () =
  (* The address is derived from the nonce the creator had BEFORE this creation,
     and the bump survives even a reverting child. *)
  let world = world_seed [ (self, self_acct ~nonce:7 ~balance:1_000_000) ] in
  let effects = cold world in
  let env = env_of () in
  let ok = run ~env ~effects (emit_create ~value:U256.zero ~offset:U256.zero ~len:U256.zero) in
  Alcotest.(check bool) "CREATE derives from the pre-increment nonce seven" true
    (U256.equal (Address_word.to_word (derive_nonce ~creator:self 7)) (word_at (output_of (run ~env ~effects (emit_create ~value:U256.zero ~offset:U256.zero ~len:U256.zero @ store_at 0x00 @ return_range ~off:0x00 ~len:0x20))) 0));
  Alcotest.(check int) "and the world nonce becomes eight" 8 (nonce_at ok self);
  (* A reverting init code still bumps the nonce and creates no account. *)
  let prog = store_initcode ic_revert_four @ emit_create ~value:U256.zero ~offset:U256.zero ~len:(u (String.length ic_revert_four)) in
  let reverted = run ~env ~effects prog in
  Alcotest.(check int) "a reverted creation still bumped the nonce" 8 (nonce_at reverted self);
  Alcotest.(check int) "and left no account at the derived address" 0
    (nonce_at reverted (derive_nonce ~creator:self 7));
  check_word "a reverted creation pushes zero" U256.zero
    (output_of (run ~env ~effects (prog @ store_at 0x00 @ return_range ~off:0x00 ~len:0x20))) 0

let test_create_static_frame_reports_ban () =
  (* The EIP-214 ban is the very first thing each state-changing opcode does, so a
     static frame with an empty stack reports the ban, never a stack underflow. *)
  let world = world_seed [ (self, self_acct ~nonce:0 ~balance:1_000_000) ] in
  let effects = cold world in
  let env = env_of ~mutability:Mutability.Static () in
  List.iter
    (fun (name, o) ->
      Alcotest.(check bool) (name ^ " in a static frame reports the ban") true
        (is_failed_with Interpreter.Static_state_change (run ~env ~effects [ op o ])))
    [ ("CREATE", Opcode.Create); ("CREATE2", Opcode.Create2); ("SELFDESTRUCT", Opcode.Selfdestruct) ]

let test_create_initcode_size_limit () =
  (* len 49153 is one over EIP-3860's ceiling: an error-class halt of the running
     frame, fired before the 3860 charge and before the offset conversion, so
     neither a shortfall nor an absurd offset can mask it. *)
  let world = world_seed [ (self, self_acct ~nonce:0 ~balance:1_000_000) ] in
  let effects = cold world in
  let env = env_of () in
  let over = emit_create ~value:U256.zero ~offset:U256.zero ~len:(u 49153) in
  Alcotest.(check bool) "ample gas still reports the size error" true
    (is_failed_with Interpreter.Initcode_too_large (run ~env ~effects over));
  Alcotest.(check bool) "gas below the 3860 meter still reports the size error, not out of gas" true
    (is_failed_with Interpreter.Initcode_too_large (run ~env ~effects ~gas:100 over));
  Alcotest.(check bool) "an absurd offset still reports the size error, not offset too large" true
    (is_failed_with Interpreter.Initcode_too_large
       (run ~env ~effects (emit_create ~value:U256.zero ~offset:(pow2 255) ~len:(u 49153))))

let test_create_exact_3860_boundary () =
  (* len exactly 49152 is at the ceiling and passes the strict check. Over
     untouched (zero) memory the init code is all STOP, so the child halts at once
     and deploys empty code. spend = 9 + 3072 (2 per word, 1536 words) + 9216
     (expansion of 1536 words) + 32000 = 44297. *)
  let world = world_seed [ (self, self_acct ~nonce:0 ~balance:1_000_000) ] in
  let effects = cold world in
  let env = env_of () in
  let prog = emit_create ~value:U256.zero ~offset:U256.zero ~len:(u 49152) in
  let stop = stop_run ~env ~effects ~allowance:50_000_000 prog in
  Alcotest.(check int) "the exact 3860 boundary succeeds at a closed 44297" 44297
    (spend_of ~allowance:50_000_000 stop);
  Alcotest.(check int) "and a created account lands at the derived address" 1
    (nonce_at stop (derive_nonce ~creator:self 0))

(* ---- the refund class: depth, balance, nonce, all hand back the whole forward *)

let test_create_depth_limit () =
  (* At the parent depth 1024 the child would run at 1025, past the limit, so the
     creation is refused and the WHOLE forward returns: push 0, spend 32009. At
     1023 the child runs at 1024, within the limit, and it creates. *)
  let world = world_seed [ (self, self_acct ~nonce:0 ~balance:1_000_000) ] in
  let effects = cold world in
  let env = env_of () in
  let prog = emit_create ~value:U256.zero ~offset:U256.zero ~len:U256.zero in
  let at_1024 = run_sub ~env ~effects ~depth:1024 (prog @ [ op Opcode.Stop ]) in
  Alcotest.(check int) "a depth-refused creation hands back the whole forward" 32009
    (spend_of ~allowance:50_000_000 at_1024);
  check_word "a depth-refused creation pushes zero" U256.zero
    (output_of (run_sub ~env ~effects ~depth:1024 (prog @ store_at 0x00 @ return_range ~off:0x00 ~len:0x20))) 0;
  check_word "a frame one shallower creates" (Address_word.to_word (derive_nonce ~creator:self 0))
    (output_of (run_sub ~env ~effects ~depth:1023 (prog @ store_at 0x00 @ return_range ~off:0x00 ~len:0x20))) 0

let test_create_balance_guard_strict () =
  (* balance 5, value 6: the transfer would underflow, so push 0, spend 32009, and
     the nonce is NOT bumped because the guard precedes the bump. value 5 equals
     the balance and passes the strict less-than, so it creates and moves it all. *)
  let world = world_seed [ (self, self_acct ~nonce:0 ~balance:5) ] in
  let effects = cold world in
  let env = env_of () in
  let refused = stop_run ~env ~effects ~allowance:50_000_000 (emit_create ~value:(u 6) ~offset:U256.zero ~len:U256.zero) in
  Alcotest.(check int) "an underfunded creation hands back the whole forward" 32009
    (spend_of ~allowance:50_000_000 refused);
  Alcotest.(check int) "and did not bump the creator nonce" 0 (nonce_at refused self);
  Alcotest.(check bool) "an underfunded creation pushes zero" true
    (U256.is_zero (pushed_word ~env ~effects ~allowance:50_000_000 (emit_create ~value:(u 6) ~offset:U256.zero ~len:U256.zero)));
  let ok = run ~env ~effects (emit_create ~value:(u 5) ~offset:U256.zero ~len:U256.zero) in
  let created = derive_nonce ~creator:self 0 in
  Alcotest.(check bool) "a value equal to the balance passes and drains the creator" true
    (U256.is_zero (balance_at ok self));
  Alcotest.(check bool) "and endows the created account" true (U256.equal (u 5) (balance_at ok created))

let test_create_nonce_at_max () =
  (* A creator whose nonce is already at the maximum cannot be bumped, so revm
     abandons the creation, pushes the zero-address word and hands the whole
     forward back: push 0, spend 32009, nonce unchanged, nothing created. *)
  let world = world_seed [ (self, self_acct ~nonce:max_int ~balance:1_000_000) ] in
  let effects = cold world in
  let env = env_of () in
  let prog = emit_create ~value:U256.zero ~offset:U256.zero ~len:U256.zero in
  let stop = stop_run ~env ~effects ~allowance:50_000_000 prog in
  Alcotest.(check int) "a nonce-max creation hands back the whole forward" 32009
    (spend_of ~allowance:50_000_000 stop);
  Alcotest.(check int) "and leaves the creator nonce untouched" max_int (nonce_at stop self);
  check_word "a nonce-max creation pushes zero" U256.zero
    (output_of (run ~env ~effects (prog @ store_at 0x00 @ return_range ~off:0x00 ~len:0x20))) 0

(* ---- the burn class: collision and the three deploy failures burn the forward *)

let test_create_collision_burns_forwarded () =
  (* The derived address is already occupied, so the forward is BURNED, not
     returned. allowance 100000: R = 100000 - 9 - 32000 = 67991, forward =
     R - R/64 = 66929 burned, so surviving = 1062 and spend = 98938. The bump and
     the created-address warmth survive the burn; no account is made. *)
  let created = derive_nonce ~creator:self 0 in
  let by_nonce = world_seed [ (self, self_acct ~nonce:0 ~balance:1_000_000); (created, self_acct ~nonce:1 ~balance:0) ] in
  let by_code = world_seed [ (self, self_acct ~nonce:0 ~balance:1_000_000); (created, Account.with_code (self_acct ~nonce:0 ~balance:0) arbitrary_code) ] in
  let prog = emit_create ~value:U256.zero ~offset:U256.zero ~len:U256.zero in
  List.iter
    (fun (name, world) ->
      let effects = cold world in
      let env = env_of () in
      let stop = stop_run ~env ~effects ~allowance:100_000 prog in
      Alcotest.(check int) (name ^ ": a collision burns the whole forward") 98938
        (spend_of ~allowance:100_000 stop);
      Alcotest.(check int) (name ^ ": the creator nonce is still bumped") 1 (nonce_at stop self);
      Alcotest.(check bool) (name ^ ": the created address is still warm") true (warm_at stop created);
      check_word (name ^ ": a collision pushes zero") U256.zero
        (output_of (run ~env ~effects ~gas:100_000 (prog @ store_at 0x00 @ return_range ~off:0x00 ~len:0x20))) 0)
    [ ("nonzero nonce", by_nonce); ("code", by_code) ]

let test_create_collision_ignores_balance () =
  (* An address that has only received ether is unoccupied and can still be created
     at: balance is never a collision conjunct. The creation succeeds and the
     endowment adds to the balance already there. *)
  let created = derive_nonce ~creator:self 0 in
  let world = world_seed [ (self, self_acct ~nonce:0 ~balance:1_000_000); (created, self_acct ~nonce:0 ~balance:100) ] in
  let effects = cold world in
  let env = env_of () in
  let ok = run ~env ~effects (emit_create ~value:(u 5) ~offset:U256.zero ~len:U256.zero) in
  Alcotest.(check bool) "a balance-only address is created at" true (U256.equal (u 105) (balance_at ok created));
  Alcotest.(check int) "and reaches nonce one" 1 (nonce_at ok created)

let test_create_refusal_clears_return_data () =
  (* A creation that reverts SETS the return-data buffer; a following refusal (here
     an underfunded creation) goes through the shared push-zero, which CLEARS it,
     so RETURNDATASIZE reads zero afterward. *)
  let world = world_seed [ (self, self_acct ~nonce:0 ~balance:5) ] in
  let effects = cold world in
  let env = env_of () in
  let prog =
    store_initcode ic_revert_four
    @ emit_create ~value:U256.zero ~offset:U256.zero ~len:(u (String.length ic_revert_four))
    @ emit_create ~value:(u 6) ~offset:U256.zero ~len:U256.zero
    @ [ op Opcode.Returndatasize ] @ store_at 0x00 @ return_range ~off:0x00 ~len:0x20
  in
  check_word "a refusal clears the buffer a prior revert set" U256.zero (output_of (run ~env ~effects prog)) 0

let test_create_over_storage_reads_zero () =
  (* The F1 pin. The derived address is unoccupied (zero nonce, no code) but holds
     storage {1 -> 7} and a balance. begin_creation must clear its storage and
     plan_store must read EIP-2200's original as zero for it. *)
  let created = derive_nonce ~creator:self 0 in
  let seeded = Account.set_slot (self_acct ~nonce:0 ~balance:3) (u 1) (u 7) in
  let world = world_seed [ (self, self_acct ~nonce:0 ~balance:1_000_000); (created, seeded) ] in
  let effects = cold world in
  let env = env_of () in
  (* (i) an SLOAD of the seeded slot inside the init code must read zero, so the
     32-byte deployed code is all zeros rather than the word seven. *)
  let deploy_prog = store_initcode ic_sload_slot1 @ emit_create ~value:U256.zero ~offset:U256.zero ~len:(u (String.length ic_sload_slot1)) in
  let deployed = run ~env ~effects deploy_prog in
  Alcotest.(check string) "a created account SLOADs zero, not the previous occupant's slot"
    (String.make 32 '\000') (Account.code (account_at deployed created));
  Alcotest.(check bool) "the pre-existing balance survives the endowment" true
    (U256.equal (u 3) (balance_at deployed created));
  (* (ii) an SSTORE of that slot is priced as a COLD FRESH SET (original 0):
     100 + 2100 + 19900. spend = upfront 32023 + child (3 + 3 + 22100) = 54129,
     refund 0. A dirty or reset classification would move both. *)
  let store_prog = store_initcode ic_sstore_slot1 @ emit_create ~value:U256.zero ~offset:U256.zero ~len:(u (String.length ic_sstore_slot1)) in
  let stored = stop_run ~env ~effects ~allowance:50_000_000 store_prog in
  Alcotest.(check int) "an SSTORE over created storage is a cold fresh set" 54129
    (spend_of ~allowance:50_000_000 stored);
  Alcotest.(check int) "and earns no restoration refund" 0 (refund_of stored);
  Alcotest.(check bool) "the write itself lands" true (U256.equal (u 7) (storage_at stored created 1))

(* ======================= create2 ======================= *)

let test_create2_one_byte_initcode_gas () =
  (* MSTORE8 a zero byte (prelude 12, reaching word 0), then CREATE2 over a
     one-byte init code (a STOP): initcode meter 2, no expansion (already reached),
     fused base 32000 + 6 = 32006. spend = 12 + 12 + 2 + 32006 = 32032. *)
  let world = world_seed [ (self, self_acct ~nonce:0 ~balance:1_000_000) ] in
  let effects = cold world in
  let env = env_of () in
  let prelude = [ push1 0x00; push1 0x00; op Opcode.Mstore8 ] in
  let prog = prelude @ emit_create2 ~value:U256.zero ~offset:U256.zero ~len:(u 1) ~salt:(u 0xabc) in
  Alcotest.(check int) "CREATE2's fused base is 32000 + 6 per init-code word" 32032
    (spend_of ~allowance:50_000_000 (run ~env ~effects (prog @ [ op Opcode.Stop ])))

let test_create2_address_matches_derivation () =
  (* The pushed word is CREATE2's salted derivation of the program's own salt and
     init code, and the world nonce still bumps under a salted creation. *)
  let world = world_seed [ (self, self_acct ~nonce:0 ~balance:1_000_000) ] in
  let effects = cold world in
  let env = env_of () in
  let salt = u 0xfeed in
  let prelude = [ push1 0x00; push1 0x00; op Opcode.Mstore8 ] in
  let prog = prelude @ emit_create2 ~value:U256.zero ~offset:U256.zero ~len:(u 1) ~salt in
  let expected = derive_salt ~creator:self ~salt ~init_code:ic_stop in
  check_word "CREATE2 pushes its salted derivation" (Address_word.to_word expected)
    (output_of (run ~env ~effects (prog @ store_at 0x00 @ return_range ~off:0x00 ~len:0x20))) 0;
  Alcotest.(check int) "and still bumps the creator nonce" 1 (nonce_at (run ~env ~effects prog) self)

let test_create2_three_item_stack_orders_errors () =
  (* The salt is a fourth pop taken only AFTER the 3860 charge and the memory work,
     so a three-item stack pays those and only then underflows. With ample gas that
     is a stack underflow; with too little for the 3860 meter it is out of gas. *)
  let world = world_seed [ (self, self_acct ~nonce:0 ~balance:1_000_000) ] in
  let effects = cold world in
  let env = env_of () in
  (* Three items only: value, offset, len (a one-word init code), no salt. *)
  let three = [ push32 (u 1); push32 U256.zero; push32 U256.zero; op Opcode.Create2 ] in
  Alcotest.(check bool) "a saltless CREATE2 underflows after the paid charges" true
    (is_failed_with Interpreter.Stack_underflow (run ~env ~effects three));
  (* Three pushes cost 9; allowance 10 leaves 1, below the 3860 meter of 2, so the
     charge that follows the memory work is what runs out of gas. *)
  Alcotest.(check bool) "and out of gas when the 3860 meter is unaffordable" true
    (is_failed_with Interpreter.Out_of_gas (run ~env ~effects ~gas:10 three))

(* ======================= deploy ======================= *)

let test_validate_deployment_ef_before_size () =
  (* The reserved-prefix check runs before the size check, an order the opcode
     surface renders as two identical burns. *)
  Alcotest.(check bool) "a 0xEF prefix is rejected before the size" true
    (match Bytecode.validate_deployment ("\xef" ^ String.make 24576 '\000') with
     | Error Bytecode.Reserved_prefix -> true
     | _ -> false);
  Alcotest.(check bool) "an over-long clean output is Too_large" true
    (match Bytecode.validate_deployment (String.make 24577 '\000') with
     | Error (Bytecode.Too_large 24577) -> true
     | _ -> false);
  Alcotest.(check bool) "a clean 24576-byte output is accepted" true
    (match Bytecode.validate_deployment (String.make 24576 '\000') with Ok () -> true | _ -> false)

let test_create_deposit_charged_to_child () =
  (* Init code returns one zero byte. The 200-per-byte deposit is charged out of
     the CHILD's leftover: spend = upfront 32023 + child 9 + deposit 200 = 32232,
     and the deployed code is that one byte. *)
  let world = world_seed [ (self, self_acct ~nonce:0 ~balance:1_000_000) ] in
  let effects = cold world in
  let env = env_of () in
  let prog = store_initcode ic_return_one_zero @ emit_create ~value:U256.zero ~offset:U256.zero ~len:(u (String.length ic_return_one_zero)) in
  let stop = stop_run ~env ~effects ~allowance:50_000_000 prog in
  Alcotest.(check int) "the deposit is charged to the child leftover" 32232
    (spend_of ~allowance:50_000_000 stop);
  let created = derive_nonce ~creator:self 0 in
  Alcotest.(check int) "the deployed code is one byte" 1 (Account.code_length (account_at stop created));
  Alcotest.(check string) "and it is the returned zero byte" "\x00" (Account.code (account_at stop created))

let test_create_revert_sets_buffer_and_returns_gas () =
  (* A reverting init code with output is the ONE creation outcome that fills the
     buffer: push 0, RETURNDATASIZE reads the four bytes, no account is made, the
     nonce is still bumped and the address is warm. *)
  let world = world_seed [ (self, self_acct ~nonce:0 ~balance:1_000_000) ] in
  let effects = cold world in
  let env = env_of () in
  let prog = store_initcode ic_revert_four @ emit_create ~value:U256.zero ~offset:U256.zero ~len:(u (String.length ic_revert_four)) in
  let observed = output_of (run ~env ~effects (prog @ [ op Opcode.Returndatasize ] @ store_at 0x00 @ return_range ~off:0x00 ~len:0x20)) in
  check_word "a reverting creation leaves its output in the buffer" (u 4) observed 0;
  let created = derive_nonce ~creator:self 0 in
  let stop = run ~env ~effects (prog @ [ op Opcode.Stop ]) in
  Alcotest.(check int) "a reverted creation makes no account" 0 (nonce_at stop created);
  Alcotest.(check int) "but still bumped the creator nonce" 1 (nonce_at stop self);
  Alcotest.(check bool) "and the derived address is warm" true (warm_at stop created);
  check_word "a reverting creation pushes zero" U256.zero
    (output_of (run ~env ~effects (prog @ store_at 0x00 @ return_range ~off:0x00 ~len:0x20))) 0

let test_create_success_clears_buffer () =
  (* Even though the child RETURNed the code bytes, RETURNDATASIZE after a
     successful CREATE reads zero: the deployed code is not return data. *)
  let world = world_seed [ (self, self_acct ~nonce:0 ~balance:1_000_000) ] in
  let effects = cold world in
  let env = env_of () in
  let prog = store_initcode ic_return_one_zero @ emit_create ~value:U256.zero ~offset:U256.zero ~len:(u (String.length ic_return_one_zero)) in
  check_word "a successful CREATE leaves the buffer empty" U256.zero
    (output_of (run ~env ~effects (prog @ [ op Opcode.Returndatasize ] @ store_at 0x00 @ return_range ~off:0x00 ~len:0x20))) 0

let test_create_deploy_failures_burn () =
  (* Each deploy failure burns the WHOLE forward, exactly as a collision does. *)
  let world = world_seed [ (self, self_acct ~nonce:0 ~balance:1_000_000) ] in
  let env = env_of () in
  let created = derive_nonce ~creator:self 0 in
  (* (a) EIP-3541, one 0xEF byte. allowance 60000: upfront 32023, R = 27977,
     surviving = floor(27977/64) = 437, spend = 59563. *)
  let ef_prog = store_initcode ic_return_ef @ emit_create ~value:U256.zero ~offset:U256.zero ~len:(u (String.length ic_return_ef)) in
  let ef = stop_run ~env ~effects:(cold world) ~allowance:60_000 ef_prog in
  Alcotest.(check int) "EIP-3541 burns the forward" 59563 (spend_of ~allowance:60_000 ef);
  Alcotest.(check int) "and deploys no code" 0 (Account.code_length (account_at ef created));
  check_word "the 0xEF deploy pushes zero" U256.zero
    (output_of (run ~env ~effects:(cold world) ~gas:60_000 (ef_prog @ store_at 0x00 @ return_range ~off:0x00 ~len:0x20))) 0;
  (* (b) EIP-170, 24577 bytes. Same upfront and allowance, the child pays its own
     expansion out of the forward: spend 59563. *)
  let over_prog = store_initcode ic_return_over_170 @ emit_create ~value:U256.zero ~offset:U256.zero ~len:(u (String.length ic_return_over_170)) in
  let over = stop_run ~env ~effects:(cold world) ~allowance:60_000 over_prog in
  Alcotest.(check int) "EIP-170 burns the forward" 59563 (spend_of ~allowance:60_000 over);
  check_word "the over-size deploy pushes zero" U256.zero
    (output_of (run ~env ~effects:(cold world) ~gas:60_000 (over_prog @ store_at 0x00 @ return_range ~off:0x00 ~len:0x20))) 0;
  (* (b') exactly 24576 with ample gas SUCCEEDS, pinning the strict > from below. *)
  let at_prog = store_initcode ic_return_at_170 @ emit_create ~value:U256.zero ~offset:U256.zero ~len:(u (String.length ic_return_at_170)) in
  let at = run ~env ~effects:(cold world) at_prog in
  Alcotest.(check int) "exactly 24576 bytes deploys" 24576 (Account.code_length (account_at at created));
  (* (c) the child completes but cannot pay the 6400 deposit. allowance 38023:
     upfront 32023, R = 6000, forward = 5907, child spends 9 and cannot pay 6400,
     surviving = floor(6000/64) = 93, spend = 37930. *)
  let oog_prog = store_initcode ic_return_word @ emit_create ~value:U256.zero ~offset:U256.zero ~len:(u (String.length ic_return_word)) in
  let oog = stop_run ~env ~effects:(cold world) ~allowance:38_023 oog_prog in
  Alcotest.(check int) "a deposit the child cannot pay burns the forward" 37930 (spend_of ~allowance:38_023 oog);
  Alcotest.(check int) "and deploys no code" 0 (Account.code_length (account_at oog created));
  check_word "the unpaid deposit pushes zero" U256.zero
    (output_of (run ~env ~effects:(cold world) ~gas:38_023 (oog_prog @ store_at 0x00 @ return_range ~off:0x00 ~len:0x20))) 0

(* ======================= selfdestruct ======================= *)

let test_selfdestruct_cold_absent_beneficiary_gas () =
  (* Funded self (pre-warmed as the tx layer would), an absent cold beneficiary:
     spend = 3 + 5000 + 25000 (had value, empty beneficiary) + 2600 (cold) = 32603.
     The account is uncreated, so it is drained not destroyed and keeps its code. *)
  let world = world_seed [ (self, Account.with_code (self_acct ~nonce:1 ~balance:1000) arbitrary_code) ] in
  let effects = warm world [ self ] in
  let env = env_of () in
  let outcome = run ~env ~effects [ push20 beneficiary; op Opcode.Selfdestruct ] in
  Alcotest.(check int) "cold absent selfdestruct spends 5000 + 25000 + 2600 + 3" 32603
    (spend_of ~allowance:50_000_000 outcome);
  Alcotest.(check bool) "the beneficiary receives the whole balance" true (U256.equal (u 1000) (balance_at outcome beneficiary));
  Alcotest.(check bool) "the drained account keeps nothing" true (U256.is_zero (balance_at outcome self));
  Alcotest.(check int) "an uncreated selfdestruct records no removal" 0 (List.length (destroyed_of outcome));
  Alcotest.(check string) "and keeps its code, deletion deferred" arbitrary_code (Account.code (account_at outcome self))

let test_selfdestruct_warm_existing_beneficiary () =
  let env = env_of () in
  (* Warm, existing beneficiary: no 25000, no 2600, spend 3 + 5000 = 5003. *)
  let existing = address_of 0xbb in
  let w1 = world_seed [ (self, Account.with_code (self_acct ~nonce:1 ~balance:1000) arbitrary_code); (existing, self_acct ~nonce:0 ~balance:50) ] in
  let o1 = run ~env ~effects:(warm w1 [ self; existing ]) [ push20 existing; op Opcode.Selfdestruct ] in
  Alcotest.(check int) "warm existing beneficiary is the bare 5003" 5003 (spend_of ~allowance:50_000_000 o1);
  (* Zero-balance self to an absent cold beneficiary: no 25000 (nothing to send),
     cold 2600, spend 3 + 5000 + 2600 = 7603. *)
  let w2 = world_seed [ (self, Account.with_code (self_acct ~nonce:1 ~balance:0) arbitrary_code) ] in
  let o2 = run ~env ~effects:(warm w2 [ self ]) [ push20 beneficiary; op Opcode.Selfdestruct ] in
  Alcotest.(check int) "a valueless drain to a cold absentee is 7603" 7603 (spend_of ~allowance:50_000_000 o2);
  (* A storage-bearing but EIP-161-empty beneficiary, pre-warmed: is_empty (not
     is_absent) is the emptiness measure, so the 25000 still applies. spend 30003. *)
  let empty_with_storage = Account.set_slot (self_acct ~nonce:0 ~balance:0) (u 3) (u 9) in
  let w3 = world_seed [ (self, Account.with_code (self_acct ~nonce:1 ~balance:1000) arbitrary_code); (beneficiary, empty_with_storage) ] in
  let o3 = run ~env ~effects:(warm w3 [ self; beneficiary ]) [ push20 beneficiary; op Opcode.Selfdestruct ] in
  Alcotest.(check int) "a storage-only beneficiary is still empty, so 30003" 30003 (spend_of ~allowance:50_000_000 o3)

let test_selfdestruct_to_self_not_created_keeps_balance () =
  (* An uncreated account naming itself as beneficiary: the no-op third arm. Its
     balance is left exactly where it is and no removal is recorded. Self is
     pre-warmed to model the frame-entry warming every reachable revm state has. *)
  let world = world_seed [ (self, Account.with_code (self_acct ~nonce:1 ~balance:1000) arbitrary_code) ] in
  let effects = warm world [ self ] in
  let env = env_of () in
  let outcome = run ~env ~effects [ push20 self; op Opcode.Selfdestruct ] in
  Alcotest.(check int) "a self-target uncreated selfdestruct is the bare 5003" 5003 (spend_of ~allowance:50_000_000 outcome);
  Alcotest.(check bool) "and leaves the balance untouched" true (U256.equal (u 1000) (balance_at outcome self));
  Alcotest.(check int) "recording no removal" 0 (List.length (destroyed_of outcome))

let test_selfdestruct_created_this_tx () =
  (* An account created THIS transaction really goes. Init code ADDRESS,
     SELFDESTRUCT with value 5: the creation succeeds as an empty deploy (the
     SelfDestruct halt is ok-class), the created address is destroyed-marked, and
     the 5 is burned because the beneficiary is the account itself. Child spend =
     2 + 5000 = 5002 (self warm, exists at nonce one, no surcharges); parent total
     = 12 + 9 + 2 + 32000 + 5002 = 37025. *)
  let world = world_seed [ (self, self_acct ~nonce:0 ~balance:1000) ] in
  let effects = cold world in
  let env = env_of () in
  let created = derive_nonce ~creator:self 0 in
  let prog = store_initcode ic_address_selfdestruct @ emit_create ~value:(u 5) ~offset:U256.zero ~len:(u (String.length ic_address_selfdestruct)) in
  let stop = stop_run ~env ~effects ~allowance:50_000_000 prog in
  Alcotest.(check int) "a create that selfdestructs to itself totals 37025" 37025 (spend_of ~allowance:50_000_000 stop);
  Alcotest.(check bool) "the created account is recorded destroyed" true
    (List.exists (Units.Address.equal created) (destroyed_of stop));
  Alcotest.(check bool) "the endowment is burned with the account" true (U256.is_zero (balance_at stop created));
  Alcotest.(check bool) "and the creator paid exactly the value out" true (U256.equal (u 995) (balance_at stop self));
  (* A distinct beneficiary C is credited instead, the account still destroyed. *)
  let c = address_of 0xcc in
  let prog2 = store_initcode (ic_selfdestruct_to c) @ emit_create ~value:(u 5) ~offset:U256.zero ~len:(u (String.length (ic_selfdestruct_to c))) in
  let stop2 = run ~env ~effects prog2 in
  Alcotest.(check bool) "a distinct beneficiary is credited" true (U256.equal (u 5) (balance_at stop2 c));
  Alcotest.(check bool) "the created account is emptied" true (U256.is_zero (balance_at stop2 created));
  Alcotest.(check bool) "and still recorded destroyed" true (List.exists (Units.Address.equal created) (destroyed_of stop2))

(* ======================= blockhash ======================= *)

let window_hashes = List.init 256 (fun i -> Keccak.digest (Printf.sprintf "ancestor-%d" i))
let window = Block_hashes.of_recent window_hashes
let hash_word i = get (U256.of_be_bytes (Keccak.to_bytes (List.nth window_hashes i)))

let test_blockhash_range_and_gas () =
  (* Full 256-hash window at number 1000. distance 1 and distance 256 return the
     seeded words; the current block, a future block, distance 257 and a diff past
     a native int all read zero. Every probe spends the table 20 plus one push. *)
  let world = world_seed [ (self, self_acct ~nonce:0 ~balance:1000) ] in
  let effects = cold world in
  let env = env_of ~number:(u 1000) ~hashes:window () in
  let probe requested = output_of (run ~env ~effects ([ push32 requested; op Opcode.Blockhash ] @ store_at 0x00 @ return_range ~off:0x00 ~len:0x20)) in
  check_word "distance one returns the newest ancestor" (hash_word 0) (probe (u 999)) 0;
  check_word "distance 256 returns the oldest in range" (hash_word 255) (probe (u 744)) 0;
  check_word "the current block reads zero" U256.zero (probe (u 1000)) 0;
  check_word "a future block reads zero" U256.zero (probe (u 1001)) 0;
  check_word "distance 257 reads zero" U256.zero (probe (u 743)) 0;
  let far_env = env_of ~number:(pow2 200) ~hashes:window () in
  check_word "a difference past a native int reads zero" U256.zero
    (output_of (run ~env:far_env ~effects ([ push32 U256.zero; op Opcode.Blockhash ] @ store_at 0x00 @ return_range ~off:0x00 ~len:0x20))) 0;
  Alcotest.(check int) "a BLOCKHASH probe spends the flat table 20 plus the push" 23
    (spend_of ~allowance:50_000_000 (run ~env ~effects [ push32 (u 999); op Opcode.Blockhash; op Opcode.Stop ]))

let test_blockhash_gas_before_pop () =
  (* The table 20 is charged by the step loop before the body pops, so an empty
     stack with 19 is out of gas and with 20 is a stack underflow. *)
  let world = world_seed [ (self, self_acct ~nonce:0 ~balance:1000) ] in
  let effects = cold world in
  let env = env_of ~number:(u 1000) ~hashes:window () in
  Alcotest.(check bool) "19 cannot pay the table 20" true
    (is_failed_with Interpreter.Out_of_gas (run ~env ~effects ~gas:19 [ op Opcode.Blockhash ]));
  Alcotest.(check bool) "20 pays the table then underflows on the empty stack" true
    (is_failed_with Interpreter.Stack_underflow (run ~env ~effects ~gas:20 [ op Opcode.Blockhash ]))

let test_blockhash_short_window_reads_zero () =
  (* A ratified divergence from revm's in-range fatal halt: a window that does not
     hold a requested in-range ancestor reads zero. A one-hash window has nothing
     at distance two. *)
  let world = world_seed [ (self, self_acct ~nonce:0 ~balance:1000) ] in
  let effects = cold world in
  let short = Block_hashes.of_recent [ Keccak.digest "only-ancestor" ] in
  let env = env_of ~number:(u 1000) ~hashes:short () in
  check_word "an in-range miss reads zero, not a fatal halt" U256.zero
    (output_of (run ~env ~effects ([ push32 (u 998); op Opcode.Blockhash ] @ store_at 0x00 @ return_range ~off:0x00 ~len:0x20))) 0

let () =
  Alcotest.run "creation"
    [
      ( "addresses",
        [
          Alcotest.test_case "CREATE2 against EIP-1014's vectors" `Quick
            test_create2_eip1014_vectors;
          Alcotest.test_case "CREATE against an independent keccak oracle" `Quick
            test_create_nonce_vectors;
          Alcotest.test_case "the nonce moves the address" `Quick
            test_create_nonce_changes_address;
          Alcotest.test_case "salt and init code move it independently" `Quick
            test_create2_salt_and_code_independent;
        ] );
      ( "create",
        [
          Alcotest.test_case "the empty-init-code flat gas" `Quick test_create_empty_initcode_gas;
          Alcotest.test_case "a zero length ignores a huge offset" `Quick
            test_create_len_zero_huge_offset_succeeds;
          Alcotest.test_case "the pushed pre-increment address" `Quick
            test_create_pushes_pre_increment_address;
          Alcotest.test_case "the static-frame ban precedes the pop" `Quick
            test_create_static_frame_reports_ban;
          Alcotest.test_case "the EIP-3860 size limit precedes the charge" `Quick
            test_create_initcode_size_limit;
          Alcotest.test_case "the exact 3860 boundary" `Quick test_create_exact_3860_boundary;
          Alcotest.test_case "the depth limit hands back the forward" `Quick
            test_create_depth_limit;
          Alcotest.test_case "the strict balance guard" `Quick test_create_balance_guard_strict;
          Alcotest.test_case "a nonce at max abandons the creation" `Quick
            test_create_nonce_at_max;
          Alcotest.test_case "a collision burns the forward" `Quick
            test_create_collision_burns_forwarded;
          Alcotest.test_case "a collision ignores balance" `Quick
            test_create_collision_ignores_balance;
          Alcotest.test_case "a refusal clears the return-data buffer" `Quick
            test_create_refusal_clears_return_data;
          Alcotest.test_case "create over storage reads zero (F1)" `Quick
            test_create_over_storage_reads_zero;
        ] );
      ( "create2",
        [
          Alcotest.test_case "the one-byte fused gas" `Quick test_create2_one_byte_initcode_gas;
          Alcotest.test_case "the pushed salted derivation" `Quick
            test_create2_address_matches_derivation;
          Alcotest.test_case "the salt is a fourth pop" `Quick
            test_create2_three_item_stack_orders_errors;
        ] );
      ( "deploy",
        [
          Alcotest.test_case "validate_deployment orders EF before size" `Quick
            test_validate_deployment_ef_before_size;
          Alcotest.test_case "the deposit is charged to the child" `Quick
            test_create_deposit_charged_to_child;
          Alcotest.test_case "a revert sets the buffer and returns gas" `Quick
            test_create_revert_sets_buffer_and_returns_gas;
          Alcotest.test_case "a success clears the buffer" `Quick
            test_create_success_clears_buffer;
          Alcotest.test_case "the three deploy failures burn" `Quick
            test_create_deploy_failures_burn;
        ] );
      ( "selfdestruct",
        [
          Alcotest.test_case "cold absent beneficiary gas" `Quick
            test_selfdestruct_cold_absent_beneficiary_gas;
          Alcotest.test_case "warm and existing beneficiaries" `Quick
            test_selfdestruct_warm_existing_beneficiary;
          Alcotest.test_case "an uncreated self-target is a no-op" `Quick
            test_selfdestruct_to_self_not_created_keeps_balance;
          Alcotest.test_case "an account created this tx is destroyed" `Quick
            test_selfdestruct_created_this_tx;
        ] );
      ( "blockhash",
        [
          Alcotest.test_case "the window, the misses and the gas" `Quick
            test_blockhash_range_and_gas;
          Alcotest.test_case "the table 20 precedes the pop" `Quick test_blockhash_gas_before_pop;
          Alcotest.test_case "a short window reads zero" `Quick
            test_blockhash_short_window_reads_zero;
        ] );
    ]
