(* The EVM precompiled contracts (0x01 ECRECOVER, 0x02 SHA256, 0x03 RIPEMD160,
   0x04 IDENTITY, 0x05 MODEXP, 0x09 BLAKE2F) and the CALL-family seam that runs
   them. Two layers: direct [Precompile.invoke] unit tests pinned to an
   independent oracle (telcoin-ocaml-chunk25-vectors.txt: go-ethereum's ECRECOVER
   vector, EIP-198/2565 MODEXP cases, and EIP-152's own BLAKE2F vectors), and
   interpreter seam tests that mirror test_calls.ml to prove the dispatch maps a
   [Succeeded] onto a [Returned] (push 1, output copied) and a [Rejected] onto a
   [Failed] (push 0, whole forwarded allowance consumed).

   Gas figures are absolute where asserted, so a mispriced builtin fails a test
   rather than quietly changing what a precompile costs. *)

module U256 = Tn_state.U256
module Account = Tn_state.Account
module Nonce = Tn_state.Nonce
module World_state = Tn_state.World_state
module Units = Tn_types.Units
module Access = Tn_evm.Access
module Code = Tn_evm.Code
module Data = Tn_evm.Data
module Effects = Tn_evm.Effects
module Env = Tn_evm.Env
module Gas = Tn_evm.Gas
module Interpreter = Tn_evm.Interpreter
module Mutability = Tn_evm.Mutability
module Opcode = Tn_evm.Opcode
module Precompile = Tn_evm.Precompile

let get = function Some x -> x | None -> Alcotest.fail "expected Some"
let u n = get (U256.of_int n)
let gas_of n = get (Gas.of_int n)
let width_of n = get (Opcode.Push_bytes.of_int n)
let nonce_of n = get (Nonce.of_int n)

(* A precompile address is [0x0…0N]: twenty bytes, all zero but the last. *)
let address_of n =
  get
    (Units.Address.of_bytes
       (String.make (Units.Address.length - 1) '\000' ^ String.make 1 (Char.chr n)))

(* A big-endian hex string (no 0x prefix) as its raw bytes, exactly as the oracle
   file writes its vectors. *)
let unhex hex =
  String.init
    (String.length hex / 2)
    (fun i -> Char.chr (int_of_string ("0x" ^ String.sub hex (2 * i) 2)))

(* A single byte value widened to a 32-byte big-endian word (the ECRECOVER [v]
   field and the MODEXP length headers below 256). *)
let word_byte v = String.make 31 '\000' ^ String.make 1 (Char.chr v)

(* ================================================================== *)
(* Unit tests: Precompile.invoke directly                             *)
(* ================================================================== *)

let invoke_at n = Precompile.invoke (address_of n)

let check_succeeded ~msg ~gas ~output result =
  match result with
  | Precompile.Succeeded { gas_used; output = out } ->
      Alcotest.(check int) (msg ^ ": gas_used") gas gas_used;
      Alcotest.(check string) (msg ^ ": output") output out
  | Precompile.Rejected -> Alcotest.fail (msg ^ ": expected Succeeded, got Rejected")
  | Precompile.Not_a_precompile ->
      Alcotest.fail (msg ^ ": expected Succeeded, got Not_a_precompile")

let check_gas ~msg ~gas result =
  match result with
  | Precompile.Succeeded { gas_used; _ } -> Alcotest.(check int) (msg ^ ": gas_used") gas gas_used
  | Precompile.Rejected -> Alcotest.fail (msg ^ ": expected Succeeded, got Rejected")
  | Precompile.Not_a_precompile ->
      Alcotest.fail (msg ^ ": expected Succeeded, got Not_a_precompile")

let check_rejected ~msg result =
  match result with
  | Precompile.Rejected -> ()
  | Precompile.Succeeded _ -> Alcotest.fail (msg ^ ": expected Rejected, got Succeeded")
  | Precompile.Not_a_precompile ->
      Alcotest.fail (msg ^ ": expected Rejected, got Not_a_precompile")

(* ---------- 0x04 IDENTITY ---------- *)

let ident33 = unhex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
let ident32 = unhex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

let test_identity () =
  check_succeeded ~msg:"identity/empty" ~gas:15 ~output:"" (invoke_at 4 ~input:"" ~gas_limit:15);
  check_succeeded ~msg:"identity/ff (len 1)" ~gas:18 ~output:(unhex "ff")
    (invoke_at 4 ~input:(unhex "ff") ~gas_limit:18);
  check_succeeded ~msg:"identity/32 bytes" ~gas:18 ~output:ident32
    (invoke_at 4 ~input:ident32 ~gas_limit:18);
  check_succeeded ~msg:"identity/33 bytes" ~gas:21 ~output:ident33
    (invoke_at 4 ~input:ident33 ~gas_limit:21);
  (* OOG one below the cost of the empty call (15). *)
  check_rejected ~msg:"identity OOG" (invoke_at 4 ~input:"" ~gas_limit:14)

(* ---------- 0x02 SHA-256 ---------- *)

let sha256_empty = unhex "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
let sha256_abc = unhex "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

let test_sha256 () =
  check_succeeded ~msg:"sha256/empty" ~gas:60 ~output:sha256_empty
    (invoke_at 2 ~input:"" ~gas_limit:60);
  check_succeeded ~msg:"sha256/abc" ~gas:72 ~output:sha256_abc
    (invoke_at 2 ~input:(unhex "616263") ~gas_limit:72);
  check_rejected ~msg:"sha256 OOG" (invoke_at 2 ~input:(unhex "616263") ~gas_limit:71)

(* ---------- 0x03 RIPEMD-160 (20-byte digest left-padded to 32) ---------- *)

let ripemd_empty = unhex "0000000000000000000000009c1185a5c5e9fc54612808977ee8f548b2258d31"
let ripemd_abc = unhex "0000000000000000000000008eb208f7e05d987a9b044a8e98c6b087f15a0bfc"

let test_ripemd160 () =
  let r_empty = invoke_at 3 ~input:"" ~gas_limit:600 in
  check_succeeded ~msg:"ripemd160/empty" ~gas:600 ~output:ripemd_empty r_empty;
  (* The 12-byte left pad must be present: 32 bytes, the first 12 all zero. *)
  (match r_empty with
  | Precompile.Succeeded { output; _ } ->
      Alcotest.(check int) "ripemd160 output width" 32 (String.length output);
      Alcotest.(check string) "ripemd160 left pad" (String.make 12 '\000') (String.sub output 0 12)
  | _ -> Alcotest.fail "ripemd160/empty: expected Succeeded");
  check_succeeded ~msg:"ripemd160/abc" ~gas:720 ~output:ripemd_abc
    (invoke_at 3 ~input:(unhex "616263") ~gas_limit:720);
  check_rejected ~msg:"ripemd160 OOG" (invoke_at 3 ~input:"" ~gas_limit:599)

(* ---------- 0x01 ECRECOVER ---------- *)

(* input = hash(32) | v(32) | r(32) | s(32). *)
let ecrecover_input ~hash ~v ~r ~s = hash ^ word_byte v ^ r ^ s

let ec_hash = unhex "456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3"
let ec_r = unhex "9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608"
let ec_s = unhex "4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada"
let ec_output = unhex "0000000000000000000000007156526fbd7a3c72969b54f64e42c10fbb768c8a"
(* high-s variant: s' = n - s, v flipped 28 -> 27; must recover the same address. *)
let ec_s_prime = unhex "b0751c428acadb72f42bb7d6733d1df79c5843b9a7d3c407b39bd3a37fb11667"

let test_ecrecover () =
  check_succeeded ~msg:"ecrecover/canonical" ~gas:3000 ~output:ec_output
    (invoke_at 1 ~input:(ecrecover_input ~hash:ec_hash ~v:28 ~r:ec_r ~s:ec_s) ~gas_limit:3000);
  check_succeeded ~msg:"ecrecover/high-s same address" ~gas:3000 ~output:ec_output
    (invoke_at 1
       ~input:(ecrecover_input ~hash:ec_hash ~v:27 ~r:ec_r ~s:ec_s_prime)
       ~gas_limit:3000);
  (* Malformed v or r is a genuine success with EMPTY output. *)
  check_succeeded ~msg:"ecrecover/v=26 invalid" ~gas:3000 ~output:""
    (invoke_at 1 ~input:(ecrecover_input ~hash:ec_hash ~v:26 ~r:ec_r ~s:ec_s) ~gas_limit:3000);
  check_succeeded ~msg:"ecrecover/v=29 invalid" ~gas:3000 ~output:""
    (invoke_at 1 ~input:(ecrecover_input ~hash:ec_hash ~v:29 ~r:ec_r ~s:ec_s) ~gas_limit:3000);
  check_succeeded ~msg:"ecrecover/r=0 invalid" ~gas:3000 ~output:""
    (invoke_at 1
       ~input:(ecrecover_input ~hash:ec_hash ~v:28 ~r:(String.make 32 '\000') ~s:ec_s)
       ~gas_limit:3000);
  check_rejected ~msg:"ecrecover OOG at 2999"
    (invoke_at 1 ~input:(ecrecover_input ~hash:ec_hash ~v:28 ~r:ec_r ~s:ec_s) ~gas_limit:2999)

(* ---------- 0x05 MODEXP (EIP-198 layout / EIP-2565 gas) ---------- *)

let be32_small n = String.make 31 '\000' ^ String.make 1 (Char.chr n)

let modexp_a =
  unhex
    "000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001030564"

let modexp_b1 =
  unhex
    "0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000"

let modexp_b2 =
  unhex
    "000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001030500"

let modexp_c =
  unhex
    "000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000028000000000000000000000000000000000000000000000000000000000000000"

let modexp_c_out = unhex "0000000000000000000000000000000000000000000000000000000000000009"

(* base_len=exp_len=mod_len=32, base=3, mod=100; gas depends only on the exponent. *)
let modexp_gas_input ~exp32 =
  be32_small 32 ^ be32_small 32 ^ be32_small 32 ^ be32_small 3 ^ exp32 ^ be32_small 100

(* trailing calldata beyond the declared lengths is discarded (revm right_pad_vec
   truncates to base_len+exp_len+mod_len): lengths 1/1/1 with base=3, exp=2,
   mod=0x07, plus a stray 0x01 byte that is dropped, so the modulus stays 0x07
   and 3^2 mod 7 = 2 (the stray byte must NOT extend it to 0x0701). *)
let modexp_extended = be32_small 1 ^ be32_small 1 ^ be32_small 1 ^ unhex "03020701"

let test_modexp () =
  check_succeeded ~msg:"modexp/3^5 mod 100" ~gas:200 ~output:(unhex "2b")
    (invoke_at 5 ~input:modexp_a ~gas_limit:100_000);
  check_succeeded ~msg:"modexp/mod_len 0 -> empty" ~gas:200 ~output:""
    (invoke_at 5 ~input:modexp_b1 ~gas_limit:100_000);
  check_succeeded ~msg:"modexp/mod 0 -> 0x00" ~gas:200 ~output:(unhex "00")
    (invoke_at 5 ~input:modexp_b2 ~gas_limit:100_000);
  check_succeeded ~msg:"modexp/3^2 mod 2^255" ~gas:200 ~output:modexp_c_out
    (invoke_at 5 ~input:modexp_c ~gas_limit:100_000);
  (* EIP-2565 gas: exp=2 -> 200 floor, exp=2^255 -> 1360. *)
  check_gas ~msg:"modexp/gas exp=2 -> 200" ~gas:200
    (invoke_at 5 ~input:(modexp_gas_input ~exp32:(be32_small 2)) ~gas_limit:100_000);
  check_gas ~msg:"modexp/gas exp=2^255 -> 1360" ~gas:1360
    (invoke_at 5
       ~input:(modexp_gas_input ~exp32:(String.make 1 '\128' ^ String.make 31 '\000'))
       ~gas_limit:100_000);
  (* trailing byte dropped: modulus stays 0x07, so 3^2 mod 7 = 0x02, not 0x09. *)
  check_succeeded ~msg:"modexp/trailing calldata dropped" ~gas:200 ~output:(unhex "02")
    (invoke_at 5 ~input:modexp_extended ~gas_limit:100_000)

(* ---------- 0x09 BLAKE2F (EIP-152) ---------- *)

let blake_in4 =
  unhex
    "0000000048c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001"

let blake_out4 =
  unhex
    "08c9bcf367e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d282e6ad7f520e511f6c3e2b8c68059b9442be0454267ce079217e1319cde05b"

let blake_in5 =
  unhex
    "0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001"

let blake_out5 =
  unhex
    "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"

let blake_in6 =
  unhex
    "0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000"

let blake_out6 =
  unhex
    "75ab69d3190a562c51aef8d88f1c2775876944407270c42c9844252c26d2875298743e7f6d5ea2f2d3e8d226039cd31b4e426ac4f2d3d666a610c2116fde4735"

let blake_in7 =
  unhex
    "0000000148c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001"

let blake_out7 =
  unhex
    "b63a380cb2897d521994a85234ee2c181b5f844d2c624c002677e9703449d2fba551b3a8333bcdf5f2f7e08993d53923de3d64fcc68c034e717b9293fed7a421"

(* 212 bytes: one short of the fixed 213-byte framing. *)
let blake_short =
  unhex
    "0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b616263000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000"

(* 213 bytes but byte[212] = 0x02 (the final-block flag must be 0 or 1). *)
let blake_bad_flag =
  unhex
    "0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000002"

(* 213 bytes, rounds = 0xffffffff; tested ONLY for a low-gas rejection. *)
let blake_huge_rounds =
  unhex
    "ffffffff48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001"

let test_blake2f () =
  check_succeeded ~msg:"blake2f/vector 4 (rounds 0)" ~gas:0 ~output:blake_out4
    (invoke_at 9 ~input:blake_in4 ~gas_limit:10);
  check_succeeded ~msg:"blake2f/vector 5 (rounds 12)" ~gas:12 ~output:blake_out5
    (invoke_at 9 ~input:blake_in5 ~gas_limit:100);
  check_succeeded ~msg:"blake2f/vector 6 (rounds 12, final 0)" ~gas:12 ~output:blake_out6
    (invoke_at 9 ~input:blake_in6 ~gas_limit:100);
  check_succeeded ~msg:"blake2f/vector 7 (rounds 1)" ~gas:1 ~output:blake_out7
    (invoke_at 9 ~input:blake_in7 ~gas_limit:100);
  check_rejected ~msg:"blake2f/wrong length (212)" (invoke_at 9 ~input:blake_short ~gas_limit:100);
  (* gas_limit 100 >= rounds 12, so the rejection is on the flag, not on gas. *)
  check_rejected ~msg:"blake2f/wrong final flag (2)"
    (invoke_at 9 ~input:blake_bad_flag ~gas_limit:100);
  check_rejected ~msg:"blake2f/huge rounds OOG"
    (invoke_at 9 ~input:blake_huge_rounds ~gas_limit:1000)

(* ================================================================== *)
(* Seam tests: the CALL family through the interpreter                *)
(* (mirrors test_calls.ml)                                            *)
(* ================================================================== *)

let byte b = String.make 1 (Char.chr b)
let op o = byte (Opcode.to_byte o)
let push1 n = op (Opcode.Push (width_of 1)) ^ byte n
let push20 address = op (Opcode.Push (width_of 20)) ^ Units.Address.to_bytes address
let push32 w = op (Opcode.Push (width_of 32)) ^ U256.to_be_bytes w
let asm parts = Code.of_string (String.concat "" parts)

let all_gas = U256.max_value

let call ~gas ~dst ~value ~in_off ~in_len ~out_off ~out_len =
  [
    push1 out_len; push1 out_off; push1 in_len; push1 in_off; push32 value;
    push20 dst; push32 gas; op Opcode.Call;
  ]

let staticcall ~gas ~dst ~in_off ~in_len ~out_off ~out_len =
  [
    push1 out_len; push1 out_off; push1 in_len; push1 in_off; push20 dst;
    push32 gas; op Opcode.Staticcall;
  ]

let delegatecall ~gas ~dst ~in_off ~in_len ~out_off ~out_len =
  [
    push1 out_len; push1 out_off; push1 in_len; push1 in_off; push20 dst;
    push32 gas; op Opcode.Delegatecall;
  ]

let store_at off = [ push1 off; op Opcode.Mstore ]
let return_range ~off ~len = [ push1 len; push1 off; op Opcode.Return ]

(* A funded executing account at a plainly non-precompile address. Precompile
   targets carry no account: the dispatch fires on the callee address before any
   sub-frame is entered, so the world needs only the caller. *)
let self = address_of 0x42
let outer_caller = address_of 0xaa
let outer_value = u 777

let world = World_state.set_account World_state.empty self
    (Account.make ~nonce:Nonce.zero ~balance:(u 1_000_000))

let base_call ~mutability =
  Env.Call.make ~target:self ~caller:outer_caller ~value:outer_value ~data:Data.empty ~mutability

let env_of ~mutability =
  Env.make
    ~block:
      (Env.Block.make ~coinbase:(address_of 0xc0) ~timestamp:(u 1_600_000_000)
         ~number:(u 15_500_000) ~prevrandao:U256.zero ~gas_limit:(u 25_000_000)
         ~basefee:(u 7) ~chain_id:(u 2017) ~hashes:Tn_evm.Block_hashes.empty)
    ~tx:(Env.Tx.make ~origin:(address_of 0x09) ~gas_price:(u 9) ~access_list:[])
    ~call:(base_call ~mutability)

let base_env = env_of ~mutability:Mutability.Mutable
let allowance = 50_000_000
let cold_effects = Effects.start ~world ~access:Access.empty

let run ?(env = base_env) parts =
  Interpreter.run ~env ~code:(asm parts) ~gas:(gas_of allowance) ~effects:cold_effects

let output_of = function
  | Interpreter.Returned { output; _ } -> output
  | Interpreter.Reverted { output; _ } -> output
  | Interpreter.Stopped _ -> Alcotest.fail "expected an outcome carrying output, got stop"
  | Interpreter.Failed e ->
      Alcotest.fail ("expected output, got failure: " ^ Interpreter.error_to_string e)

let remaining_of = function
  | Interpreter.Stopped { gas_left; _ }
  | Interpreter.Returned { gas_left; _ }
  | Interpreter.Reverted { gas_left; _ } ->
      Gas.remaining gas_left
  | Interpreter.Failed e ->
      Alcotest.fail ("expected a halt carrying gas, got " ^ Interpreter.error_to_string e)

let spent outcome = allowance - remaining_of outcome
let word_at output i = get (U256.of_be_bytes (String.sub output (i * 32) 32))

let check_word msg expected output i =
  Alcotest.(check bool) msg true (U256.equal expected (word_at output i))

let word_of_bytes b = get (U256.of_be_bytes b)

(* The word 0x616263 places "abc" in the low three bytes of the word at mem[0],
   so [in_off=29, in_len=3] hands the precompile exactly the calldata "abc". *)
let store_abc = [ push32 (u 0x616263) ] @ store_at 0x00

(* ---------- SEAM 1: CALL to 0x02 (sha256) succeeds, output copied ---------- *)

let test_seam_call_sha256 () =
  let outcome =
    run
      (store_abc
      @ call ~gas:all_gas ~dst:(address_of 2) ~value:U256.zero ~in_off:29 ~in_len:3
          ~out_off:0x40 ~out_len:0x20
      @ store_at 0x60 (* the CALL success flag, still on top *)
      @ return_range ~off:0x40 ~len:0x40)
  in
  let output = output_of outcome in
  check_word "CALL to sha256 copied the correct 32-byte hash" (word_of_bytes sha256_abc) output 0;
  check_word "CALL to a precompile that Succeeded pushes 1" U256.one output 1;
  Alcotest.(check int) "the seam spends the CALL cost plus sha256's 72" 2726 (spent outcome)

(* ---------- SEAM 2: CALL to 0x01 (ecrecover) bad sig -> push 1, empty ---- *)

let test_seam_call_ecrecover_bad_sig () =
  (* 128 zero bytes of calldata: v = 0 is malformed, so ECRECOVER succeeds with
     empty output — the CALL must still push 1 and leave a zero-length buffer. *)
  let outcome =
    run
      (call ~gas:all_gas ~dst:(address_of 1) ~value:U256.zero ~in_off:0 ~in_len:128
         ~out_off:0x40 ~out_len:0x20
      @ [ op Opcode.Returndatasize ] (* stack: [rds; flag] *)
      @ store_at 0x20 @ store_at 0x00
      @ return_range ~off:0x00 ~len:0x40)
  in
  let output = output_of outcome in
  check_word "a Succeeded-empty precompile still pushes 1" U256.one output 0;
  check_word "and leaves an empty return-data buffer" U256.zero output 1

(* ---------- SEAM 3: CALL to 0x05 (modexp) OOG -> push 0, gas consumed ---- *)

let test_seam_call_modexp_oog () =
  (* Forward only 100 gas; MODEXP's floor is 200, so it Rejects. The seam must map
     that onto a Failed outcome: push 0 and forfeit the whole forwarded 100. *)
  let outcome =
    run
      (call ~gas:(u 100) ~dst:(address_of 5) ~value:U256.zero ~in_off:0 ~in_len:0
         ~out_off:0x00 ~out_len:0x00
      @ store_at 0x00
      @ return_range ~off:0x00 ~len:0x20)
  in
  check_word "a Rejected precompile pushes 0" U256.zero (output_of outcome) 0;
  Alcotest.(check int) "the whole forwarded 100 gas is consumed (not refunded)" 2736 (spent outcome)

(* ---------- SEAM 4: STATICCALL to 0x02 works ---------- *)

let test_seam_staticcall_sha256 () =
  let outcome =
    run
      (store_abc
      @ staticcall ~gas:all_gas ~dst:(address_of 2) ~in_off:29 ~in_len:3 ~out_off:0x40
          ~out_len:0x20
      @ store_at 0x60
      @ return_range ~off:0x40 ~len:0x40)
  in
  let output = output_of outcome in
  check_word "STATICCALL to sha256 copied the hash" (word_of_bytes sha256_abc) output 0;
  check_word "STATICCALL to a precompile pushes 1" U256.one output 1

(* ---------- SEAM 5: DELEGATECALL to 0x02 works ---------- *)

let test_seam_delegatecall_sha256 () =
  let outcome =
    run
      (store_abc
      @ delegatecall ~gas:all_gas ~dst:(address_of 2) ~in_off:29 ~in_len:3 ~out_off:0x40
          ~out_len:0x20
      @ store_at 0x60
      @ return_range ~off:0x40 ~len:0x40)
  in
  let output = output_of outcome in
  check_word "DELEGATECALL to sha256 copied the hash" (word_of_bytes sha256_abc) output 0;
  check_word "DELEGATECALL to a precompile pushes 1" U256.one output 1

(* ================================================================== *)

let () =
  Alcotest.run "tn_evm_precompile"
    [
      ( "unit",
        [
          Alcotest.test_case "0x04 IDENTITY" `Quick test_identity;
          Alcotest.test_case "0x02 SHA256" `Quick test_sha256;
          Alcotest.test_case "0x03 RIPEMD160" `Quick test_ripemd160;
          Alcotest.test_case "0x01 ECRECOVER" `Quick test_ecrecover;
          Alcotest.test_case "0x05 MODEXP" `Quick test_modexp;
          Alcotest.test_case "0x09 BLAKE2F" `Quick test_blake2f;
        ] );
      ( "seam",
        [
          Alcotest.test_case "CALL to sha256 succeeds" `Quick test_seam_call_sha256;
          Alcotest.test_case "CALL to ecrecover bad sig pushes 1, empty" `Quick
            test_seam_call_ecrecover_bad_sig;
          Alcotest.test_case "CALL to modexp OOG pushes 0, gas consumed" `Quick
            test_seam_call_modexp_oog;
          Alcotest.test_case "STATICCALL to sha256 works" `Quick test_seam_staticcall_sha256;
          Alcotest.test_case "DELEGATECALL to sha256 works" `Quick test_seam_delegatecall_sha256;
        ] );
    ]
