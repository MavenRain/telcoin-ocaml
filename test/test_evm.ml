(* Tests for the EVM arithmetic and logic unit (the interpreter chunk's first
   piece): the raw 256-bit word operations added to {!Tn_state.U256} and the
   total EVM opcode semantics layered over them in {!Tn_evm.Alu}.

   Two complementary batches. First, hand-computed canonical vectors pin the
   opcode edge cases the yellow paper singles out — division and modulus by zero,
   the [-2^255 / -1] signed-division overflow, wrapping [MUL], [EXP] modulo
   [2^256], sign extension, the shift boundaries at 256 bits. Second, randomised
   property tests check every operation against an independent oracle built from
   zarith (arbitrary-precision integers reduced to the 256-bit ring), so the
   hand-rolled schoolbook multiplication and binary long division are held to a
   reference that shares none of their code. The qcheck driver is pinned to a
   fixed [Random.State] so the sampled cases — and the verdict — replay. *)

module U256 = Tn_state.U256
module Alu = Tn_evm.Alu

let get = function Some x -> x | None -> Alcotest.fail "expected Some"
let u n = get (U256.of_int n)
let hex s = get (U256.of_hex s)

(* A word for [-n] as a two's-complement 256-bit value. *)
let sneg n = U256.sub U256.zero (u n)

let max = U256.max_value
let two255 = hex ("8" ^ String.make 63 '0')

let u256 =
  Alcotest.testable (fun ppf w -> Format.pp_print_string ppf (U256.to_hex w)) U256.equal

let check msg expected actual = Alcotest.(check u256) msg expected actual

(* ---------- zarith oracle ---------- *)

let modulus = Z.shift_left Z.one 256
let mask256 = Z.sub modulus Z.one
let two_255 = Z.shift_left Z.one 255
let z_of w = Z.of_string ("0x" ^ U256.to_hex w)

(* Reduce a Z value into [0, 2^256) and re-encode it big-endian — the inverse of
   {!z_of}, so a signed (possibly negative) result lands as its two's-complement
   word. Byte extraction by shift-and-mask avoids any reliance on Z's formatting. *)
let word_of_z z =
  let r = Z.erem z modulus in
  get
    (U256.of_be_bytes
       (String.init 32 (fun i ->
            let shift = 8 * (31 - i) in
            Char.chr (Z.to_int (Z.logand (Z.shift_right r shift) (Z.of_int 0xff))))))

let signed_of w =
  let v = z_of w in
  if Z.geq v two_255 then Z.sub v modulus else v

let neg_word w = Z.geq (z_of w) two_255
let is0 w = U256.is_zero w
let zbool b = if b then U256.one else U256.zero

(* Oracle implementations, one per opcode, each purely in terms of Z. *)
let o_add a b = word_of_z (Z.add (z_of a) (z_of b))
let o_sub a b = word_of_z (Z.sub (z_of a) (z_of b))
let o_mul a b = word_of_z (Z.mul (z_of a) (z_of b))
let o_div a b = if is0 b then U256.zero else word_of_z (Z.div (z_of a) (z_of b))
let o_mod a b = if is0 b then U256.zero else word_of_z (Z.rem (z_of a) (z_of b))

let o_sdiv a b =
  if is0 b then U256.zero
  else
    let sa = signed_of a and sb = signed_of b in
    let q = Z.div (Z.abs sa) (Z.abs sb) in
    word_of_z (if Z.sign sa * Z.sign sb < 0 then Z.neg q else q)

let o_smod a b =
  if is0 b then U256.zero
  else
    let sa = signed_of a and sb = signed_of b in
    let r = Z.rem (Z.abs sa) (Z.abs sb) in
    word_of_z (if Z.sign sa < 0 then Z.neg r else r)

let o_addmod a b n =
  if is0 n then U256.zero else word_of_z (Z.rem (Z.add (z_of a) (z_of b)) (z_of n))

let o_mulmod a b n =
  if is0 n then U256.zero else word_of_z (Z.rem (Z.mul (z_of a) (z_of b)) (z_of n))

let o_exp a b = word_of_z (Z.powm (z_of a) (z_of b) modulus)
let o_lt a b = zbool (Z.lt (z_of a) (z_of b))
let o_gt a b = zbool (Z.gt (z_of a) (z_of b))
let o_slt a b = zbool (Z.lt (signed_of a) (signed_of b))
let o_sgt a b = zbool (Z.gt (signed_of a) (signed_of b))
let o_eq a b = zbool (Z.equal (z_of a) (z_of b))
let o_iszero a = zbool (Z.equal (z_of a) Z.zero)
let o_and a b = word_of_z (Z.logand (z_of a) (z_of b))
let o_or a b = word_of_z (Z.logor (z_of a) (z_of b))
let o_xor a b = word_of_z (Z.logxor (z_of a) (z_of b))
let o_not a = word_of_z (Z.logxor (z_of a) mask256)

let o_byte i x =
  if Z.geq (z_of i) (Z.of_int 32) then U256.zero
  else U256.of_byte (Char.code (String.get (U256.to_be_bytes x) (Z.to_int (z_of i))))

let o_shl shift value =
  if Z.geq (z_of shift) (Z.of_int 256) then U256.zero
  else word_of_z (Z.shift_left (z_of value) (Z.to_int (z_of shift)))

let o_shr shift value =
  if Z.geq (z_of shift) (Z.of_int 256) then U256.zero
  else word_of_z (Z.shift_right (z_of value) (Z.to_int (z_of shift)))

let o_sar shift value =
  if Z.geq (z_of shift) (Z.of_int 256) then
    if neg_word value then word_of_z mask256 else U256.zero
  else word_of_z (Z.shift_right (signed_of value) (Z.to_int (z_of shift)))

let o_signextend b x =
  if Z.geq (z_of b) (Z.of_int 31) then x
  else
    let bits = 8 * (Z.to_int (z_of b) + 1) in
    let low = Z.logand (z_of x) (Z.sub (Z.shift_left Z.one bits) Z.one) in
    word_of_z (if Z.testbit low (bits - 1) then Z.sub low (Z.shift_left Z.one bits) else low)

(* ---------- hand-computed vectors ---------- *)

let test_mul () =
  check "6 * 7 = 42" (u 42) (Alu.mul (u 6) (u 7));
  (* (2^256 - 1)^2 = 2^512 - 2^257 + 1 ≡ 1 (mod 2^256). *)
  check "max * max wraps to one" U256.one (Alu.mul max max);
  check "max * 2 = -2 (mod 2^256)" (sneg 2) (Alu.mul max (u 2))

let test_div () =
  check "7 / 2 = 3" (u 3) (Alu.div (u 7) (u 2));
  check "x / 0 = 0" U256.zero (Alu.div (u 5) U256.zero);
  check "max / 1 = max" max (Alu.div max U256.one);
  check "0 / 5 = 0" U256.zero (Alu.div U256.zero (u 5));
  (* A divisor with bit 255 set drives the long-division top-bit carry: the
     shifted remainder exceeds 2^256 and must still compare as >= the divisor. *)
  check "max / 2^255 = 1" (u 1) (Alu.div max two255);
  check "max mod 2^255 = 2^255 - 1" (U256.sub two255 U256.one) (Alu.modulo max two255)

let test_sdiv () =
  check "-1 / 1 = -1" (sneg 1) (Alu.sdiv (sneg 1) U256.one);
  check "-7 / 2 = -3 (toward zero)" (sneg 3) (Alu.sdiv (sneg 7) (u 2));
  check "7 / -2 = -3" (sneg 3) (Alu.sdiv (u 7) (sneg 2));
  (* the lone overflow case: MIN / -1 = MIN. *)
  check "-2^255 / -1 = -2^255" two255 (Alu.sdiv two255 (sneg 1));
  check "signed x / 0 = 0" U256.zero (Alu.sdiv (sneg 7) U256.zero)

let test_mod () =
  check "7 mod 3 = 1" (u 1) (Alu.modulo (u 7) (u 3));
  check "x mod 0 = 0" U256.zero (Alu.modulo (u 5) U256.zero);
  check "-7 smod 3 = -1 (sign of dividend)" (sneg 1) (Alu.smod (sneg 7) (u 3));
  check "7 smod -3 = 1" (u 1) (Alu.smod (u 7) (sneg 3));
  check "signed x smod 0 = 0" U256.zero (Alu.smod (sneg 7) U256.zero)

let test_addmod_mulmod () =
  (* 2^256 ≡ 2 (mod 7), so (max + 2) ≡ (2^256 + 1) ≡ 3 (mod 7). *)
  check "addmod(max, 2, 7) = 3" (u 3) (Alu.addmod max (u 2) (u 7));
  check "addmod(5, 6, 7) = 4" (u 4) (Alu.addmod (u 5) (u 6) (u 7));
  check "addmod(_, _, 0) = 0" U256.zero (Alu.addmod (u 5) (u 6) U256.zero);
  (* max ≡ 1 (mod 7), so max * max ≡ 1 (mod 7). *)
  check "mulmod(max, max, 7) = 1" (u 1) (Alu.mulmod max max (u 7));
  check "mulmod(5, 6, 7) = 2" (u 2) (Alu.mulmod (u 5) (u 6) (u 7));
  check "mulmod(_, _, 0) = 0" U256.zero (Alu.mulmod (u 5) (u 6) U256.zero)

let test_exp () =
  check "2 ^ 10 = 1024" (u 1024) (Alu.exp (u 2) (u 10));
  check "a ^ 0 = 1" U256.one (Alu.exp (u 3) U256.zero);
  check "0 ^ 0 = 1" U256.one (Alu.exp U256.zero U256.zero);
  check "0 ^ 5 = 0" U256.zero (Alu.exp U256.zero (u 5));
  check "2 ^ 256 = 0 (mod 2^256)" U256.zero (Alu.exp (u 2) (u 256));
  check "7 ^ 1 = 7" (u 7) (Alu.exp (u 7) U256.one)

let test_signextend () =
  check "signextend(0, 0xff) = -1" max (Alu.signextend U256.zero (u 0xff));
  check "signextend(0, 0x7f) = 0x7f" (u 0x7f) (Alu.signextend U256.zero (u 0x7f));
  check "signextend(1, 0xffff) = -1" max (Alu.signextend U256.one (u 0xffff));
  check "signextend(1, 0x7fff) = 0x7fff" (u 0x7fff) (Alu.signextend U256.one (u 0x7fff));
  check "signextend(31, x) = x" two255 (Alu.signextend (u 31) two255);
  check "signextend(32, x) = x" two255 (Alu.signextend (u 32) two255)

let test_compare () =
  check "1 < 2" U256.one (Alu.lt (u 1) (u 2));
  check "2 < 1 is false" U256.zero (Alu.lt (u 2) (u 1));
  check "max > 1 unsigned" U256.one (Alu.gt max (u 1));
  check "1 <s 2" U256.one (Alu.slt (u 1) (u 2));
  (* max is -1 signed: below 1 signed, above 1 unsigned. *)
  check "max <s 1 (signed)" U256.one (Alu.slt max U256.one);
  check "max <u 1 is false" U256.zero (Alu.lt max U256.one);
  check "-1 <s 0" U256.one (Alu.slt (sneg 1) U256.zero);
  check "-1 >s 0 is false" U256.zero (Alu.sgt (sneg 1) U256.zero);
  check "5 = 5" U256.one (Alu.eq (u 5) (u 5));
  check "5 = 6 is false" U256.zero (Alu.eq (u 5) (u 6));
  check "iszero 0" U256.one (Alu.iszero U256.zero);
  check "iszero 1 is false" U256.zero (Alu.iszero U256.one)

let test_bitwise () =
  check "max & 0x0f = 0x0f" (u 0x0f) (Alu.logand max (u 0x0f));
  check "0 | 5 = 5" (u 5) (Alu.logor U256.zero (u 5));
  check "max ^ max = 0" U256.zero (Alu.logxor max max);
  check "not 0 = max" max (Alu.lognot U256.zero);
  check "not max = 0" U256.zero (Alu.lognot max)

let test_byte () =
  let sample = hex ("11" ^ String.make 60 '0' ^ "ff") in
  check "byte 0 is the most significant" (u 0x11) (Alu.byte U256.zero sample);
  check "byte 31 is the least significant" (u 0xff) (Alu.byte (u 31) sample);
  check "byte 32 is zero" U256.zero (Alu.byte (u 32) sample)

let test_shifts () =
  check "1 << 4 = 16" (u 16) (Alu.shl (u 4) U256.one);
  check "1 << 256 = 0" U256.zero (Alu.shl (u 256) U256.one);
  check "1 << 255 = 2^255" two255 (Alu.shl (u 255) U256.one);
  check "0xff >> 4 = 0x0f" (u 0x0f) (Alu.shr (u 4) (u 0xff));
  check "max >> 256 = 0" U256.zero (Alu.shr (u 256) max);
  (* arithmetic right shift sign-fills: 0x80..0 >> 4 sets the top five bits. *)
  check "sar 4 of 2^255 sign-fills" (hex ("f8" ^ String.make 62 '0')) (Alu.sar (u 4) two255);
  check "sar 256 of -1 = -1" max (Alu.sar (u 256) (sneg 1));
  check "sar 1 of 2 = 1 (positive)" (u 1) (Alu.sar (u 1) (u 2))

(* ---------- randomised oracle checks ---------- *)

let gen_word =
  let open QCheck.Gen in
  let edges =
    [
      U256.zero; U256.one; max; two255; U256.two_pow 128;
      u 2; u 3; u 7; u 255; u 256; sneg 1; sneg 2;
    ]
  in
  let random_bytes =
    map
      (fun s -> get (U256.of_be_bytes s))
      (string_size ~gen:(map Char.chr (int_range 0 255)) (return 32))
  in
  let small = map (fun n -> u n) (int_range 0 100_000) in
  (* Weight the distribution toward full-width random words while still visiting
     the boundary constants and small operands (divisor/modulus edge cases). *)
  int_range 0 8 >>= fun k ->
  if k < 2 then oneof_list edges else if k < 4 then small else random_bytes

let h1 = U256.to_hex
let arb1 = QCheck.make ~print:h1 gen_word
let arb2 = QCheck.make ~print:(fun (a, b) -> Printf.sprintf "%s %s" (h1 a) (h1 b))
    QCheck.Gen.(pair gen_word gen_word)
let arb3 =
  QCheck.make
    ~print:(fun (a, b, c) -> Printf.sprintf "%s %s %s" (h1 a) (h1 b) (h1 c))
    QCheck.Gen.(triple gen_word gen_word gen_word)

(* Each property becomes one alcotest case: build the qcheck test and run it under
   a fixed [rand] so the sampled cases and the verdict replay, with a per-property
   salt so properties that share a generator don't sample identical cases. [mk] is
   polymorphic in the arbitrary, so binary, unary and ternary properties share it. *)
let mk ~salt ~count name arb fn =
  Alcotest.test_case name `Slow (fun () ->
      QCheck.Test.check_exn
        ~rand:(Random.State.make [| 0x7e1c0ffee; salt |])
        (QCheck.Test.make ~count ~name arb fn))

let prop_cases =
  [
    mk ~salt:1 ~count:300 "add" arb2 (fun (a, b) -> U256.equal (Alu.add a b) (o_add a b));
    mk ~salt:2 ~count:300 "sub" arb2 (fun (a, b) -> U256.equal (Alu.sub a b) (o_sub a b));
    mk ~salt:3 ~count:300 "mul" arb2 (fun (a, b) -> U256.equal (Alu.mul a b) (o_mul a b));
    mk ~salt:4 ~count:300 "div" arb2 (fun (a, b) -> U256.equal (Alu.div a b) (o_div a b));
    mk ~salt:5 ~count:300 "sdiv" arb2 (fun (a, b) -> U256.equal (Alu.sdiv a b) (o_sdiv a b));
    mk ~salt:6 ~count:300 "mod" arb2 (fun (a, b) -> U256.equal (Alu.modulo a b) (o_mod a b));
    mk ~salt:7 ~count:300 "smod" arb2 (fun (a, b) -> U256.equal (Alu.smod a b) (o_smod a b));
    mk ~salt:8 ~count:100 "exp" arb2 (fun (a, b) -> U256.equal (Alu.exp a b) (o_exp a b));
    mk ~salt:9 ~count:300 "lt" arb2 (fun (a, b) -> U256.equal (Alu.lt a b) (o_lt a b));
    mk ~salt:10 ~count:300 "gt" arb2 (fun (a, b) -> U256.equal (Alu.gt a b) (o_gt a b));
    mk ~salt:11 ~count:300 "slt" arb2 (fun (a, b) -> U256.equal (Alu.slt a b) (o_slt a b));
    mk ~salt:12 ~count:300 "sgt" arb2 (fun (a, b) -> U256.equal (Alu.sgt a b) (o_sgt a b));
    mk ~salt:13 ~count:300 "eq" arb2 (fun (a, b) -> U256.equal (Alu.eq a b) (o_eq a b));
    mk ~salt:14 ~count:300 "and" arb2 (fun (a, b) -> U256.equal (Alu.logand a b) (o_and a b));
    mk ~salt:15 ~count:300 "or" arb2 (fun (a, b) -> U256.equal (Alu.logor a b) (o_or a b));
    mk ~salt:16 ~count:300 "xor" arb2 (fun (a, b) -> U256.equal (Alu.logxor a b) (o_xor a b));
    mk ~salt:17 ~count:300 "byte" arb2 (fun (a, b) -> U256.equal (Alu.byte a b) (o_byte a b));
    mk ~salt:18 ~count:300 "shl" arb2 (fun (a, b) -> U256.equal (Alu.shl a b) (o_shl a b));
    mk ~salt:19 ~count:300 "shr" arb2 (fun (a, b) -> U256.equal (Alu.shr a b) (o_shr a b));
    mk ~salt:20 ~count:300 "sar" arb2 (fun (a, b) -> U256.equal (Alu.sar a b) (o_sar a b));
    mk ~salt:21 ~count:300 "signextend" arb2
      (fun (a, b) -> U256.equal (Alu.signextend a b) (o_signextend a b));
    mk ~salt:22 ~count:300 "not" arb1 (fun a -> U256.equal (Alu.lognot a) (o_not a));
    mk ~salt:23 ~count:300 "iszero" arb1 (fun a -> U256.equal (Alu.iszero a) (o_iszero a));
    mk ~salt:24 ~count:200 "addmod" arb3
      (fun (a, b, c) -> U256.equal (Alu.addmod a b c) (o_addmod a b c));
    mk ~salt:25 ~count:200 "mulmod" arb3
      (fun (a, b, c) -> U256.equal (Alu.mulmod a b c) (o_mulmod a b c));
  ]

let () =
  Alcotest.run "tn_evm"
    [
      ( "alu vectors",
        [
          Alcotest.test_case "mul wraps" `Quick test_mul;
          Alcotest.test_case "unsigned division and zero" `Quick test_div;
          Alcotest.test_case "signed division and overflow" `Quick test_sdiv;
          Alcotest.test_case "modulus, signed and zero" `Quick test_mod;
          Alcotest.test_case "addmod and mulmod" `Quick test_addmod_mulmod;
          Alcotest.test_case "exponentiation" `Quick test_exp;
          Alcotest.test_case "sign extension" `Quick test_signextend;
          Alcotest.test_case "comparisons signed and unsigned" `Quick test_compare;
          Alcotest.test_case "bitwise" `Quick test_bitwise;
          Alcotest.test_case "byte extraction" `Quick test_byte;
          Alcotest.test_case "shifts" `Quick test_shifts;
        ] );
      ("alu vs zarith", prop_cases);
    ]
