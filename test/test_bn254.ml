(* The BN254 field tower behind the 0x06 ecAdd, 0x07 ecMul and 0x08 ecPairing
   precompiles. This chunk covers the two lowest levels, Fq and Fq2, in two
   layers: unit cases that pin the accept/reject boundary the precompile ABI
   depends on, and randomised algebra that pins the arithmetic.

   Each rejection case carries a POSITIVE CONTROL beside it: p is rejected AND
   p - 1 is accepted, a 31-byte word is rejected AND a 32-byte word is accepted.
   Without the control a broken decoder that refuses everything would pass the
   rejection half and look green. *)

module Fq = Tn_evm.Bn254_field.Fq
module Fq2 = Tn_evm.Bn254_field.Fq2
module Fq6 = Tn_evm.Bn254_field.Fq6
module Fq12 = Tn_evm.Bn254_field.Fq12
module G1 = Tn_evm.Bn254_curve.G1
module G2 = Tn_evm.Bn254_curve.G2
module Pairing = Tn_evm.Bn254_pairing
module Precompile = Tn_evm.Precompile
module Access = Tn_evm.Access
module Code = Tn_evm.Code
module Data = Tn_evm.Data
module Effects = Tn_evm.Effects
module Env = Tn_evm.Env
module Gas = Tn_evm.Gas
module Interpreter = Tn_evm.Interpreter
module Mutability = Tn_evm.Mutability
module Opcode = Tn_evm.Opcode
module Account = Tn_state.Account
module Nonce = Tn_state.Nonce
module U256 = Tn_state.U256
module World_state = Tn_state.World_state
module Units = Tn_types.Units

(* ------------------------------------------------------------------ *)
(* Helpers                                                             *)
(* ------------------------------------------------------------------ *)

(* One byte of the low 8 bits of [b]. [Buffer.add_uint8] masks its argument, so
   this needs no range proof and no partial conversion. *)
let byte b =
  let buf = Buffer.create 1 in
  Buffer.add_uint8 buf b;
  Buffer.contents buf

(* The [len] bytes of [s] that start at [off], zero-filled past the end of [s].
   The fold carries the position, so the read is total. *)
let window s ~off ~len =
  let buf = Buffer.create len in
  let _ =
    String.fold_left
      (fun i c ->
        if i >= off && i < off + len then Buffer.add_char buf c;
        i + 1)
      0 s
  in
  let got = Buffer.length buf in
  if got >= len then Buffer.contents buf
  else Buffer.contents buf ^ String.make (len - got) '\000'

(* The raw bytes of a big-endian hex string, folded rather than indexed: each
   pair of hex digits becomes one byte, and a digit outside [0-9a-fA-F] reads as
   zero. The generated vectors hold only hex digits in even-length runs, so
   neither fallback fires. *)
let unhex hex =
  let buf = Buffer.create (String.length hex / 2) in
  let _ =
    String.fold_left
      (fun pending c ->
        let v =
          Option.value ~default:0 (int_of_string_opt (Printf.sprintf "0x%c" c))
        in
        Option.fold ~none:(Some v)
          ~some:(fun hi ->
            Buffer.add_uint8 buf ((hi * 16) + v);
            None)
          pending)
      None hex
  in
  Buffer.contents buf

(* 32 big-endian bytes of [z]. Unlike [Fq.to_be_bytes] this accepts a value at
   or above p, which is exactly what the rejection cases need. The buffer is
   local and [Buffer.add_uint8] keeps only the low 8 bits of its argument, so
   the encoder has no index and no partial accessor. *)
let be32 z =
  let buf = Buffer.create 32 in
  List.iter
    (fun i ->
      Buffer.add_uint8 buf
        (Z.to_int (Z.logand (Z.shift_right z ((31 - i) * 8)) (Z.of_int 0xff))))
    (List.init 32 Fun.id);
  Buffer.contents buf

let show_fq a = Z.to_string (Fq.to_z a)
let show_fq2 x = Printf.sprintf "(%s, %s)" (show_fq (Fq2.c0 x)) (show_fq (Fq2.c1 x))

let fq =
  Alcotest.testable (fun fmt a -> Format.pp_print_string fmt (show_fq a)) Fq.equal

let fq2 =
  Alcotest.testable (fun fmt a -> Format.pp_print_string fmt (show_fq2 a)) Fq2.equal

let z_of_int n = Z.of_int n
let p_minus_2 = Z.sub Fq.p (z_of_int 2)
let minus_one = z_of_int (-1)

(* ================================================================== *)
(* field-unit                                                         *)
(* ================================================================== *)

(* A coordinate word is rejected at p, not reduced: arkworks' canonical
   deserialiser refuses a non-reduced value (arkworks.rs:21-32). *)
let test_decode_rejects_p () =
  Alcotest.(check bool)
    "p itself is rejected" true
    (Option.is_none (Fq.of_be_bytes (be32 Fq.p)));
  Alcotest.(check bool)
    "p + 1 is rejected" true
    (Option.is_none (Fq.of_be_bytes (be32 (Z.succ Fq.p))));
  Alcotest.(check bool)
    "an all-ones word is rejected" true
    (Option.is_none (Fq.of_be_bytes (String.make 32 '\255')));
  Alcotest.check (Alcotest.option fq) "p - 1 is accepted"
    (Some (Fq.of_z (Z.pred Fq.p)))
    (Fq.of_be_bytes (be32 (Z.pred Fq.p)))

(* The word width is fixed at 32 bytes; nothing else decodes. *)
let test_decode_rejects_width () =
  Alcotest.(check bool)
    "31 bytes are rejected" true
    (Option.is_none (Fq.of_be_bytes (String.make 31 '\000')));
  Alcotest.(check bool)
    "33 bytes are rejected" true
    (Option.is_none (Fq.of_be_bytes (String.make 33 '\000')));
  Alcotest.(check bool)
    "an empty word is rejected" true
    (Option.is_none (Fq.of_be_bytes ""));
  Alcotest.check (Alcotest.option fq) "32 zero bytes are zero" (Some Fq.zero)
    (Fq.of_be_bytes (String.make 32 '\000'))

(* Zero is the one element with no inverse, at both levels. *)
let test_inv_zero_is_none () =
  Alcotest.(check bool) "Fq.inv zero" true (Option.is_none (Fq.inv Fq.zero));
  Alcotest.(check bool) "Fq2.inv zero" true (Option.is_none (Fq2.inv Fq2.zero));
  Alcotest.check (Alcotest.option fq) "Fq.inv one" (Some Fq.one) (Fq.inv Fq.one);
  Alcotest.check (Alcotest.option fq2) "Fq2.inv one" (Some Fq2.one)
    (Fq2.inv Fq2.one)

(* Subtraction below zero wraps to the canonical residue, never to a negative
   integer: [Z.erem], not [Z.rem]. *)
let test_sub_stays_canonical () =
  Alcotest.(check bool)
    "zero - one is p - 1" true
    (Z.equal (Fq.to_z (Fq.sub Fq.zero Fq.one)) (Z.pred Fq.p));
  Alcotest.(check bool)
    "neg one is p - 1" true
    (Z.equal (Fq.to_z (Fq.neg Fq.one)) (Z.pred Fq.p));
  Alcotest.(check bool)
    "of_z of -1 is p - 1" true
    (Z.equal (Fq.to_z (Fq.of_z minus_one)) (Z.pred Fq.p))

(* The Fq2 non-residue is -1: u squares to -1, and -1 is not 1. *)
let test_u_squared_is_minus_one () =
  let u = Fq2.make Fq.zero Fq.one in
  Alcotest.check fq2 "u squared" (Fq2.neg Fq2.one) (Fq2.square u);
  Alcotest.check fq2 "u times u" (Fq2.neg Fq2.one) (Fq2.mul u u);
  Alcotest.(check bool)
    "-1 differs from 1" false
    (Fq2.equal (Fq2.neg Fq2.one) Fq2.one)

(* A negative exponent is refused rather than read as an inverse power. *)
let test_pow_negative_is_none () =
  Alcotest.(check bool)
    "Fq.pow one (-1)" true
    (Option.is_none (Fq.pow Fq.one minus_one));
  Alcotest.(check bool)
    "Fq2.pow one (-1)" true
    (Option.is_none (Fq2.pow Fq2.one minus_one));
  Alcotest.check (Alcotest.option fq) "Fq.pow one 0" (Some Fq.one)
    (Fq.pow Fq.one Z.zero);
  Alcotest.check (Alcotest.option fq) "Fq.pow two 8"
    (Some (Fq.of_z (z_of_int 256)))
    (Fq.pow (Fq.of_z (z_of_int 2)) (z_of_int 8))

(* The codec is big-endian and left-zero-padded. *)
let test_codec_is_big_endian () =
  Alcotest.(check string)
    "one encodes to 31 zeros then 0x01"
    (String.make 31 '\000' ^ "\001")
    (Fq.to_be_bytes Fq.one);
  Alcotest.(check string)
    "256 encodes to 30 zeros then 0x01 0x00"
    (String.make 30 '\000' ^ "\001\000")
    (Fq.to_be_bytes (Fq.of_z (z_of_int 256)));
  Alcotest.(check int) "the width is 32" 32
    (String.length (Fq.to_be_bytes Fq.zero))

(* ================================================================== *)
(* field-props                                                        *)
(* ================================================================== *)

(* A full 256-bit word, built byte by byte, so the sample spans values above p
   as well as below it and [of_z] gets exercised on both sides of the bound. *)
let gen_z =
  QCheck.Gen.(
    map
      (List.fold_left (fun acc b -> Z.add (Z.shift_left acc 8) (Z.of_int b)) Z.zero)
      (list_size (return 32) (int_range 0 255)))

let gen_fq = QCheck.Gen.map Fq.of_z gen_z
let gen_fq2 = QCheck.Gen.(map (fun (a, b) -> Fq2.make a b) (pair gen_fq gen_fq))

let arb_fq = QCheck.make ~print:show_fq gen_fq

let arb_fq3 =
  QCheck.make
    ~print:(fun (a, b, c) ->
      Printf.sprintf "%s %s %s" (show_fq a) (show_fq b) (show_fq c))
    QCheck.Gen.(triple gen_fq gen_fq gen_fq)

let arb_fq2 = QCheck.make ~print:show_fq2 gen_fq2

let arb_fq2_3 =
  QCheck.make
    ~print:(fun (a, b, c) ->
      Printf.sprintf "%s %s %s" (show_fq2 a) (show_fq2 b) (show_fq2 c))
    QCheck.Gen.(triple gen_fq2 gen_fq2 gen_fq2)

let arb_fq_fq2 =
  QCheck.make
    ~print:(fun (k, x) -> Printf.sprintf "%s %s" (show_fq k) (show_fq2 x))
    QCheck.Gen.(pair gen_fq gen_fq2)

let mk ~salt ~count name arb fn =
  Alcotest.test_case name `Slow (fun () ->
      QCheck.Test.check_exn
        ~rand:(Random.State.make [| 0x5eed_43; salt |])
        (QCheck.Test.make ~count ~name arb fn))

let prop_fq_ring (a, b, c) =
  Fq.equal (Fq.add (Fq.add a b) c) (Fq.add a (Fq.add b c))
  && Fq.equal (Fq.add a b) (Fq.add b a)
  && Fq.equal (Fq.mul (Fq.mul a b) c) (Fq.mul a (Fq.mul b c))
  && Fq.equal (Fq.mul a b) (Fq.mul b a)

let prop_fq_distributes (a, b, c) =
  Fq.equal (Fq.mul a (Fq.add b c)) (Fq.add (Fq.mul a b) (Fq.mul a c))
  && Fq.equal (Fq.sub (Fq.add a b) b) a
  && Fq.equal (Fq.square a) (Fq.mul a a)
  && Fq.equal (Fq.add a (Fq.neg a)) Fq.zero
  && Z.lt (Fq.to_z (Fq.sub a b)) Fq.p
  && Z.geq (Fq.to_z (Fq.sub a b)) Z.zero

(* Fermat: on a non-zero element the inverse is the (p - 2)th power. Both routes
   must agree, and the inverse must actually invert. *)
let prop_fq_fermat a =
  Fq.is_zero a
  || Option.equal Fq.equal (Fq.inv a) (Fq.pow a p_minus_2)
     && Option.fold ~none:false
          ~some:(fun i -> Fq.equal (Fq.mul a i) Fq.one)
          (Fq.inv a)

let prop_fq_codec a =
  Option.equal Fq.equal (Fq.of_be_bytes (Fq.to_be_bytes a)) (Some a)
  && Int.equal (String.length (Fq.to_be_bytes a)) 32

let prop_fq2_ring (a, b, c) =
  Fq2.equal (Fq2.add (Fq2.add a b) c) (Fq2.add a (Fq2.add b c))
  && Fq2.equal (Fq2.add a b) (Fq2.add b a)
  && Fq2.equal (Fq2.mul (Fq2.mul a b) c) (Fq2.mul a (Fq2.mul b c))
  && Fq2.equal (Fq2.mul a b) (Fq2.mul b a)

let prop_fq2_distributes (a, b, c) =
  Fq2.equal (Fq2.mul a (Fq2.add b c)) (Fq2.add (Fq2.mul a b) (Fq2.mul a c))
  && Fq2.equal (Fq2.sub (Fq2.add a b) b) a
  && Fq2.equal (Fq2.square a) (Fq2.mul a a)
  && Fq2.equal (Fq2.mul a Fq2.one) a

let prop_fq2_inverse a =
  Fq2.is_zero a
  || Option.fold ~none:false
       ~some:(fun i -> Fq2.equal (Fq2.mul a i) Fq2.one)
       (Fq2.inv a)

(* Conjugation is the Frobenius map on Fq2, so it must agree with the pth power
   computed independently by square-and-multiply. *)
let prop_fq2_frobenius a =
  Fq2.equal (Fq2.conjugate (Fq2.conjugate a)) a
  && Fq2.equal (Fq2.frobenius 1 a) (Fq2.conjugate a)
  && Fq2.equal (Fq2.frobenius 2 a) a
  && Option.fold ~none:false
       ~some:(fun x -> Fq2.equal x (Fq2.conjugate a))
       (Fq2.pow a Fq.p)

let prop_fq2_scale (k, x) =
  Fq2.equal (Fq2.mul_by_fq k x) (Fq2.mul (Fq2.make k Fq.zero) x)

(* ================================================================== *)
(* tower-props                                                        *)
(* ================================================================== *)

(* Fq6 and Fq12 conceal their coefficients, so their testables print a tag
   instead of a value. Each assertion below carries its own message, which is
   what names the failure. *)
let opaque tag eq =
  Alcotest.testable (fun fmt _ -> Format.pp_print_string fmt tag) eq

let fq6 = opaque "<fq6>" Fq6.equal
let fq12 = opaque "<fq12>" Fq12.equal
let fq_of n = Fq.of_z (z_of_int n)
let fq2_of a b = Fq2.make (fq_of a) (fq_of b)
let fq2_of_dec a b = Fq2.make (Fq.of_z (Z.of_string a)) (Fq.of_z (Z.of_string b))

(* The tower generators the pins are stated in: xi = 9 + u is the Fq6
   non-residue, v and v^2 span the two upper Fq6 slots, and w generates Fq12
   over Fq6. *)
let xi = fq2_of 9 1
let v = Fq6.make Fq2.zero Fq2.one Fq2.zero
let v_squared = Fq6.make Fq2.zero Fq2.zero Fq2.one
let w = Fq12.make Fq6.zero Fq6.one
let sample_fq6 = Fq6.make (fq2_of 1 2) (fq2_of 3 4) (fq2_of 5 6)
let sample_fq6_b = Fq6.make (fq2_of 7 11) (fq2_of 13 17) (fq2_of 19 23)
let sample_fq12 = Fq12.make sample_fq6 sample_fq6_b

(* Square and multiply written here rather than taken from the module under
   test, so the Frobenius comparison has an oracle the module does not supply. *)
let pow_by ~mul ~one x e =
  let rec go e acc base =
    if Z.sign e <= 0 then acc
    else
      let acc = if Z.equal (Z.logand e Z.one) Z.one then mul acc base else acc in
      go (Z.shift_right e 1) acc (mul base base)
  in
  go e one x

(* v cubes to xi. The Fq6 product folds v^3 away, so this is the one place the
   non-residue itself is visible. *)
let test_v_cubed_equals_xi () =
  Alcotest.check fq6 "v squared sits in the top slot" v_squared (Fq6.square v);
  Alcotest.check fq6 "v cubed is xi"
    (Fq6.make xi Fq2.zero Fq2.zero)
    (Fq6.mul (Fq6.square v) v);
  Alcotest.(check bool)
    "9 + u differs from 9 - u" false
    (Fq2.equal xi (Fq2.make (fq_of 9) (Fq.neg Fq.one)))

(* w squares to v, so w^6 lands back on xi. *)
let test_w_squared_equals_v () =
  Alcotest.check fq12 "w squared is v" (Fq12.make v Fq6.zero) (Fq12.square w);
  Alcotest.check fq12 "w to the fourth is v squared"
    (Fq12.make v_squared Fq6.zero)
    (Fq12.square (Fq12.square w));
  Alcotest.check fq12 "w to the sixth is xi"
    (Fq12.make (Fq6.make xi Fq2.zero Fq2.zero) Fq6.zero)
    (Fq12.mul (Fq12.square w) (Fq12.square (Fq12.square w)))

(* The rotation shortcut must agree with the dense product by v. *)
let test_mul_by_v_matches_mul () =
  List.iter
    (fun a ->
      Alcotest.check fq6 "mul_by_v is multiplication by v" (Fq6.mul a v)
        (Fq6.mul_by_v a))
    [ Fq6.one; v; v_squared; sample_fq6; sample_fq6_b ]

(* The sparse product of the line evaluation: c0, c3 and c4 name slots 0, 3 and
   4 of the six Fq2 slots, and the other three slots stay zero. A slot read the
   wrong way round would move a coefficient into a different Fq6. *)
let test_mul_by_034_matches_dense () =
  let c0 = fq2_of 2 3 and c3 = fq2_of 5 7 and c4 = fq2_of 11 13 in
  Alcotest.check fq12 "the sparse factor fills slots 0, 3 and 4"
    (Fq12.mul sample_fq12
       (Fq12.make (Fq6.make c0 Fq2.zero Fq2.zero) (Fq6.make c3 c4 Fq2.zero)))
    (Fq12.mul_by_034 ~c0 ~c3 ~c4 sample_fq12);
  Alcotest.check fq12 "a slot-0 factor alone scales the whole value"
    (Fq12.mul sample_fq12
       (Fq12.make (Fq6.make c0 Fq2.zero Fq2.zero) Fq6.zero))
    (Fq12.mul_by_034 ~c0 ~c3:Fq2.zero ~c4:Fq2.zero sample_fq12)

(* The Frobenius map is the p^k power, at every level. The tables are derived,
   so this comparison is what stops a derivation that agrees at k = 1 and drifts
   later. *)
let test_frobenius_matches_powm () =
  List.iter
    (fun k ->
      let pk = Z.pow Fq.p k in
      let label = Printf.sprintf " at k = %d" k in
      Alcotest.check fq2
        ("Fq2 frobenius" ^ label)
        (pow_by ~mul:Fq2.mul ~one:Fq2.one (fq2_of 3 5) pk)
        (Fq2.frobenius k (fq2_of 3 5));
      Alcotest.check fq6
        ("Fq6 frobenius" ^ label)
        (pow_by ~mul:Fq6.mul ~one:Fq6.one sample_fq6 pk)
        (Fq6.frobenius k sample_fq6);
      Alcotest.check fq12
        ("Fq12 frobenius" ^ label)
        (pow_by ~mul:Fq12.mul ~one:Fq12.one sample_fq12 pk)
        (Fq12.frobenius k sample_fq12))
    [ 1; 2; 3 ]

(* The vendored Frobenius entries at index 1 (ark-bn254 fields/fq6.rs:16-90 and
   fields/fq12.rs:15-88, ground truth RD-6). The port DERIVES its tables, so
   these literals are the only copy of the vendored numbers and the pins below
   tie the derivation to them. *)
let fp6_c1_one =
  fq2_of_dec
    "21575463638280843010398324269430826099269044274347216827212613867836435027261"
    "10307601595873709700152284273816112264069230130616436755625194854815875713954"

let fp6_c2_one =
  fq2_of_dec
    "2581911344467009335267311115468803099551665605076196740867805258568234346338"
    "19937756971775647987995932169929341994314640652964949448313374472400716661030"

let fp12_c1_one =
  fq2_of_dec
    "8376118865763821496583973867626364092589906065868298776909617916018768340080"
    "16469823323077808223889137241176536799009286646108169935659301613961712198316"

(* TWIST_MUL_BY_Q_X and TWIST_MUL_BY_Q_Y, the two constants the Miller loop's
   character step needs (ark-bn254 curves/mod.rs:27-34, ground truth RE-0). They
   are also P_POWER_ENDOMORPHISM_COEFF_0 and _1 (curves/g2.rs:118-129), so
   pinning them cross-confirms both transcriptions. *)
let twist_mul_by_q_x =
  fq2_of_dec
    "21575463638280843010398324269430826099269044274347216827212613867836435027261"
    "10307601595873709700152284273816112264069230130616436755625194854815875713954"

let twist_mul_by_q_y =
  fq2_of_dec
    "2821565182194536844548159561693502659359617185244120367078079554186484126554"
    "3505843767911556378687030309984248845540243509899259641013678093033130930403"

(* The derived tables read through the public Frobenius maps: frobenius 1 of v
   is FP6_C1[1] times v, frobenius 1 of v^2 is FP6_C2[1] times v^2, and
   frobenius 1 of w is FP12_C1[1] times w. Entry 6 of the Fq12 table is -1,
   which is what makes conjugation the sixth Frobenius map. *)
let test_frobenius_pins () =
  Alcotest.check fq6 "the derived FP6_C1 entry 1"
    (Fq6.make Fq2.zero fp6_c1_one Fq2.zero)
    (Fq6.frobenius 1 v);
  Alcotest.check fq6 "the derived FP6_C2 entry 1"
    (Fq6.make Fq2.zero Fq2.zero fp6_c2_one)
    (Fq6.frobenius 1 v_squared);
  Alcotest.check fq12 "the derived FP12_C1 entry 1"
    (Fq12.make Fq6.zero (Fq6.make fp12_c1_one Fq2.zero Fq2.zero))
    (Fq12.frobenius 1 w);
  Alcotest.check fq2 "TWIST_MUL_BY_Q_X is the FP6_C1 entry 1" fp6_c1_one
    twist_mul_by_q_x;
  Alcotest.check fq2 "TWIST_MUL_BY_Q_Y is xi to the (p - 1) / 2" twist_mul_by_q_y
    (pow_by ~mul:Fq2.mul ~one:Fq2.one xi (Z.shift_right (Z.pred Fq.p) 1));
  Alcotest.check fq12 "the sixth Frobenius map is conjugation" (Fq12.conjugate w)
    (Fq12.frobenius 6 w)

(* Both upper levels are fields: everything but zero inverts, and zero does
   not. *)
let test_tower_inverses () =
  List.iter
    (fun a ->
      Alcotest.(check bool)
        "the Fq6 inverse inverts" true
        (Option.fold ~none:false
           ~some:(fun i -> Fq6.equal (Fq6.mul a i) Fq6.one)
           (Fq6.inv a)))
    [ Fq6.one; v; v_squared; sample_fq6; sample_fq6_b ];
  Alcotest.(check bool)
    "the Fq6 inverse of zero is none" true
    (Option.is_none (Fq6.inv Fq6.zero));
  Alcotest.(check bool)
    "the Fq12 inverse of zero is none" true
    (Option.is_none (Fq12.inv (Fq12.make Fq6.zero Fq6.zero)))

(* The Fq12 operations the final exponentiation is built out of. *)
let test_fq12_inverse_and_conjugate () =
  Alcotest.(check bool)
    "the Fq12 inverse inverts" true
    (Option.fold ~none:false
       ~some:(fun i -> Fq12.is_one (Fq12.mul sample_fq12 i))
       (Fq12.inv sample_fq12));
  Alcotest.(check bool)
    "one is one" true (Fq12.is_one Fq12.one);
  Alcotest.(check bool) "w is not one" false (Fq12.is_one w);
  Alcotest.check fq12 "pow agrees with square and multiply"
    (pow_by ~mul:Fq12.mul ~one:Fq12.one sample_fq12 (z_of_int 37))
    (Option.value ~default:w (Fq12.pow sample_fq12 (z_of_int 37)));
  Alcotest.(check bool)
    "a negative Fq12 exponent is none" true
    (Option.is_none (Fq12.pow Fq12.one minus_one));
  Alcotest.check fq12 "exp_x is the X power"
    (pow_by ~mul:Fq12.mul ~one:Fq12.one sample_fq12
       (Z.of_string "4965661367192848881"))
    (Fq12.exp_x sample_fq12)

(* ================================================================== *)
(* curve                                                              *)
(* ================================================================== *)

let g1 =
  Alcotest.testable
    (fun fmt pt ->
      Format.pp_print_string fmt
        (Option.fold ~none:"infinity"
           ~some:(fun (x, y) -> Printf.sprintf "(%s, %s)" (show_fq x) (show_fq y))
           (G1.xy pt)))
    G1.equal

let two = Fq.of_z (z_of_int 2)

(* Multiples 0 to 5 of the generator, infinity first. [G1.mul] refuses only a
   negative scalar, so the fallback below is unreachable; it is infinity, which
   the round-trip case then checks like any other point. *)
let multiples =
  List.map
    (fun k ->
      Option.value ~default:G1.infinity (G1.mul (z_of_int k) G1.generator))
    (List.init 6 Fun.id)

(* The generator (1, 2) is on y^2 = x^3 + 3, and a neighbour is not: the gate is
   the curve equation, not the shape of the pair. *)
let test_g1_generator_on_curve () =
  Alcotest.check (Alcotest.option g1) "the generator is (1, 2)"
    (Some G1.generator)
    (G1.make ~x:Fq.one ~y:two);
  Alcotest.(check bool)
    "(1, 3) is off the curve" true
    (Option.is_none (G1.make ~x:Fq.one ~y:(Fq.of_z (z_of_int 3))));
  Alcotest.(check bool)
    "(0, 0) is off the curve" true
    (Option.is_none (G1.make ~x:Fq.zero ~y:Fq.zero));
  Alcotest.(check bool) "the generator is not infinity" false
    (G1.is_infinity G1.generator)

(* A negative scalar is refused rather than read as a multiple of the negated
   point. Zero and one are the positive controls beside it. *)
let test_g1_mul_negative_is_none () =
  Alcotest.(check bool)
    "mul (-1) is none" true
    (Option.is_none (G1.mul minus_one G1.generator));
  Alcotest.(check bool)
    "mul (-1) of infinity is none too" true
    (Option.is_none (G1.mul minus_one G1.infinity));
  Alcotest.check (Alcotest.option g1) "mul 0 is infinity" (Some G1.infinity)
    (G1.mul Z.zero G1.generator);
  Alcotest.check (Alcotest.option g1) "mul 1 is the generator"
    (Some G1.generator)
    (G1.mul Z.one G1.generator)

(* The group law and the scalar ladder must agree, and infinity must behave as
   the identity on both sides. *)
let test_g1_add_matches_double () =
  Alcotest.check (Alcotest.option g1) "G + G is 2G"
    (Some (G1.add G1.generator G1.generator))
    (G1.mul (z_of_int 2) G1.generator);
  Alcotest.check (Alcotest.option g1) "2G + G is 3G"
    (Option.map (fun p2 -> G1.add p2 G1.generator) (G1.mul (z_of_int 2) G1.generator))
    (G1.mul (z_of_int 3) G1.generator);
  Alcotest.check g1 "G + infinity is G" G1.generator
    (G1.add G1.generator G1.infinity);
  Alcotest.check g1 "infinity + G is G" G1.generator
    (G1.add G1.infinity G1.generator);
  Alcotest.check g1 "G + (-G) is infinity" G1.infinity
    (G1.add G1.generator (G1.neg G1.generator))

(* Every point encodes to exactly 64 bytes and decodes back to itself, infinity
   included: infinity is the all-zero word pair and skips the curve equation. A
   coordinate at the modulus and a word of the wrong width are the rejections
   beside those controls. *)
let test_g1_codec_round_trip () =
  List.iter
    (fun pt ->
      Alcotest.(check int) "the encoding is 64 bytes" 64
        (String.length (G1.encode pt));
      Alcotest.check (Alcotest.option g1) "encode then decode is the identity"
        (Some pt)
        (G1.decode (G1.encode pt)))
    multiples;
  Alcotest.(check string)
    "infinity encodes to 64 zero bytes" (String.make 64 '\000')
    (G1.encode G1.infinity);
  Alcotest.check (Alcotest.option g1) "64 zero bytes decode to infinity"
    (Some G1.infinity)
    (G1.decode (String.make 64 '\000'));
  Alcotest.(check bool)
    "an x coordinate equal to p is rejected" true
    (Option.is_none (G1.decode (be32 Fq.p ^ String.make 32 '\000')));
  Alcotest.(check bool)
    "a y coordinate equal to p is rejected" true
    (Option.is_none (G1.decode (String.make 32 '\000' ^ be32 Fq.p)));
  Alcotest.(check bool)
    "63 bytes are rejected" true
    (Option.is_none (G1.decode (String.make 63 '\000')));
  Alcotest.(check bool)
    "65 bytes are rejected" true
    (Option.is_none (G1.decode (String.make 65 '\000')))

let g2 =
  Alcotest.testable
    (fun fmt pt ->
      Format.pp_print_string fmt
        (Option.fold ~none:"infinity"
           ~some:(fun (x, y) ->
             Printf.sprintf "(%s, %s)" (show_fq2 x) (show_fq2 y))
           (G2.xy pt)))
    G2.equal

let curve_r = Tn_evm.Bn254_curve.r

(* The vendored G2 generator coordinates (ark-bn254 curves/g2.rs:99-114), given
   as the real coefficient then the u coefficient. *)
let g2_gen_x =
  fq2_of_dec
    "10857046999023057135944570762232829481370756359578518086990519993285655852781"
    "11559732032986387107991004021392285783925812861821192530917403151452391805634"

let g2_gen_y =
  fq2_of_dec
    "8495653923123431417604973247489272438418190587263600148770280649306958101930"
    "4082367875863433681332203403145435568316851327593401208105741076214120093531"

(* One G2 point on the wire. The u coefficient of each 64-byte half comes FIRST
   and the real coefficient second (arkworks.rs:44-49). *)
let g2_bytes x y =
  be32 (Fq.to_z (Fq2.c1 x))
  ^ be32 (Fq.to_z (Fq2.c0 x))
  ^ be32 (Fq.to_z (Fq2.c1 y))
  ^ be32 (Fq.to_z (Fq2.c0 y))

(* The same point written the other way round, the layout the port must NOT
   read. It is the negative control beside the generator case. *)
let g2_bytes_real_first x y =
  be32 (Fq.to_z (Fq2.c0 x))
  ^ be32 (Fq.to_z (Fq2.c1 x))
  ^ be32 (Fq.to_z (Fq2.c0 y))
  ^ be32 (Fq.to_z (Fq2.c1 y))

(* The generator decodes from its own wire bytes, and only in the u-first word
   order. That pins the layout and the twist constant at once: a point built on
   a different b would fail the twist equation. *)
let test_g2_generator_decode () =
  Alcotest.check (Alcotest.option g2) "the wire generator is the generator"
    (Some G2.generator)
    (G2.decode (g2_bytes g2_gen_x g2_gen_y));
  Alcotest.check (Alcotest.option g2) "the generator is on the twist"
    (Some G2.generator)
    (G2.make ~x:g2_gen_x ~y:g2_gen_y);
  Alcotest.(check bool)
    "the real-first word order does not decode" true
    (Option.is_none (G2.decode (g2_bytes_real_first g2_gen_x g2_gen_y)));
  Alcotest.check (Alcotest.option g2) "128 zero bytes are infinity"
    (Some G2.infinity)
    (G2.decode (String.make 128 '\000'));
  Alcotest.(check bool)
    "127 bytes are rejected" true
    (Option.is_none (G2.decode (String.make 127 '\000')));
  Alcotest.(check bool)
    "129 bytes are rejected" true
    (Option.is_none (G2.decode (String.make 129 '\000')));
  Alcotest.(check bool)
    "a word at the modulus is rejected" true
    (Option.is_none (G2.decode (be32 Fq.p ^ String.make 96 '\000')));
  Alcotest.(check bool) "the generator is not infinity" false
    (G2.is_infinity G2.generator)

(* The generator has order r, so r copies of it are infinity and the subgroup
   test accepts it. The small multiples beside it pin the ladder. *)
let test_g2_r_times_gen_is_infinity () =
  Alcotest.check (Alcotest.option g2) "r copies of the generator are infinity"
    (Some G2.infinity)
    (G2.mul curve_r G2.generator);
  Alcotest.(check bool)
    "the generator is in the subgroup" true
    (G2.in_subgroup G2.generator);
  Alcotest.(check bool)
    "infinity is in the subgroup" true (G2.in_subgroup G2.infinity);
  Alcotest.check (Alcotest.option g2) "one copy is the generator"
    (Some G2.generator)
    (G2.mul Z.one G2.generator);
  Alcotest.check (Alcotest.option g2) "no copies are infinity"
    (Some G2.infinity)
    (G2.mul Z.zero G2.generator);
  Alcotest.check (Alcotest.option g2) "two copies match the group law"
    (Some (G2.add G2.generator G2.generator))
    (G2.mul (z_of_int 2) G2.generator);
  Alcotest.check g2 "the generator plus its negation is infinity" G2.infinity
    (G2.add G2.generator (G2.neg G2.generator));
  Alcotest.(check bool)
    "a negative scalar is none" true
    (Option.is_none (G2.mul minus_one G2.generator))

(* ================================================================== *)
(* pairing-props                                                      *)
(* ================================================================== *)

(* e(G1gen, G2gen), computed once. A pairing is by far the most expensive
   operation in this suite, and four assertions below are stated against this
   one value. *)
let base_pairing = Pairing.pair G1.generator G2.generator

(* The pairing is non-degenerate: the generators pair to something other than
   one, which is what makes the 0x08 answer carry information at all. The
   positive control beside it is the pair against infinity, which IS one. *)
let test_pairing_nondegenerate () =
  Alcotest.(check bool)
    "the pairing of the generators is defined" true
    (Option.is_some base_pairing);
  Alcotest.(check bool)
    "the pairing of the generators is not one" false
    (Option.fold ~none:true ~some:Fq12.is_one base_pairing);
  Alcotest.(check bool)
    "a pairing against an infinite G1 is one" true
    (Option.fold ~none:false ~some:Fq12.is_one
       (Pairing.pair G1.infinity G2.generator));
  Alcotest.(check bool)
    "a pairing against an infinite G2 is one" true
    (Option.fold ~none:false ~some:Fq12.is_one
       (Pairing.pair G1.generator G2.infinity))

(* Bilinearity on one pair of small scalars: e([a]P, [b]Q) = e(P, Q)^(a*b). The
   three options thread through Option.bind, so a None on either side is a
   different value from a Some and the case reddens. *)
let bilinear_case a b =
  let lhs =
    Option.bind
      (G1.mul (z_of_int a) G1.generator)
      (fun p ->
        Option.bind (G2.mul (z_of_int b) G2.generator) (Pairing.pair p))
  in
  let rhs =
    Option.bind base_pairing (fun e -> Fq12.pow e (z_of_int (a * b)))
  in
  Alcotest.(check bool)
    (Printf.sprintf "e([%d]G1, [%d]G2) is defined" a b)
    true (Option.is_some lhs);
  Alcotest.check (Alcotest.option fq12)
    (Printf.sprintf "e([%d]G1, [%d]G2) is e(G1, G2)^%d" a b (a * b))
    rhs lhs

let test_pairing_bilinear () =
  bilinear_case 2 3;
  bilinear_case 3 2

(* The 0x08 core over whole lists. A point and its negation against the same G2
   cancel, one generator pair alone does not, and every element with a point at
   infinity drops out, so a list of nothing but those is the empty product. *)
let test_pairing_cancels () =
  Alcotest.(check bool)
    "e(P, Q) times e(-P, Q) is one" true
    (Pairing.pairing_check
       [ (G1.generator, G2.generator); (G1.neg G1.generator, G2.generator) ]);
  Alcotest.(check bool)
    "one generator pair alone is not one" false
    (Pairing.pairing_check [ (G1.generator, G2.generator) ]);
  Alcotest.(check bool) "the empty product is one" true (Pairing.pairing_check []);
  Alcotest.(check bool)
    "an element with an infinite G1 is dropped" true
    (Pairing.pairing_check [ (G1.infinity, G2.generator) ]);
  Alcotest.(check bool)
    "an element with an infinite G2 is dropped" true
    (Pairing.pairing_check [ (G1.generator, G2.infinity) ])

(* ================================================================== *)
(* goldens                                                            *)
(* ================================================================== *)

let address_of n =
  Option.value ~default:Units.Address.zero
    (Units.Address.of_bytes (String.make (Units.Address.length - 1) '\000' ^ byte n))

let invoke_at n = Precompile.invoke (address_of n)

let kind_of = function
  | Precompile.Not_a_precompile -> "not_a_precompile"
  | Precompile.Succeeded _ -> "succeeded"
  | Precompile.Rejected -> "rejected"

(* A gas figure and an output no successful call can produce, so a response of
   the wrong kind fails the assertion that reads it as well as the kind check. *)
let gas_of_response = function
  | Precompile.Succeeded { gas_used; _ } -> gas_used
  | Precompile.Not_a_precompile -> -1
  | Precompile.Rejected -> -1

let output_of_response = function
  | Precompile.Succeeded { output; _ } -> output
  | Precompile.Not_a_precompile -> "\255"
  | Precompile.Rejected -> "\255"

(* One oracle row driven through the dispatch. A rejecting row asserts the kind
   alone: revm's error variant is documentation here, because the port collapses
   every failure into one [Rejected]. *)
let check_row row =
  let result =
    invoke_at row.Bn254_vectors.addr
      ~input:(unhex row.Bn254_vectors.input_hex)
      ~gas_limit:row.Bn254_vectors.gas_limit
  in
  let name = row.Bn254_vectors.name in
  match row.Bn254_vectors.expect with
  | Bn254_vectors.Succeeds { gas_used; output_hex } ->
      Alcotest.(check string) (name ^ ": kind") "succeeded" (kind_of result);
      Alcotest.(check int) (name ^ ": gas_used") gas_used (gas_of_response result);
      Alcotest.(check string)
        (name ^ ": output") (unhex output_hex)
        (output_of_response result)
  | Bn254_vectors.Rejects _ ->
      Alcotest.(check string) (name ^ ": kind") "rejected" (kind_of result)

(* The row count is asserted as well as the rows: a vector file that silently
   lost its cases would otherwise pass an empty fold. *)
let check_rows ~addr ~count () =
  let rows =
    List.filter
      (fun row -> Int.equal row.Bn254_vectors.addr addr)
      Bn254_vectors.all
  in
  Alcotest.(check int)
    (Printf.sprintf "0x%02x row count" addr)
    count (List.length rows);
  List.iter check_row rows

(* ================================================================== *)
(* seam: the CALL family through the interpreter                      *)
(* (mirrors test_precompile.ml)                                       *)
(* ================================================================== *)

(* A [PUSH] of a given immediate width. The width is [None] only outside 1 to
   32, which no call below asks for; an empty instruction on that dead arm makes
   the code malformed, which every assertion here rejects. *)
let push_op n =
  Option.fold ~none:""
    ~some:(fun w -> byte (Opcode.to_byte (Opcode.Push w)))
    (Opcode.Push_bytes.of_int n)

let op o = byte (Opcode.to_byte o)
let push1 n = push_op 1 ^ byte n
let push20 address = push_op 20 ^ Units.Address.to_bytes address

(* A [PUSH32] carries its immediate verbatim, so a 32-byte word of vector input
   enters the code as itself with no integer round trip. *)
let push_word w = push_op 32 ^ w

let asm parts = Code.of_string (String.concat "" parts)

(* Every literal forwarded below is a small non-negative int, so [U256.of_int]
   never refuses one. *)
let u n = Option.value ~default:U256.zero (U256.of_int n)

let call ~gas ~dst ~in_off ~in_len ~out_off ~out_len =
  [
    push1 out_len; push1 out_off; push1 in_len; push1 in_off;
    push_word (U256.to_be_bytes U256.zero); push20 dst; push_word (U256.to_be_bytes gas);
    op Opcode.Call;
  ]

let store_at off = [ push1 off; op Opcode.Mstore ]
let return_range ~off ~len = [ push1 len; push1 off; op Opcode.Return ]

(* [s] laid into memory from offset zero, one 32-byte word per [MSTORE]. Only
   whole words are stored, and every input used here is a whole number of
   words. *)
let mstore_words s =
  List.concat
    (List.mapi
       (fun i w -> [ push_word w; push1 (i * 32); op Opcode.Mstore ])
       (List.init (String.length s / 32) (fun i -> window s ~off:(i * 32) ~len:32)))

let self = address_of 0x42
let allowance = 50_000_000

let world =
  World_state.set_account World_state.empty self
    (Account.make ~nonce:Nonce.zero ~balance:(u 1_000_000))

let base_env =
  Env.make
    ~block:
      (Env.Block.make ~coinbase:(address_of 0xc0) ~timestamp:(u 1_600_000_000)
         ~number:(u 15_500_000) ~prevrandao:U256.zero ~gas_limit:(u 25_000_000)
         ~basefee:(u 7)
         ~basefee_address:Tn_evm.System_contracts.governance_safe_address
         ~chain_id:(u 2017) ~blob_gasprice:Env.Block.consensus_blob_gasprice
         ~hashes:Tn_evm.Block_hashes.empty)
    ~tx:(Env.Tx.make ~origin:(address_of 0x09) ~gas_price:(u 9) ~access_list:[])
    ~call:
      (Env.Call.make ~target:self ~caller:(address_of 0xaa) ~value:(u 777)
         ~data:Data.empty ~mutability:Mutability.Mutable)

let cold_effects = Effects.start ~world ~access:Access.empty

let outcome_output = function
  | Interpreter.Returned { output; _ } -> output
  | Interpreter.Reverted { output; _ } -> output
  | Interpreter.Stopped _ -> ""
  | Interpreter.Failed _ -> ""

let outcome_remaining = function
  | Interpreter.Stopped { gas_left; _ } -> Gas.remaining gas_left
  | Interpreter.Returned { gas_left; _ } -> Gas.remaining gas_left
  | Interpreter.Reverted { gas_left; _ } -> Gas.remaining gas_left
  | Interpreter.Failed _ -> 0

(* The observable pair of a run: the bytes the frame returned, and the gas it
   spent out of the fixed allowance. [Gas.of_int] refuses only a negative
   allowance, so the [None] arm is unreachable; it reads as no output and no
   spend, which every assertion below rejects. *)
let observe parts =
  Option.fold ~none:("", 0)
    ~some:(fun gas ->
      let outcome =
        Interpreter.run ~env:base_env ~code:(asm parts) ~gas ~effects:cold_effects
      in
      (outcome_output outcome, allowance - outcome_remaining outcome))
    (Gas.of_int allowance)

let zero_word = String.make 32 '\000'
let one_word = String.make 31 '\000' ^ byte 1

let row_named name =
  List.find_opt
    (fun row -> String.equal row.Bn254_vectors.name name)
    Bn254_vectors.all

let row_input name =
  Option.fold ~none:""
    ~some:(fun row -> unhex row.Bn254_vectors.input_hex)
    (row_named name)

let row_output name =
  Option.fold ~none:""
    ~some:(fun row ->
      match row.Bn254_vectors.expect with
      | Bn254_vectors.Succeeds { output_hex; _ } -> unhex output_hex
      | Bn254_vectors.Rejects _ -> "")
    (row_named name)

(* One canonical coordinate word of [s] at [off], or [None] if it is at or above
   the modulus. *)
let fq_at s ~off = Fq.of_be_bytes (window s ~off ~len:32)

(* The oracle's wrong-subgroup vector, one 192-byte pair whose G1 half is the
   generator and whose G2 half is ON the twist but OUTSIDE the r-order subgroup.
   arkworks rejects it through its own subgroup predicate, so the port must
   reject it too, and it must reject it at the subgroup test rather than at the
   twist equation: the three assertions below separate those two reasons. *)
let test_g2_wrong_subgroup_rejected () =
  let input = row_input "pair_g2_wrong_subgroup" in
  Alcotest.(check int) "the vector is one 192-byte pair" 192 (String.length input);
  let point = window input ~off:64 ~len:128 in
  let parsed =
    Option.bind (fq_at point ~off:0) (fun x1 ->
        Option.bind (fq_at point ~off:32) (fun x0 ->
            Option.bind (fq_at point ~off:64) (fun y1 ->
                Option.map
                  (fun y0 -> (Fq2.make x0 x1, Fq2.make y0 y1))
                  (fq_at point ~off:96))))
  in
  Alcotest.(check bool)
    "the four coordinate words are canonical" true (Option.is_some parsed);
  Alcotest.(check bool)
    "the point is on the twist" true
    (Option.fold ~none:false
       ~some:(fun (x, y) -> Option.is_some (G2.make ~x ~y))
       parsed);
  Alcotest.(check bool)
    "the point is outside the r-order subgroup" false
    (Option.fold ~none:true
       ~some:(fun (x, y) ->
         Option.fold ~none:true ~some:G2.in_subgroup (G2.make ~x ~y))
       parsed);
  Alcotest.(check bool)
    "the wire point is rejected" true
    (Option.is_none (G2.decode point));
  Alcotest.check (Alcotest.option g2)
    "the generator's bytes still decode, so the reject is the subgroup test"
    (Some G2.generator)
    (G2.decode (g2_bytes g2_gen_x g2_gen_y))

(* A CALL to 0x06 with the oracle's own valid input: the seam must copy the
   64-byte sum into memory and push 1. *)
let test_seam_call_ecadd () =
  let input = row_input "add_valid" in
  Alcotest.(check int) "the add vector is 128 bytes" 128 (String.length input);
  let ret, _ =
    observe
      (mstore_words input
      @ call ~gas:(u 200) ~dst:(address_of 6) ~in_off:0 ~in_len:128 ~out_off:0x80
          ~out_len:0x40
      @ store_at 0xc0
      @ return_range ~off:0x80 ~len:0x60)
  in
  Alcotest.(check string)
    "CALL to 0x06 copied the 64-byte sum" (row_output "add_valid")
    (window ret ~off:0 ~len:64);
  Alcotest.(check string)
    "a Succeeded precompile pushes 1" one_word
    (window ret ~off:64 ~len:32)

(* The same CALL shape twice, once to 0x07 with a point off the curve and once
   to a plain empty account. The empty account is the control: it returns the
   forwarded gas, so the difference between the two spends is exactly the gas
   the rejected precompile forfeited. *)
let test_seam_call_ecmul_malformed () =
  let input = row_input "mul_not_on_curve" in
  Alcotest.(check int) "the mul vector is 96 bytes" 96 (String.length input);
  let program dst =
    mstore_words input
    @ call ~gas:(u 6000) ~dst:(address_of dst) ~in_off:0 ~in_len:96 ~out_off:0x80
        ~out_len:0x40
    @ store_at 0xc0
    @ return_range ~off:0x80 ~len:0x60
  in
  let rejected, spent_rejected = observe (program 7) in
  let control, spent_control = observe (program 0x33) in
  Alcotest.(check string)
    "a Rejected precompile pushes 0" zero_word
    (window rejected ~off:64 ~len:32);
  Alcotest.(check string)
    "the control call to an empty account pushes 1" one_word
    (window control ~off:64 ~len:32);
  Alcotest.(check string)
    "a Rejected precompile returns no output" zero_word
    (window rejected ~off:0 ~len:32);
  Alcotest.(check int)
    "the whole forwarded 6000 is forfeited, not refunded" 6000
    (spent_rejected - spent_control)

(* An under-funded CALL to 0x08. The empty input costs the 45_000 base and
   nothing else, so one unit short of it is the cheapest rejection the pairing
   has, and the control call to an empty account measures what the rejection
   forfeited. *)
let test_seam_call_ecpairing_oog () =
  let program dst =
    call ~gas:(u 44_999) ~dst:(address_of dst) ~in_off:0 ~in_len:0 ~out_off:0x80
      ~out_len:0x20
    @ store_at 0xa0
    @ return_range ~off:0x80 ~len:0x40
  in
  let rejected, spent_rejected = observe (program 8) in
  let control, spent_control = observe (program 0x34) in
  Alcotest.(check string)
    "a Rejected precompile pushes 0" zero_word
    (window rejected ~off:32 ~len:32);
  Alcotest.(check string)
    "the control call to an empty account pushes 1" one_word
    (window control ~off:32 ~len:32);
  Alcotest.(check string)
    "a Rejected precompile returns no output" zero_word
    (window rejected ~off:0 ~len:32);
  Alcotest.(check int)
    "the whole forwarded 44999 is forfeited, not refunded" 44_999
    (spent_rejected - spent_control)

(* A funded CALL to 0x08 with no input at all. The empty product is one, so the
   seam must copy back a 32-byte word holding 1, not an empty return. *)
let test_seam_call_ecpairing_empty () =
  let ret, _ =
    observe
      (call ~gas:(u 45_000) ~dst:(address_of 8) ~in_off:0 ~in_len:0 ~out_off:0x80
         ~out_len:0x20
      @ store_at 0xa0
      @ return_range ~off:0x80 ~len:0x40)
  in
  Alcotest.(check string)
    "CALL to 0x08 copied the 32-byte true word" one_word
    (window ret ~off:0 ~len:32);
  Alcotest.(check string)
    "a Succeeded precompile pushes 1" one_word
    (window ret ~off:32 ~len:32)

(* ================================================================== *)

let () =
  Alcotest.run "tn_evm_bn254"
    [
      ( "field-unit",
        [
          Alcotest.test_case "a coordinate equal to p is rejected" `Quick
            test_decode_rejects_p;
          Alcotest.test_case "only a 32-byte word decodes" `Quick
            test_decode_rejects_width;
          Alcotest.test_case "the inverse of zero is none" `Quick
            test_inv_zero_is_none;
          Alcotest.test_case "subtraction stays canonical" `Quick
            test_sub_stays_canonical;
          Alcotest.test_case "u squared is minus one" `Quick
            test_u_squared_is_minus_one;
          Alcotest.test_case "a negative exponent is none" `Quick
            test_pow_negative_is_none;
          Alcotest.test_case "the coordinate codec is big-endian" `Quick
            test_codec_is_big_endian;
        ] );
      ( "field-props",
        [
          mk ~salt:1 ~count:100 "Fq is a commutative ring" arb_fq3 prop_fq_ring;
          mk ~salt:2 ~count:100 "Fq multiplication distributes" arb_fq3
            prop_fq_distributes;
          mk ~salt:3 ~count:30 "the Fq inverse is the Fermat power" arb_fq
            prop_fq_fermat;
          mk ~salt:4 ~count:100 "the Fq byte codec round-trips" arb_fq
            prop_fq_codec;
          mk ~salt:5 ~count:100 "Fq2 is a commutative ring" arb_fq2_3
            prop_fq2_ring;
          mk ~salt:6 ~count:100 "Fq2 multiplication distributes" arb_fq2_3
            prop_fq2_distributes;
          mk ~salt:7 ~count:100 "the Fq2 inverse inverts" arb_fq2
            prop_fq2_inverse;
          mk ~salt:8 ~count:30 "Fq2 conjugation is the Frobenius map" arb_fq2
            prop_fq2_frobenius;
          mk ~salt:9 ~count:100 "Fq2 scaling by an Fq agrees with a full multiply"
            arb_fq_fq2 prop_fq2_scale;
        ] );
      ( "tower-props",
        [
          Alcotest.test_case "v-cubed-equals-xi" `Quick test_v_cubed_equals_xi;
          Alcotest.test_case "w-squared-equals-v" `Quick test_w_squared_equals_v;
          Alcotest.test_case "mul_by_v-matches-mul" `Quick
            test_mul_by_v_matches_mul;
          Alcotest.test_case "mul_by_034-matches-dense-mul" `Quick
            test_mul_by_034_matches_dense;
          Alcotest.test_case "frobenius-matches-powm" `Slow
            test_frobenius_matches_powm;
          Alcotest.test_case "frobenius-pins" `Quick test_frobenius_pins;
          Alcotest.test_case "tower-inverses" `Quick test_tower_inverses;
          Alcotest.test_case "fq12-inverse-and-conjugate" `Quick
            test_fq12_inverse_and_conjugate;
        ] );
      ( "curve",
        [
          Alcotest.test_case "g1-generator-on-curve" `Quick
            test_g1_generator_on_curve;
          Alcotest.test_case "g1-mul-negative-is-none" `Quick
            test_g1_mul_negative_is_none;
          Alcotest.test_case "g1-add-matches-double" `Quick
            test_g1_add_matches_double;
          Alcotest.test_case "g1-codec-round-trip" `Quick
            test_g1_codec_round_trip;
          Alcotest.test_case "g2-generator-decode" `Quick
            test_g2_generator_decode;
          Alcotest.test_case "g2-r-times-gen-is-infinity" `Slow
            test_g2_r_times_gen_is_infinity;
          Alcotest.test_case "g2-wrong-subgroup-rejected" `Slow
            test_g2_wrong_subgroup_rejected;
        ] );
      ( "pairing-props",
        [
          Alcotest.test_case "nondegeneracy" `Slow test_pairing_nondegenerate;
          Alcotest.test_case "bilinearity" `Slow test_pairing_bilinear;
          Alcotest.test_case "cancellation" `Slow test_pairing_cancels;
        ] );
      ( "goldens",
        [
          Alcotest.test_case "goldens-add" `Quick (check_rows ~addr:6 ~count:9);
          Alcotest.test_case "goldens-mul" `Quick (check_rows ~addr:7 ~count:8);
          Alcotest.test_case "goldens-pair" `Slow (check_rows ~addr:8 ~count:11);
        ] );
      ( "seam",
        [
          Alcotest.test_case "call-0x06-succeeds" `Quick test_seam_call_ecadd;
          Alcotest.test_case "call-0x07-malformed-consumes-all-forwarded-gas"
            `Quick test_seam_call_ecmul_malformed;
          Alcotest.test_case "call-0x08-oog" `Quick test_seam_call_ecpairing_oog;
          Alcotest.test_case "call-0x08-empty-input-true" `Slow
            test_seam_call_ecpairing_empty;
        ] );
    ]
