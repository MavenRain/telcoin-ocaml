(* The BN254 optimal ate pairing: one Miller loop per pair over arkworks' own
   signed-digit schedule, then a single final exponentiation over the product.

   Every constant here is transcribed from ark-bn254 0.5.0 curves/mod.rs and the
   step formulas from ark-ec 0.5.0 models/bn/g2.rs. The twist is type D, and the
   BN parameter X is positive, so the two branches arkworks guards on
   (X_IS_NEGATIVE, TWIST_TYPE) each collapse to their taken side and the untaken
   side is unwritten rather than dead. *)

module Fq = Bn254_field.Fq
module Fq2 = Bn254_field.Fq2
module Fq12 = Bn254_field.Fq12
module G1 = Bn254_curve.G1
module G2 = Bn254_curve.G2

let fq_of_dec s = Fq.of_z (Z.of_string s)
let fq2_of_dec c0 c1 = Fq2.make (fq_of_dec c0) (fq_of_dec c1)

(* 1/2 in the base field, the scaling the doubling step needs twice. Two is not
   zero modulo an odd prime, so the default is unreachable and any slip into it
   would redden every pairing case at once. *)
let two_inv = Option.value ~default:Fq.zero (Fq.inv (Fq.of_z (Z.of_int 2)))

(* The B coefficient of the sextic twist, 3/(u + 9) (ark-bn254 curves/g2.rs:
   35-45). Bn254_curve holds the same value privately, over the same twist
   equation; the two are pinned together by the pairing goldens, which fail on
   any point either module reads differently. *)
let twist_b =
  fq2_of_dec
    "19485874751759354771024239261021720505790618469301721065564631296452457478373"
    "266929791119991161246907387137283842545076965332900288569378510910307636690"

(* The two constants of the untwist-Frobenius-twist map (ark-bn254
   curves/mod.rs:27-34). They are the Fq2 scalings that turn a Frobenius on the
   twist into the Frobenius on the curve. *)
let twist_mul_by_q_x =
  fq2_of_dec
    "21575463638280843010398324269430826099269044274347216827212613867836435027261"
    "10307601595873709700152284273816112264069230130616436755625194854815875713954"

let twist_mul_by_q_y =
  fq2_of_dec
    "2821565182194536844548159561693502659359617185244120367078079554186484126554"
    "3505843767911556378687030309984248845540243509899259641013678093033130930403"

(* |6X + 2| in signed-digit form, 65 entries, index 0 the least significant and
   index 64 the most significant (ark-ec models/bn/mod.rs:21-25). Verbatim: a
   single wrong digit computes a different, wrong-order pairing. *)
let ate_loop_count =
  [
    0; 0; 0; 1; 0; 1; 0; -1; 0; 0; -1; 0; 0; 0; 1; 0; 0; -1; 0; -1; 0; 0; 0; 1;
    0; -1; 0; 0; 0; 0; -1; 0; 0; 1; 0; -1; 0; 0; 1; 0; 0; 0; 0; 0; -1; 0; 0; -1;
    0; 1; 0; -1; 0; 0; 0; -1; 0; -1; 0; 0; 0; 1; 0; 1; 1;
  ]

(* The digits the loop steps through, most significant first: indices 63 down to
   0. The digit at index 64 seeds the accumulator instead of stepping it, which
   is why arkworks skips it (models/bn/mod.rs:70). *)
let ate_digits = List.rev (List.filteri (fun i _ -> i < 64) ate_loop_count)

(* A G2 point in homogeneous projective coordinates, the shape the line
   functions update in place upstream. It never leaves this module. *)
type proj = { x : Fq2.t; y : Fq2.t; z : Fq2.t }

(* The three Fq2 coefficients of one line, in the D-twist slot order that
   {!ell} feeds to Fq12.mul_by_034. *)
type line = { l0 : Fq2.t; l1 : Fq2.t; l2 : Fq2.t }

(* The doubling step of the Miller loop (ark-ec models/bn/g2.rs:56-67), D-twist,
   with the tangent line at [r] pushed out as (-h, 3j, i). *)
let double_step r =
  let a = Fq2.mul_by_fq two_inv (Fq2.mul r.x r.y) in
  let b = Fq2.square r.y in
  let c = Fq2.square r.z in
  let e = Fq2.mul twist_b (Fq2.add c (Fq2.add c c)) in
  let e3 = Fq2.add e (Fq2.add e e) in
  let g = Fq2.mul_by_fq two_inv (Fq2.add b e3) in
  let h = Fq2.sub (Fq2.square (Fq2.add r.y r.z)) (Fq2.add b c) in
  let i = Fq2.sub e b in
  let j = Fq2.square r.x in
  let e2 = Fq2.square e in
  ( {
      x = Fq2.mul a (Fq2.sub b e3);
      y = Fq2.sub (Fq2.square g) (Fq2.add e2 (Fq2.add e2 e2));
      z = Fq2.mul b h;
    },
    { l0 = Fq2.neg h; l1 = Fq2.add j (Fq2.add j j); l2 = i } )

(* The addition step of the Miller loop (ark-ec models/bn/g2.rs:73-89), D-twist,
   adding the affine point [(qx, qy)] into [r] and pushing the chord line out as
   (lambda, -theta, j). The new coordinates read the old [y] and [z], so the
   record is rebuilt rather than updated field by field. *)
let add_step r ~qx ~qy =
  let theta = Fq2.sub r.y (Fq2.mul qy r.z) in
  let lambda = Fq2.sub r.x (Fq2.mul qx r.z) in
  let c = Fq2.square theta in
  let d = Fq2.square lambda in
  let e = Fq2.mul lambda d in
  let f = Fq2.mul r.z c in
  let g = Fq2.mul r.x d in
  let h = Fq2.sub (Fq2.add e f) (Fq2.add g g) in
  ( {
      x = Fq2.mul lambda h;
      y = Fq2.sub (Fq2.mul theta (Fq2.sub g h)) (Fq2.mul e r.y);
      z = Fq2.mul r.z e;
    },
    {
      l0 = lambda;
      l1 = Fq2.neg theta;
      l2 = Fq2.sub (Fq2.mul theta qx) (Fq2.mul lambda qy);
    } )

(* One sparse line multiplied into the accumulator (ark-ec models/bn/mod.rs:
   184-201). On a D-twist the first coefficient is scaled by the G1 y coordinate
   and the second by the G1 x coordinate, and the three land in Fq12 slots 0, 3
   and 4. *)
let ell f l ~px ~py =
  Fq12.mul_by_034 ~c0:(Fq2.mul_by_fq py l.l0) ~c3:(Fq2.mul_by_fq px l.l1)
    ~c4:l.l2 f

(* The untwist-Frobenius-twist map on an affine G2 point (ark-ec
   models/bn/g2.rs:171-181). *)
let mul_by_char ~x ~y =
  ( Fq2.mul (Fq2.frobenius 1 x) twist_mul_by_q_x,
    Fq2.mul (Fq2.frobenius 1 y) twist_mul_by_q_y )

(* The Miller loop of one affine pair. The accumulator starts at one and is
   squared at every step but the first; the projective point starts at the
   affine [q] with [z] one. After the digits are spent, two more additions bring
   in the Frobenius images q1 and q2 of [q], with the y coordinate of q2 negated
   (models/bn/g2.rs:127-137). X is positive here, so neither the accumulator nor
   the running point is conjugated or negated in between. *)
let miller_affine ~px ~py ~qx ~qy =
  let neg_qy = Fq2.neg qy in
  let step_add r ~ax ~ay f =
    let stepped, l = add_step r ~qx:ax ~qy:ay in
    (stepped, ell f l ~px ~py)
  in
  let rec go digits r f first =
    match digits with
    | [] -> (r, f)
    | digit :: rest ->
        let squared = if first then f else Fq12.square f in
        let doubled, l = double_step r in
        let lined = ell squared l ~px ~py in
        let stepped, acc =
          if Int.equal digit 0 then (doubled, lined)
          else
            step_add doubled ~ax:qx
              ~ay:(if digit > 0 then qy else neg_qy)
              lined
        in
        go rest stepped acc false
  in
  let seeded, walked = go ate_digits { x = qx; y = qy; z = Fq2.one } Fq12.one true in
  let q1x, q1y = mul_by_char ~x:qx ~y:qy in
  let q2x, q2y = mul_by_char ~x:q1x ~y:q1y in
  let after_q1, f_q1 = step_add seeded ~ax:q1x ~ay:q1y walked in
  let _, f_q2 = step_add after_q1 ~ax:q2x ~ay:(Fq2.neg q2y) f_q1 in
  f_q2

(* The Miller loop of a wire pair. A point at infinity contributes nothing to
   the product, which is the identity, so it answers one without a loop: that is
   what arkworks' filter amounts to. *)
let miller_loop p q =
  Option.fold ~none:Fq12.one
    ~some:(fun (px, py) ->
      Option.fold ~none:Fq12.one
        ~some:(fun (qx, qy) -> miller_affine ~px ~py ~qx ~qy)
        (G2.xy q))
    (G1.xy p)

(* [t] to the power -X, which on the cyclotomic subgroup the easy part lands in
   is the conjugate of [t] to the power X (ark-ec models/bn/mod.rs:203-209). *)
let exp_by_neg_x t = Fq12.conjugate (Fq12.exp_x t)

(* The final exponentiation (ark-ec models/bn/mod.rs:106-167). The easy part
   lifts [f] to (p^6 - 1)(p^2 + 1) with one inversion, the only place the whole
   pairing can answer [None]. The hard part is the Fuentes-Castaneda addition
   chain, transcribed step by step with arkworks' own y0..y16 names, and its
   cyclotomic squarings are plain Fq12 squarings: the two agree in value on this
   subgroup, and arkworks itself names plain squaring the valid fallback
   (ark-ff fields/models/fp12_2over3over2.rs:210-212). *)
let final_exponentiation f =
  Option.map
    (fun inverse ->
      let easy_base = Fq12.mul (Fq12.conjugate f) inverse in
      let r = Fq12.mul (Fq12.frobenius 2 easy_base) easy_base in
      let y0 = exp_by_neg_x r in
      let y1 = Fq12.square y0 in
      let y2 = Fq12.square y1 in
      let y3 = Fq12.mul y2 y1 in
      let y4 = exp_by_neg_x y3 in
      let y5 = Fq12.square y4 in
      let y6 = exp_by_neg_x y5 in
      (* arkworks conjugates y3 and y6 in place at this point, so every later
         line reads the conjugated value. *)
      let y3 = Fq12.conjugate y3 in
      let y6 = Fq12.conjugate y6 in
      let y7 = Fq12.mul y6 y4 in
      let y8 = Fq12.mul y7 y3 in
      let y9 = Fq12.mul y8 y1 in
      let y10 = Fq12.mul y8 y4 in
      let y11 = Fq12.mul y10 r in
      let y12 = Fq12.frobenius 1 y9 in
      let y13 = Fq12.mul y12 y11 in
      let y14 = Fq12.mul (Fq12.frobenius 2 y8) y13 in
      let y15 = Fq12.frobenius 3 (Fq12.mul (Fq12.conjugate r) y9) in
      Fq12.mul y15 y14)
    (Fq12.inv f)

let pair p q = final_exponentiation (miller_loop p q)

let pairing_check pairs =
  let survivors =
    List.filter
      (fun (p, q) -> not (G1.is_infinity p || G2.is_infinity q))
      pairs
  in
  match survivors with
  | [] -> true
  | _ :: _ ->
      Option.fold ~none:false ~some:Fq12.is_one
        (final_exponentiation
           (List.fold_left
              (fun acc (p, q) -> Fq12.mul acc (miller_loop p q))
              Fq12.one survivors))
