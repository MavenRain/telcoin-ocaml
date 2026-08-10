(* The BN254 curve groups. G1 is the group of the short Weierstrass curve
   y^2 = x^3 + 3 over Fq; G2 is the group of its sextic twist
   y^2 = x^3 + 3/(u + 9) over Fq2. The group order r that the 0x07 scalar is
   reduced by sits beside them.

   The representation is affine with the point at infinity kept as its own
   constructor, the secp256k1.ml template: every group law is a case analysis
   that guards each inversion, so addition, doubling and scalar multiplication
   are total and need no Result. Byte reads fold over the string instead of
   indexing it, so the codec carries no partial accessor either.

   The two groups differ in one place that matters on the wire. G1 has cofactor
   1 (ark-bn254 curves/g1.rs:21-89), so an on-curve point is already in the
   r-order subgroup and no subgroup filter applies. G2 has a large cofactor
   (curves/g2.rs:20-25), so a point can sit on the twist and still fall outside
   the r-order subgroup: G2.decode runs a genuine subgroup test that G1.decode
   has no counterpart to. *)

module Fq = Bn254_field.Fq
module Fq2 = Bn254_field.Fq2

(* r, the group order (ark-bn254 fields/fr.rs:4). In decimal:
   21888242871839275222246405745257275088548364400416034343698204186575808495617. *)
let r =
  Z.of_string "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"

(* One coordinate word on the precompile wire. *)
let word = 32

(* The [len] bytes of [s] that start at [off], zero-filled past the end of [s].
   The fold carries the position, so the read is total: it has no index and no
   partial accessor, and an out-of-range window is padded rather than refused.
   Only exactly-sized inputs reach it here, so the padding stays unused. *)
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

module G1 = struct
  type t = Infinity | Affine of { x : Fq.t; y : Fq.t }

  (* The curve constant b of y^2 = x^3 + b, and the 3 of the tangent slope. The
     two are the same number and different quantities. *)
  let b = Fq.of_z (Z.of_int 3)
  let three = Fq.of_z (Z.of_int 3)
  let infinity = Infinity
  let generator = Affine { x = Fq.one; y = Fq.of_z (Z.of_int 2) }

  let is_on_curve x y =
    Fq.equal (Fq.square y) (Fq.add (Fq.mul x (Fq.square x)) b)

  let make ~x ~y = if is_on_curve x y then Some (Affine { x; y }) else None
  let xy = function Infinity -> None | Affine { x; y } -> Some (x, y)
  let is_infinity = function Infinity -> true | Affine _ -> false

  let equal p1 p2 =
    match (p1, p2) with
    | Infinity, Infinity -> true
    | Infinity, Affine _ -> false
    | Affine _, Infinity -> false
    | Affine u, Affine v -> Fq.equal u.x v.x && Fq.equal u.y v.y

  (* Negation reflects in the x axis. It fixes infinity, and it fixes a point of
     order 2, where y and its negation agree. *)
  let neg = function
    | Infinity -> Infinity
    | Affine { x; y } -> Affine { x; y = Fq.neg y }

  (* Doubling. A vertical tangent (y = 0) meets the curve only at infinity;
     every other point has 2y non-zero, so the inverse exists and the [None] arm
     is unreachable. Infinity is the correct value on that dead arm anyway. *)
  let double = function
    | Infinity -> Infinity
    | Affine { x; y } ->
        if Fq.is_zero y then Infinity
        else
          Option.fold ~none:Infinity
            ~some:(fun i ->
              let lambda = Fq.mul (Fq.mul three (Fq.square x)) i in
              let x3 = Fq.sub (Fq.square lambda) (Fq.add x x) in
              Affine { x = x3; y = Fq.sub (Fq.mul lambda (Fq.sub x x3)) y })
            (Fq.inv (Fq.add y y))

  (* The chord-and-tangent group law. Equal x coordinates mean either the same
     point, which doubles, or a point and its negation, whose sum is infinity.
     Distinct x coordinates leave x2 - x1 non-zero, so that inverse exists too
     and its [None] arm is unreachable. *)
  let add p1 p2 =
    match (p1, p2) with
    | Infinity, Infinity -> Infinity
    | Infinity, Affine _ -> p2
    | Affine _, Infinity -> p1
    | Affine u, Affine v ->
        if Fq.equal u.x v.x then if Fq.equal u.y v.y then double p1 else Infinity
        else
          Option.fold ~none:Infinity
            ~some:(fun i ->
              let lambda = Fq.mul (Fq.sub v.y u.y) i in
              let x3 = Fq.sub (Fq.sub (Fq.square lambda) u.x) v.x in
              Affine { x = x3; y = Fq.sub (Fq.mul lambda (Fq.sub u.x x3)) u.y })
            (Fq.inv (Fq.sub v.x u.x))

  (* Double-and-add over the bits of [k], low bit first, the secp256k1.ml idiom.
     A negative scalar is refused rather than read as a negated multiple:
     totality is carried by the type. The 0x07 arm passes a residue modulo r, so
     the [None] arm is dead there. *)
  let mul k pt =
    if Z.sign k < 0 then None
    else
      let rec go k acc base =
        if Z.equal k Z.zero then acc
        else
          let acc =
            if Z.equal (Z.logand k Z.one) Z.one then add acc base else acc
          in
          go (Z.shift_right k 1) acc (double base)
      in
      Some (go k infinity pt)

  (* Exactly 64 bytes, x then y, each a canonical 32-byte big-endian word: a
     coordinate at or above p is refused, never reduced. An all-zero pair is the
     point at infinity and skips the curve equation, exactly as the arkworks
     reader does (arkworks.rs:62-68); any other pair must satisfy the curve
     equation. Every refusal is the same [None]. *)
  let decode s =
    if String.length s <> 2 * word then None
    else
      Option.bind
        (Fq.of_be_bytes (window s ~off:0 ~len:word))
        (fun x ->
          Option.bind
            (Fq.of_be_bytes (window s ~off:word ~len:word))
            (fun y ->
              if Fq.is_zero x && Fq.is_zero y then Some Infinity else make ~x ~y))

  let encode = function
    | Infinity -> String.make (2 * word) '\000'
    | Affine { x; y } -> Fq.to_be_bytes x ^ Fq.to_be_bytes y
end

module G2 = struct
  type t = Infinity | Affine of { x : Fq2.t; y : Fq2.t }

  (* The twist constant b = 3/(u + 9), transcribed from the vendored value
     (ark-bn254 curves/g2.rs:39-44), and the 3 of the tangent slope, which lives
     in the base field embedded in Fq2. *)
  let b =
    Fq2.make
      (Fq.of_z
         (Z.of_string
            "19485874751759354771024239261021720505790618469301721065564631296452457478373"))
      (Fq.of_z
         (Z.of_string
            "266929791119991161246907387137283842545076965332900288569378510910307636690"))

  let three = Fq2.make (Fq.of_z (Z.of_int 3)) Fq.zero
  let infinity = Infinity

  (* The vendored generator (curves/g2.rs:99-114). Each coordinate is an Fq2,
     given here as the real part then the u part. *)
  let generator =
    Affine
      {
        x =
          Fq2.make
            (Fq.of_z
               (Z.of_string
                  "10857046999023057135944570762232829481370756359578518086990519993285655852781"))
            (Fq.of_z
               (Z.of_string
                  "11559732032986387107991004021392285783925812861821192530917403151452391805634"));
        y =
          Fq2.make
            (Fq.of_z
               (Z.of_string
                  "8495653923123431417604973247489272438418190587263600148770280649306958101930"))
            (Fq.of_z
               (Z.of_string
                  "4082367875863433681332203403145435568316851327593401208105741076214120093531"));
      }

  let is_on_curve x y =
    Fq2.equal (Fq2.square y) (Fq2.add (Fq2.mul x (Fq2.square x)) b)

  let make ~x ~y = if is_on_curve x y then Some (Affine { x; y }) else None
  let xy = function Infinity -> None | Affine { x; y } -> Some (x, y)
  let is_infinity = function Infinity -> true | Affine _ -> false

  let equal p1 p2 =
    match (p1, p2) with
    | Infinity, Infinity -> true
    | Infinity, Affine _ -> false
    | Affine _, Infinity -> false
    | Affine u, Affine v -> Fq2.equal u.x v.x && Fq2.equal u.y v.y

  let neg = function
    | Infinity -> Infinity
    | Affine { x; y } -> Affine { x; y = Fq2.neg y }

  (* Doubling over Fq2, the G1 case analysis one level up: a vertical tangent
     meets the twist only at infinity, and every other point has 2y invertible,
     so the [None] arm is unreachable and infinity is its correct value anyway. *)
  let double = function
    | Infinity -> Infinity
    | Affine { x; y } ->
        if Fq2.is_zero y then Infinity
        else
          Option.fold ~none:Infinity
            ~some:(fun i ->
              let lambda = Fq2.mul (Fq2.mul three (Fq2.square x)) i in
              let x3 = Fq2.sub (Fq2.square lambda) (Fq2.add x x) in
              Affine
                { x = x3; y = Fq2.sub (Fq2.mul lambda (Fq2.sub x x3)) y })
            (Fq2.inv (Fq2.add y y))

  let add p1 p2 =
    match (p1, p2) with
    | Infinity, Infinity -> Infinity
    | Infinity, Affine _ -> p2
    | Affine _, Infinity -> p1
    | Affine u, Affine v ->
        if Fq2.equal u.x v.x then
          if Fq2.equal u.y v.y then double p1 else Infinity
        else
          Option.fold ~none:Infinity
            ~some:(fun i ->
              let lambda = Fq2.mul (Fq2.sub v.y u.y) i in
              let x3 = Fq2.sub (Fq2.sub (Fq2.square lambda) u.x) v.x in
              Affine
                { x = x3; y = Fq2.sub (Fq2.mul lambda (Fq2.sub u.x x3)) u.y })
            (Fq2.inv (Fq2.sub v.x u.x))

  (* Double and add over the bits of [k], low bit first, as G1.mul. A negative
     scalar is refused rather than read as a multiple of the negated point. *)
  let mul k pt =
    if Z.sign k < 0 then None
    else
      let rec go k acc base =
        if Z.equal k Z.zero then acc
        else
          let acc =
            if Z.equal (Z.logand k Z.one) Z.one then add acc base else acc
          in
          go (Z.shift_right k 1) acc (double base)
      in
      Some (go k infinity pt)

  (* The r-order subgroup test, stated as its own definition: [r]P is infinity
     exactly on the points of order dividing r. arkworks reaches the same set by
     an endomorphism identity ([p]P = [6X^2]P, curves/g2.rs:56-63), which
     eprint 2022/352 proves equivalent on the twist, so the accept and reject
     sets agree and the wire behaviour is unchanged. r is positive, so [mul]
     never answers [None] here. *)
  let in_subgroup pt =
    Option.fold ~none:false ~some:(fun q -> equal q infinity) (mul r pt)

  (* Exactly 128 bytes, four canonical 32-byte big-endian words. Within each
     64-byte Fq2 half the u coefficient comes FIRST and the real coefficient
     second, because the arkworks reader parses the second word before the first
     (arkworks.rs:44-49, 158-162): the words are x.c1, x.c0, y.c1, y.c0.

     All 128 zero bytes are the point at infinity and skip both checks. Any other
     input must satisfy the twist equation AND lie in the r-order subgroup
     (arkworks.rs:86-99). Every refusal is the same [None]. *)
  let decode s =
    if String.length s <> 4 * word then None
    else
      Option.bind
        (Fq.of_be_bytes (window s ~off:0 ~len:word))
        (fun x1 ->
          Option.bind
            (Fq.of_be_bytes (window s ~off:word ~len:word))
            (fun x0 ->
              Option.bind
                (Fq.of_be_bytes (window s ~off:(2 * word) ~len:word))
                (fun y1 ->
                  Option.bind
                    (Fq.of_be_bytes (window s ~off:(3 * word) ~len:word))
                    (fun y0 ->
                      let x = Fq2.make x0 x1 and y = Fq2.make y0 y1 in
                      if Fq2.is_zero x && Fq2.is_zero y then Some Infinity
                      else
                        Option.bind (make ~x ~y) (fun pt ->
                            if in_subgroup pt then Some pt else None)))))
end
