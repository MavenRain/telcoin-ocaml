(* BLAKE2b compression, following revm's portable path
   ([revm-precompile-32.0.0/src/blake2.rs] [mod algo]), itself the RFC 7693
   reference. All arithmetic is on 64-bit words: [Int64] addition already wraps
   modulo [2^64], which is exactly the [wrapping_add] the mixing needs. *)

(* The initialisation vector, RFC 7693 section 2.6 (BLAKE2b): the fractional
   parts of the square roots of the first eight primes. *)
let iv =
  [|
    0x6a09e667f3bcc908L;
    0xbb67ae8584caa73bL;
    0x3c6ef372fe94f82bL;
    0xa54ff53a5f1d36f1L;
    0x510e527fade682d1L;
    0x9b05688c2b3e6c1fL;
    0x1f83d9abfb41bd6bL;
    0x5be0cd19137e2179L;
  |]

(* The message-word permutation SIGMA, RFC 7693 section 2.7. Ten rows; the round
   function selects row [r mod 10], so any round count is defined. *)
let sigma =
  [|
    [| 0; 1; 2; 3; 4; 5; 6; 7; 8; 9; 10; 11; 12; 13; 14; 15 |];
    [| 14; 10; 4; 8; 9; 15; 13; 6; 1; 12; 0; 2; 11; 7; 5; 3 |];
    [| 11; 8; 12; 0; 5; 2; 15; 13; 10; 14; 3; 6; 7; 1; 9; 4 |];
    [| 7; 9; 3; 1; 13; 12; 11; 14; 2; 6; 5; 10; 4; 0; 15; 8 |];
    [| 9; 0; 5; 7; 2; 4; 10; 15; 14; 1; 11; 12; 6; 8; 3; 13 |];
    [| 2; 12; 6; 10; 0; 11; 8; 3; 4; 13; 7; 5; 15; 14; 1; 9 |];
    [| 12; 5; 1; 15; 14; 13; 4; 10; 0; 7; 6; 3; 9; 2; 8; 11 |];
    [| 13; 11; 7; 14; 12; 1; 3; 9; 5; 0; 15; 4; 8; 6; 2; 10 |];
    [| 6; 15; 14; 9; 11; 3; 0; 8; 12; 2; 13; 7; 1; 4; 10; 5 |];
    [| 10; 2; 8; 4; 7; 6; 1; 5; 15; 11; 9; 14; 3; 12; 13; 0 |];
  |]

(* A right rotation of a 64-bit word by [n] bits (0 < n < 64). *)
let ror x n =
  Int64.logor (Int64.shift_right_logical x n) (Int64.shift_left x (64 - n))

(* The mixing function G, RFC 7693 section 3.1, in place on the working vector. *)
let g v a b c d x y =
  let ( +% ) = Int64.add in
  let ( ^% ) = Int64.logxor in
  v.(a) <- v.(a) +% v.(b) +% x;
  v.(d) <- ror (v.(d) ^% v.(a)) 32;
  v.(c) <- v.(c) +% v.(d);
  v.(b) <- ror (v.(b) ^% v.(c)) 24;
  v.(a) <- v.(a) +% v.(b) +% y;
  v.(d) <- ror (v.(d) ^% v.(a)) 16;
  v.(c) <- v.(c) +% v.(d);
  v.(b) <- ror (v.(b) ^% v.(c)) 63

(* One round: the eight G applications of RFC 7693 section 3.2, in the column
   then diagonal order, under this round's permutation row. *)
let round v m r =
  let s = sigma.(r mod 10) in
  g v 0 4 8 12 m.(s.(0)) m.(s.(1));
  g v 1 5 9 13 m.(s.(2)) m.(s.(3));
  g v 2 6 10 14 m.(s.(4)) m.(s.(5));
  g v 3 7 11 15 m.(s.(6)) m.(s.(7));
  g v 0 5 10 15 m.(s.(8)) m.(s.(9));
  g v 1 6 11 12 m.(s.(10)) m.(s.(11));
  g v 2 7 8 13 m.(s.(12)) m.(s.(13));
  g v 3 4 9 14 m.(s.(14)) m.(s.(15))

let compress ~rounds ~h ~m ~t0 ~t1 ~final =
  (* The working vector: state in the low half, IV in the high half, with the
     counter mixed into words 12/13 and the final-block flag inverting word 14. *)
  let v = Array.make 16 0L in
  Array.blit h 0 v 0 8;
  Array.blit iv 0 v 8 8;
  v.(12) <- Int64.logxor v.(12) t0;
  v.(13) <- Int64.logxor v.(13) t1;
  if final then v.(14) <- Int64.lognot v.(14);
  let rec spin r = if r >= rounds then () else (round v m r; spin (r + 1)) in
  spin 0;
  (* Fold the two halves of the working vector back into the state. *)
  Array.init 8 (fun i -> Int64.logxor h.(i) (Int64.logxor v.(i) v.(i + 8)))
