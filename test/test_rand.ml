(* Tests for tn_rand: rand 0.9.2's StdRng (ChaCha12Rng) and the two samplers
   the committee shuffle consumes, against golden vectors generated once from
   the pinned Rust crates (rand 0.9.2, rand_chacha 0.9.0, rand_core 0.9.5:
   telcoin-network's Cargo.lock). A representative spread of the vector file
   (telcoin-ocaml-chunk32-rand-vectors.json) is embedded here: keystream
   heads, the first words of the second block (where a counter bug first
   shows), keystream tails, u64 heads and tails, every Fisher-Yates case with
   the len-33 case whole, every choose_multiple case, and all sixteen draws
   of every range bound, for all three seeds.

   rand_chacha 0.9.0 publishes no ChaCha12 known-answer vector (its
   test_chacha_true_values_* tests all pin ChaCha20), so the golden next_u32
   arrays are the keystream pins here.

   Every sampler test ends by probing the next keystream word against the
   pinned stream, so the tests see not only the draw values but exactly how
   much keystream each draw consumed. Two oracles are additionally
   independent of the harness that produced the vector file: the u64-path
   expectations are recomputed in-test with Zarith big-integer arithmetic
   from the pinned u64 draws, and the bias-correction-branch pins were
   cross-checked against a second implementation outside this repository. *)

module Chacha12 = Tn_rand.Chacha12
module Std_rng = Tn_rand.Std_rng
module Rand_seq = Tn_rand.Rand_seq
module Hash32 = Tn_evm.Hash32

(* ---------- helpers ---------- *)

let hex s =
  let digit c =
    match c with
    | '0' .. '9' -> Char.code c - Char.code '0'
    | 'a' .. 'f' -> Char.code c - Char.code 'a' + 10
    | 'A' .. 'F' -> Char.code c - Char.code 'A' + 10
    | _ -> 0
  in
  String.init
    (String.length s / 2)
    (fun i ->
      Char.chr ((digit (String.get s (2 * i)) lsl 4) lor digit (String.get s ((2 * i) + 1))))

let hash32 bytes =
  match Hash32.of_bytes bytes with
  | Some h -> h
  | None -> Alcotest.failf "seed fixture is %d bytes, not 32" (String.length bytes)

let rng_of_hex h = Std_rng.of_randomness (hash32 (hex h))

let nth l i =
  match List.nth_opt l i with
  | Some v -> v
  | None -> Alcotest.failf "vector index %d out of range" i

(* The first [len] elements from position [pos]. *)
let slice pos len l = List.filteri (fun i _ -> i >= pos && i < pos + len) l

(* [n] successive u32 draws, oldest first. *)
let words n rng =
  let rec go n acc rng =
    if n = 0 then (List.rev acc, rng)
    else
      let w, rng = Std_rng.next_u32 rng in
      go (n - 1) (w :: acc) rng
  in
  go n [] rng

(* [n] successive u64 draws, oldest first. *)
let u64s n rng =
  let rec go n acc rng =
    if n = 0 then (List.rev acc, rng)
    else
      let w, rng = Std_rng.next_u64 rng in
      go (n - 1) (w :: acc) rng
  in
  go n [] rng

let draw ~bound rng =
  match Std_rng.random_range_inclusive rng ~bound with
  | Ok r -> r
  | Error e -> Alcotest.fail (Std_rng.error_to_string e)

(* [n] successive range draws at one bound, oldest first. *)
let draws n ~bound rng =
  let rec go n acc rng =
    if n = 0 then (List.rev acc, rng)
    else
      let v, rng = draw ~bound rng in
      go (n - 1) (v :: acc) rng
  in
  go n [] rng

(* After a sampler test, the next keystream word must be the pinned word at
   [index]: the draw values AND the amount of keystream consumed agree. *)
let probe name index expected rng =
  let w, _ = Std_rng.next_u32 rng in
  Alcotest.(check int) (name ^ ": next keystream word is word " ^ string_of_int index) expected w

(* A u64 as a Zarith natural, for in-test recomputation of expectations. *)
let z_of_u64 x =
  if Int64.compare x 0L >= 0 then Z.of_int64 x
  else Z.add (Z.of_int64 x) (Z.pow (Z.of_int 2) 64)

(* The Fisher-Yates of shuffle_new_committee (block.rs:466-470): for i from
   len - 1 down to 1, j = random_range(0..=i), swap slots i and j. Returns
   the draw sequence (oldest first) and the final permutation of 0..len-1. *)
let fisher_yates len rng =
  let swap l i j =
    let vi = nth l i and vj = nth l j in
    List.mapi (fun k x -> if k = i then vj else if k = j then vi else x) l
  in
  let rec go perm acc rng i =
    if i < 1 then (List.rev acc, perm, rng)
    else
      let j, rng = draw ~bound:i rng in
      go (swap perm i j) (j :: acc) rng (i - 1)
  in
  go (List.init len Fun.id) [] rng (len - 1)

(* ---------- golden vectors (rand 0.9.2 / rand_chacha 0.9.0) ---------- *)

type seed_vectors = {
  hex : string;  (** the 32-byte StdRng seed *)
  u32_head : int list;  (** keystream words 0-15 *)
  u32_block1 : int list;  (** keystream words 16-19 *)
  u32_tail : int list;  (** keystream words 60-63 *)
  u64_head : int64 list;  (** u64 draws 0-3 of a fresh rng *)
  u64_tail : int64 list;  (** u64 draws 30-31 *)
  fy : (int * int list * int list) list;  (** len, draws, shuffled *)
  cm : (int * int * int list) list;  (** pool, amount, chosen *)
  ri : (int * int list) list;  (** inclusive bound, 16 draws *)
  u64_path : (int * int) list;  (** u64-dispatch bound, first draw *)
}

let vectors =
  [
    {
      hex = "0000000000000000000000000000000000000000000000000000000000000001";
      u32_head =
        [ 2607801029; 646719537; 2099327372; 2208813800; 2086979566; 2196016427; 1520627846;
          1264178733; 2230606278; 1014585398; 2600836504; 2164441342; 3192365374; 2362285634;
          1666319826; 77648151 ];
      u32_block1 = [ 1149489484; 1453872210; 205606722; 2561053166 ];
      u32_tail = [ 598160984; 2721489302; 2786882276; 2745709416 ];
      u64_head = [ 2777639263707062981L; 0x83a7d2e87d21318cL; 0x82e48d2b7c64c7eeL; 0x4b59d62d5aa2f086L ];
      u64_tail = [ 0xa236a19623a73658L; 0xa3a83368a61c72e4L ];
      fy =
        [ (4, [ 2; 0; 0 ], [ 1; 3; 0; 2 ]);
          (5, [ 3; 0; 1; 1 ], [ 4; 2; 1; 0; 3 ]);
          (33,
           [ 20; 4; 15; 15; 14; 14; 9; 7; 12; 5; 13; 11; 15; 11; 7; 0; 4; 5; 0; 8; 12; 6; 5; 7;
             8; 7; 6; 3; 2; 1; 2; 1 ],
           [ 27; 10; 16; 1; 2; 3; 19; 26; 22; 18; 32; 6; 24; 8; 17; 23; 31; 0; 25; 21; 29; 11;
             13; 5; 12; 7; 9; 28; 14; 30; 15; 4; 20 ]) ];
      cm =
        [ (7, 3, [ 4; 1; 5 ]);
          (3, 5, [ 0; 1; 2 ]);
          (5, 5, [ 0; 1; 2; 3; 4 ]);
          (12, 4, [ 5; 1; 2; 11 ]) ];
      ri =
        [ (2, [ 1; 0; 1; 1; 1; 1; 1; 0; 1; 0; 1; 1; 2; 1; 1; 0 ]);
          (3, [ 2; 0; 1; 2; 1; 2; 1; 1; 2; 0; 2; 2; 2; 2; 1; 0 ]);
          (6, [ 4; 1; 3; 3; 3; 3; 2; 2; 3; 1; 4; 3; 5; 3; 2; 0 ]);
          (7, [ 4; 1; 3; 4; 3; 4; 2; 2; 4; 1; 4; 4; 5; 4; 3; 0 ]);
          (10, [ 6; 1; 5; 5; 5; 5; 3; 3; 5; 2; 6; 5; 8; 6; 4; 0 ]);
          (33, [ 20; 5; 16; 17; 16; 17; 12; 10; 17; 8; 20; 17; 25; 18; 13; 0 ]);
          (100, [ 61; 15; 49; 51; 49; 51; 35; 29; 52; 23; 61; 50; 75; 55; 39; 1 ]);
          (255, [ 155; 38; 125; 131; 124; 130; 90; 75; 132; 60; 155; 129; 190; 140; 99; 4 ]) ];
      u64_path = [ (4294967296, 646719537); (4611686018427387903, 694409815926765745) ];
    };
    {
      hex = "abababababababababababababababababababababababababababababababab";
      u32_head =
        [ 2014114406; 3255196121; 487253471; 34826870; 963008380; 3364629530; 1075700750;
          2020874737; 2983091653; 1428668461; 3216651493; 3618397098; 2059652000; 2768054020;
          3950011670; 3014518775 ];
      u32_block1 = [ 3722868284; 928820013; 2113432522; 2193722041 ];
      u32_tail = [ 2795686810; 2174525269; 1791139999; 1736078125 ];
      u64_head = [ 0xc20659d9780cf266L; 149580268159296991L; 0xc88c2c1a3966577cL; 0x787419f1401de40eL ];
      u64_tail = [ 0x819c9f55a6a2cb9aL; 0x677a732d6ac2a09fL ];
      fy =
        [ (4, [ 1; 2; 0 ], [ 3; 0; 2; 1 ]);
          (5, [ 2; 3; 0; 0 ], [ 1; 4; 0; 3; 2 ]);
          (33,
           [ 15; 24; 3; 0; 6; 21; 6; 12; 17; 7; 17; 18; 10; 12; 17; 12; 14; 3; 7; 7; 2; 5; 1; 6;
             6; 4; 2; 1; 1; 0; 1; 0 ],
           [ 8; 32; 13; 29; 11; 20; 27; 4; 9; 26; 1; 5; 2; 16; 23; 30; 14; 19; 22; 25; 10; 18;
             31; 7; 17; 12; 28; 21; 6; 0; 3; 24; 15 ]) ];
      cm =
        [ (7, 3, [ 6; 3; 2 ]);
          (3, 5, [ 0; 1; 2 ]);
          (5, 5, [ 0; 1; 2; 3; 4 ]);
          (12, 4, [ 7; 1; 10; 3 ]) ];
      ri =
        [ (2, [ 1; 2; 0; 0; 0; 2; 0; 1; 2; 0; 2; 2; 1; 1; 2; 2 ]);
          (3, [ 1; 3; 0; 0; 0; 3; 1; 1; 2; 1; 2; 3; 1; 2; 3; 2 ]);
          (6, [ 3; 5; 0; 0; 1; 5; 1; 3; 4; 2; 5; 5; 3; 4; 6; 4 ]);
          (7, [ 3; 6; 0; 0; 1; 6; 2; 3; 5; 2; 5; 6; 3; 5; 7; 5 ]);
          (10, [ 5; 8; 1; 0; 2; 8; 2; 5; 7; 3; 8; 9; 5; 7; 10; 7 ]);
          (33, [ 15; 25; 3; 0; 7; 26; 8; 15; 23; 11; 25; 28; 16; 21; 31; 23 ]);
          (100, [ 47; 76; 11; 0; 22; 79; 25; 47; 70; 33; 75; 85; 48; 65; 92; 70 ]);
          (255, [ 120; 194; 29; 2; 57; 200; 64; 120; 177; 85; 191; 215; 122; 164; 235; 179 ]) ];
      u64_path = [ (4294967296, 3255196122); (4611686018427387903, 3495240220943793305) ];
    };
    {
      hex = "2f4c6986a3c0ddfa1734516e8ba8c5e2ff1c39567390adcae704213e5b7895b2";
      u32_head =
        [ 1144964766; 3052886811; 1231770282; 4215658794; 1895006803; 2839168456; 2402096148;
          3984773925; 10435737; 1036286784; 344100645; 3558338689; 1790384386; 1660683421;
          2804196320; 2910117296 ];
      u32_block1 = [ 3631629222; 962980983; 806649551; 593475805 ];
      u32_tail = [ 2085873565; 2054970952; 3593693727; 4006006504 ];
      u64_head = [ 0xb5f75b1b443ec69eL; 0xfb45d92a496b52aaL; 0xa93a45c870f38253L; 0xed82d3258f2d1414L ];
      u64_tail = [ 0x7a7c5e487c53e79dL; 0xeec6cee8d6336a1fL ];
      fy =
        [ (4, [ 1; 2; 0 ], [ 3; 0; 2; 1 ]);
          (5, [ 1; 2; 0; 1 ], [ 3; 4; 0; 2; 1 ]);
          (33,
           [ 8; 22; 8; 29; 12; 18; 15; 24; 0; 5; 1; 18; 8; 7; 12; 12; 14; 3; 2; 1; 1; 6; 3; 6;
             0; 2; 4; 5; 1; 2; 0; 1 ],
           [ 10; 9; 20; 19; 17; 23; 4; 16; 25; 11; 26; 6; 13; 31; 2; 3; 14; 21; 28; 7; 30; 27;
             1; 5; 0; 24; 15; 18; 12; 29; 32; 22; 8 ]) ];
      cm =
        [ (7, 3, [ 0; 5; 2 ]);
          (3, 5, [ 0; 1; 2 ]);
          (5, 5, [ 0; 1; 2; 3; 4 ]);
          (12, 4, [ 0; 4; 6; 8 ]) ];
      ri =
        [ (2, [ 0; 2; 0; 2; 1; 1; 1; 2; 0; 0; 0; 2; 1; 1; 1; 2 ]);
          (3, [ 1; 2; 1; 3; 1; 2; 2; 3; 0; 0; 0; 3; 1; 1; 2; 2 ]);
          (6, [ 1; 4; 2; 6; 3; 4; 3; 6; 0; 1; 0; 5; 2; 2; 4; 4 ]);
          (7, [ 2; 5; 2; 7; 3; 5; 4; 7; 0; 1; 0; 6; 3; 3; 5; 5 ]);
          (10, [ 2; 7; 3; 10; 4; 7; 6; 10; 0; 2; 0; 9; 4; 4; 7; 7 ]);
          (33, [ 9; 24; 9; 33; 15; 22; 19; 31; 0; 8; 2; 28; 14; 13; 22; 23 ]);
          (100, [ 26; 71; 28; 99; 44; 66; 56; 93; 0; 24; 8; 83; 42; 39; 65; 68 ]);
          (255, [ 68; 181; 73; 251; 112; 169; 143; 237; 0; 61; 20; 212; 106; 98; 167; 173 ]) ];
      u64_path = [ (4294967296, 3052886811); (4611686018427387903, 3278012253194924455) ];
    };
  ]

let each f () = List.iter f vectors

(* ---------- keystream ---------- *)

(* The next_u32 golden arrays ARE the keystream in BlockRng dispensing order:
   head (block 0 whole), the start of block 1 (where a counter bug first
   shows) and the tail (block 3). *)
let test_keystream =
  each (fun v ->
      let all, _ = words 64 (rng_of_hex v.hex) in
      Alcotest.(check (list int)) (v.hex ^ ": words 0-15") v.u32_head (slice 0 16 all);
      Alcotest.(check (list int)) (v.hex ^ ": words 16-19") v.u32_block1 (slice 16 4 all);
      Alcotest.(check (list int)) (v.hex ^ ": words 60-63") v.u32_tail (slice 60 4 all);
      (* the same stream through the Chacha12 surface itself *)
      let w0, _ = Chacha12.next_word (Chacha12.of_key (hash32 (hex v.hex))) in
      Alcotest.(check int) (v.hex ^ ": Chacha12.next_word is word 0") (nth v.u32_head 0) w0)

(* ---------- next_u64 ---------- *)

let test_next_u64 =
  each (fun v ->
      let all, _ = u64s 32 (rng_of_hex v.hex) in
      Alcotest.(check (list int64)) (v.hex ^ ": u64 draws 0-3") v.u64_head (slice 0 4 all);
      Alcotest.(check (list int64)) (v.hex ^ ": u64 draws 30-31") v.u64_tail (slice 30 2 all);
      (* low word first: draw 0 is exactly (word1 << 32) | word0 *)
      let expected =
        Int64.logor
          (Int64.shift_left (Int64.of_int (nth v.u32_head 1)) 32)
          (Int64.of_int (nth v.u32_head 0))
      in
      Alcotest.(check int64) (v.hex ^ ": u64 is low word first") expected (nth all 0))

(* ---------- random_range_inclusive, u32 dispatch ---------- *)

let test_range_inclusive =
  each (fun v ->
      List.iter
        (fun (bound, expected) ->
          let got, rng = draws 16 ~bound (rng_of_hex v.hex) in
          Alcotest.(check (list int))
            (v.hex ^ ": 16 draws at bound " ^ string_of_int bound)
            expected got;
          (* none of the pinned streams fires the bias-correction draw, so
             exactly one word per draw was consumed *)
          probe (v.hex ^ " bound " ^ string_of_int bound) 16 (nth v.u32_block1 0) rng)
        v.ri)

(* bound = u32::MAX is the crate's whole-word special case: the draw is the
   raw keystream word (uniform_int.rs:191-194). *)
let test_range_u32_max () =
  let v = nth vectors 0 in
  let d, rng = draw ~bound:0xFFFFFFFF (rng_of_hex v.hex) in
  Alcotest.(check int) "bound u32::MAX draws the raw word" (nth v.u32_head 0) d;
  probe "bound u32::MAX" 1 (nth v.u32_head 1) rng

(* ---------- random_range_inclusive, u64 dispatch ---------- *)

(* Bounds above u32::MAX take the u64 sampler, whose widening multiply is
   hand-built from Int64 halves. The pins are recomputed here with Zarith
   from the pinned u64 draw, so this oracle is independent of the harness
   that generated the vector file: expected = (x * (bound + 1)) >> 64. *)
let test_range_u64_dispatch =
  each (fun v ->
      List.iter
        (fun (bound, expected) ->
          let got, rng = draw ~bound (rng_of_hex v.hex) in
          Alcotest.(check int)
            (v.hex ^ ": u64-path draw at bound " ^ string_of_int bound)
            expected got;
          let z =
            Z.to_int
              (Z.shift_right
                 (Z.mul (z_of_u64 (nth v.u64_head 0)) (Z.add (Z.of_int bound) Z.one))
                 64)
          in
          Alcotest.(check int) (v.hex ^ ": Zarith recomputation agrees") z got;
          (* one u64 draw = two words consumed *)
          probe (v.hex ^ " u64-path bound " ^ string_of_int bound) 2 (nth v.u32_head 2) rng)
        v.u64_path)

(* ---------- Fisher-Yates over random_range_inclusive ---------- *)

let test_fisher_yates =
  each (fun v ->
      List.iter
        (fun (len, exp_draws, exp_shuffled) ->
          let got_draws, got_perm, rng = fisher_yates len (rng_of_hex v.hex) in
          Alcotest.(check (list int))
            (v.hex ^ ": FY draws, len " ^ string_of_int len)
            exp_draws got_draws;
          Alcotest.(check (list int))
            (v.hex ^ ": FY permutation, len " ^ string_of_int len)
            exp_shuffled got_perm;
          if len - 1 < 16 then
            probe (v.hex ^ " FY len " ^ string_of_int len) (len - 1)
              (nth v.u32_head (len - 1))
              rng)
        v.fy)

(* ---------- choose_multiple ---------- *)

let test_choose_multiple =
  each (fun v ->
      List.iter
        (fun (pool, amount, expected) ->
          let got, rng =
            Rand_seq.choose_multiple (rng_of_hex v.hex) ~amount (List.init pool Fun.id)
          in
          Alcotest.(check (list int))
            (v.hex ^ ": choose_multiple " ^ string_of_int amount ^ " of "
           ^ string_of_int pool)
            expected got;
          (* one draw per element beyond the reservoir, zero when the pool
             cannot overflow it (the amount >= length cases) *)
          let consumed = if pool > amount then pool - amount else 0 in
          probe
            (v.hex ^ " choose_multiple " ^ string_of_int amount ^ " of " ^ string_of_int pool)
            consumed
            (nth v.u32_head consumed)
            rng)
        v.cm)

(* amount = 0 has Rust semantics: the reservoir is full at once, so every
   element still costs a draw even though none can be selected. *)
let test_choose_multiple_zero () =
  let v = nth vectors 0 in
  let got, rng = Rand_seq.choose_multiple (rng_of_hex v.hex) ~amount:0 [ 10; 20; 30 ] in
  Alcotest.(check (list int)) "amount 0 selects nothing" [] got;
  probe "amount 0 still draws per element" 3 (nth v.u32_head 3) rng

(* A negative amount has no Rust image: nothing selected, nothing drawn. *)
let test_choose_multiple_negative () =
  let v = nth vectors 0 in
  let got, rng = Rand_seq.choose_multiple (rng_of_hex v.hex) ~amount:(-2) [ 10; 20; 30 ] in
  Alcotest.(check (list int)) "negative amount selects nothing" [] got;
  probe "negative amount draws nothing" 0 (nth v.u32_head 0) rng

(* ---------- the bias-correction branch ---------- *)

(* None of the golden streams fires Canon's second draw: its chance is about
   (bound + 1) / 2^32 per draw, vanishing for these bounds. Seeds that do
   fire it within 16 draws were therefore located by exhaustive search with a
   second implementation outside this repository, which also produced these
   pins. Each stream fires the branch exactly once at bound 100, so its 16
   draws consume 17 words, which the probe observes; the second seed's firing
   draw additionally lands in the carry case, pinning the increment of
   uniform_int.rs:203-205. A port that skips the second draw or drops the
   increment diverges here and nowhere in the golden streams. *)
let test_bias_correction () =
  List.iter
    (fun (seed, expected, probe_word) ->
      let got, rng = draws 16 ~bound:100 (rng_of_hex seed) in
      Alcotest.(check (list int)) (seed ^ ": 16 draws at bound 100") expected got;
      probe ("bias-correction stream " ^ seed) 17 probe_word rng)
    [
      ( "bf1e280000000000000000000000000000000000000000000000000000000000",
        [ 24; 85; 24; 49; 83; 12; 45; 13; 78; 9; 87; 66; 50; 7; 72; 94 ],
        1465883725 );
      ( "70c35c0000000000000000000000000000000000000000000000000000000000",
        [ 64; 11; 12; 74; 37; 24; 73; 99; 82; 65; 7; 17; 81; 71; 93; 83 ],
        2370610635 );
    ]

(* ---------- the error surface ---------- *)

let test_negative_bound () =
  let v = nth vectors 0 in
  match Std_rng.random_range_inclusive (rng_of_hex v.hex) ~bound:(-1) with
  | Ok _ -> Alcotest.fail "a negative bound must be refused"
  | Error (Std_rng.Negative_bound b) ->
      Alcotest.(check int) "the bound is reported" (-1) b;
      Alcotest.(check string) "and rendered"
        "random_range_inclusive: negative inclusive bound -1"
        (Std_rng.error_to_string (Std_rng.Negative_bound b))

let () =
  Alcotest.run "rand"
    [
      ( "keystream",
        [
          Alcotest.test_case "ChaCha12 words in dispensing order" `Quick test_keystream;
          Alcotest.test_case "next_u64 is two words, low first" `Quick test_next_u64;
        ] );
      ( "range sampler",
        [
          Alcotest.test_case "u32 dispatch: draws and consumption" `Quick test_range_inclusive;
          Alcotest.test_case "u32::MAX bound special case" `Quick test_range_u32_max;
          Alcotest.test_case "u64 dispatch: wmul64 vs Zarith" `Quick test_range_u64_dispatch;
          Alcotest.test_case "the bias-correction draw fires" `Quick test_bias_correction;
          Alcotest.test_case "a negative bound is an error" `Quick test_negative_bound;
        ] );
      ( "sequences",
        [
          Alcotest.test_case "Fisher-Yates draws and permutations" `Quick test_fisher_yates;
          Alcotest.test_case "choose_multiple reservoir" `Quick test_choose_multiple;
          Alcotest.test_case "choose_multiple amount zero" `Quick test_choose_multiple_zero;
          Alcotest.test_case "choose_multiple negative amount" `Quick
            test_choose_multiple_negative;
        ] );
    ]
