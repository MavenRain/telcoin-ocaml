(* rand 0.9.2's StdRng (ChaCha12, rand-0.9.2/src/rngs/std.rs:14-16) surface
   for the committee shuffle. The range sampler is the exact usize dispatch of
   UniformUsize::sample_single_inclusive (uniform_int.rs:562-584): bounds at
   or below u32::MAX go through UniformInt::<u32> (whose sample type is u32,
   uniform_int.rs:270), larger bounds through UniformInt::<u64>. Both are
   Canon's biased method (uniform_int.rs:170-209, the default feature set):
   one draw, a widening multiply by the range, and a second draw only when
   the low half lands in the biased zone. *)

type t = Chacha12.t

let of_randomness = Chacha12.of_key
let next_u32 = Chacha12.next_word

(* BlockRng::next_u64 (rand_core-0.9.5/src/block.rs:197-219) reads the low
   word then the high word. Its three buffer-position cases (mid-buffer, at
   the last word, buffer empty) all dispense the same two sequential
   keystream words, so two [next_u32] draws are the exact image. *)
let next_u64 t =
  let lo, t = next_u32 t in
  let hi, t = next_u32 t in
  (Int64.logor (Int64.shift_left (Int64.of_int hi) 32) (Int64.of_int lo), t)

type error = Negative_bound of int

let error_to_string (Negative_bound b) =
  "random_range_inclusive: negative inclusive bound " ^ string_of_int b

let mask32 = 0xFFFFFFFF

(* Canon's method at u32 (uniform_int.rs:176-209 instantiated with sample
   type u32). [range] is in [1, 2^32 - 1]; the range-is-zero special case
   (bound = u32::MAX) is the caller's. The 32x32 widening multiply rides
   Int64: the full product is below 2^64, so [shift_right_logical] recovers
   the unsigned high half exactly and there is no silent-overflow site. *)
let sample_u32 t range =
  let x, t = next_u32 t in
  let p = Int64.mul (Int64.of_int x) (Int64.of_int range) in
  let result = Int64.to_int (Int64.shift_right_logical p 32) in
  let lo_order = Int64.to_int (Int64.logand p 0xFFFFFFFFL) in
  (* range.wrapping_neg() as u32; range is nonzero here, so no mask wrap. *)
  let wneg = 0x1_0000_0000 - range in
  if lo_order > wneg then
    (* The sample is biased: one more draw decides whether to increment
       (uniform_int.rs:199-206). This branch consumes keystream. *)
    let y, t = next_u32 t in
    let q = Int64.mul (Int64.of_int y) (Int64.of_int range) in
    let new_hi = Int64.to_int (Int64.shift_right_logical q 32) in
    let overflow = lo_order + new_hi > mask32 in
    (result + Bool.to_int overflow, t)
  else (result, t)

(* 64x64 -> 128 widening multiply, the image of u64's [wmul]
   (rand-0.9.2/src/distr/utils.rs:60-61, which widens through u128), built
   from Int64 halves because OCaml has no u128. The low half is the wrapping
   product; the high half assembles the four 32x32 partial products. The
   carry sum is at most 3 * (2^32 - 1), which fits Int64 without wrapping,
   and the high-half sum is congruent mod 2^64 to a value below 2^64, so
   Int64's wrapping addition computes it exactly. *)
let wmul64 x y =
  let m = 0xFFFFFFFFL in
  let xl = Int64.logand x m and xh = Int64.shift_right_logical x 32 in
  let yl = Int64.logand y m and yh = Int64.shift_right_logical y 32 in
  let ll = Int64.mul xl yl in
  let lh = Int64.mul xl yh in
  let hl = Int64.mul xh yl in
  let hh = Int64.mul xh yh in
  let carry =
    Int64.shift_right_logical
      (Int64.add
         (Int64.add (Int64.shift_right_logical ll 32) (Int64.logand lh m))
         (Int64.logand hl m))
      32
  in
  let hi =
    Int64.add
      (Int64.add hh (Int64.shift_right_logical lh 32))
      (Int64.add (Int64.shift_right_logical hl 32) carry)
  in
  (hi, Int64.mul x y)

(* Canon's method at u64 (uniform_int.rs:176-209 with sample type u64),
   reached for bounds above u32::MAX. [range] is in [2^32 + 1, 2^62] because
   the bound is a native int, so the u64 range-is-zero special case (bound =
   u64::MAX) is unrepresentable here and has no arm. The result is below the
   range, hence at most 2^62 - 1 after the bias increment's cap, so
   [Int64.to_int]'s 63-bit truncation is exact. *)
let sample_u64 t range =
  let x, t = next_u64 t in
  let result, lo_order = wmul64 x range in
  (* range.wrapping_neg() at u64 is two's-complement negation. *)
  let wneg = Int64.neg range in
  if Int64.unsigned_compare lo_order wneg > 0 then
    let y, t = next_u64 t in
    let new_hi, _ = wmul64 y range in
    let sum = Int64.add lo_order new_hi in
    (* checked_add is None exactly when the unsigned sum wrapped. *)
    let overflow = Int64.unsigned_compare sum lo_order < 0 in
    (Int64.to_int (Int64.add result (Int64.of_int (Bool.to_int overflow))), t)
  else (Int64.to_int result, t)

let random_range_inclusive t ~bound =
  if bound < 0 then Error (Negative_bound bound)
  else if bound > mask32 then
    (* uniform_int.rs:578-580: the u64 sampler. The range rides Int64 so
       that bound = max_int does not wrap the native int. *)
    Ok (sample_u64 t (Int64.add (Int64.of_int bound) 1L))
  else if bound = mask32 then
    (* range = 2^32 truncates to u32 zero: the whole-word special case,
       uniform_int.rs:191-194. *)
    Ok (next_u32 t)
  else Ok (sample_u32 t (bound + 1))
