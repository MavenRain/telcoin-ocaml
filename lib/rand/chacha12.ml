(* ChaCha12 exactly as rand_chacha 0.9.0 computes it (guts.rs), restricted to
   what StdRng consumes: stream id zero, block counter from zero, keystream
   dispensed word-by-word.

   guts.rs vectorizes four blocks per [refill4] and rand_core's [BlockRng]
   buffers those 64 words, but the observable word sequence is identical to
   generating one 16-word block at a time: [next_u32] walks the buffer in
   order and refills sequentially (rand_core-0.9.5/src/block.rs:184-194), and
   [refill4] gives block i of a batch the counter d + i then advances the
   counter by four (guts.rs:143-148, 182). This port therefore buffers a
   single block and advances the counter by one per block, which is the same
   stream.

   Words are native [int]s in [0, 2^32): OCaml's 63-bit int carries a u32
   exactly, and every operation masks back to 32 bits. Rows are immutable
   4-tuples, as guts.rs's SIMD lanes are values; nothing is mutated. *)

type row = int * int * int * int

type t = {
  key_b : row; (* key words 0-3, the state's second row *)
  key_c : row; (* key words 4-7, the state's third row *)
  ctr : Int64.t; (* next block position, a wrapping u64 (state words 12-13) *)
  pending : int list; (* words of the current block not yet dispensed *)
}

let mask32 = 0xFFFFFFFF
let add32 a b = (a + b) land mask32
let rotl32 n x = ((x lsl n) lor (x lsr (32 - n))) land mask32
let map4 f (x0, x1, x2, x3) = (f x0, f x1, f x2, f x3)

let map2_4 f (x0, x1, x2, x3) (y0, y1, y2, y3) =
  (f x0 y0, f x1 y1, f x2 y2, f x3 y3)

let add4 = map2_4 add32
let xor4 = map2_4 ( lxor )

(* The four rows of the working state, as guts.rs's [State]. *)
type state = { a : row; b : row; c : row; d : row }

(* One vectorized quarter-round over all four columns (guts.rs:45-55). The
   crate's right-rotations by 16/20/24/25 are the classic left-rotations by
   16/12/8/7. *)
let round { a; b; c; d } =
  let a = add4 a b in
  let d = map4 (rotl32 16) (xor4 d a) in
  let c = add4 c d in
  let b = map4 (rotl32 12) (xor4 b c) in
  let a = add4 a b in
  let d = map4 (rotl32 8) (xor4 d a) in
  let c = add4 c d in
  let b = map4 (rotl32 7) (xor4 b c) in
  { a; b; c; d }

(* Lane rotations that turn a column round on the shuffled state into a
   diagonal round on the original (guts.rs:58-70): row b moves left by one
   lane, c by two, d by three, so column j of the diagonalized state is the
   j-th diagonal (a.(j), b.(j+1), c.(j+2), d.(j+3)); undiagonalize inverts. *)
let lanes1 (x0, x1, x2, x3) = (x1, x2, x3, x0)
let lanes2 (x0, x1, x2, x3) = (x2, x3, x0, x1)
let lanes3 (x0, x1, x2, x3) = (x3, x0, x1, x2)
let diagonalize { a; b; c; d } = { a; b = lanes1 b; c = lanes2 c; d = lanes3 d }
let undiagonalize { a; b; c; d } = { a; b = lanes3 b; c = lanes2 c; d = lanes1 d }

(* drounds = 6 for ChaCha12 (chacha.rs:339-345): each refill iteration is a
   column round then a diagonal round (guts.rs:167-170), 12 rounds total. *)
let double_rounds = 6

(* "expand 32-byte k", guts.rs:158. *)
let constants = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)

(* d row for block position [ctr]: a little-endian u64 across state words
   12-13, with the stream id (words 14-15) fixed at zero. *)
let d_row ctr =
  ( Int64.to_int (Int64.logand ctr 0xFFFFFFFFL),
    Int64.to_int (Int64.logand (Int64.shift_right_logical ctr 32) 0xFFFFFFFFL),
    0,
    0 )

(* One 16-word output block: [double_rounds] double rounds, then the
   feed-forward addition of the initial state, dispensed in state-word order
   a b c d (guts.rs:171-181). Returns head and tail so the caller never
   faces an empty list. *)
let block key_b key_c ctr =
  let init = { a = constants; b = key_b; c = key_c; d = d_row ctr } in
  let final =
    List.fold_left
      (fun st _ -> undiagonalize (round (diagonalize (round st))))
      init
      (List.init double_rounds Fun.id)
  in
  let a0, a1, a2, a3 = add4 final.a init.a in
  let b0, b1, b2, b3 = add4 final.b init.b in
  let c0, c1, c2, c3 = add4 final.c init.c in
  let d0, d1, d2, d3 = add4 final.d init.d in
  (a0, [ a1; a2; a3; b0; b1; b2; b3; c0; c1; c2; c3; d0; d1; d2; d3 ])

(* Little-endian u32 at byte offset [4 * i] (guts.rs:243-246). The index is
   bounded by construction: [Hash32.to_bytes] is exactly 32 bytes and [i] is
   0..7, so [String.get] never escapes the string. *)
let word_le s i =
  Char.code (String.get s (4 * i))
  lor (Char.code (String.get s ((4 * i) + 1)) lsl 8)
  lor (Char.code (String.get s ((4 * i) + 2)) lsl 16)
  lor (Char.code (String.get s ((4 * i) + 3)) lsl 24)

let of_key h =
  let s = Tn_hash32.Hash32.to_bytes h in
  {
    key_b = (word_le s 0, word_le s 1, word_le s 2, word_le s 3);
    key_c = (word_le s 4, word_le s 5, word_le s 6, word_le s 7);
    ctr = 0L;
    pending = [];
  }

let next_word t =
  match t.pending with
  | w :: rest -> (w, { t with pending = rest })
  | [] ->
      let w, rest = block t.key_b t.key_c t.ctr in
      (w, { t with ctr = Int64.add t.ctr 1L; pending = rest })
