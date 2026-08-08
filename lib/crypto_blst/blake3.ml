(* Pure-OCaml BLAKE3, default (unkeyed) hash mode, 32-byte output only.

   Reference: the BLAKE3 paper's reference implementation. Words are 32-bit
   values carried in the native int and re-masked to [mask] after every
   addition, shift and rotation; [lxor] of two masked words needs no re-mask.
   State and message blocks are immutable tuples and byte access is
   combinator-only ([String.fold_left], [Buffer]) — no indexing anywhere, so
   every step is total by construction. The only mutable values are
   [Buffer.t]s local to a function body; nothing mutable escapes. *)

let mask = 0xffffffff

(* The 8-word IV (the SHA-256/BLAKE2s initial constants). In hash mode the
   key words equal the IV; the compression matrix also seeds its third row
   with the first four IV words. *)
let iv0 = 0x6a09e667
let iv1 = 0xbb67ae85
let iv2 = 0x3c6ef372
let iv3 = 0xa54ff53a
let iv4 = 0x510e527f
let iv5 = 0x9b05688c
let iv6 = 0x1f83d9ab
let iv7 = 0x5be0cd19
let key_words = (iv0, iv1, iv2, iv3, iv4, iv5, iv6, iv7)

(* Domain flags (the keyed/derive_key flags are out of scope). *)
let flag_chunk_start = 1
let flag_chunk_end = 2
let flag_parent = 4
let flag_root = 8

(* 32-bit addition on native int. *)
let ( +^ ) a b = (a + b) land mask

(* Rotate a masked 32-bit word right by [n], for 0 < n < 32. *)
let rotr32 x n = ((x lsr n) lor (x lsl (32 - n))) land mask

(* The G quarter-round on four state words and two message words. *)
let g a b c d mx my =
  let a = a +^ b +^ mx in
  let d = rotr32 (d lxor a) 16 in
  let c = c +^ d in
  let b = rotr32 (b lxor c) 12 in
  let a = a +^ b +^ my in
  let d = rotr32 (d lxor a) 8 in
  let c = c +^ d in
  let b = rotr32 (b lxor c) 7 in
  (a, b, c, d)

(* One round: G down the four columns, then G down the four diagonals. *)
let round
    (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15)
    (m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15) =
  let v0, v4, v8, v12 = g v0 v4 v8 v12 m0 m1 in
  let v1, v5, v9, v13 = g v1 v5 v9 v13 m2 m3 in
  let v2, v6, v10, v14 = g v2 v6 v10 v14 m4 m5 in
  let v3, v7, v11, v15 = g v3 v7 v11 v15 m6 m7 in
  let v0, v5, v10, v15 = g v0 v5 v10 v15 m8 m9 in
  let v1, v6, v11, v12 = g v1 v6 v11 v12 m10 m11 in
  let v2, v7, v8, v13 = g v2 v7 v8 v13 m12 m13 in
  let v3, v4, v9, v14 = g v3 v4 v9 v14 m14 m15 in
  (v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15)

(* The fixed message-word permutation applied between rounds:
   m'[i] = m[perm[i]] with perm = 2 6 3 10 7 0 4 13 1 11 12 5 9 14 15 8. *)
let permute
    (m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15) =
  (m2, m6, m3, m10, m7, m0, m4, m13, m1, m11, m12, m5, m9, m14, m15, m8)

(* Compress one 64-byte block [m] into chaining value [h] under 64-bit
   counter [t], block length [blen] and [flags]: 7 rounds, permuting the
   message words between rounds. Only the first 8 output words are ever
   needed here (chunk/parent chaining values and the 32-byte root output),
   so the second half of the output matrix is not computed. *)
let compress (h0, h1, h2, h3, h4, h5, h6, h7) m t blen flags =
  let st =
    ( h0, h1, h2, h3, h4, h5, h6, h7,
      iv0, iv1, iv2, iv3,
      t land mask, (t lsr 32) land mask, blen, flags )
  in
  let final, _ =
    List.fold_left
      (fun (v, m) () -> (round v m, permute m))
      (st, m)
      [ (); (); (); (); (); (); () ]
  in
  let v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15 =
    final
  in
  ( v0 lxor v8, v1 lxor v9, v2 lxor v10, v3 lxor v11,
    v4 lxor v12, v5 lxor v13, v6 lxor v14, v7 lxor v15 )

(* Split [s] into consecutive pieces of [size] bytes, in order; the final
   piece may be short, and the empty string yields one empty piece (BLAKE3
   gives the empty input one empty chunk of one empty block, so a caller
   always has a final piece to flag). Only the local [Buffer.t] mutates. *)
let group size s =
  let buf = Buffer.create size in
  let full =
    String.fold_left
      (fun acc ch ->
        Buffer.add_char buf ch;
        if Buffer.length buf = size then (
          let piece = Buffer.contents buf in
          Buffer.clear buf;
          piece :: acc)
        else acc)
      [] s
  in
  let all =
    if Buffer.length buf > 0 || List.is_empty full then
      Buffer.contents buf :: full
    else full
  in
  List.rev all

let zero16 = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

(* Shift the 16-word window left by one, appending [w]: pushing 16 words in
   order onto [zero16] yields exactly those words in order. *)
let push
    (_m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15) w
    =
  (m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, w)

(* The 16 little-endian message words of one block of at most 64 bytes,
   zero-padded to 64. [String.make]'s count is clamped nonnegative, and the
   fold completes a word exactly every 4 bytes, so 64 padded bytes push 16
   words through [push]. *)
let words_of_block block =
  let padded = block ^ String.make (max 0 (64 - String.length block)) '\000' in
  let m, _, _ =
    String.fold_left
      (fun (m, w, shift) ch ->
        let w = w lor (Char.code ch lsl shift) in
        if shift = 24 then (push m w, 0, 0) else (m, w, shift + 8))
      (zero16, 0, 0) padded
  in
  m

(* Chaining value of one chunk (a string of at most 1024 bytes) under chunk
   counter [t]. The chaining value threads across the chunk's up-to-16
   blocks starting from the key words; the first block carries CHUNK_START,
   the last CHUNK_END (a single-block chunk carries both), and when [root]
   is set (single-chunk tree) the last block also carries ROOT. Every block
   of a chunk compresses under the chunk's own counter. *)
let chunk_cv t ~root chunk =
  let blocks = group 64 chunk in
  let n = List.length blocks in
  List.fold_left
    (fun h (i, block) ->
      let flags =
        (if i = 0 then flag_chunk_start else 0)
        lor
        (if i = n - 1 then flag_chunk_end lor (if root then flag_root else 0)
         else 0)
      in
      compress h (words_of_block block) t (String.length block) flags)
    key_words
    (List.mapi (fun i block -> (i, block)) blocks)

(* Parent-node compression: the two child chaining values are the 16
   message words, the input chaining value is the key words, the counter is
   0 and the block length 64; ROOT only at the tree root. *)
let parent_cv (l0, l1, l2, l3, l4, l5, l6, l7)
    (r0, r1, r2, r3, r4, r5, r6, r7) ~root =
  compress key_words
    (l0, l1, l2, l3, l4, l5, l6, l7, r0, r1, r2, r3, r4, r5, r6, r7)
    0 64
    (flag_parent lor (if root then flag_root else 0))

(* Largest power of two <= [x], for [x >= 1]. Terminates: the accumulator
   strictly doubles until doubling would exceed [x]. *)
let po2_floor x =
  let rec go p = if p lsl 1 <= x then go (p lsl 1) else p in
  go 1

(* The all-zero chaining value, only ever produced on the unreachable empty
   branch of [tree_cv] (its callers always pass a non-empty list). *)
let zero_cv = (0, 0, 0, 0, 0, 0, 0, 0)

(* Root/subtree chaining value over an in-order list of chunk chaining
   values. The left subtree takes the largest power-of-two number of chunks
   strictly smaller than the total, so a subtree completes exactly at a
   power-of-two chunk count (the left-leaning tree rule); children are never
   the root, and a single-chunk list is already its own (chunk-level rooted)
   chaining value. *)
let rec tree_cv cvs ~root =
  match cvs with
  | [] -> zero_cv (* unreachable: [group] never returns an empty list *)
  | [ cv ] -> cv
  | _ :: _ :: _ ->
      let n = List.length cvs in
      let k = po2_floor (n - 1) in
      let left = List.filteri (fun i _ -> i < k) cvs in
      let right = List.filteri (fun i _ -> i >= k) cvs in
      parent_cv (tree_cv left ~root:false) (tree_cv right ~root:false) ~root

(* Serialize the 8-word root chaining value little-endian via [Buffer]
   appends (total; [Int32.of_int] keeps the low 32 bits, exactly the masked
   word). *)
let cv_to_string (c0, c1, c2, c3, c4, c5, c6, c7) =
  let buf = Buffer.create 32 in
  List.iter
    (fun w -> Buffer.add_int32_le buf (Int32.of_int w))
    [ c0; c1; c2; c3; c4; c5; c6; c7 ];
  Buffer.contents buf

let hash s =
  let chunks = group 1024 s in
  let single = List.length chunks = 1 in
  let cvs = List.mapi (fun t chunk -> chunk_cv t ~root:single chunk) chunks in
  cv_to_string (tree_cv cvs ~root:true)
