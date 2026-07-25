(* Nibble paths. The representation is an [int array], each element in [0, 15],
   most-significant nibble first. It is deliberately unexposed (the .mli keeps
   [t] abstract) so the range invariant is the module's alone to maintain: every
   producer masks into range, and every accessor is total. Byte/nibble order and
   the pack rule are the reth pin nybbles 0.4.8 (src/nibbles.rs:421-425 unpack,
   1324-1331 pack). *)

type t = int array

(* A byte splits high nibble first, so index [i] of the result reads the high
   nibble of byte [i / 2] when [i] is even and the low nibble when odd. String
   access is bounded: [i] ranges over [0, 2n), hence [i / 2] over [0, n). *)
let unpack s =
  let n = String.length s in
  Array.init (2 * n) (fun i ->
      let b = Char.code (String.get s (i / 2)) in
      if i land 1 = 0 then b lsr 4 else b land 0xf)

let of_int_list xs = Array.of_list (List.map (fun x -> x land 0xf) xs)

let to_list t = Array.to_list t

let length t = Array.length t

(* The sole accessor. The bounds test precedes the [Array.get], so it never
   raises and callers pattern-match the [option] exhaustively. *)
let nth_opt t i = if i >= 0 && i < Array.length t then Some (Array.get t i) else None

(* Clamp [pos] into [0, n] and [len] into [0, n - pos] before delegating to
   [Array.sub], which is then always in range and cannot raise. *)
let sub t ~pos ~len =
  let n = Array.length t in
  let pos = if pos < 0 then 0 else if pos > n then n else pos in
  let len = if len < 0 then 0 else if pos + len > n then n - pos else len in
  Array.sub t pos len

let drop t i = sub t ~pos:i ~len:(Array.length t - i)

(* [(n + 1) / 2] bytes. For byte [j] the high nibble is at [2j] and the low at
   [2j + 1]; a missing low nibble (odd length) reads as [0] through [nth_opt],
   so the trailing nibble lands in the high four bits with a zero low nibble. *)
let pack t =
  let nib i = match nth_opt t i with Some x -> x | None -> 0 in
  let nbytes = (Array.length t + 1) / 2 in
  String.init nbytes (fun j -> Char.chr (((nib (2 * j)) lsl 4) lor nib (2 * j + 1)))

(* Count matching nibbles from [from], never reading past the shorter path: the
   scan stops at [stop = min (length a) (length b)], and [start] is clamped into
   [0, stop], so [start >= stop] (an exhausted key) yields [0]. Each [Array.get]
   is guarded by [i < stop], which is [<=] both lengths. *)
let common_prefix_len a b ~from =
  let stop = min (Array.length a) (Array.length b) in
  let rec go i =
    if i >= stop then i
    else if Array.get a i = Array.get b i then go (i + 1)
    else i
  in
  let start = if from < 0 then 0 else if from > stop then stop else from in
  go start - start

(* Lexicographic, shorter-before-longer. The scan compares up to the shorter
   length, then breaks the tie on length, so a prefix sorts before its
   extensions. Each [Array.get] is guarded by [i < stop]. *)
let compare a b =
  let la = Array.length a and lb = Array.length b in
  let stop = min la lb in
  let rec go i =
    if i >= stop then Int.compare la lb
    else
      let c = Int.compare (Array.get a i) (Array.get b i) in
      if c <> 0 then c else go (i + 1)
  in
  go 0

let to_hex t =
  let hex_char n =
    let n = n land 0xf in
    if n < 10 then Char.chr (Char.code '0' + n) else Char.chr (Char.code 'a' + (n - 10))
  in
  String.init (Array.length t) (fun i ->
      match nth_opt t i with Some x -> hex_char x | None -> '0')
