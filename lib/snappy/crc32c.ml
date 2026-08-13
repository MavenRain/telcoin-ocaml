(* CRC-32C, one bit at a time.  There is no 256-item lookup table on
   purpose: a table needs a raw array index, which is partial, and the house
   rule bans partial indexing in this port.  Eight shift-and-xor steps per
   byte are the total equivalent of one table step, and the known-answer rows
   in test_snappy pin the result against snap 1.1.1 itself. *)

type error = Out_of_bounds of { pos : int; len : int; length : int }

let error_to_string = function
  | Out_of_bounds { pos; len; length } ->
      Printf.sprintf
        "crc32c: window pos=%d len=%d is not inside a string of %d bytes" pos
        len length

(* snap/build.rs:6 CASTAGNOLI_POLY, reflected. *)
let poly = 0x82f6_3b78

(* The register is 32 bits wide; an OCaml int holds 63, so every step masks
   back down explicitly through [lsr] and this constant. *)
let all_ones = 0xffff_ffff

(* snap/src/crc32.rs:37. *)
let mask_addend = 0xa282_ead8

(* One byte into the register (snap/src/crc32.rs:85-111), unrolled as a tail
   recursion over the 8 bits rather than a loop keyword. *)
let step reg byte =
  let rec bit n reg =
    if n = 0 then reg
    else
      bit (n - 1)
        (if reg land 1 = 1 then reg lsr 1 lxor poly else reg lsr 1)
  in
  bit 8 (reg lxor (byte land 0xff))

let digest s =
  String.fold_left (fun reg c -> step reg (Char.code c)) all_ones s lxor all_ones

let update prev s ~pos ~len =
  let length = String.length s in
  if pos < 0 || len < 0 || pos > length - len then
    Error (Out_of_bounds { pos; len; length })
  else
    let stop = pos + len in
    let _, reg =
      String.fold_left
        (fun (i, reg) c ->
          (i + 1, if i >= pos && i < stop then step reg (Char.code c) else reg))
        (0, prev lxor all_ones)
        s
    in
    Ok (reg lxor all_ones)

let mask crc =
  (((crc lsr 15) lor (crc lsl 17 land all_ones)) + mask_addend) land all_ones
