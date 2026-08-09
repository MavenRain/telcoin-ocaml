(* The 2048-bit logs bloom (m3:2048), a verbatim port of alloy-primitives'
   [Bloom] (1.6.0, [src/bits/bloom.rs]). reth does not redefine it, so the alloy
   computation is reth's.

   The value is an immutable set of set-bit indices in [0, 2047]. Accrual is a
   pure union and serialization a pure [String.init] gather, so no buffer is ever
   mutated in place ("gather not scatter"). *)

module Bit_set = Set.Make (Int)

type t = Bit_set.t

let empty = Bit_set.empty

(* One input sets exactly three bits, read as 2-byte big-endian pairs at hash
   offsets [i] in [{0, 2, 4}], masked to [0, 2047] (alloy [bloom.rs:152-165]). *)
let accrue t input =
  let h = Tn_keccak.to_bytes (Tn_keccak.digest input) in
  let byte i = Char.code (String.get h i) in
  let bit_at i = ((byte i lsl 8) lor byte (i + 1)) land 0x7FF in
  List.fold_left (fun acc i -> Bit_set.add (bit_at i) acc) t [ 0; 2; 4 ]

let of_logs logs =
  List.fold_left
    (fun acc log ->
      let acc = accrue acc (Tn_types.Units.Address.to_bytes (Log.address log)) in
      List.fold_left
        (fun acc topic -> accrue acc (Tn_state.U256.to_be_bytes topic))
        acc
        (Log.Topics.to_list (Log.topics log)))
    empty logs

(* alloy sets [self.0.(255 - bit/8) |= 1 lsl (bit mod 8)]. The gather inverts
   that: output byte [j] collects every set bit whose [255 - bit/8 = j], i.e.
   [bit/8 = 255 - j], contributing [1 lsl (bit mod 8)]. *)
let to_bytes t =
  String.init 256 (fun j ->
      let target = 255 - j in
      let mask =
        Bit_set.fold
          (fun bit acc -> if bit / 8 = target then acc lor (1 lsl (bit mod 8)) else acc)
          t 0
      in
      Char.chr mask)

(* The scatter [to_bytes] is the gather of. Byte [j] of the serialization holds
   the eight bits whose [bit / 8] is [255 - j], so byte [j]'s bit [k] is bit
   index [(255 - j) * 8 + k]. Folded over the string with the index carried in
   the accumulator, so no character is reached by an offset accessor. *)
let of_bytes s =
  match Int.equal (String.length s) 256 with
  | false -> None
  | true ->
      Some
        (snd
           (String.fold_left
              (fun (j, bits) c ->
                let byte = Char.code c in
                let target = 255 - j in
                ( Stdlib.succ j,
                  List.fold_left
                    (fun acc k ->
                      if byte land (1 lsl k) <> 0 then
                        Bit_set.add ((target * 8) + k) acc
                      else acc)
                    bits
                    (List.init 8 Fun.id) ))
              (0, Bit_set.empty) s))

let equal = Bit_set.equal
