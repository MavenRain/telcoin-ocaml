module Offsets = Set.Make (Int)

type t = { code : string; jumpdests : Offsets.t }

let length t = String.length t.code

(* Past either end the code reads as zero — the [STOP] instruction. This is the
   total form of the padding revm appends, and it also makes a truncated [PUSH]
   immediate read zero-extended. *)
let byte_at t i = if i < 0 || i >= String.length t.code then 0 else Char.code (String.get t.code i)

(* How far the analysis advances from a byte: past the opcode and past any
   immediate data it carries. An unassigned byte, like any instruction without an
   immediate, advances by one — it is only ever data to the analysis, never an
   error. *)
let stride byte =
  1
  + Option.fold ~none:0 ~some:Opcode.immediate_bytes
      (Opcode.decode byte)

let is_jumpdest byte =
  Option.fold ~none:false
    ~some:(fun op -> Opcode.equal op Opcode.Jumpdest)
    (Opcode.decode byte)

(* Walk the code marking every [JUMPDEST] that is reached as an instruction. The
   walk steps over each [PUSH]'s immediate data, so a [0x5b] inside it is never
   reached and never marked. The offset strictly increases (the stride is at
   least one), so the walk terminates; a trailing [PUSH] whose data is truncated
   simply steps past the end and ends it. *)
let rec analyse code offset found =
  if offset >= String.length code then found
  else
    let byte = Char.code (String.get code offset) in
    analyse code (offset + stride byte)
      (if is_jumpdest byte then Offsets.add offset found else found)

let of_string code = { code; jumpdests = analyse code 0 Offsets.empty }
let is_valid_jumpdest t offset = Offsets.mem offset t.jumpdests
let jumpdests t = Offsets.elements t.jumpdests
