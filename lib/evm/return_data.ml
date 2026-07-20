(* The buffer is the bytes themselves; any string is one, so there is no smart
   constructor and no error type. *)
type t = string

let empty = ""
let of_string s = s
let size t = String.length t

(* The strict bounds [RETURNDATACOPY] obeys, the opposite of [Data]'s zero-fill.
   [offset] and [length] are the non-negative counts the caller converted (the
   source offset saturating, the length checked), so the end is their sum, formed
   with a saturating add so an [offset] near [max_int] cannot wrap to a small end
   and slip through. The window is in range exactly when that end does not pass
   the buffer; a zero length therefore succeeds at [offset = size] (its end is
   [size]) and fails beyond it, which is revm's [data_end > buffer.len()] on a
   saturating [data_offset + len] ([instructions/system.rs:203-206]).

   [String.sub] is reached only inside the bound, where [0 <= offset] and
   [offset + length <= size], which is exactly its precondition, so it cannot
   raise. *)
let read t ~offset ~length =
  let total = String.length t in
  let data_end = if offset > max_int - length then max_int else offset + length in
  if data_end <= total then Some (String.sub t offset length) else None
