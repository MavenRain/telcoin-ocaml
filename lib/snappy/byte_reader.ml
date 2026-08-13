(* Bytes.sub_string is the one primitive used here.  It is reached only
   through [inside], which establishes 0 <= pos and pos + len <= length, so
   the Invalid_argument it would otherwise report is unreachable and no
   caller of this module ever holds an index.  The raw single-byte accessors
   of the Bytes and String modules are absent on purpose: the house rule bans
   partial indexing, and a one-byte window folded to an int is the total
   replacement. *)

type t = { data : Bytes.t }

let of_string s = { data = Bytes.of_string s }
let length t = Bytes.length t.data

(* A window is inside the buffer when it starts at or after 0 and ends at or
   before the last byte.  Written as [pos <= length - len] rather than
   [pos + len <= length] so no sum is computed at all. *)
let inside t ~pos ~len = pos >= 0 && len >= 0 && pos <= length t - len

let sub t ~pos ~len =
  if inside t ~pos ~len then
    Some (Bytes.sub_string t.data pos len) (* @total-accessor: [inside] guards *)
  else None

(* Little-endian assembly of a short byte window, least significant byte
   first, over the fold the stdlib gives on strings. *)
let le_of_string s =
  fst
    (String.fold_left
       (fun (acc, shift) c -> (acc lor (Char.code c lsl shift), shift + 8))
       (0, 0) s)

let le t ~pos ~len = Option.map le_of_string (sub t ~pos ~len)
let byte t ~pos = le t ~pos ~len:1
