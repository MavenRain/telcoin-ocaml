module W = Tn_state.U256
module Bytes_map = Map.Make (Int)

type word = W.t

(* The paid-for word count and the bytes that have been written. Only nonzero
   bytes are kept — an absent key is a zero byte, which is also what an
   unwritten byte reads as — so the representation is canonical and structural
   equality of the two fields is exact content equality. *)
type t = { words : int; bytes : char Bytes_map.t }

let word_size = 32
let empty = { words = 0; bytes = Bytes_map.empty }
let words t = t.words
let size_bytes t = t.words * word_size

(* Four gibibytes. The derivation is in the interface; the short version is that
   a memory this large costs 35_184_774_742_016 gas, about a million times a
   block's whole limit, so nothing payable is refused. *)
let max_extent = 0x1_0000_0000

(* Rounding up to whole words, guarding the one addition that can leave the
   representable range and, more tightly, holding the extent to [max_extent].
   The tighter test subsumes the looser one — [max_extent] is far below [max_int]
   — so [offset + length] below cannot overflow. [length < 0] is tested first so
   that [max_extent - length] is never formed for a length that would wrap it.

   The bound is not the gas schedule's: gas alone leaves extents up to some
   1.55e12 bytes payable, and reaching one drives [slice] and [Data.read] into an
   allocation the host may or may not survive. Refusing here is what keeps
   [Interpreter.run] total on every input rather than on every affordable one. *)
let words_needed ~offset ~length =
  if length = 0 then Some 0
  else if offset < 0 || length < 0 || offset > max_extent - length then None
  else
    (* Round up by dividing first and counting the partial word separately. The
       familiar [(extent + word_size - 1) / word_size] would add 31 to a sum
       already known only to be at most [max_int], and for the last 31 extents it
       wraps negative — a negative word count then reads downstream as "no
       expansion needed", so the frame would reach that memory for free and its
       size would silently disagree with what was written. Dividing first cannot
       overflow at all, so the guard above is the only bound needed. *)
    let extent = offset + length in
    Some ((extent / word_size) + if extent mod word_size = 0 then 0 else 1)

let expand t words = if words <= t.words then t else { t with words }

(* An unwritten byte is zero; a write of zero removes the key rather than storing
   it, which is what keeps the map canonical. *)
let byte t i = Option.fold ~none:'\000' ~some:Fun.id (Bytes_map.find_opt i t.bytes)

let set_byte t i c =
  {
    t with
    bytes =
      (if Char.equal c '\000' then Bytes_map.remove i t.bytes
       else Bytes_map.add i c t.bytes);
  }

let load_word t offset =
  (* Every 32-byte string is a valid word, so this cannot fail; the [None] arm
     is unreachable and returns zero rather than raising. *)
  Option.value ~default:W.zero
    (W.of_be_bytes (String.init word_size (fun i -> byte t (offset + i))))

let store_word t offset w =
  let source = W.to_be_bytes w in
  List.fold_left
    (fun t i -> set_byte t (offset + i) (String.get source i))
    t
    (List.init word_size (fun i -> i))

let store_byte t offset n = set_byte t offset (Char.chr (n land 0xff))

(* Folding [store_byte] over the source is what keeps the zero-byte-removes-the-
   key rule in one place: a bulk write that stored zeroes would break canonicity,
   and copying zeroes over written memory is the common case, not a corner. The
   fold carries the destination index alongside the memory so no intermediate
   list of offsets is built. *)
let store_bytes t ~offset source =
  fst
    (String.fold_left
       (fun (t, i) c -> (store_byte t (offset + i) (Char.code c), i + 1))
       (t, 0) source)
let slice t ~offset ~length = String.init length (fun i -> byte t (offset + i))

let equal a b =
  Int.equal a.words b.words && Bytes_map.equal Char.equal a.bytes b.bytes
