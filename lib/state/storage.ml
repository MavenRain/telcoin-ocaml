module Slot_map = Map.Make (U256)

(* Only the nonzero slots are kept — an absent key is a zero word, which is also
   what an unwritten slot reads as — so the representation is canonical and
   structural equality of the map is exact content equality. *)
type t = U256.t Slot_map.t

let empty = Slot_map.empty
let is_empty t = Slot_map.is_empty t
let get t slot = Option.value (Slot_map.find_opt slot t) ~default:U256.zero

(* Writing zero removes the key rather than storing a zero word. Without this
   the same logical storage would have many representations, [equal] would stop
   being exact, and [is_empty] would have to scan for a nonzero value instead of
   asking the map whether it holds anything at all. *)
let set t slot value =
  if U256.is_zero value then Slot_map.remove slot t else Slot_map.add slot value t

let bindings t = Slot_map.bindings t
let equal a b = Slot_map.equal U256.equal a b
let compare a b = Slot_map.compare U256.compare a b
