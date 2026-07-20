open Tn_types
module U256 = Tn_state.U256

type word = U256.t

(* The key is the pair, never the slot alone. The comparison is lexicographic on
   address then slot, which is a total order because both components have one.
   This duplicates {!Access}'s [Slot_key] deliberately: that module keeps it
   private, and the two maps must not become coupled through a shared key type
   when one is a priced access set and the other is storage. The comparator is
   written out rather than left to [Stdlib.compare], which would be polymorphic
   structural comparison over two abstract types. *)
module Slot_key = struct
  type t = Units.Address.t * U256.t

  let compare (addr_a, slot_a) (addr_b, slot_b) =
    let by_address = Units.Address.compare addr_a addr_b in
    if by_address <> 0 then by_address else U256.compare slot_a slot_b
end

module Slot_map = Map.Make (Slot_key)

type t = word Slot_map.t

let empty = Slot_map.empty
let get t address ~slot = Option.value (Slot_map.find_opt (address, slot) t) ~default:U256.zero

let set t address ~slot ~value =
  if U256.is_zero value then Slot_map.remove (address, slot) t
  else Slot_map.add (address, slot) value t

let is_empty = Slot_map.is_empty
let length = Slot_map.cardinal

let bindings t =
  List.map (fun ((address, slot), value) -> (address, slot, value)) (Slot_map.bindings t)

let equal = Slot_map.equal U256.equal
