open Tn_types
module U256 = Tn_state.U256
module Address_set = Set.Make (Units.Address)

(* A slot is keyed by the pair, never by the slot alone: two contracts holding
   the same slot number are two different trie reads and are priced as two. The
   comparison is lexicographic on address then slot, which is a total order
   because both components have one. *)
module Slot_key = struct
  type t = Units.Address.t * U256.t

  let compare (addr_a, slot_a) (addr_b, slot_b) =
    let by_address = Units.Address.compare addr_a addr_b in
    if by_address <> 0 then by_address else U256.compare slot_a slot_b
end

module Slot_set = Set.Make (Slot_key)

type t = { accounts : Address_set.t; slots : Slot_set.t }

(* [Cold] and [Warm] are constructors of a type the interface keeps abstract, so
   outside this module the only source of a value is a [touch_*] that really
   consulted the set. That is the whole enforcement: a caller cannot fabricate
   the argument the cold surcharge is priced from. *)
type warmth = Cold | Warm

let empty = { accounts = Address_set.empty; slots = Slot_set.empty }

let of_transaction ~addresses ~slots =
  {
    accounts = List.fold_left (fun set a -> Address_set.add a set) Address_set.empty addresses;
    slots = List.fold_left (fun set key -> Slot_set.add key set) Slot_set.empty slots;
  }

(* The membership test and the insertion happen together, and the witness is
   built from the test, so the two can never disagree. *)
let touch_account t addr =
  let warmth = if Address_set.mem addr t.accounts then Warm else Cold in
  (warmth, { t with accounts = Address_set.add addr t.accounts })

let touch_slot t addr slot =
  let key = (addr, slot) in
  let warmth = if Slot_set.mem key t.slots then Warm else Cold in
  (warmth, { t with slots = Slot_set.add key t.slots })

let is_cold warmth =
  match warmth with
  | Cold -> true
  | Warm -> false

let mem_account t addr = Address_set.mem addr t.accounts
let mem_slot t addr slot = Slot_set.mem (addr, slot) t.slots

let equal a b =
  Address_set.equal a.accounts b.accounts && Slot_set.equal a.slots b.slots
