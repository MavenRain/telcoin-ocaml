open Tn_types
module Addresses = Set.Make (Units.Address)

type t = { created : Addresses.t; destroyed : Addresses.t }

let empty = { created = Addresses.empty; destroyed = Addresses.empty }
let record_creation t address = { t with created = Addresses.add address t.created }
let created_here t address = Addresses.mem address t.created

let record_destruction t address =
  { t with destroyed = Addresses.add address t.destroyed }

let destroyed t = Addresses.elements t.destroyed

let equal a b =
  Addresses.equal a.created b.created && Addresses.equal a.destroyed b.destroyed
