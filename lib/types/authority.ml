type t = {
  id : Authority_id.t; (* cached derivation of protocol_key *)
  protocol_key : Tn_crypto.Public_key.t;
  execution_address : Units.Address.t;
}

let make ~protocol_key ~execution_address =
  { id = Authority_id.of_public_key protocol_key; protocol_key; execution_address }

let id t = t.id
let protocol_key t = t.protocol_key
let execution_address t = t.execution_address
let voting_power _ = Units.Stake.one
let equal a b = Authority_id.equal a.id b.id
let compare a b = Authority_id.compare a.id b.id
