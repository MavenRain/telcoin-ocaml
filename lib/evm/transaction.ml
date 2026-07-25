open Tn_types
module U256 = Tn_state.U256
module Nonce = Tn_state.Nonce

type word = U256.t

type kind = Call of Units.Address.t | Create

type fee =
  | Legacy of { gas_price : word }
  | Access_list of { gas_price : word }
  | Dynamic of { max_fee : word; max_priority : word option }

type t = {
  sender : Units.Address.t;
  nonce : Nonce.t;
  gas_limit : int;
  kind : kind;
  value : word;
  data : string;
  access_list : (Units.Address.t * word list) list;
  chain_id : word option;
  fee : fee;
}

let make ~sender ~nonce ~gas_limit ~kind ~value ~data ~access_list ~chain_id ~fee =
  { sender; nonce; gas_limit; kind; value; data; access_list; chain_id; fee }

let sender t = t.sender
let nonce t = t.nonce
let gas_limit t = t.gas_limit
let kind t = t.kind
let value t = t.value
let data t = t.data
let access_list t = t.access_list
let chain_id t = t.chain_id
let fee t = t.fee

(* [base_fee + priority], saturating at the 256-bit ceiling exactly as revm's
   [saturating_add] does, so an absurd priority fee cannot wrap to a small tip. *)
let saturating_add a b =
  Option.value (U256.checked_add a b) ~default:U256.max_value

let effective_gas_price t ~base_fee =
  match t.fee with
  | Legacy { gas_price } -> gas_price
  | Access_list { gas_price } -> gas_price
  | Dynamic { max_fee; max_priority = None } -> max_fee
  | Dynamic { max_fee; max_priority = Some priority } ->
      let capped = saturating_add base_fee priority in
      if U256.compare max_fee capped <= 0 then max_fee else capped

let max_fee_per_gas t =
  match t.fee with
  | Legacy { gas_price } -> gas_price
  | Access_list { gas_price } -> gas_price
  | Dynamic { max_fee; max_priority = _ } -> max_fee
