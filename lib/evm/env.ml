open Tn_types
module U256 = Tn_state.U256

type word = U256.t

module Block = struct
  type t = {
    coinbase : Units.Address.t;
    timestamp : word;
    number : word;
    prevrandao : word;
    gas_limit : word;
    basefee : word;
    chain_id : word;
    hashes : Block_hashes.t;
  }

  let make ~coinbase ~timestamp ~number ~prevrandao ~gas_limit ~basefee ~chain_id
      ~hashes =
    { coinbase; timestamp; number; prevrandao; gas_limit; basefee; chain_id; hashes }

  let coinbase t = t.coinbase
  let timestamp t = t.timestamp
  let number t = t.number
  let prevrandao t = t.prevrandao
  let gas_limit t = t.gas_limit
  let basefee t = t.basefee
  let chain_id t = t.chain_id
  let hashes t = t.hashes

  let equal a b =
    Units.Address.equal a.coinbase b.coinbase
    && U256.equal a.timestamp b.timestamp
    && U256.equal a.number b.number
    && U256.equal a.prevrandao b.prevrandao
    && U256.equal a.gas_limit b.gas_limit
    && U256.equal a.basefee b.basefee
    && U256.equal a.chain_id b.chain_id
    && Block_hashes.equal a.hashes b.hashes
end

module Tx = struct
  type t = {
    origin : Units.Address.t;
    gas_price : word;
    access_list : (Units.Address.t * word list) list;
  }

  let make ~origin ~gas_price ~access_list = { origin; gas_price; access_list }
  let origin t = t.origin
  let gas_price t = t.gas_price
  let access_list t = t.access_list

  (* The access list is compared as the list it is, order included: it is
     transaction data, and two transactions that list the same entries in
     different orders are different transactions on the wire. [Access.t], which
     is where order stops mattering, does its own comparison as a set. *)
  let equal_entry (addr_a, slots_a) (addr_b, slots_b) =
    Units.Address.equal addr_a addr_b && List.equal U256.equal slots_a slots_b

  let equal a b =
    Units.Address.equal a.origin b.origin
    && U256.equal a.gas_price b.gas_price
    && List.equal equal_entry a.access_list b.access_list

  (* The one flatten in the port. The wire groups slots under their address;
     [Access] keys a slot by the (address, slot) pair, so the grouping has to be
     undone exactly once and this is where. Naming an account is itself a
     warming — EIP-2930 charges ACCESS_LIST_ADDRESS_COST for an entry that lists
     no slots at all — so every entry's address goes into the first component
     whether or not it carried slots. Total on every input: the empty list gives
     ([], []), and nothing here can fail. Repeats and orderings are passed
     through rather than normalised because [Access.of_transaction] folds both
     components into sets, where a repeat is a no-op and order is not
     observable. *)
  let declared_warm t =
    ( List.map fst t.access_list,
      List.concat_map
        (fun (addr, slots) -> List.map (fun slot -> (addr, slot)) slots)
        t.access_list )
end

module Call = struct
  type t = {
    target : Units.Address.t;
    caller : Units.Address.t;
    value : word;
    data : Data.t;
    mutability : Mutability.t;
  }

  let make ~target ~caller ~value ~data ~mutability =
    { target; caller; value; data; mutability }

  let target t = t.target
  let caller t = t.caller
  let value t = t.value
  let data t = t.data
  let mutability t = t.mutability

  let equal a b =
    Units.Address.equal a.target b.target
    && Units.Address.equal a.caller b.caller
    && U256.equal a.value b.value
    && Data.equal a.data b.data
    && Mutability.equal a.mutability b.mutability
end

type t = { block : Block.t; tx : Tx.t; call : Call.t }

let make ~block ~tx ~call = { block; tx; call }
let block t = t.block
let tx t = t.tx
let call t = t.call

(* The only producer of a changed environment, and it changes exactly one
   field. A sub-frame therefore cannot rebind [ORIGIN], [GASPRICE] or anything
   in the block: there is no function that would let it. *)
let with_call t call = { t with call }

let equal a b =
  Block.equal a.block b.block && Tx.equal a.tx b.tx && Call.equal a.call b.call
