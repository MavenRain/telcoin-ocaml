(* The unsigned transaction, a port of alloy-consensus 1.8.3's [TxLegacy]
   ([src/transaction/legacy.rs:19-71]), [TxEip2930]
   ([src/transaction/eip2930.rs:16-65]) and [TxEip1559]
   ([src/transaction/eip1559.rs:16-79]).

   Each record below is declared in RLP WIRE order, which is not alloy's struct
   order: the wire puts the priority-fee cap before the max-fee cap and [input]
   before [access_list], while the Rust structs do the opposite. Both fee fields
   share a type, so mirroring the struct compiles and silently inverts the fee
   semantics; declaring in wire order makes the encoder a straight read-off. *)

open Tn_types

module W = Tn_state.U256

type word = W.t

type variant =
  | Legacy of { chain_id : word option; gas_price : word }
  | Eip2930 of { chain_id : word; gas_price : word }
  | Eip1559 of { chain_id : word; max_priority_fee_per_gas : word; max_fee_per_gas : word }

type t =
  | Tx_legacy of {
      nonce : Tn_state.Nonce.t;
      gas_price : word;
      gas_limit : int;
      kind : Transaction.kind;
      value : word;
      data : string;
      chain_id : word option;
          (* last: never an envelope field, only item 7 of the signing payload
             or folded into [v] *)
    }
  | Tx_eip2930 of {
      chain_id : word;
      nonce : Tn_state.Nonce.t;
      gas_price : word;
      gas_limit : int;
      kind : Transaction.kind;
      value : word;
      data : string;
      access_list : (Units.Address.t * word list) list;
    }
  | Tx_eip1559 of {
      chain_id : word;
      nonce : Tn_state.Nonce.t;
      max_priority_fee_per_gas : word;
      max_fee_per_gas : word;
      gas_limit : int;
      kind : Transaction.kind;
      value : word;
      data : string;
      access_list : (Units.Address.t * word list) list;
    }

let legacy ~nonce ~gas_price ~gas_limit ~kind ~value ~data ~chain_id =
  Tx_legacy { nonce; gas_price; gas_limit; kind; value; data; chain_id }

let eip2930 ~chain_id ~nonce ~gas_price ~gas_limit ~kind ~value ~data ~access_list =
  Tx_eip2930 { chain_id; nonce; gas_price; gas_limit; kind; value; data; access_list }

let eip1559 ~chain_id ~nonce ~max_priority_fee_per_gas ~max_fee_per_gas ~gas_limit ~kind
    ~value ~data ~access_list =
  Tx_eip1559
    {
      chain_id;
      nonce;
      max_priority_fee_per_gas;
      max_fee_per_gas;
      gas_limit;
      kind;
      value;
      data;
      access_list;
    }

let variant t =
  match t with
  | Tx_legacy { chain_id; gas_price; _ } -> Legacy { chain_id; gas_price }
  | Tx_eip2930 { chain_id; gas_price; _ } -> Eip2930 { chain_id; gas_price }
  | Tx_eip1559 { chain_id; max_priority_fee_per_gas; max_fee_per_gas; _ } ->
      Eip1559 { chain_id; max_priority_fee_per_gas; max_fee_per_gas }

let type_byte t =
  match t with Tx_legacy _ -> 0 | Tx_eip2930 _ -> 1 | Tx_eip1559 _ -> 2

let chain_id t =
  match t with
  | Tx_legacy { chain_id; _ } -> chain_id
  | Tx_eip2930 { chain_id; _ } -> Some chain_id
  | Tx_eip1559 { chain_id; _ } -> Some chain_id

let nonce t =
  match t with
  | Tx_legacy { nonce; _ } -> nonce
  | Tx_eip2930 { nonce; _ } -> nonce
  | Tx_eip1559 { nonce; _ } -> nonce

let gas_limit t =
  match t with
  | Tx_legacy { gas_limit; _ } -> gas_limit
  | Tx_eip2930 { gas_limit; _ } -> gas_limit
  | Tx_eip1559 { gas_limit; _ } -> gas_limit

let kind t =
  match t with
  | Tx_legacy { kind; _ } -> kind
  | Tx_eip2930 { kind; _ } -> kind
  | Tx_eip1559 { kind; _ } -> kind

let value t =
  match t with
  | Tx_legacy { value; _ } -> value
  | Tx_eip2930 { value; _ } -> value
  | Tx_eip1559 { value; _ } -> value

let data t =
  match t with
  | Tx_legacy { data; _ } -> data
  | Tx_eip2930 { data; _ } -> data
  | Tx_eip1559 { data; _ } -> data

(* A legacy transaction has no access-list field at all, so the empty list here
   is the absence of the field and not a defaulted value. *)
let access_list t =
  match t with
  | Tx_legacy _ -> []
  | Tx_eip2930 { access_list; _ } -> access_list
  | Tx_eip1559 { access_list; _ } -> access_list

(* The one place the two fee models differ: the executor's [Dynamic] carries an
   OPTIONAL priority fee, while the wire always has one, so the [Some] is
   total. *)
let fee t =
  match variant t with
  | Legacy { gas_price; _ } -> Transaction.Legacy { gas_price }
  | Eip2930 { gas_price; _ } -> Transaction.Access_list { gas_price }
  | Eip1559 { max_priority_fee_per_gas; max_fee_per_gas; _ } ->
      Transaction.Dynamic
        { max_fee = max_fee_per_gas; max_priority = Some max_priority_fee_per_gas }

let to_transaction t ~sender =
  Transaction.make ~sender ~nonce:(nonce t) ~gas_limit:(gas_limit t) ~kind:(kind t)
    ~value:(value t) ~data:(data t) ~access_list:(access_list t) ~chain_id:(chain_id t)
    ~fee:(fee t)
