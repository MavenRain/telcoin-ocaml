open Tn_types
module Addr_map = Map.Make (Units.Address)

type t = Account.t Addr_map.t

let empty = Addr_map.empty
let account t addr = Option.value (Addr_map.find_opt addr t) ~default:Account.empty

(* Storing an empty account is the same as storing none (EIP-161), so keep the
   representation canonical: an empty account removes the entry. This makes
   [equal] exact and gives every logically-equal state one representation. *)
let set_account t addr acct =
  if Account.is_empty acct then Addr_map.remove addr t else Addr_map.add addr acct t

let of_alloc allocs =
  List.fold_left
    (fun t (addr, balance) ->
      set_account t addr (Account.make ~nonce:Nonce.zero ~balance))
    empty allocs

let balance t addr = Account.balance (account t addr)
let nonce t addr = Account.nonce (account t addr)
let accounts t = Addr_map.bindings t
let equal a b = Addr_map.equal Account.equal a b
