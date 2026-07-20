open Tn_types
module Addr_map = Map.Make (Units.Address)

type t = Account.t Addr_map.t

let empty = Addr_map.empty
let account t addr = Option.value (Addr_map.find_opt addr t) ~default:Account.empty

(* Storing an entry that carries no information is the same as storing none, so
   keep the representation canonical by removing it. The predicate is
   [is_absent], not the EIP-161 [is_empty]: [is_empty] ignores storage, so
   pruning on it would silently drop an [SSTORE] into a zero-nonce zero-balance
   account and [equal] would stop being exact — two states differing in that
   slot would compare equal. [is_absent] covers every field [Account.equal]
   compares, which is what canonicity needs. *)
let set_account t addr acct =
  if Account.is_absent acct then Addr_map.remove addr t else Addr_map.add addr acct t

let remove_account t addr = Addr_map.remove addr t

(* [Account.make] installs empty storage, so this is lossy for any genesis
   account that specifies slots: Rust's [GenesisAccount] carries a storage map
   this argument type cannot even name. Nothing passes storage at genesis yet,
   so nothing is dropped today; expressing one means widening the argument to an
   [Account.t], not patching slots in afterwards. See the .mli. *)
let of_alloc allocs =
  List.fold_left
    (fun t (addr, balance) ->
      set_account t addr (Account.make ~nonce:Nonce.zero ~balance))
    empty allocs

let balance t addr = Account.balance (account t addr)
let nonce t addr = Account.nonce (account t addr)
let storage t addr key = Account.slot (account t addr) key

(* Reading through [account] makes this total at both levels: an address with no
   entry reads as [Account.empty], whose every slot is zero. Writing back
   through [set_account] means clearing the last slot of an otherwise-empty
   account removes the entry again, so the round trip is the identity. *)
let set_storage t addr key value =
  set_account t addr (Account.set_slot (account t addr) key value)

let accounts t = Addr_map.bindings t
let equal a b = Addr_map.equal Account.equal a b
