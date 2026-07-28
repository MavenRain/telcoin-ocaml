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
   compares, which is what canonicity needs.

   The named divergence this buys: revm's EIP-161 touch-clearing DELETES a
   touched zero-nonce zero-balance code-less account even when it holds
   storage, where this prune keeps it. Such an account is unconstructible
   here today: execution cannot leave storage on a code-less account, and the
   genesis loader, which CAN now seed storage ([of_genesis_alloc]), refuses
   exactly the storage-without-code shape ([Storage_without_code]) so that
   growing storage support did not make the divergent class reachable. The
   two rules therefore still agree on every reachable state; if that refusal
   is ever relaxed, this is the invariant to revisit. *)
let set_account t addr acct =
  if Account.is_absent acct then Addr_map.remove addr t else Addr_map.add addr acct t

let remove_account t addr = Addr_map.remove addr t

type alloc_error =
  | Storage_without_code of Units.Address.t
  | Malformed_delegation of Units.Address.t * Delegation.decode_error

let hex_of_address addr =
  String.concat ""
    (List.map
       (fun c -> Printf.sprintf "%02x" (Char.code c))
       (List.of_seq (String.to_seq (Units.Address.to_bytes addr))))

let error_to_string e =
  match e with
  | Storage_without_code addr ->
      Printf.sprintf "genesis alloc entry 0x%s pre-populates storage but installs no code"
        (hex_of_address addr)
  | Malformed_delegation (addr, d) ->
      Printf.sprintf "genesis alloc entry 0x%s installs 0xef01-prefixed code that is not a delegation designator: %s"
        (hex_of_address addr)
        (Delegation.decode_error_to_string d)

(* The [Undecodable] arm of [Delegation.classify], lifted to an entry. revm
   reaches those bytes only as a DATABASE DECODE FAILURE
   ([revm-bytecode] [bytecode.rs:101-110]) and never as executable code, so
   refusing them at the genesis door is what keeps [Delegation.Undecodable]
   unreachable from any world a transaction runs against. A WELL-FORMED
   designator is admitted and is live: classification is on the first two bytes,
   with no authorization involved. *)
let malformed_delegation entry =
  Option.bind (Genesis_account.code entry) (fun code ->
      match Delegation.classify code with
      | Undecodable e -> Some e
      | Codeless -> None
      | Contract -> None
      | Delegated _ -> None)

(* One total function of the alloc, but for the single refusal. Each entry
   becomes an [Account.t] by seeding balance and nonce, then storage, then
   code; [set_account] keeps the map canonical (an absent account stores
   nothing, a repeated address takes its last entry because [Addr_map.add]
   replaces). The refusal fires BEFORE the account is built: an entry with
   storage and no code is the one alloc shape that would make the EIP-161
   divergence documented at [set_account] reachable, so it returns [Error]
   rather than a state that revm would disagree with. *)
let of_genesis_alloc allocs =
  let seed t addr entry =
    let base =
      Account.with_storage
        (Account.make
           ~nonce:(Genesis_account.nonce entry)
           ~balance:(Genesis_account.balance entry))
        (Genesis_account.storage entry)
    in
    let account =
      Option.fold ~none:base ~some:(Account.with_code base) (Genesis_account.code entry)
    in
    set_account t addr account
  in
  List.fold_left
    (fun acc (addr, entry) ->
      Result.bind acc (fun t ->
          let refused =
            (not (Genesis_account.has_code entry))
            && not (Storage.is_empty (Genesis_account.storage entry))
          in
          if refused then Error (Storage_without_code addr)
          else
            (* Ordered AFTER the storage refusal, so that error's identity is
               unchanged for its own input. The [Result.map] keeps [seed] out of
               an eager [~none:]. *)
            Result.map
              (fun () -> seed t addr entry)
              (Option.fold ~none:(Ok ())
                 ~some:(fun d -> Error (Malformed_delegation (addr, d)))
                 (malformed_delegation entry))))
    (Ok empty) allocs

(* The balance-only special case, delegating so genesis stays one function. A
   [balance_only] entry carries no storage, so [of_genesis_alloc] cannot refuse
   it; the [~default] discharges the unreachable [Error] without a partial
   match. *)
let of_alloc allocs =
  Result.value ~default:empty
    (of_genesis_alloc
       (List.map (fun (addr, balance) -> (addr, Genesis_account.balance_only balance)) allocs))

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
