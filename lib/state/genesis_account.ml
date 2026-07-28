(* An alloc entry, canonical by construction. The canonicity all lives here so
   that [equal] can be plain field equality: [Storage.set] already keeps the
   slot map canonical (last write wins, zero clears), and empty code is
   collapsed to [None] because every reader of code - [Account.code_length],
   EIP-161's code conjunct, [World_state.of_genesis_alloc]'s refusal - treats
   zero bytes as no code, so letting [Some ""] and [None] coexist would make
   [equal] distinguish two entries that mean the same account. *)

type t = {
  nonce : Nonce.t;
  balance : U256.t;
  code : string option;
  storage : Storage.t;
}

let make ~nonce ~balance ~code ~storage =
  {
    nonce;
    balance;
    code = Option.bind code (fun c -> if String.length c = 0 then None else Some c);
    storage =
      List.fold_left (fun acc (slot, value) -> Storage.set acc slot value) Storage.empty storage;
  }

let balance_only balance = make ~nonce:Nonce.zero ~balance ~code:None ~storage:[]
let nonce t = t.nonce
let balance t = t.balance
let code t = t.code
let storage t = t.storage
let has_code t = Option.is_some t.code

let equal a b =
  Nonce.equal a.nonce b.nonce
  && U256.equal a.balance b.balance
  && Option.equal String.equal a.code b.code
  && Storage.equal a.storage b.storage
