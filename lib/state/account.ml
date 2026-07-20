type t = {
  nonce : Nonce.t;
  balance : U256.t;
  storage : Storage.t;
  code : Bytecode.t;
}

let make ~nonce ~balance =
  { nonce; balance; storage = Storage.empty; code = Bytecode.empty }

let empty =
  {
    nonce = Nonce.zero;
    balance = U256.zero;
    storage = Storage.empty;
    code = Bytecode.empty;
  }

let nonce t = t.nonce
let balance t = t.balance
let storage t = t.storage
let with_storage t storage = { t with storage }
let slot t key = Storage.get t.storage key
let set_slot t key value = { t with storage = Storage.set t.storage key value }
let code t = Bytecode.to_string t.code
let code_length t = Bytecode.length t.code
let code_hash t = Bytecode.hash t.code
let with_code t bytes = { t with code = Bytecode.of_string bytes }

(* The literal EIP-161 test, now with its third conjunct present: no code. It was
   the two-field test while no account could carry code; code exists as of this
   chunk, so the specification's full predicate is written. Storage is still not a
   conjunct, on purpose: EIP-161 clears a touched account on nonce, balance and
   code alone. The world state prunes on [is_absent] instead. *)
let is_empty t =
  Nonce.equal t.nonce Nonce.zero && U256.is_zero t.balance
  && Bytecode.is_empty t.code

let is_absent t = is_empty t && Storage.is_empty t.storage

let credit t amount =
  Option.map (fun balance -> { t with balance }) (U256.checked_add t.balance amount)

let debit t amount =
  Option.map (fun balance -> { t with balance }) (U256.checked_sub t.balance amount)

let increment_nonce t = { t with nonce = Nonce.succ t.nonce }

let equal a b =
  Nonce.equal a.nonce b.nonce
  && U256.equal a.balance b.balance
  && Storage.equal a.storage b.storage
  && Bytecode.equal a.code b.code

let compare a b =
  let c = Nonce.compare a.nonce b.nonce in
  if c <> 0 then c
  else
    let c = U256.compare a.balance b.balance in
    if c <> 0 then c
    else
      let c = Storage.compare a.storage b.storage in
      if c <> 0 then c else Bytecode.compare a.code b.code
