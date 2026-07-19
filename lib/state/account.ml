type t = { nonce : Nonce.t; balance : U256.t }

let make ~nonce ~balance = { nonce; balance }
let empty = { nonce = Nonce.zero; balance = U256.zero }
let nonce t = t.nonce
let balance t = t.balance
let is_empty t = Nonce.equal t.nonce Nonce.zero && U256.is_zero t.balance

let credit t amount =
  Option.map (fun balance -> { t with balance }) (U256.checked_add t.balance amount)

let debit t amount =
  Option.map (fun balance -> { t with balance }) (U256.checked_sub t.balance amount)

let increment_nonce t = { t with nonce = Nonce.succ t.nonce }
let equal a b = Nonce.equal a.nonce b.nonce && U256.equal a.balance b.balance

let compare a b =
  let c = Nonce.compare a.nonce b.nonce in
  if c <> 0 then c else U256.compare a.balance b.balance
