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
let code_class t = Delegation.classify (code t)
let delegation t = Option.map Delegation.target (Delegation.of_code (code t))

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

let increment_nonce_checked t =
  Option.map (fun nonce -> { t with nonce }) (Nonce.succ_checked t.nonce)

(* revm's [delegate] ([revm-context-interface] [journaled_state/account.rs:448-459])
   as one indivisible move: the code the assignment installs, then the nonce
   bump that both of its branches perform. Splitting the two would be three
   chances to forget the bump, and the bump is what keeps a delegated authority
   out of EIP-161's clearing pass.

   The saturated nonce is a [~default], not a raise: revm's [delegate] calls
   [bump_nonce] and DISCARDS its boolean ([account.rs:392-400]), so an account
   at the maximum keeps its nonce and still takes the code. *)
let delegate t target =
  let coded = with_code t (Delegation.code_of_assignment (Delegation.assignment target)) in
  Option.value (increment_nonce_checked coded) ~default:coded

(* revm's create-collision predicate ([revm-context] [journal/inner.rs:409]):
   [code_hash != KECCAK_EMPTY || nonce != 0]. Balance is deliberately absent, and
   its absence is the rule rather than an omission: an address that has only ever
   received ether is still free to be created at, which is what makes it possible
   to fund a counterfactual CREATE2 address before its contract exists. Storage
   is absent for the same reason — nothing but code and a nonce can occupy an
   address. *)
let is_occupied t =
  (not (Bytecode.is_empty t.code)) || not (Nonce.equal t.nonce Nonce.zero)

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
