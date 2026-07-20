open Tn_types
module W = Tn_state.U256

type word = W.t

type t = {
  address : Units.Address.t;
  beneficiary : Units.Address.t;
  balance : word;
  beneficiary_exists : bool;
  deletes : bool;
}

let make ~address ~beneficiary ~balance ~beneficiary_exists ~deletes =
  { address; beneficiary; balance; beneficiary_exists; deletes }

let address t = t.address
let beneficiary t = t.beneficiary
let balance t = t.balance
let had_value t = not (W.is_zero t.balance)
let beneficiary_exists t = t.beneficiary_exists
let deletes t = t.deletes

let equal a b =
  Units.Address.equal a.address b.address
  && Units.Address.equal a.beneficiary b.beneficiary
  && W.equal a.balance b.balance
  && Bool.equal a.beneficiary_exists b.beneficiary_exists
  && Bool.equal a.deletes b.deletes
