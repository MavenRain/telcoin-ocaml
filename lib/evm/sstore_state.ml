module U256 = Tn_state.U256

type word = U256.t
type t = { original : word; present : word; updated : word }

let make ~original ~present ~updated = { original; present; updated }
let original t = t.original
let present t = t.present
let updated t = t.updated

type change = No_op | Fresh_set | Fresh_reset | Dirty

(* The four cases are revm's partition at
   [revm-context-interface/src/cfg/gas_params.rs:441-449], read as a decision
   tree rather than as its two nested conditions. revm charges the set-or-reset
   term only when [new_values_changes_present() && is_original_eq_present()];
   negating either conjunct is what this port names [No_op] and [Dirty], and the
   inner test on [is_original_zero()] is what splits the remainder into
   [Fresh_set] and [Fresh_reset].

   The order of the tests is the partition: [No_op] is decided first because a
   write of the present value is a no-op whether or not the slot is dirty, and
   [Dirty] before the two fresh cases because those two are defined only when
   original and present agree. *)
let classify t =
  if U256.equal t.updated t.present then No_op
  else if not (U256.equal t.original t.present) then Dirty
  else if U256.is_zero t.original then Fresh_set
  else Fresh_reset

let equal a b =
  U256.equal a.original b.original
  && U256.equal a.present b.present
  && U256.equal a.updated b.updated
