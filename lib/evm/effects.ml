module World_state = Tn_state.World_state

(* [base] is written once, by [start], and read by [plan_store] alone. There is
   deliberately no [with_base]: EIP-2200's [original] is transaction-scoped, and
   a setter is all it would take for a future [CALL] to reset it to the sub-frame
   entry state and silently reprice every net-metered write in the callee. *)
type t = {
  world : World_state.t;
  base : World_state.t;
  access : Access.t;
  refund : Refund.t;
}

(* [commit] is the write this lookup will perform if the frame can pay for it.
   A read's is the identity, a [plan_store]'s closes over the address, the slot
   and the value it planned to write.

   Carrying the pending write as a function rather than as an [option] of a
   target record is what keeps [commit_store] total. The alternative shape has a
   [None] case that no read can reach — [commit_store] takes an
   [Sstore_state.t load], and [plan_store] is the only producer of one — so it
   would be an unreachable branch needing an invented answer. Here there is no
   branch: every load knows what committing it means, and for a read that
   meaning is "nothing". *)
type 'a load = {
  value : 'a;
  warmth : Access.warmth;
  effects : t;
  commit : t -> t;
}

let start ~world ~access = { world; base = world; access; refund = Refund.zero }
let world t = t.world
let base t = t.base
let access t = t.access
let refund t = t.refund
let loaded l = l.value
let warmth l = l.warmth
let warmed l = l.effects

(* Every read goes through this: touch, keep the grown set, and pair the witness
   with the value that same touch justifies. Nothing else in the module builds a
   [load] for a read, so a value and a warmth in one record always describe the
   same lookup. *)
let read t ~touched ~access ~value =
  { value; warmth = touched; effects = { t with access }; commit = Fun.id }

let balance t address =
  let touched, access = Access.touch_account t.access address in
  read t ~touched ~access ~value:(World_state.balance t.world address)

(* No witness escapes: the touch's [warmth] is dropped here, on purpose, so that
   there is nothing for a caller to hand to [Gas.account_access_cost]. The set
   still grows, because revm's [Host::balance] loads the account through the
   journal and the instruction merely ignores [is_cold]. *)
let self_balance t address =
  let _touched, access = Access.touch_account t.access address in
  (World_state.balance t.world address, { t with access })

let storage t address ~slot =
  let touched, access = Access.touch_slot t.access address slot in
  read t ~touched ~access ~value:(World_state.storage t.world address slot)

let plan_store t address ~slot ~value =
  let touched, access = Access.touch_slot t.access address slot in
  (* [original] from [base] and [present] from [world]: the first is the
     transaction's view, the second is this run's, and reading both from the same
     state is the EIP-2200 bug this split exists to make unwritable. *)
  let write =
    Sstore_state.make
      ~original:(World_state.storage t.base address slot)
      ~present:(World_state.storage t.world address slot)
      ~updated:value
  in
  {
    value = write;
    warmth = touched;
    effects = { t with access };
    commit =
      (fun effects ->
        {
          effects with
          world = World_state.set_storage effects.world address slot value;
          refund = Refund.add effects.refund (Gas.sstore_refund write);
        });
  }

let commit_store l = l.commit l.effects

let equal a b =
  World_state.equal a.world b.world
  && World_state.equal a.base b.base
  && Access.equal a.access b.access
  && Refund.equal a.refund b.refund
