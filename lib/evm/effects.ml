module World_state = Tn_state.World_state
module Account = Tn_state.Account

(* [base] is written once, by [start], and read by [plan_store] alone. There is
   deliberately no [with_base]: EIP-2200's [original] is transaction-scoped, and
   a setter is all it would take for a future [CALL] to reset it to the sub-frame
   entry state and silently reprice every net-metered write in the callee. *)
type t = {
  world : World_state.t;
  base : World_state.t;
  access : Access.t;
  refund : Refund.t;
  logs : Log_journal.t;
  transient : Transient.t;
  lifecycle : Lifecycle.t;
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

let start ~world ~access =
  {
    world;
    base = world;
    access;
    refund = Refund.zero;
    logs = Log_journal.empty;
    transient = Transient.empty;
    lifecycle = Lifecycle.empty;
  }

let world t = t.world
let base t = t.base
let access t = t.access
let refund t = t.refund
let logs t = t.logs
let transient t = t.transient
let lifecycle t = t.lifecycle
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

(* The whole account, warmed like [balance] but handed back entire, because the
   three readers that want it each want a different projection of it: its code
   length, its EIP-1052 code hash, its code bytes. Deriving those here would
   split what is one account access at revm's [berlin_load_account!] into three
   near-copies; deriving them at the instruction keeps the touch one fact. The
   warmth is the same account touch [balance] records, so a [BALANCE] then an
   [EXTCODESIZE] of one address is warm the second time, and either after the
   other is too. *)
let ext_account t address =
  let touched, access = Access.touch_account t.access address in
  read t ~touched ~access ~value:(World_state.account t.world address)

(* No witness escapes: the touch's [warmth] is dropped here, on purpose, so that
   there is nothing for a caller to hand to [Gas.account_access_cost]. The set
   still grows, because revm's [Host::balance] loads the account through the
   journal and the instruction merely ignores [is_cold]. *)
let self_balance t address =
  let _touched, access = Access.touch_account t.access address in
  (World_state.balance t.world address, { t with access })

(* The executing account, whole, warmed and with no witness escaping — exactly
   {!self_balance}'s bargain, for the caller that needs the nonce as well as the
   balance. A creation reads both: the balance to check the endowment, the nonce
   to derive the address. revm loads the caller the same way
   ([revm-handler] [frame.rs:280], [load_account_mut]) and never prices it. *)
let self_account t address =
  let _touched, access = Access.touch_account t.access address in
  (World_state.account t.world address, { t with access })

let storage t address ~slot =
  let touched, access = Access.touch_slot t.access address slot in
  read t ~touched ~access ~value:(World_state.storage t.world address slot)

(* The permit is taken and discarded. Its whole job is to be an argument the
   caller could not have produced without consulting the frame's mutability, so
   binding it to [_permit] here is not it being ignored, it is it having already
   done its work at the call site. *)
let log t (_permit : Mutability.permit) entry =
  { t with logs = Log_journal.append t.logs entry }

let transient_load t address ~slot = Transient.get t.transient address ~slot

let transient_store t (_permit : Mutability.permit) address ~slot ~value =
  { t with transient = Transient.set t.transient address ~slot ~value }

let plan_store t (_permit : Mutability.permit) address ~slot ~value =
  let touched, access = Access.touch_slot t.access address slot in
  (* [original] from [base] and [present] from [world]: the first is the
     transaction's view, the second is this run's, and reading both from the same
     state is the EIP-2200 bug this split exists to make unwritable. *)
  (* An account created by this transaction has no pre-transaction storage, so
     [original] is zero for every slot of it rather than whatever the address
     held before. revm reaches the same answer from the other side: a
     newly-created account never consults the database for a slot and reads zero
     ([inner.rs:754,773-778]), so the value SSTORE nets against is that zero.
     Without this guard a contract created at an address that already held
     storage would be net-metered against the previous occupant's values, which
     misprices EIP-2200 and can pay out a refund that was never earned. *)
  let write =
    Sstore_state.make
      ~original:
        (if Lifecycle.created_here t.lifecycle address then Tn_state.U256.zero
         else World_state.storage t.base address slot)
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

(* The value a [CALL]/[CALLCODE] moves, debited from the sender and credited to
   the recipient, threading the world so that a self-transfer (a [CALLCODE], where
   sender and recipient are one account) reads the recipient from the already-
   debited world and nets to no change. [None] on either failure — a sender
   underflow (revm [InsufficientFunds]) or a recipient overflow (revm
   [OverflowPayment]) — because both are total refusals the caller maps to the
   call failing (push zero, no transfer), never to a forced state that would
   create or destroy ether. It moves value alone: no account is warmed and the
   access set, the refund, the logs and the transient store are untouched, since
   the warming already happened when the target was loaded. *)
let transfer t ~from ~to_ ~value =
  Option.bind (Account.debit (World_state.account t.world from) value) (fun debited ->
      let world = World_state.set_account t.world from debited in
      Option.map
        (fun credited -> { t with world = World_state.set_account world to_ credited })
        (Account.credit (World_state.account world to_) value))

(* The creator's nonce, advanced before its address is derived so that the
   address is derived from the value the nonce had BEFORE this creation
   ([revm-handler] [frame.rs:289-297] reads [old_nonce] and bumps in between).
   [None] at the maximum, which is revm abandoning the creation rather than
   deriving the same address twice. *)
let bump_nonce t address =
  Option.map
    (fun bumped -> { t with world = World_state.set_account t.world address bumped })
    (Account.increment_nonce_checked (World_state.account t.world address))

(* Bring the account into existence and endow it, revm's [create_account_checkpoint]
   ([revm-context] [journal/inner.rs:391-444]) minus the collision test, which the
   caller has already made with {!Tn_state.Account.is_occupied}:

   - the new account's nonce goes to one (EIP-161, [inner.rs:423]). It is reached
     by incrementing rather than by assignment because the collision test the
     caller has passed guarantees the nonce was zero, so the two agree and this
     way needs no setter;
   - its code is left alone, for the same reason: that test guarantees there is
     none, so revm's explicit clearing at [inner.rs:419] is a no-op here;
   - its storage IS cleared, and that is not a no-op. The collision test looks at
     code and the nonce alone, so an address can hold storage and still be
     created at. revm gives such a creation an empty storage by answering every
     slot of a newly-created account with zero instead of reading the database
     ([inner.rs:754,773-778]), which is the same state reached here by emptying
     the map. Leaving it would let a fresh contract read the previous occupant's
     slots;
   - the address is recorded as created in this transaction, which is what a
     later [SELFDESTRUCT] consults for EIP-6780;
   - the endowment moves last, through {!transfer}, so a sender underflow or the
     unreachable recipient overflow is reported rather than forced.

   The permit is EIP-214's: a creation is a state change, and a static frame can
   never produce one. *)
let begin_creation t (_permit : Mutability.permit) ~creator ~created ~value =
  let born =
    Account.with_storage
      (Account.increment_nonce (World_state.account t.world created))
      Tn_state.Storage.empty
  in
  transfer
    {
      t with
      world = World_state.set_account t.world created born;
      lifecycle = Lifecycle.record_creation t.lifecycle created;
    }
    ~from:creator ~to_:created ~value

(* Install the code a creation frame returned. The account exists already —
   {!begin_creation} made it — so this is the last step of a successful creation
   and nothing else in the port writes code to an account. *)
let deploy_code t (_permit : Mutability.permit) address code =
  {
    t with
    world =
      World_state.set_account t.world address
        (Account.with_code (World_state.account t.world address) code);
  }

(* [SELFDESTRUCT] priced but not yet applied. The beneficiary is warmed here,
   which is the touch whose {!Access.warmth} prices the cold surcharge, and the
   four facts the instruction needs are read from the state before anything moves.

   [beneficiary_exists] is the EIP-161 emptiness test, not "has an entry": an
   account with no nonce, no balance and no code does not exist for the 25000's
   purpose ([revm-context] [journal/inner.rs:505] uses
   [state_clear_aware_is_empty]). *)
let plan_destruction t ~address ~beneficiary =
  let touched, access = Access.touch_account t.access beneficiary in
  let plan =
    Destruction.make ~address ~beneficiary
      ~balance:(World_state.balance t.world address)
      ~beneficiary_exists:
        (not (Account.is_empty (World_state.account t.world beneficiary)))
      ~deletes:(Lifecycle.created_here t.lifecycle address)
  in
  (* [commit] is the identity, and honestly so: applying a destruction can fail
     on the recipient overflow, so it cannot be a [t -> t] and does not live in
     that field. {!commit_destruction} is the writer, and the types keep the two
     apart — {!commit_store} accepts only an [Sstore_state.t load]. *)
  { value = plan; warmth = touched; effects = { t with access }; commit = Fun.id }

(* Apply a planned destruction, EIP-6780 as revm branches it
   ([revm-context] [journal/inner.rs:507-549]). Three outcomes, not two:

   - the account was created in this transaction, so it really goes. Its balance
     moves to the beneficiary and it is recorded for removal at the end of the
     transaction. When the beneficiary IS the account, there is nowhere for the
     balance to go and it is burned with the account ([inner.rs:531-539] takes
     the same branch and zeroes the balance without crediting anyone, because the
     credit at [:507-515] is guarded on the two addresses differing);
   - it was not, so it stays: only the balance moves, and the code, the nonce and
     the storage remain. This is what EIP-6780 turned [SELFDESTRUCT] into;
   - it was not, and it names itself as beneficiary: nothing happens at all
     ([inner.rs:543-548] returns no journal entry).

   The removal is recorded rather than performed: the account is still callable,
   readable and destroyable for the rest of the transaction, and only the
   transaction layer takes it out. *)
let commit_destruction l (_permit : Mutability.permit) =
  let plan = l.value in
  let address = Destruction.address plan in
  let beneficiary = Destruction.beneficiary plan in
  let effects = l.effects in
  let recorded =
    if Destruction.deletes plan then
      { effects with lifecycle = Lifecycle.record_destruction effects.lifecycle address }
    else effects
  in
  if Tn_types.Units.Address.equal address beneficiary then
    if Destruction.deletes plan then
      (* Burned: debiting the whole balance always succeeds, so this is total. *)
      Option.map
        (fun emptied ->
          { recorded with world = World_state.set_account recorded.world address emptied })
        (Account.debit (World_state.account recorded.world address) (Destruction.balance plan))
    else Some recorded
  else
    transfer recorded ~from:address ~to_:beneficiary ~value:(Destruction.balance plan)

let equal a b =
  World_state.equal a.world b.world
  && World_state.equal a.base b.base
  && Access.equal a.access b.access
  && Refund.equal a.refund b.refund
  && Log_journal.equal a.logs b.logs
  && Transient.equal a.transient b.transient
  && Lifecycle.equal a.lifecycle b.lifecycle
