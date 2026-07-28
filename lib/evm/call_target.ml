(* One-hop delegation resolution, shared by the interpreter's four call opcodes
   and the executor's depth-0 frame ([call_helpers.rs:165-186] and
   [handler.rs:317-332] are the same rule at revm's two entry points). The
   non-delegated branch is a record literal whose [code] field is the exact
   expression both call sites evaluated before this module existed: the
   identity, with a zero surcharge and physically untouched effects. *)
module Account = Tn_state.Account

type t = {
  code : Code.t;
  effects : Effects.t;
  surcharge : int;
  delegate : Tn_types.Units.Address.t option;
}

(* Exactly ONE hop: the delegate's account is read once and its raw code handed
   over, never re-classified ([call_helpers.rs:176-184] and [handler.rs:319]
   are a single [if let] with no loop and no re-check). A delegate that itself
   bears a designator hands those 23 bytes to the frame, which halts on the
   first byte. The delegate load goes through {!Effects.ext_account} so its
   warming is a SECOND, independent entry beside the target's own
   ([call_helpers.rs:150-154]), and the surcharge is priced off that same
   load's warmth, so the two cannot drift apart. *)
let resolve effects account =
  Option.fold
    ~none:
      {
        code = Code.of_string (Account.code account);
        effects;
        surcharge = 0;
        delegate = None;
      }
    ~some:(fun target ->
      let load = Effects.ext_account effects target in
      {
        code = Code.of_string (Account.code (Effects.loaded load));
        effects = Effects.warmed load;
        surcharge = Gas.delegation_cost (Some (Effects.warmth load));
        delegate = Some target;
      })
    (Account.delegation account)

let code t = t.code
let effects t = t.effects
let surcharge t = t.surcharge
let delegate t = t.delegate
