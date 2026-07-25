open Tn_types
module World_state = Tn_state.World_state
module Account = Tn_state.Account
module Bytecode = Tn_state.Bytecode
module U256 = Tn_state.U256
module Nonce = Tn_state.Nonce

type error =
  | Invalid_chain_id
  | Missing_chain_id
  | Gas_price_below_base_fee
  | Priority_fee_above_max_fee
  | Gas_limit_above_block
  | Init_code_size_limit
  | Intrinsic_gas_above_limit
  | Gas_floor_above_limit
  | Sender_has_code
  | Nonce_mismatch of { expected : Nonce.t; actual : Nonce.t }
  | Insufficient_funds
  | Overflow_payment

let error_to_string = function
  | Invalid_chain_id -> "invalid chain id"
  | Missing_chain_id -> "missing chain id"
  | Gas_price_below_base_fee -> "gas price below base fee"
  | Priority_fee_above_max_fee -> "priority fee above max fee"
  | Gas_limit_above_block -> "gas limit above block gas limit"
  | Init_code_size_limit -> "init code size limit (EIP-3860)"
  | Intrinsic_gas_above_limit -> "intrinsic gas above gas limit"
  | Gas_floor_above_limit -> "gas floor above gas limit"
  | Sender_has_code -> "sender has code (EIP-3607)"
  | Nonce_mismatch { expected; actual } ->
      Printf.sprintf "nonce mismatch (expected %s, got %s)"
        (Nonce.to_string expected) (Nonce.to_string actual)
  | Insufficient_funds -> "insufficient funds for max fee and value"
  | Overflow_payment -> "overflow computing max payment"

(* The three shapes a first frame can end in, each carrying the world that
   survives it (before the caller and beneficiary credits) and the gas that came
   back. A halt carries no surviving gas: it burns the whole forwarded allowance,
   so {!finalize} treats its spend as the full limit. *)
type frame_outcome =
  | Ran_success of {
      world : World_state.t;
      remaining : int;
      refund : int;
      logs : Log.t list;
      output : string;
      created : Units.Address.t option;
    }
  | Ran_revert of { world : World_state.t; remaining : int; output : string }
  | Ran_halt of { world : World_state.t; reason : Receipt.halt_reason }

let word_of_int n = Option.value (U256.of_int n) ~default:U256.zero

(* [a * b] with overflow detection, since {!U256.mul} wraps at [2^256] and revm
   rejects an overflowing [gas_limit * max_fee] with [OverflowPaymentInTransaction].
   Division by the nonzero factor recovers the other iff the product did not
   wrap. *)
let mul_checked a b =
  if U256.is_zero b then Some U256.zero
  else
    let product = U256.mul a b in
    match U256.udiv product b with
    | None -> None
    | Some quotient -> if U256.equal quotient a then Some product else None

(* Credit an account, pruning it back out if the credit leaves it
   {!Account.is_absent} (a zero credit to an absent account), which is what keeps
   a zero-value target and a zero-reward beneficiary from materializing as empty
   accounts (EIP-161). A credit that would overflow [2^256] is dropped, which no
   real total supply reaches. *)
let add_balance world address amount =
  Option.fold ~none:world
    ~some:(World_state.set_account world address)
    (Account.credit (World_state.account world address) amount)

(* Flatten the grouped access list into the two lists {!Access.of_transaction}
   consumes: every named address, and every (address, slot) pair. *)
let declared_warm access_list =
  let addresses = List.map fst access_list in
  let slots =
    List.concat_map
      (fun (address, slots) -> List.map (fun slot -> (address, slot)) slots)
      access_list
  in
  (addresses, slots)

(* The precompile addresses warmed before the first frame: 0x01..0x0a. This
   approximates the Prague warm set, which additionally warms the EIP-2537 BLS
   addresses 0x0b..0x11; those are unimplemented in this port's {!Precompile} and
   are not warmed, an approximation that is unobservable unless executed code
   touches one of them. *)
let precompile_addresses =
  List.filter_map
    (fun n ->
      Units.Address.of_bytes
        (String.make (Units.Address.length - 1) '\000' ^ String.make 1 (Char.chr n)))
    [ 1; 2; 3; 4; 5; 6; 7; 8; 9; 10 ]

(* Post-execution: EIP-3529 refund cap, then the EIP-7623 floor, then the two
   credits. The order is load-bearing ([handler.rs:227-234]): the cap divides the
   gross spend and runs first, so the floor sees an already-capped refund and can
   then zero it. *)
let finalize ~gas_limit ~floor_gas ~effective ~base_fee ~sender ~coinbase outcome =
  let surviving_world, spent0, refund0, make_receipt =
    match outcome with
    | Ran_success { world; remaining; refund; logs; output; created } ->
        ( world,
          gas_limit - remaining,
          refund,
          fun ~gas_used ~gas_refunded ->
            Receipt.Success { output; created; gas_used; gas_refunded; logs } )
    | Ran_revert { world; remaining; output } ->
        ( world,
          gas_limit - remaining,
          0,
          fun ~gas_used ~gas_refunded:_ -> Receipt.Reverted { output; gas_used } )
    | Ran_halt { world; reason } ->
        ( world,
          gas_limit,
          0,
          fun ~gas_used ~gas_refunded:_ -> Receipt.Halted { reason; gas_used } )
  in
  (* EIP-3529 cap: [min(refund, spent/5)] over the gross spend, integer floor
     division. A negative counter is unreachable by contract; revm's [as u64] cast
     wraps it to a huge value that the [min] clamps to [spent/5], reproduced
     here. *)
  let cap = spent0 / 5 in
  let refund1 = if refund0 < 0 then cap else min refund0 cap in
  (* EIP-7623 floor: if the net spend is below the floor, charge the floor and
     zero the refund. *)
  let spent_final, refund_final =
    if spent0 - refund1 < floor_gas then (floor_gas, 0) else (spent0, refund1)
  in
  let used = spent_final - refund_final in
  (* The caller is reimbursed for [remaining + refunded = gas_limit - used] units
     at the full effective price; the beneficiary is paid for [used] units at the
     effective price less the base fee, which is burned. *)
  let caller_credit = U256.mul effective (word_of_int (gas_limit - used)) in
  let coinbase_price =
    Option.value (U256.checked_sub effective base_fee) ~default:U256.zero
  in
  let coinbase_credit = U256.mul coinbase_price (word_of_int used) in
  let world_credited =
    add_balance (add_balance surviving_world sender caller_credit) coinbase coinbase_credit
  in
  (make_receipt ~gas_used:used ~gas_refunded:refund_final, world_credited)

let execute world ~block tx =
  let ( let* ) = Result.bind in
  let sender = Transaction.sender tx in
  let base_fee = Env.Block.basefee block in
  let effective = Transaction.effective_gas_price tx ~base_fee in
  let max_fee = Transaction.max_fee_per_gas tx in
  let gas_limit = Transaction.gas_limit tx in
  let gl_word = word_of_int gas_limit in
  let coinbase = Env.Block.coinbase block in
  let intrinsic_kind =
    match Transaction.kind tx with
    | Transaction.Call _ -> Intrinsic.Call
    | Transaction.Create -> Intrinsic.Create
  in
  (* A legacy transaction carries no access list; a stray one is ignored for both
     the intrinsic charge and the warm set. *)
  let effective_access_list =
    match Transaction.fee tx with
    | Transaction.Legacy _ -> []
    | Transaction.Access_list _ | Transaction.Dynamic _ -> Transaction.access_list tx
  in
  let initial_gas =
    Intrinsic.initial_gas ~kind:intrinsic_kind ~data:(Transaction.data tx)
      ~access_list:effective_access_list
  in
  let floor_gas = Intrinsic.floor_gas ~data:(Transaction.data tx) in
  (* VALIDATE: environment, then initial-gas, then against-state. *)
  let* () =
    match Transaction.chain_id tx with
    | Some c ->
        if U256.equal c (Env.Block.chain_id block) then Ok () else Error Invalid_chain_id
    | None -> (
        match Transaction.fee tx with
        | Transaction.Legacy _ -> Ok ()
        | Transaction.Access_list _ | Transaction.Dynamic _ -> Error Missing_chain_id)
  in
  let* () =
    match Transaction.fee tx with
    | Transaction.Legacy { gas_price } | Transaction.Access_list { gas_price } ->
        if U256.compare gas_price base_fee < 0 then Error Gas_price_below_base_fee
        else Ok ()
    | Transaction.Dynamic { max_fee = mf; max_priority } ->
        let* () =
          match max_priority with
          | None -> Ok ()
          | Some p ->
              if U256.compare p mf > 0 then Error Priority_fee_above_max_fee else Ok ()
        in
        if U256.compare mf base_fee < 0 then Error Gas_price_below_base_fee else Ok ()
  in
  let* () =
    if U256.compare gl_word (Env.Block.gas_limit block) > 0 then Error Gas_limit_above_block
    else Ok ()
  in
  let* () =
    match Transaction.kind tx with
    | Transaction.Call _ -> Ok ()
    | Transaction.Create ->
        if String.length (Transaction.data tx) > Bytecode.max_initcode_size then
          Error Init_code_size_limit
        else Ok ()
  in
  let* () = if initial_gas > gas_limit then Error Intrinsic_gas_above_limit else Ok () in
  let* () = if floor_gas > gas_limit then Error Gas_floor_above_limit else Ok () in
  let* () =
    if Account.code_length (World_state.account world sender) > 0 then Error Sender_has_code
    else Ok ()
  in
  let* () =
    let account_nonce = World_state.nonce world sender in
    if Nonce.equal (Transaction.nonce tx) account_nonce then Ok ()
    else Error (Nonce_mismatch { expected = account_nonce; actual = Transaction.nonce tx })
  in
  let* () =
    match mul_checked gl_word max_fee with
    | None -> Error Overflow_payment
    | Some product -> (
        match U256.checked_add product (Transaction.value tx) with
        | None -> Error Overflow_payment
        | Some max_balance ->
            if U256.compare (World_state.balance world sender) max_balance < 0 then
              Error Insufficient_funds
            else Ok ())
  in
  (* DEDUCT: debit the gas fee at the effective price, and bump the nonce for a
     call (a creation bumps inside its frame). The debit is validated to succeed. *)
  let deduct_wei = U256.mul gl_word effective in
  let* world1 =
    let account = World_state.account world sender in
    match Account.debit account deduct_wei with
    | None -> Error Insufficient_funds
    | Some debited ->
        let account' =
          match Transaction.kind tx with
          | Transaction.Call _ ->
              (* Nonce-overflow is not an error: revm ignores the [bump_nonce]
                 bool and leaves the nonce at its maximum. *)
              Option.value (Account.increment_nonce_checked debited) ~default:debited
          | Transaction.Create -> debited
        in
        Ok (World_state.set_account world sender account')
  in
  (* WARM: caller, beneficiary (EIP-3651), the call target, the precompiles, and
     the access list (typed transactions only). The created address is warmed at
     frame construction instead. *)
  let tx_env =
    Env.Tx.make ~origin:sender ~gas_price:effective ~access_list:effective_access_list
  in
  let al_addresses, al_slots = declared_warm effective_access_list in
  let base_addresses = sender :: coinbase :: (precompile_addresses @ al_addresses) in
  let addresses =
    match Transaction.kind tx with
    | Transaction.Call target -> target :: base_addresses
    | Transaction.Create -> base_addresses
  in
  let effects_start =
    Effects.start ~world:world1 ~access:(Access.of_transaction ~addresses ~slots:al_slots)
  in
  let* forwarded =
    Option.to_result ~none:Intrinsic_gas_above_limit
      (Gas.of_int (gas_limit - initial_gas))
  in
  let value = Transaction.value tx in
  (* FIRST FRAME: a call transfers value then runs the target's code; a creation
     bumps the creator, warms the derived address, checks the collision, endows
     the account and runs the init code, then deposits the returned code. *)
  let run_call target =
    match Effects.transfer effects_start ~from:sender ~to_:target ~value with
    | None -> Ran_halt { world = world1; reason = Receipt.Value_overflow }
    | Some effects -> (
        (* A top-level call whose target is a precompile dispatches the builtin,
           exactly as the interpreter's CALL path does ([interpreter.ml:1219-1239]);
           only a plain account runs its own code. Without this a direct
           transaction to e.g. IDENTITY would run the (empty) account code and
           diverge from revm, which executes the precompile at the first frame too.
           A deferred builtin answers [Not_a_precompile] and falls through to the
           empty-code path, staying consistent with the sub-frame path. *)
        match
          Precompile.invoke target ~input:(Transaction.data tx)
            ~gas_limit:(Gas.remaining forwarded)
        with
        | Precompile.Succeeded { gas_used; output } -> (
            (* A precompile touches no world state beyond the value move already
               folded into [effects]; a gas shortfall is an exceptional halt that
               forfeits the forwarded allowance. *)
            match Gas.charge gas_used forwarded with
            | None ->
                Ran_halt
                  { world = world1; reason = Receipt.Frame_halt Interpreter.Out_of_gas }
            | Some gas_left ->
                Ran_success
                  {
                    world = Effects.world effects;
                    remaining = Gas.remaining gas_left;
                    refund = Refund.to_int (Effects.refund effects);
                    logs = Log_journal.to_list (Effects.logs effects);
                    output;
                    created = None;
                  })
        | Precompile.Rejected ->
            (* The whole forwarded allowance is forfeit and the value move is
               dropped, exactly as [do_call] treats a rejecting builtin. *)
            Ran_halt
              { world = world1; reason = Receipt.Frame_halt Interpreter.Out_of_gas }
        | Precompile.Not_a_precompile ->
            let code = Code.of_string (Account.code (World_state.account world1 target)) in
            let env =
              Env.make ~block ~tx:tx_env
                ~call:
                  (Env.Call.make ~target ~caller:sender ~value
                     ~data:(Data.of_string (Transaction.data tx))
                     ~mutability:Mutability.Mutable)
            in
            (match Interpreter.run ~env ~code ~gas:forwarded ~effects with
            | Interpreter.Stopped { gas_left; effects } ->
                Ran_success
                  {
                    world = Effects.world effects;
                    remaining = Gas.remaining gas_left;
                    refund = Refund.to_int (Effects.refund effects);
                    logs = Log_journal.to_list (Effects.logs effects);
                    output = "";
                    created = None;
                  }
            | Interpreter.Returned { output; gas_left; effects } ->
                Ran_success
                  {
                    world = Effects.world effects;
                    remaining = Gas.remaining gas_left;
                    refund = Refund.to_int (Effects.refund effects);
                    logs = Log_journal.to_list (Effects.logs effects);
                    output;
                    created = None;
                  }
            | Interpreter.Reverted { output; gas_left } ->
                Ran_revert { world = world1; remaining = Gas.remaining gas_left; output }
            | Interpreter.Failed error ->
                Ran_halt { world = world1; reason = Receipt.Frame_halt error }))
  in
  let run_create permit =
    match Effects.bump_nonce effects_start sender with
    | None -> Ran_halt { world = world1; reason = Receipt.Create_nonce_exhausted }
    | Some bumped ->
        let created =
          Contract_address.derive ~creator:sender
            (Contract_address.From_nonce (Transaction.nonce tx))
        in
        let load = Effects.ext_account bumped created in
        let warmed = Effects.warmed load in
        if Account.is_occupied (Effects.loaded load) then
          Ran_halt { world = Effects.world warmed; reason = Receipt.Create_collision }
        else (
          match Effects.begin_creation warmed permit ~creator:sender ~created ~value with
          | None -> Ran_halt { world = Effects.world warmed; reason = Receipt.Value_overflow }
          | Some child_effects ->
              let env =
                Env.make ~block ~tx:tx_env
                  ~call:
                    (Env.Call.make ~target:created ~caller:sender ~value ~data:Data.empty
                       ~mutability:Mutability.Mutable)
              in
              (* The end of a successful init run, mirroring the interpreter's
                 [deposit_code] ([interpreter.ml:906-930]): validate the code
                 (EIP-3541 then EIP-170), charge 200/byte, deploy. Any failure
                 burns all forwarded gas and drops the value transfer, keeping only
                 the creator's nonce bump and the address warming ([warmed]). *)
              let deposit ~output ~gas_left ~effects =
                match Bytecode.validate_deployment output with
                | Error Reserved_prefix ->
                    Ran_halt
                      { world = Effects.world warmed; reason = Receipt.Create_reserved_prefix }
                | Error (Too_large n) ->
                    Ran_halt
                      {
                        world = Effects.world warmed;
                        reason = Receipt.Create_code_size_limit n;
                      }
                | Ok () -> (
                    match Gas.charge (Gas.code_deposit_cost (String.length output)) gas_left with
                    | None ->
                        Ran_halt
                          {
                            world = Effects.world warmed;
                            reason = Receipt.Create_deposit_out_of_gas;
                          }
                    | Some paid ->
                        let deployed = Effects.deploy_code effects permit created output in
                        Ran_success
                          {
                            world = Effects.world deployed;
                            remaining = Gas.remaining paid;
                            refund = Refund.to_int (Effects.refund deployed);
                            logs = Log_journal.to_list (Effects.logs deployed);
                            output;
                            created = Some created;
                          })
              in
              (match
                 Interpreter.run ~env ~code:(Code.of_string (Transaction.data tx))
                   ~gas:forwarded ~effects:child_effects
               with
              | Interpreter.Stopped { gas_left; effects } ->
                  deposit ~output:"" ~gas_left ~effects
              | Interpreter.Returned { output; gas_left; effects } ->
                  deposit ~output ~gas_left ~effects
              | Interpreter.Reverted { output; gas_left } ->
                  Ran_revert
                    { world = Effects.world warmed; remaining = Gas.remaining gas_left; output }
              | Interpreter.Failed error ->
                  Ran_halt { world = Effects.world warmed; reason = Receipt.Frame_halt error }))
  in
  let outcome =
    match Transaction.kind tx with
    | Transaction.Call target -> run_call target
    | Transaction.Create -> (
        (* The top-level frame is never static, so [Mutable] always yields a
           permit; the [None] arm is dead and maps to the static-write halt. *)
        match Mutability.permit Mutability.Mutable with
        | None ->
            Ran_halt
              { world = world1; reason = Receipt.Frame_halt Interpreter.Static_state_change }
        | Some permit -> run_create permit)
  in
  Ok (finalize ~gas_limit ~floor_gas ~effective ~base_fee ~sender ~coinbase outcome)
