(* The system-call path. The whole module is one function plus the two shapes
   that keep its illegal states unnameable: no caller argument, and no way to
   reach the raw post-call world. *)

module World_state = Tn_state.World_state
module U256 = Tn_state.U256

type error = Rejected of Executor.error

let error_to_string = function
  | Rejected e -> "system call rejected: " ^ Executor.error_to_string e

let gas_limit = 30_000_000

(* [U256.of_int] is fallible and 30_000_000 is far below [2^256], so the default
   is dead. It is [U256.zero] rather than anything larger on purpose: a zero
   block gas limit would make [Executor]'s strict [>] check fire and surface as
   [Rejected], a LOUD failure, never a wrong state root. *)
let gas_limit_word = Option.value ~default:U256.zero (U256.of_int gas_limit)

type outcome = {
  receipt : Receipt.t;
  world : World_state.t;
  world_keeping_all_but_system : World_state.t;
}

let receipt o = o.receipt
let succeeded o = Receipt_envelope.status o.receipt
let world o = o.world
let world_keeping_all_but_system o = o.world_keeping_all_but_system

(* Telcoin's two [core::mem::swap]s ([evm/mod.rs:194-212]) expressed as a
   rebuild, because [Env.Block] has no updater. The other nine fields are
   carried through by their own accessors, so a field added to [Env.Block] is a
   compile error here rather than a silently dropped one. TN's swaps touch only
   [block.gas_limit], [block.basefee] and [cfg.disable_nonce_check]
   ([evm/mod.rs:198-203]); neither the blob env nor the fork level is among
   them, so [blob_gasprice] and [spec] ride through untouched and a frame
   inside a system call reads the same values as the enclosing block. The fork
   level in particular is NOT re-derived here: a system call runs at the fork
   level of the block that made it, and there is no timestamp of its own to
   derive one from. *)
let system_block block =
  Env.Block.make_at_spec
    ~spec:(Env.Block.spec block)
    ~coinbase:(Env.Block.coinbase block)
    ~timestamp:(Env.Block.timestamp block)
    ~number:(Env.Block.number block)
    ~prevrandao:(Env.Block.prevrandao block)
    ~gas_limit:gas_limit_word ~basefee:U256.zero
    ~basefee_address:(Env.Block.basefee_address block)
    ~chain_id:(Env.Block.chain_id block)
    ~blob_gasprice:(Env.Block.blob_gasprice block)
    ~hashes:(Env.Block.hashes block)

(* The [retain]: the post-call world is the PRE-call world with exactly the
   target's account replaced, never the executor's world with accounts removed.
   Rebuilding forward is what makes "only the target was committed" a property
   of the expression rather than of a filter someone has to read. *)
let retain_target ~before ~after ~contract =
  World_state.set_account before contract (World_state.account after contract)

(* The OTHER commit rule, [res.state.remove(&SYSTEM_ADDRESS)] then
   [db.commit(res.state)] ([block.rs:184-187, 224-226]): the post-call world
   with the system address's account put back to its pre-call value, every
   other touched account kept. [World_state.set_account] prunes an absent
   account ([world_state.ml:26-27]), so a system address that was absent
   before the call is absent again after it, exactly what [remove] leaves in
   the Rust map. *)
let keep_all_but_system ~before ~after =
  World_state.set_account after System_contracts.system_address
    (World_state.account before System_contracts.system_address)

let run before ~block ~contract ~data =
  let tx =
    Transaction.make ~sender:System_contracts.system_address
      ~nonce:(World_state.nonce before System_contracts.system_address)
      ~gas_limit ~kind:(Transaction.Call contract) ~value:U256.zero ~data
      ~access_list:[] ~chain_id:None
      ~fee:(Transaction.Legacy { gas_price = U256.zero })
  in
  Executor.execute before ~block:(system_block block) tx
  |> Result.map_error (fun e -> Rejected e)
  |> Result.map (fun (receipt, after) ->
         {
           receipt;
           world = retain_target ~before ~after ~contract;
           world_keeping_all_but_system = keep_all_but_system ~before ~after;
         })
