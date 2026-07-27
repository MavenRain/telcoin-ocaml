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

type outcome = { receipt : Receipt.t; world : World_state.t }

let receipt o = o.receipt
let succeeded o = Receipt_envelope.status o.receipt
let world o = o.world

(* Telcoin's two [core::mem::swap]s ([evm/mod.rs:194-212]) expressed as a
   rebuild, because [Env.Block] has no updater. The other six fields are carried
   through by their own accessors, so a field added to [Env.Block] is a compile
   error here rather than a silently dropped one. *)
let system_block block =
  Env.Block.make
    ~coinbase:(Env.Block.coinbase block)
    ~timestamp:(Env.Block.timestamp block)
    ~number:(Env.Block.number block)
    ~prevrandao:(Env.Block.prevrandao block)
    ~gas_limit:gas_limit_word ~basefee:U256.zero
    ~chain_id:(Env.Block.chain_id block)
    ~hashes:(Env.Block.hashes block)

(* The [retain]: the post-call world is the PRE-call world with exactly the
   target's account replaced, never the executor's world with accounts removed.
   Rebuilding forward is what makes "only the target was committed" a property
   of the expression rather than of a filter someone has to read. *)
let retain_target ~before ~after ~contract =
  World_state.set_account before contract (World_state.account after contract)

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
         { receipt; world = retain_target ~before ~after ~contract })
