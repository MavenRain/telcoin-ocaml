(* The block-execution spine. Two pre-block system calls, then one left fold.
   Every step that can fail returns a [result] carrying the offending
   transaction's index, so a caller never has to recount the list to find out
   which transaction stopped the block. *)

module World_state = Tn_state.World_state
module Digest = Tn_crypto.Digest
module Digests = Tn_types.Digests

type error =
  | Consensus_root_call of System_call.error
  | Blockhashes_call of System_call.error
  | Recovery of { index : int; error : Tx_recovery.error }
  | Transaction_rejected of { index : int; error : Executor.error }
  | Gas_limit_above_available of {
      index : int;
      transaction_gas_limit : int;
      block_available_gas : int;
    }
  | Block_gas_exceeded of { index : int }

let error_to_string = function
  | Consensus_root_call e ->
      "consensus root contract call: " ^ System_call.error_to_string e
  | Blockhashes_call e ->
      "blockhashes contract call: " ^ System_call.error_to_string e
  | Recovery { index; error } ->
      Printf.sprintf "transaction %d: %s" index
        (Tx_recovery.error_to_string error)
  | Transaction_rejected { index; error } ->
      Printf.sprintf "transaction %d rejected: %s" index
        (Executor.error_to_string error)
  | Gas_limit_above_available { index; transaction_gas_limit; block_available_gas }
    ->
      Printf.sprintf
        "transaction %d wants %d gas but only %d remain in the block" index
        transaction_gas_limit block_available_gas
  | Block_gas_exceeded { index } ->
      Printf.sprintf "transaction %d passed the block gas limit" index

module Pre_block = struct
  type consensus_root =
    | Root_skipped_at_genesis
    | Root_skipped_after_first_batch
    | Root_written of System_call.outcome

  type blockhashes =
    | Hash_skipped_at_genesis
    | Hash_written of System_call.outcome

  type t = {
    world : World_state.t;
    consensus_root : consensus_root;
    blockhashes : blockhashes;
  }

  (* Not in the .mli: the token stays constructorless from outside, and this is
     the one place inside the module that builds one, immediately after both
     steps have run. *)
  let make ~world ~consensus_root ~blockhashes =
    { world; consensus_root; blockhashes }

  let world t = t.world
  let consensus_root t = t.consensus_root
  let blockhashes t = t.blockhashes
end

let ( let* ) = Result.bind

(* [Digests] exposes only [to_digest]/[to_hex], so the 32 bytes of the EIP-4788
   calldata come through [Tn_crypto.Digest.to_bytes]. *)
let output_digest_bytes root =
  Digest.to_bytes (Digests.Output_digest.to_digest root)

(* The EIP-4788 step. The pair scrutinee makes the nesting explicit and keeps
   the match exhaustive over the product of two booleans with no wildcard:
   [first_batch] is telcoin's OUTER gate ([block.rs:775]) and the genesis check
   lives inside the call it guards ([block.rs:643-665]), so a block that is
   both reports the outer reason. *)
let consensus_root_step world ~context =
  match
    (Block_context.first_batch context, Block_context.is_genesis context)
  with
  | false, false | false, true ->
      Ok (world, Pre_block.Root_skipped_after_first_batch)
  | true, true -> Ok (world, Pre_block.Root_skipped_at_genesis)
  | true, false ->
      System_call.run world
        ~block:(Block_context.block context)
        ~contract:System_contracts.beacon_roots_address
        ~data:(output_digest_bytes (Block_context.consensus_root context))
      |> Result.map_error (fun e -> Consensus_root_call e)
      |> Result.map (fun outcome ->
             (System_call.world outcome, Pre_block.Root_written outcome))

(* The EIP-2935 step. Genesis is its only gate: it is NOT gated on
   [first_batch] ([block.rs:782-784]), and the calldata is the parent hash
   rather than the consensus digest. *)
let blockhashes_step world ~context =
  match Block_context.is_genesis context with
  | true -> Ok (world, Pre_block.Hash_skipped_at_genesis)
  | false ->
      System_call.run world
        ~block:(Block_context.block context)
        ~contract:System_contracts.history_storage_address
        ~data:(Tn_keccak.to_bytes (Block_context.parent_hash context))
      |> Result.map_error (fun e -> Blockhashes_call e)
      |> Result.map (fun outcome ->
             (System_call.world outcome, Pre_block.Hash_written outcome))

(* The order is the contract: 4788 first, then 2935 against the world 4788 left
   behind. Threading the world through the two [let*]s is what makes the second
   call see the first call's writes. *)
let apply_pre_block world ~context =
  let* world, consensus_root = consensus_root_step world ~context in
  let* world, blockhashes = blockhashes_step world ~context in
  Ok (Pre_block.make ~world ~consensus_root ~blockhashes)

type outcome = {
  world : World_state.t;
  transactions : Tx_envelope.t list;
  receipts : (int * Receipt.t) list;
  gas_used : int;
  logs_bloom : Bloom.t;
}

(* The fold's accumulator. The two lists are built reversed and turned once at
   the end, so the fold never appends. Field names are distinct from
   {!outcome}'s on purpose: the two records are never confusable at a use
   site. *)
type step_state = {
  index : int;
  running_world : World_state.t;
  meter : Block_gas.t;
  receipts_rev : (int * Receipt.t) list;
  transactions_rev : Tx_envelope.t list;
}

(* One transaction, in telcoin's order: recover, check the REMAINING block gas,
   execute, then advance the meter, then record. The meter advances BEFORE the
   receipt is recorded, which is why a receipt's cumulative gas includes its own
   transaction ([block.rs:893] precedes [block.rs:896-902]); this port gets that
   from [Block_roots.receipts_root]'s inclusive prefix sum, and the meter here
   agrees with it by construction because both add [Receipt.gas_used]. *)
let step context previous envelope =
  let* state = previous in
  let* transaction =
    Tx_recovery.recover envelope
    |> Result.map_error (fun error -> Recovery { index = state.index; error })
  in
  let transaction_gas_limit = Transaction.gas_limit transaction in
  let block_available_gas = Block_gas.available state.meter in
  let* () =
    if transaction_gas_limit > block_available_gas then
      Error
        (Gas_limit_above_available
           { index = state.index; transaction_gas_limit; block_available_gas })
    else Ok ()
  in
  let* receipt, world =
    Executor.execute state.running_world
      ~block:(Block_context.block context)
      transaction
    |> Result.map_error (fun error ->
           Transaction_rejected { index = state.index; error })
  in
  let* meter =
    Block_gas.charge_receipt state.meter receipt
    |> Option.to_result ~none:(Block_gas_exceeded { index = state.index })
  in
  Ok
    {
      index = state.index + 1;
      running_world = world;
      meter;
      receipts_rev =
        (Block_roots.type_byte transaction, receipt) :: state.receipts_rev;
      transactions_rev = envelope :: state.transactions_rev;
    }

(* [Bloom.of_logs] over the concatenation of every receipt's logs, never a union
   of per-receipt blooms: [block.rs:957] flattens, and this port has no
   [Bloom.union] with which to write the other formulation. *)
let block_bloom receipts =
  Bloom.of_logs (List.concat_map (fun entry -> Receipt.logs (snd entry)) receipts)

let run_transactions pre ~context envelopes =
  let initial =
    Ok
      {
        index = 0;
        running_world = Pre_block.world pre;
        meter = Block_gas.start context;
        receipts_rev = [];
        transactions_rev = [];
      }
  in
  List.fold_left (step context) initial envelopes
  |> Result.map (fun final ->
         let receipts = List.rev final.receipts_rev in
         {
           world = final.running_world;
           transactions = List.rev final.transactions_rev;
           receipts;
           gas_used = Block_gas.used final.meter;
           logs_bloom = block_bloom receipts;
         })

let world o = o.world
let transactions o = o.transactions
let receipts o = o.receipts
let gas_used o = o.gas_used
let logs_bloom o = o.logs_bloom

let execute world ~context envelopes =
  let* pre = apply_pre_block world ~context in
  let* outcome = run_transactions pre ~context envelopes in
  Ok (pre, outcome)
