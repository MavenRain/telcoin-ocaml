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
  | Epoch_close of Epoch_close.error

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
  | Epoch_close e -> "epoch close: " ^ Epoch_close.error_to_string e

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

(* The state the fold starts from and the outcome it ends in, factored out
   because BOTH entry points below are the same fold over the same [step]: the
   only thing they differ in is what they do with a [Transaction_rejected]. *)
let initial_state pre ~context =
  {
    index = 0;
    running_world = Pre_block.world pre;
    meter = Block_gas.start context;
    receipts_rev = [];
    transactions_rev = [];
  }

let outcome_of final =
  let receipts = List.rev final.receipts_rev in
  {
    world = final.running_world;
    transactions = List.rev final.transactions_rev;
    receipts;
    gas_used = Block_gas.used final.meter;
    logs_bloom = block_bloom receipts;
  }

let run_transactions pre ~context envelopes =
  List.fold_left (step context) (Ok (initial_state pre ~context)) envelopes
  |> Result.map outcome_of

module Invalid_tx = struct
  type t = { index : int; error : Executor.error }

  (* Not in the .mli: the skipping fold below is the only producer, so the
     record stays constructorless from outside, exactly as [Pre_block.make]. *)
  let make ~index ~error = { index; error }
  let index t = t.index
  let error t = t.error

  let to_string t =
    Printf.sprintf "transaction %d skipped: %s" t.index
      (Executor.error_to_string t.error)
end

(* The one place the two stances differ. Every arm is named and there is no
   wildcard, so an error class added to [error] later cannot fall into the skip
   class by inheritance: it has to be classified here. Skipping resumes from
   [state] itself, which is the state BEFORE the refused transaction, because a
   transaction [Executor.execute] refuses commits no world, no receipt and no
   gas. The index the record carries is the one [step] was holding, and
   advancing it past the skip is what keeps every later index an INPUT
   position. *)
let skip_or_stop state skipped_rev = function
  | Transaction_rejected { index; error } ->
      Ok
        ( { state with index = index + 1 },
          Invalid_tx.make ~index ~error :: skipped_rev )
  | ( Consensus_root_call _ | Blockhashes_call _ | Recovery _
    | Gas_limit_above_available _ | Block_gas_exceeded _ | Epoch_close _ ) as
    fatal ->
      Error fatal

(* [step] unchanged and unwrapped: the skip decision is taken on its result, so
   the strict path and the builder path execute the same code up to the point
   where they disagree. *)
let skipping_step context previous envelope =
  let* state, skipped_rev = previous in
  step context (Ok state) envelope
  |> Result.fold
       ~ok:(fun advanced -> Ok (advanced, skipped_rev))
       ~error:(skip_or_stop state skipped_rev)

let run_transactions_skipping_invalid pre ~context envelopes =
  List.fold_left (skipping_step context)
    (Ok (initial_state pre ~context, []))
    envelopes
  |> Result.map (fun (final, skipped_rev) ->
         (outcome_of final, List.rev skipped_rev))

let world o = o.world
let transactions o = o.transactions
let receipts o = o.receipts
let gas_used o = o.gas_used
let logs_bloom o = o.logs_bloom

let execute world ~context envelopes =
  let* pre = apply_pre_block world ~context in
  let* outcome = run_transactions pre ~context envelopes in
  Ok (pre, outcome)

module Finished = struct
  type t = {
    world : World_state.t;
    outcome : outcome;
    close_disposition : Epoch_close.disposition option;
  }

  (* Not in the .mli: [finish] below is the only producer, so the token stays
     constructorless from outside, exactly as [Pre_block.make]. *)
  let make ~world ~outcome ~close_disposition =
    { world; outcome; close_disposition }

  let world t = t.world
  let outcome t = t.outcome
  let close_disposition t = t.close_disposition
end

(* The applyIncentives pairs, derived FROM the boundary's withdrawal records:
   same addresses, same amounts, same order. The .mli states why this
   single-sourcing is a disclosed hardening over Rust's two counter reads and
   why the values are identical on every input Rust produces. *)
let reward_pairs withdrawals =
  List.map (fun w -> (Withdrawal.address w, Withdrawal.amount w)) withdrawals

let finish outcome ~context =
  match Block_context.boundary context with
  | Epoch_boundary.Open ->
      Ok (Finished.make ~world:outcome.world ~outcome ~close_disposition:None)
  | Epoch_boundary.Closing { randomness; withdrawals } ->
      Epoch_close.close outcome.world
        ~block:(Block_context.block context)
        ~rewards:(reward_pairs withdrawals)
        ~randomness
      |> Result.map_error (fun e -> Epoch_close e)
      |> Result.map (fun (world, disposition) ->
             Finished.make ~world ~outcome ~close_disposition:(Some disposition))
