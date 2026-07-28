(* The epoch-close system calls: two mandatory writes under the
   remove-SYSTEM-commit-ALL rule bracketing two structurally non-committing
   reads. Every frame goes through System_call.run, so the environment
   discipline lives in exactly one place; this module adds only WHICH calls,
   in WHICH order, under WHICH commit rule, and that failure is fatal. *)

module World_state = Tn_state.World_state

type error =
  | Rewards_call of System_call.error
  | Rewards_unsuccessful
  | Conclude_call of System_call.error
  | Conclude_unsuccessful
  | Pool_read of { status : Registry_abi.Eligible_status.t; error : System_call.error }
  | Pool_read_unsuccessful of Registry_abi.Eligible_status.t
  | Pool_decode of Registry_abi.decode_error
  | Size_read of System_call.error
  | Size_read_unsuccessful
  | Size_decode of Registry_abi.decode_error

let status_to_string = function
  | Registry_abi.Eligible_status.Active -> "Active"
  | Registry_abi.Eligible_status.Pending_activation -> "PendingActivation"
  | Registry_abi.Eligible_status.Pending_exit -> "PendingExit"

let error_to_string = function
  | Rewards_call e -> "applyIncentives: " ^ System_call.error_to_string e
  | Rewards_unsuccessful -> "applyIncentives reverted or halted"
  | Conclude_call e -> "concludeEpoch: " ^ System_call.error_to_string e
  | Conclude_unsuccessful -> "concludeEpoch reverted or halted"
  | Pool_read { status; error } ->
      "pool read (" ^ status_to_string status ^ "): " ^ System_call.error_to_string error
  | Pool_read_unsuccessful status ->
      "pool read (" ^ status_to_string status ^ ") reverted or halted"
  | Pool_decode e -> "pool decode: " ^ Registry_abi.error_to_string e
  | Size_read e -> "getNextCommitteeSize: " ^ System_call.error_to_string e
  | Size_read_unsuccessful -> "getNextCommitteeSize reverted or halted"
  | Size_decode e -> "committee-size decode: " ^ Registry_abi.error_to_string e

let ( let* ) = Result.bind

(* A read's yield is its success output and nothing else: Reverted and Halted
   both collapse to the caller's [unsuccessful], matching read_state_on_chain's
   single is_success gate (block.rs:613-618), and the worlds the outcome
   carries are deliberately never touched. *)
let read world ~block ~data ~call_error ~unsuccessful =
  let* outcome =
    System_call.run world ~block ~contract:System_contracts.consensus_registry_address ~data
    |> Result.map_error call_error
  in
  match System_call.receipt outcome with
  | Receipt.Success { output; created = _; gas_used = _; gas_refunded = _; logs = _ } ->
      Ok output
  | Receipt.Reverted { output = _; gas_used = _ } -> Error unsuccessful
  | Receipt.Halted { reason = _; gas_used = _ } -> Error unsuccessful

let read_eligible_pool world ~block =
  let status = Registry_abi.Eligible_status.Active in
  let* output =
    read world ~block
      ~data:(Registry_abi.get_validators_calldata status)
      ~call_error:(fun error -> Pool_read { status; error })
      ~unsuccessful:(Pool_read_unsuccessful status)
  in
  Registry_abi.decode_validator_info_array output
  |> Result.map_error (fun e -> Pool_decode e)

let read_next_committee_size world ~block =
  let* output =
    read world ~block ~data:Registry_abi.get_next_committee_size_calldata
      ~call_error:(fun e -> Size_read e)
      ~unsuccessful:Size_read_unsuccessful
  in
  Registry_abi.decode_uint16 output |> Result.map_error (fun e -> Size_decode e)

type disposition = {
  first_calldata : string;
  second_calldata : string;
  rewards_outcome : System_call.outcome;
  conclude_outcome : System_call.outcome;
}

let first_calldata d = d.first_calldata
let second_calldata d = d.second_calldata
let rewards_outcome d = d.rewards_outcome
let conclude_outcome d = d.conclude_outcome

(* A write is mandatory-success: the outcome comes back whole (the disposition
   keeps it), but only if the frame really succeeded. *)
let write world ~block ~data ~call_error ~unsuccessful =
  let* outcome =
    System_call.run world ~block ~contract:System_contracts.consensus_registry_address ~data
    |> Result.map_error call_error
  in
  if System_call.succeeded outcome then Ok outcome else Error unsuccessful

let close world ~block ~rewards ~randomness =
  let first_calldata = Registry_abi.apply_incentives_calldata rewards in
  let* rewards_outcome =
    write world ~block ~data:first_calldata
      ~call_error:(fun e -> Rewards_call e)
      ~unsuccessful:Rewards_unsuccessful
  in
  let after_rewards = System_call.world_keeping_all_but_system rewards_outcome in
  (* Both reads run against the POST-rewards world, exactly where Rust's DB
     stands when apply_closing_epoch_contract_call starts (block.rs:794-834
     runs the rewards commit first); their outcomes are consumed for bytes
     only. *)
  let* pool = read_eligible_pool after_rewards ~block in
  let* size = read_next_committee_size after_rewards ~block in
  (* The ascending sort is HERE at encode time (block.rs:394-395): the
     shuffle's own output order is pinned unsorted by its tests, and
     conclude_epoch_calldata encodes as given. *)
  let committee =
    List.sort Tn_types.Units.Address.compare
      (Committee_shuffle.shuffle ~pool ~committee_size:size ~randomness)
  in
  let second_calldata = Registry_abi.conclude_epoch_calldata committee in
  let* conclude_outcome =
    write after_rewards ~block ~data:second_calldata
      ~call_error:(fun e -> Conclude_call e)
      ~unsuccessful:Conclude_unsuccessful
  in
  Ok
    ( System_call.world_keeping_all_but_system conclude_outcome,
      { first_calldata; second_calldata; rewards_outcome; conclude_outcome } )
