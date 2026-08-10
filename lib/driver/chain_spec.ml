open Tn_types
module U256 = Tn_state.U256
module World_state = Tn_state.World_state
module System_contracts = Tn_evm.System_contracts
module Anchor = Tn_engine.Anchor
module Config = Tn_engine.Config
module Fork_schedule = Tn_evm.Fork_schedule

module Epoch_duration = struct
  type t = int

  let of_secs n = if n > 0 then Some n else None
  let to_secs d = d
  let equal = Int.equal
end

type t = {
  chain_id : U256.t;
  basefee_address : Units.Address.t;
  anchor : Anchor.t;
  world : World_state.t;
  genesis_timestamp : Units.Timestamp.t;
  epoch_duration : Epoch_duration.t;
  ancestors : Tn_keccak.t list;
  fork_schedule : Fork_schedule.t;
}

type error = Alloc of World_state.alloc_error

let error_to_string (Alloc e) =
  "chain spec alloc: " ^ World_state.error_to_string e

(* [fork_schedule] defaults to the testnet schedule, which activates Shanghai,
   Cancun and Prague all at timestamp 0. That is the chain this port modelled
   before a schedule existed, so a spec built without one describes exactly the
   chain it described before. A mainnet spec passes [Fork_schedule.mainnet]. *)
let create ~chain_id ~basefee_address ~genesis_hash ~genesis_base_fee
    ~genesis_gas_limit ~genesis_timestamp ~epoch_duration ?(ancestors = [])
    ?(fork_schedule = Fork_schedule.testnet) ~registry ~extra_alloc () =
  (* The registry entry comes LAST so the alloc's later-entry-wins rule makes
     it impossible for an [extra_alloc] entry at the registry address to
     displace it; [predeploy] then overwrites the system-contract and
     deployer slots the same way. *)
  let alloc =
    extra_alloc @ [ (System_contracts.consensus_registry_address, registry) ]
  in
  Result.map_error
    (fun e -> Alloc e)
    (Result.map
       (fun seeded ->
         {
           chain_id;
           basefee_address;
           anchor =
             Anchor.of_genesis ~hash:genesis_hash ~base_fee:genesis_base_fee
               ~gas_limit:genesis_gas_limit;
           world = System_contracts.predeploy seeded;
           genesis_timestamp;
           epoch_duration;
           ancestors;
           fork_schedule;
         })
       (World_state.of_genesis_alloc alloc))

let anchor t = t.anchor
let world t = t.world
let chain_id t = t.chain_id
let basefee_address t = t.basefee_address
let genesis_timestamp t = t.genesis_timestamp
let epoch_duration t = t.epoch_duration
let ancestors t = t.ancestors
let fork_schedule t = t.fork_schedule

let first_boundary t =
  Units.Timestamp.add_secs t.genesis_timestamp
    (Epoch_duration.to_secs t.epoch_duration)

(* The COLD-START conversion site ([Driver.resume] forwards the same schedule
   to [Engine.resume] at resumption), so the schedule reaches the engine by
   riding inside this record rather than by every caller of [engine_config]
   learning about forks: both call sites are textually unchanged. *)
let engine_config t ~committee =
  Config.create_on_schedule ~fork_schedule:t.fork_schedule ~anchor:t.anchor
    ~ancestors:t.ancestors ~world:t.world ~chain_id:t.chain_id
    ~basefee_address:t.basefee_address ~epoch_boundary:(first_boundary t)
    ~committee
