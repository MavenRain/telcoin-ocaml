open Tn_types
module U256 = Tn_state.U256
module World_state = Tn_state.World_state
module System_contracts = Tn_evm.System_contracts
module Anchor = Tn_engine.Anchor
module Config = Tn_engine.Config

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
}

type error = Alloc of World_state.alloc_error

let error_to_string (Alloc e) =
  "chain spec alloc: " ^ World_state.error_to_string e

let create ~chain_id ~basefee_address ~genesis_hash ~genesis_base_fee
    ~genesis_gas_limit ~genesis_timestamp ~epoch_duration ?(ancestors = [])
    ~registry ~extra_alloc () =
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
         })
       (World_state.of_genesis_alloc alloc))

let anchor t = t.anchor
let world t = t.world
let chain_id t = t.chain_id
let basefee_address t = t.basefee_address
let genesis_timestamp t = t.genesis_timestamp
let epoch_duration t = t.epoch_duration
let ancestors t = t.ancestors

let first_boundary t =
  Units.Timestamp.add_secs t.genesis_timestamp
    (Epoch_duration.to_secs t.epoch_duration)

let engine_config t ~committee =
  Config.create ~anchor:t.anchor ~ancestors:t.ancestors ~world:t.world
    ~chain_id:t.chain_id ~basefee_address:t.basefee_address
    ~epoch_boundary:(first_boundary t) ~committee
