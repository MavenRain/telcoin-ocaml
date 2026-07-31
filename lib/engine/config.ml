type t = {
  anchor : Anchor.t;
  ancestors : Tn_keccak.t list;
  world : Tn_state.World_state.t;
  chain_id : Tn_state.U256.t;
  basefee_address : Tn_types.Units.Address.t;
  epoch_boundary : Tn_types.Units.Timestamp.t;
  committee : Tn_types.Committee.t;
}

let create ~anchor ~ancestors ~world ~chain_id ~basefee_address ~epoch_boundary
    ~committee =
  {
    anchor;
    ancestors;
    world;
    chain_id;
    basefee_address;
    epoch_boundary;
    committee;
  }

let anchor t = t.anchor
let ancestors t = t.ancestors
let world t = t.world
let chain_id t = t.chain_id
let basefee_address t = t.basefee_address
let epoch_boundary t = t.epoch_boundary
let committee t = t.committee
