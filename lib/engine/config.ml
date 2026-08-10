type t = {
  anchor : Anchor.t;
  ancestors : Tn_keccak.t list;
  world : Tn_state.World_state.t;
  chain_id : Tn_state.U256.t;
  basefee_address : Tn_types.Units.Address.t;
  epoch_boundary : Tn_types.Units.Timestamp.t;
  committee : Tn_types.Committee.t;
  fork_schedule : Tn_evm.Fork_schedule.t;
}

let create_on_schedule ~fork_schedule ~anchor ~ancestors ~world ~chain_id
    ~basefee_address ~epoch_boundary ~committee =
  {
    anchor;
    ancestors;
    world;
    chain_id;
    basefee_address;
    epoch_boundary;
    committee;
    fork_schedule;
  }

(* [create] is [create_on_schedule] on [Fork_schedule.testnet] - Shanghai,
   Cancun and Prague all at timestamp 0. It is the chain the port modelled
   before a schedule existed, so an engine configured without one executes
   exactly the blocks it executed before. [Engine.resume]'s [?fork_schedule]
   default restates the same value for resumption. TWO production sites
   forward a chain's own schedule: [Chain_spec.engine_config] at cold start,
   and [Driver.resume], which passes [Chain_spec.fork_schedule] to
   [Engine.resume ?fork_schedule]. A second constructor rather than an
   optional argument, for the reason [Env.Block.make] gives: OCaml erases an
   optional argument only when a positional argument follows it, and this one
   has none. *)
let create ~anchor ~ancestors ~world ~chain_id ~basefee_address ~epoch_boundary
    ~committee =
  create_on_schedule ~fork_schedule:Tn_evm.Fork_schedule.testnet ~anchor
    ~ancestors ~world ~chain_id ~basefee_address ~epoch_boundary ~committee

let anchor t = t.anchor
let ancestors t = t.ancestors
let world t = t.world
let chain_id t = t.chain_id
let basefee_address t = t.basefee_address
let epoch_boundary t = t.epoch_boundary
let committee t = t.committee
let fork_schedule t = t.fork_schedule
