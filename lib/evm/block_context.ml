(* One block's execution context. The record holds the seven constructor
   arguments plus the three narrowed integers, so the narrowing happens exactly
   once, at the only place a [t] can be born. *)

module U256 = Tn_state.U256
module Digest = Tn_crypto.Digest
module Digests = Tn_types.Digests
module Units = Tn_types.Units

type block_field = Number | Timestamp | Gas_limit

let block_field_to_string = function
  | Number -> "number"
  | Timestamp -> "timestamp"
  | Gas_limit -> "gas limit"

type error =
  | Genesis_consensus_root_not_zero
  | Block_field_above_int of { field : block_field }

let error_to_string = function
  | Genesis_consensus_root_not_zero ->
      "block zero carries a nonzero consensus root"
  | Block_field_above_int { field } ->
      Printf.sprintf "block %s does not fit a native int"
        (block_field_to_string field)

type t = {
  block : Env.Block.t;
  parent_hash : Tn_keccak.t;
  consensus_root : Digests.Output_digest.t;
  nonce : Units.Sequence_number.t;
  batch_digest : Digests.Batch_digest.t;
  position : Batch_position.t;
  boundary : Epoch_boundary.t;
  number : int;
  timestamp : int;
  gas_limit : int;
}

let ( let* ) = Result.bind

(* [U256.to_int] is the one narrowing in this chunk. Its [None] is threaded with
   [Option.to_result] rather than defaulted, because telcoin's [saturating_to()]
   is precisely the silent clamp this refuses to reproduce. *)
let narrow field word =
  Option.to_result ~none:(Block_field_above_int { field }) (U256.to_int word)

(* The 32 bytes telcoin compares [parent_beacon_block_root] against at genesis
   ([block.rs:642-665]). [Digests] exposes only [to_digest]/[to_hex], so the
   bytes come through [Tn_crypto.Digest.to_bytes]. *)
let zero_root_bytes = String.make Digest.length '\000'

let consensus_root_is_zero root =
  String.equal
    (Digest.to_bytes (Digests.Output_digest.to_digest root))
    zero_root_bytes

let make ~block ~parent_hash ~consensus_root ~nonce ~batch_digest ~position
    ~boundary =
  let* number = narrow Number (Env.Block.number block) in
  let* timestamp = narrow Timestamp (Env.Block.timestamp block) in
  let* gas_limit = narrow Gas_limit (Env.Block.gas_limit block) in
  if number = 0 && not (consensus_root_is_zero consensus_root) then
    Error Genesis_consensus_root_not_zero
  else
    Ok
      {
        block;
        parent_hash;
        consensus_root;
        nonce;
        batch_digest;
        position;
        boundary;
        number;
        timestamp;
        gas_limit;
      }

let block t = t.block
let parent_hash t = t.parent_hash
let consensus_root t = t.consensus_root
let nonce t = t.nonce
let batch_digest t = t.batch_digest
let position t = t.position
let boundary t = t.boundary
let number t = t.number
let timestamp t = t.timestamp
let gas_limit t = t.gas_limit
let is_genesis t = t.number = 0
let first_batch t = Batch_position.is_first_batch t.position

(* The three narrowed integers are a function of [block], so comparing the seven
   inputs decides equality outright. *)
let equal a b =
  Env.Block.equal a.block b.block
  && Tn_keccak.equal a.parent_hash b.parent_hash
  && Digests.Output_digest.equal a.consensus_root b.consensus_root
  && Units.Sequence_number.equal a.nonce b.nonce
  && Digests.Batch_digest.equal a.batch_digest b.batch_digest
  && Batch_position.equal a.position b.position
  && Epoch_boundary.equal a.boundary b.boundary
