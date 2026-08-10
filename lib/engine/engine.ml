module Digests = Tn_types.Digests
module Units = Tn_types.Units
module Batch_payload = Tn_batch.Batch_payload
module Block_plan = Tn_batch.Block_plan
module Output = Tn_batch.Output
module Nonempty = Tn_std.Nonempty
module Sub_dag = Tn_consensus.Sub_dag
module Consensus_block = Tn_execution.Consensus_block
module Batch_position = Tn_evm.Batch_position
module Block_context = Tn_evm.Block_context
module Block_execution = Tn_evm.Block_execution
module Block_header = Tn_evm.Block_header
module Env = Tn_evm.Env
module Epoch_boundary = Tn_evm.Epoch_boundary
module Fork_schedule = Tn_evm.Fork_schedule
module Hash32 = Tn_evm.Hash32
module Rewards_counter = Tn_evm.Rewards_counter
module U256 = Tn_state.U256
module Committee = Tn_types.Committee

let ( let* ) = Result.bind

type config = Config.t
type output = Output.t
type block = Executed_block.t
type height = Block_number.t

type error =
  | Epoch_sealed
  | Boundary_not_advanced of {
      closed_at : Units.Timestamp.t;
      proposed : Units.Timestamp.t;
    }
  | Plan of Block_plan.error
  | Withdrawals of Rewards_counter.error
  | Context of { number : int; error : Tn_evm.Block_context.error }
  | Execution of { number : int; error : Tn_evm.Block_execution.error }
  | Assembly of { number : int; error : Tn_evm.Block_header.error }

let error_to_string = function
  | Epoch_sealed ->
      "epoch sealed: the closing block is built and the next committee has not \
       been installed"
  | Boundary_not_advanced { closed_at; proposed } ->
      Printf.sprintf
        "epoch boundary %Ld does not advance past the timestamp %Ld at which \
         the last epoch closed"
        (Units.Timestamp.to_sec proposed)
        (Units.Timestamp.to_sec closed_at)
  | Plan error -> "block plan: " ^ Block_plan.error_to_string error
  | Withdrawals error ->
      "withdrawals: " ^ Rewards_counter.error_to_string error
  | Context { number; error } ->
      Printf.sprintf "block %d context: %s" number
        (Tn_evm.Block_context.error_to_string error)
  | Execution { number; error } ->
      Printf.sprintf "block %d execution: %s" number
        (Tn_evm.Block_execution.error_to_string error)
  | Assembly { number; error } ->
      Printf.sprintf "block %d header: %s" number
        (Tn_evm.Block_header.error_to_string error)

(* Where the engine stands in the epoch it is executing. This is what makes
   double-closing unreachable rather than merely unlikely: [committed_at >=
   epoch_boundary] is MONOTONE, so an engine that kept a bare boundary and went
   on folding would close the epoch again on every later output, paying the same
   counts out twice. Upstream avoids it structurally, by tearing the epoch task
   down and restarting it with a fresh boundary, a fresh committee and a cleared
   accumulator (run_epoch.rs:142,227,675); a phase is that teardown expressed as
   a type. *)
type phase =
  | Running of { boundary : Units.Timestamp.t; committee : Committee.t }
      (** The epoch is open: [boundary] is the timestamp an output must reach to
          close it, and [committee] is whose leader counts are accruing. *)
  | Sealed of { closed_at : Units.Timestamp.t; committee : Committee.t }
      (** The closing block is built. [closed_at] is the COMMIT timestamp of the
          output that closed the epoch, which is the timestamp the next epoch's
          boundary must strictly advance past; [committee] is the one that just
          finished, still readable so a driver can decide the next one. *)

(* The engine's whole state. [config] is what it was told and never changes;
   everything else moves as outputs are folded, and all of it is dropped
   together when one fails, which is exactly telcoin's reorg back to the
   pre-output anchor (payload_builder.rs:200-212,300-308). *)
type t = {
  config : Config.t;
  anchor : Anchor.t;
  tip : Executed_block.t option;
  world : Tn_state.World_state.t;
  hashes : Recent_hashes.t;
  rewards : Rewards_counter.t;
  phase : phase;
}

let create config =
  {
    config;
    anchor = Config.anchor config;
    tip = None;
    world = Config.world config;
    hashes =
      Recent_hashes.of_genesis
        (Anchor.hash (Config.anchor config))
        ~ancestors:(Config.ancestors config);
    rewards =
      Rewards_counter.set_committee Rewards_counter.empty
        (Config.committee config);
    phase =
      Running
        {
          boundary = Config.epoch_boundary config;
          committee = Config.committee config;
        };
  }

let config t = t.config
let anchor t = t.anchor
let tip t = t.tip
let height t = Anchor.number t.anchor
let world t = t.world
let recent_hashes t = t.hashes
let rewards t = t.rewards

let phase t = t.phase

(* Whose leader counts the phase is accruing, or whose it just finished. A
   projection of the PHASE rather than of the engine, so a resumed engine reads
   it out of the same one place. *)
let phase_committee = function
  | Running { committee; boundary = _ } -> committee
  | Sealed { committee; closed_at = _ } -> committee

let committee t = phase_committee t.phase

let is_sealed t =
  match t.phase with Running _ -> false | Sealed _ -> true

(* The timestamp a proposed boundary must strictly advance past. On a sealed
   engine it is the commit timestamp that closed the epoch, so the next epoch's
   first output cannot re-close it; on a running one it is the boundary already
   installed, so a caller cannot walk the frontier backwards mid-epoch. *)
let phase_frontier = function
  | Running { boundary; committee = _ } -> boundary
  | Sealed { closed_at; committee = _ } -> closed_at

let frontier t = phase_frontier t.phase

let begin_epoch t ~boundary ~committee =
  let closed_at = frontier t in
  if Units.Timestamp.compare boundary closed_at > 0 then
    Ok
      {
        t with
        (* [clear] strictly AFTER the closing block and BEFORE the new
           committee: the counts the closing block rooted are this epoch's, and
           the next epoch's leaders must resolve through the next epoch's
           addresses. *)
        rewards =
          Rewards_counter.set_committee
            (Rewards_counter.clear t.rewards)
            committee;
        phase = Running { boundary; committee };
      }
  else Error (Boundary_not_advanced { closed_at; proposed = boundary })

(* A big-endian byte string as a word. [U256.of_be_bytes] is an option because
   it refuses a width other than 32, and the plan's mix_hash is 32 bytes by
   construction (both XOR operands are [Tn_crypto.Digest.to_bytes] of a 32-byte
   digest), so the only thing an option buys here is an unreachable arm to
   fabricate a default in. Folding the bytes answers the same value on the
   width that occurs, and answers it totally. *)
let word_of_be_bytes bytes =
  String.fold_left
    (fun acc c ->
      U256.logor (U256.shl acc (U256.of_byte 8)) (U256.of_byte (Char.code c)))
    U256.zero bytes

(* Native ints reach the EVM environment the same way every other u64 does. *)
let word_of_int n = U256.of_u64_bits (Int64.of_int n)

(* A batch's declared fee as the environment's word. The parameter [build_block]
   takes is the WORD and not the [Units.Base_fee.t], because the close block
   inherits the anchor's base fee, which is already a word: routing it through
   the u64 fee type would silently narrow a parent fee that does not fit, and
   "verbatim" would stop being true for exactly the values it matters for. *)
let word_of_base_fee fee = U256.of_u64_bits (Units.Base_fee.to_int64 fee)

(* What one output's blocks build up as they are folded. It starts as a copy of
   the engine's chain state and is settled back onto it only if every block of
   the output succeeds: an [Error] drops this record whole, which is telcoin's
   reorg back to the pre-output anchor (payload_builder.rs:200-212,300-308).
   [produced] is newest first, so a block is prepended rather than appended. *)
type building = {
  anchor : Anchor.t;
  world : Tn_state.World_state.t;
  hashes : Recent_hashes.t;
  produced : Executed_block.t list;
}

let start (state : t) =
  {
    anchor = state.anchor;
    world = state.world;
    hashes = state.hashes;
    produced = [];
  }

(* The last block of a chain-ordered list, or what was tip before it if the
   list is empty. A fold rather than an index: there is no position to get
   wrong. *)
let latest previous produced =
  List.fold_left (fun _ block -> Some block) previous produced

(* One block, from the parameters the plan or the anchor supplies. The engine
   synthesises nothing here: it contributes the parent hash, the height, the
   BLOCKHASH window and the two configured chain facts, and every other field
   is passed through.

   The order is telcoin's and is load-bearing twice. The window is read BEFORE
   the block is built and the assembled hash is pushed AFTER, because a block
   cannot see its own hash; and the world the next block starts from is the
   FINISHED world, not the outcome's, so a closing block's epoch writes are in
   the state its successor reads. *)
let build_block (acc : building) ~config ~boundary ~beneficiary ~timestamp
    ~mix_hash ~gas_limit ~base_fee ~consensus_root ~nonce ~batch_digest
    ~position ~transactions =
  let number = Block_number.succ (Anchor.number acc.anchor) in
  let at = Block_number.to_int number in
  (* The fork level is resolved ONCE per block, here, from the chain's schedule
     and this block's own timestamp, and then rides on the environment. That is
     upstream's shape too: the spec is folded into the per-block configuration
     before the EVM is handed it, so no later step re-derives it and no two
     frames of one block can disagree about which fork they are on. *)
  let block =
    Env.Block.make_at_spec
      ~spec:(Fork_schedule.active_at (Config.fork_schedule config) ~timestamp)
      ~coinbase:beneficiary
      ~timestamp:(U256.of_u64_bits (Units.Timestamp.to_sec timestamp))
      ~number:(word_of_int at)
      ~prevrandao:(word_of_be_bytes mix_hash)
      ~gas_limit:(U256.of_u64_bits gas_limit)
      ~basefee:base_fee
      ~basefee_address:(Config.basefee_address config)
      ~chain_id:(Config.chain_id config)
      ~blob_gasprice:Env.Block.consensus_blob_gasprice
      ~hashes:(Recent_hashes.window acc.hashes)
  in
  let* context =
    Result.map_error
      (fun error -> Context { number = at; error })
      (Block_context.make ~block ~parent_hash:(Anchor.hash acc.anchor)
         ~consensus_root ~nonce ~batch_digest ~position ~boundary)
  in
  let executing error = Execution { number = at; error } in
  let* pre =
    Result.map_error executing (Block_execution.apply_pre_block acc.world ~context)
  in
  (* The BUILDER's stance, not the executor's: a transaction the executor
     refuses is recorded and skipped, because a batch that duplicates another
     worker's transaction is normal operation and telcoin's builder logs it and
     continues ([crates/tn-reth/src/lib.rs:855-866]). *)
  let* outcome, skipped =
    Result.map_error executing
      (Block_execution.run_transactions_skipping_invalid pre ~context
         transactions)
  in
  let* finished =
    Result.map_error executing (Block_execution.finish outcome ~context)
  in
  let world = Block_execution.Finished.world finished in
  Result.map
    (fun header ->
      {
        anchor = Anchor.of_header header;
        world;
        hashes = Recent_hashes.push acc.hashes (Block_header.hash header);
        produced =
          Executed_block.make ~header ~number ~pre_block:pre
            ~transactions:(Block_execution.transactions outcome)
            ~receipts:(Block_execution.receipts outcome)
            ~skipped ~world
            ~close_disposition:
              (Block_execution.Finished.close_disposition finished)
          :: acc.produced;
      })
    (Result.map_error
       (fun error -> Assembly { number = at; error })
       (Block_header.assemble ~context ~finished))

(* One batch's block. The transaction list is the batch's own payload put
   through the drop layer, which is the shorter list telcoin's builder hands
   its executor ([lib.rs:821-835]). The boundary is a PARAMETER rather than a
   constant because exactly one block of a closing output carries the epoch
   commitment and every other block of it is open; the block is otherwise built
   the same way either way, which is what makes the transactions root of a
   closing block equal to the same block's under an open boundary. *)
let block_of_spec config acc spec ~boundary =
  build_block acc ~config ~boundary
    ~beneficiary:(Block_plan.Spec.beneficiary spec)
    ~timestamp:(Block_plan.Spec.timestamp spec)
    ~mix_hash:(Block_plan.Spec.mix_hash spec)
    ~gas_limit:(Block_plan.Spec.gas_limit spec)
    ~base_fee:(word_of_base_fee (Block_plan.Spec.base_fee spec))
    ~consensus_root:(Block_plan.Spec.consensus_root spec)
    ~nonce:(Block_plan.Spec.nonce spec)
    ~batch_digest:(Block_plan.Spec.batch_digest spec)
    ~position:(Block_plan.Spec.position spec)
    ~transactions:(Batch_payload.executable_txs (Block_plan.Spec.batch spec))

(* Settle a finished [building] back onto the engine. Only a whole output ever
   reaches here, which is what makes the fold all-or-nothing. *)
let settle (state : t) built =
  let blocks = List.rev built.produced in
  ( {
      state with
      anchor = built.anchor;
      world = built.world;
      hashes = built.hashes;
      tip = latest state.tip blocks;
    },
    blocks )

(* Everything but the last spec, and the last. A fold that pushes the PREVIOUS
   element rather than an index or a length: there is no position to get wrong
   and no off-by-one to make, and the last element comes from {!Nonempty.last},
   which cannot be absent. *)
let split specs =
  let leading_rev, _ =
    List.fold_left
      (fun (acc, previous) spec ->
        (Option.fold ~none:acc ~some:(fun p -> p :: acc) previous, Some spec))
      ([], None) (Nonempty.to_list specs)
  in
  (List.rev leading_rev, Nonempty.last specs)

(* Seal the epoch behind a closing block. [closed_at] is the output's COMMIT
   timestamp, not the boundary it crossed: the boundary is the frontier the
   epoch was measured against and the commit timestamp is where the epoch
   actually ended, and only the latter is past every output this epoch saw. *)
let seal output (state, blocks) =
  ( {
      state with
      phase =
        Sealed
          { closed_at = Output.committed_at output; committee = committee state };
    },
    blocks )

(* The closing commitment: the 32 bytes that go verbatim into [extra_data] and
   the withdrawal records the header roots.

   The randomness is TAKEN, never recomputed. The sub-DAG already carries the
   keccak256 of the leader certificate's aggregate signature
   ([types/src/primary/output.rs:378-382]), so re-deriving it here would be a
   second implementation of the same rule, free to drift. No width check is
   possible or needed: the sub-DAG carries the 32-byte gate itself, so there is
   no string to measure.

   The counts read are the ones this output already advanced, so the leader of
   the closing output appears in its OWN withdrawals, which is what telcoin's
   ordering at [payload_builder.rs:40] produces. *)
let closing_boundary (state : t) output =
  let randomness =
    Sub_dag.randomness (Consensus_block.sub_dag (Output.consensus output))
  in
  Result.map
    (fun withdrawals -> Epoch_boundary.Closing { randomness; withdrawals })
    (Result.map_error
       (fun error -> Withdrawals error)
       (Rewards_counter.generate_withdrawals state.rewards))

(* The close-epoch empty block (payload_builder.rs:116-160). Four of its header
   fields have no batch to come from, and each is a decision rather than a
   default:

   - the ommers slot takes the ZERO batch digest, not the output digest and not
     the leader's, because there is no batch;
   - the packed difficulty word is zero, which is batch 0 of worker 0, so the
     block IS a first batch and the EIP-4788 consensus-root write runs on it
     exactly as it would on a real output's first block;
   - the base fee and the gas limit are the PARENT's, read off the anchor.
     Verbatim, both of them: a zero parent base fee stays zero rather than
     rising to the protocol floor, because this port has no fee market and
     telcoin copies the field rather than recomputing it.

   The prev_randao is the plan's [mix_hash] unchanged, which on this path is the
   raw output digest with no batch digest to XOR in, and the transaction list is
   empty: the block exists to carry the epoch commitment, not to execute. *)
let close_context (state : t) acc spec ~boundary =
  build_block acc ~config:state.config ~boundary
    ~beneficiary:(Block_plan.Close_spec.beneficiary spec)
    ~timestamp:(Block_plan.Close_spec.timestamp spec)
    ~mix_hash:(Block_plan.Close_spec.mix_hash spec)
    ~gas_limit:(Int64.of_int (Anchor.gas_limit acc.anchor))
    ~base_fee:(Anchor.base_fee acc.anchor)
    ~consensus_root:(Block_plan.Close_spec.consensus_root spec)
    ~nonce:(Block_plan.Close_spec.nonce spec)
    ~batch_digest:Digests.Batch_digest.zero
    ~position:(Batch_position.of_word U256.zero)
    ~transactions:[]

(* The whole closing output: one block, the same all-or-nothing settle the
   batch fold uses, and the epoch sealed behind it. *)
let close_block (state : t) output spec =
  Result.map
    (fun built -> seal output (settle state built))
    (Result.bind (closing_boundary state output) (fun boundary ->
         close_context state (start state) spec ~boundary))

(* The output's blocks, in plan order, all or nothing. The specs are folded AS
   GIVEN: no sort, no filter, no re-derivation, so a batch whose payload is
   empty still produces its block and the plan's certificate-major order is the
   execution order.

   The list is SPLIT at its last element and every leading block is built with
   an open boundary UNCONDITIONALLY. Telcoin sets [close_epoch_for_last_batch]
   at the last index and nowhere else (payload_builder.rs:163-186), so a closing
   epoch commits on exactly one block; splitting is how that stops being a
   property of the plan the engine trusts and starts being one the engine
   cannot violate. The closing block is still a full block: it executes its own
   batch, and only its boundary differs. *)
let build_blocks (state : t) output specs =
  let leading, final = split specs in
  let* acc =
    List.fold_left
      (fun acc spec ->
        Result.bind acc (fun a ->
            block_of_spec state.config a spec ~boundary:Epoch_boundary.Open))
      (Ok (start state)) leading
  in
  if Block_plan.Spec.closes_epoch final then
    Result.bind (closing_boundary state output) (fun boundary ->
        Result.map
          (fun built -> seal output (settle state built))
          (block_of_spec state.config acc final ~boundary))
  else
    Result.map (settle state)
      (block_of_spec state.config acc final ~boundary:Epoch_boundary.Open)

(* The output's leader, whose count this output advances whatever else it
   does. *)
let leader_of output =
  Sub_dag.leader_author (Consensus_block.sub_dag (Output.consensus output))

let execute state output =
  (* First statement, before the boundary recompute, before planning and before
     the branch: telcoin increments the leader count at payload_builder.rs:40,
     ahead of the empty-output test at :99 and the skip return at :113, and
     never rewinds it. An output that produces no block is still an output its
     leader led, and the closing block's withdrawals commit to that. *)
  let rewarded =
    {
      state with
      rewards = Rewards_counter.inc_leader_count state.rewards (leader_of output);
    }
  in
  (* The boundary is read out of the PHASE, so a sealed engine refuses here and
     never reaches the plan: [committed_at >= epoch_boundary] is monotone, and
     an engine that answered a boundary after its epoch closed would close it
     again on this output and pay the same counts out twice. *)
  let* boundary =
    match state.phase with
    | Running { boundary; committee = _ } -> Ok boundary
    | Sealed _ -> Error Epoch_sealed
  in
  let closes_epoch = Output.closes_epoch output ~epoch_boundary:boundary in
  Result.bind
    (Result.map_error
       (fun error -> Plan error)
       (Block_plan.plan output ~closes_epoch))
    (fun plan ->
      match plan with
      | Block_plan.Skip -> Ok (rewarded, [])
      | Block_plan.Close_block spec -> close_block rewarded output spec
      | Block_plan.Batch_blocks specs -> build_blocks rewarded output specs)

(* Everything the engine carries that MOVES: [t] minus [config], which never
   changes and is rebuilt by [resume] from the facts that genuinely are
   configuration, and minus [tip], which a resumed engine legitimately lacks
   because the block behind [anchor] was produced in a previous life.

   Declared HERE, below every function that builds a [t], and not beside [t]:
   the two records share five field names, and a shared name in scope would
   make the record expressions above resolve against the later type instead. *)
type persisted = {
  anchor : Anchor.t;
  world : Tn_state.World_state.t;
  hashes : Recent_hashes.t;
  rewards : Rewards_counter.t;
  phase : phase;
}

(* The only producer of a [persisted], which is what keeps the window full and
   the counts earned by the engine that accumulated them. *)
let snapshot (t : t) : persisted =
  {
    anchor = t.anchor;
    world = t.world;
    hashes = t.hashes;
    rewards = t.rewards;
    phase = t.phase;
  }

(* Rebuild an engine from persistence. Total, mirroring [create]: each field's
   own producers discharge every INTRA-field obligation, and the one genuinely
   cross-field obligation - the window's newest entry must be the anchor's own
   hash, because [build_block] reads BLOCKHASH out of one and [parent_hash]
   out of the other in the same block - is not trusted but re-established: the
   window is re-seated as [Recent_hashes.of_genesis (Anchor.hash p.anchor)]
   over the persisted ancestors, so the invariant is a post-fact of resume.
   [persisted] is a transparent record ([snapshot] is its intended producer,
   not its only possible one), and a hand-built value that skews the pair
   would otherwise execute with a BLOCKHASH answer disagreeing with its own
   parent hash, silently and rootward. On a [snapshot]-produced value the
   re-seat is the identity - [of_genesis (newest t) ~ancestors:(ancestors t)]
   rebuilds the very same window - and on a skewed one it NORMALIZES rather
   than refuses, because refusing would make [resume] fallible for an arm no
   snapshot can reach, rippling through [Checkpoint] and [Driver.resume].

   The reconstructed [Config.t] is the other value minted, and its epoch-shaped
   field is read out of the PHASE - the installed boundary while Running, the
   closing commit time while Sealed - through the same [phase_frontier] that
   [begin_epoch] compares against, so the config describes the engine rather
   than misreporting it. The ancestors are [Recent_hashes.ancestors] and never
   [to_list]: the window's newest entry IS the anchor's own hash (by the
   re-seat above, not by trust), and [Config.create_on_schedule] wants
   everything strictly below it, so the whole window would be one entry too
   long and shift every BLOCKHASH answer by one. [fork_schedule] defaults to
   [Fork_schedule.testnet], mirroring [Config.create]'s cold-start default;
   the schedule is not persisted, so [Driver.resume] must forward the chain's
   own (see the .mli warning). *)
let resume ?(fork_schedule = Fork_schedule.testnet) ~chain_id ~basefee_address
    (p : persisted) : t =
  let ancestors = Recent_hashes.ancestors p.hashes in
  let hashes = Recent_hashes.of_genesis (Anchor.hash p.anchor) ~ancestors in
  {
    config =
      Config.create_on_schedule ~fork_schedule ~anchor:p.anchor ~ancestors
        ~world:p.world ~chain_id ~basefee_address
        ~epoch_boundary:(phase_frontier p.phase)
        ~committee:(phase_committee p.phase);
    anchor = p.anchor;
    tip = None;
    world = p.world;
    hashes;
    rewards = p.rewards;
    phase = p.phase;
  }
