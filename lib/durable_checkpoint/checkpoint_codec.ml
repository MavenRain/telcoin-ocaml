(* The checkpoint's BCS codecs, Tier B of the storage chunk's codec plan.
   Ordered by dependency: a type's codec is written after every codec it names,
   so the file reads bottom-up as the value nests.

   Two rules hold throughout. Every decoder reaches its value through the type's
   own producer, so an invariant the abstract type protects is re-established
   from the wire rather than trusted; and nothing derived or cached is written,
   so a tampered copy of a value the reader recomputes is inert. *)

module Bcs = Tn_codec.Bcs
module Digest = Tn_crypto.Digest
module Public_key = Tn_crypto.Public_key
module Digests = Tn_types.Digests
module Units = Tn_types.Units
module Round = Tn_types.Round
module Authority = Tn_types.Authority
module Authority_id = Tn_types.Authority_id
module Committee_t = Tn_types.Committee
module U256 = Tn_state.U256
module Nonce = Tn_state.Nonce
module Storage_t = Tn_state.Storage
module Account_t = Tn_state.Account
module World_state = Tn_state.World_state
module Hash32 = Tn_evm.Hash32
module Bloom = Tn_evm.Bloom
module Batch_position = Tn_evm.Batch_position
module Withdrawal = Tn_evm.Withdrawal
module Block_header_t = Tn_evm.Block_header
module Rewards_counter = Tn_evm.Rewards_counter
module Anchor = Tn_engine.Anchor
module Recent_hashes_t = Tn_engine.Recent_hashes
module Engine = Tn_engine.Engine
module Checkpoint = Tn_driver.Checkpoint
module Consensus_block = Tn_execution.Consensus_block

(* ------------------------------------------------------------------ *)
(* Scalars                                                             *)
(* ------------------------------------------------------------------ *)

(* A wire u64 the host int cannot hold is refused rather than wrapped: the same
   gate [Record_codec.Meta] applies, restated here because the two libraries
   share no module. *)
let host_int_of_u64 v =
  match Int64.compare v 0L < 0 || Int64.compare v (Int64.of_int max_int) > 0 with
  | true -> None
  | false -> Some (Int64.to_int v)

(* Every count, height and gas figure on this wire: an 8-byte little-endian
   field refined to a non-negative host int. [what] names the field, so a
   refusal says which one it was. *)
let nat what =
  Bcs.refine
    ~inject:(fun v ->
      Option.to_result ~none:(what ^ ": out of range") (host_int_of_u64 v))
    ~project:Int64.of_int Bcs.u64

let u256 =
  Bcs.refine
    ~inject:(fun raw ->
      Option.to_result ~none:"u256: not 32 bytes" (U256.of_be_bytes raw))
    ~project:U256.to_be_bytes
    (Bcs.fixed_bytes 32)

(* The storage door named in [tn_keccak.mli]: a block hash cannot be re-derived
   from anything a resumed node still holds, so it travels as its own bytes. *)
let keccak =
  Bcs.refine
    ~inject:(fun raw ->
      Option.to_result ~none:"keccak digest: wrong width"
        (Tn_keccak.of_stored_bytes raw))
    ~project:Tn_keccak.to_bytes
    (Bcs.fixed_bytes Tn_keccak.length)

let hash32 =
  Bcs.refine
    ~inject:(fun raw ->
      Option.to_result ~none:"32-byte field: wrong width" (Hash32.of_bytes raw))
    ~project:Hash32.to_bytes
    (Bcs.fixed_bytes Hash32.length)

let address =
  Bcs.refine
    ~inject:(fun raw ->
      Option.to_result ~none:"address: wrong width" (Units.Address.of_bytes raw))
    ~project:Units.Address.to_bytes
    (Bcs.fixed_bytes Units.Address.length)

let digest_raw =
  Bcs.refine
    ~inject:(fun raw ->
      Option.to_result ~none:"digest: wrong width" (Digest.of_bytes raw))
    ~project:Digest.to_bytes
    (Bcs.fixed_bytes Digest.length)

let batch_digest =
  Bcs.iso ~inject:Digests.Batch_digest.of_digest
    ~project:Digests.Batch_digest.to_digest digest_raw

let output_digest =
  Bcs.iso ~inject:Digests.Output_digest.of_digest
    ~project:Digests.Output_digest.to_digest digest_raw

let epoch =
  Bcs.refine
    ~inject:(fun v ->
      Option.to_result ~none:"epoch: out of range"
        (Option.bind (host_int_of_u64 v) Units.Epoch.of_int))
    ~project:(fun e -> Int64.of_int (Units.Epoch.to_int e))
    Bcs.u64

let round =
  Bcs.refine
    ~inject:(fun v ->
      Option.to_result ~none:"round: out of range"
        (Option.bind (host_int_of_u64 v) Round.of_int))
    ~project:(fun r -> Int64.of_int (Round.to_int r))
    Bcs.u64

let timestamp =
  Bcs.refine
    ~inject:(fun v ->
      Option.to_result ~none:"timestamp: out of range" (Units.Timestamp.of_sec v))
    ~project:Units.Timestamp.to_sec Bcs.u64

(* The header's [nonce] is the leader's (epoch, round) pair, stored TYPED, so
   the wire carries the pair rather than the packed word: [Sequence_number] has
   no inverse of [to_int64] and needs none. *)
let sequence_number =
  Bcs.iso
    ~inject:(fun (e, r) -> Units.Sequence_number.of_epoch_round e r)
    ~project:(fun n ->
      (Units.Sequence_number.epoch n, Units.Sequence_number.round n))
    (Bcs.pair epoch round)

let nonce =
  Bcs.refine
    ~inject:(fun v ->
      Option.to_result ~none:"account nonce: out of range"
        (Option.bind (host_int_of_u64 v) Nonce.of_int))
    ~project:(fun n -> Int64.of_int (Nonce.to_int n))
    Bcs.u64

let bloom =
  Bcs.refine
    ~inject:(fun raw ->
      Option.to_result ~none:"logs bloom: not 256 bytes" (Bloom.of_bytes raw))
    ~project:Bloom.to_bytes
    (Bcs.fixed_bytes 256)

(* Total in both directions: every 256-bit word is a position. *)
let position =
  Bcs.iso ~inject:Batch_position.of_word ~project:Batch_position.word u256

let withdrawal =
  Bcs.refine
    ~inject:(fun ((index, validator_index, address), amount) ->
      Option.to_result ~none:"withdrawal: refused by make"
        (Withdrawal.make ~index ~validator_index ~address ~amount))
    ~project:(fun w ->
      ( (Withdrawal.index w, Withdrawal.validator_index w, Withdrawal.address w),
        Withdrawal.amount w ))
    (Bcs.pair
       (Bcs.triple (nat "withdrawal index")
          (nat "withdrawal validator index")
          address)
       (nat "withdrawal amount"))

let public_key =
  Bcs.refine
    ~inject:(fun raw ->
      Option.to_result ~none:"protocol key: not a public key"
        (Public_key.of_bytes raw))
    ~project:Public_key.to_bytes Bcs.bytes

let authority_id =
  Bcs.refine
    ~inject:(fun raw ->
      Option.to_result ~none:"authority id: wrong width"
        (Authority_id.of_bytes raw))
    ~project:Authority_id.to_bytes Bcs.bytes

let authority =
  Bcs.iso
    ~inject:(fun (protocol_key, execution_address) ->
      Authority.make ~protocol_key ~execution_address)
    ~project:(fun a ->
      (Authority.protocol_key a, Authority.execution_address a))
    (Bcs.pair public_key address)

(* ------------------------------------------------------------------ *)
(* B1-B11                                                              *)
(* ------------------------------------------------------------------ *)

let storage =
  Bcs.iso
    ~inject:
      (List.fold_left
         (fun s (slot, value) -> Storage_t.set s slot value)
         Storage_t.empty)
    ~project:Storage_t.bindings
    (Bcs.sorted_map u256 u256 ~compare:U256.compare)

let account =
  Bcs.iso
    ~inject:(fun ((nonce, balance), (code, storage)) ->
      Account_t.with_storage
        (Account_t.with_code (Account_t.make ~nonce ~balance) code)
        storage)
    ~project:(fun a ->
      ( (Account_t.nonce a, Account_t.balance a),
        (Account_t.code a, Account_t.storage a) ))
    (Bcs.pair (Bcs.pair nonce u256) (Bcs.pair Bcs.bytes storage))

let world_state =
  Bcs.iso
    ~inject:
      (List.fold_left
         (fun w (addr, acct) -> World_state.set_account w addr acct)
         World_state.empty)
    ~project:World_state.accounts
    (Bcs.sorted_map address account ~compare:Units.Address.compare)

(* B4, the twenty-two stored header fields. Nested pairs and triples because
   the codec algebra offers no wider product; the projection lists them in the
   record's declaration order, so a transposition of two same-typed fields is
   the one error the shape cannot catch and the suite's round trip does. *)
let block_header =
  Bcs.iso
    ~inject:(fun
        ( ( (parent_hash, ommers_hash, beneficiary),
            (state_root, transactions_root, receipts_root) ),
          ( ( (logs_bloom, position, number),
              (gas_limit, gas_used, timestamp) ),
            ( ( (extra_data, mix_hash, nonce),
                (base_fee_per_gas, withdrawals, withdrawals_root) ),
              ( (parent_beacon_block_root, blob_gas_used, excess_blob_gas),
                requests_hash ) ) ) )
      ->
      Block_header_t.of_persisted ~parent_hash ~ommers_hash ~beneficiary
        ~state_root ~transactions_root ~receipts_root ~logs_bloom ~position
        ~number ~gas_limit ~gas_used ~timestamp ~extra_data ~mix_hash ~nonce
        ~base_fee_per_gas ~withdrawals ~withdrawals_root
        ~parent_beacon_block_root ~blob_gas_used ~excess_blob_gas
        ~requests_hash)
    ~project:(fun h ->
      ( ( ( Block_header_t.parent_hash h,
            Block_header_t.ommers_hash h,
            Block_header_t.beneficiary h ),
          ( Block_header_t.state_root h,
            Block_header_t.transactions_root h,
            Block_header_t.receipts_root h ) ),
        ( ( ( Block_header_t.logs_bloom h,
              Block_header_t.position h,
              Block_header_t.number h ),
            ( Block_header_t.gas_limit h,
              Block_header_t.gas_used h,
              Block_header_t.timestamp h ) ),
          ( ( ( Block_header_t.extra_data h,
                Block_header_t.mix_hash h,
                Block_header_t.nonce h ),
              ( Block_header_t.base_fee_per_gas h,
                Block_header_t.withdrawals h,
                Block_header_t.withdrawals_root h ) ),
            ( ( Block_header_t.parent_beacon_block_root h,
                Block_header_t.blob_gas_used h,
                Block_header_t.excess_blob_gas h ),
              Block_header_t.requests_hash h ) ) ) ))
    (Bcs.pair
       (Bcs.pair
          (Bcs.triple keccak batch_digest address)
          (Bcs.triple hash32 hash32 hash32))
       (Bcs.pair
          (Bcs.pair
             (Bcs.triple bloom position (nat "block number"))
             (Bcs.triple (nat "gas limit") (nat "gas used")
                (nat "block timestamp")))
          (Bcs.pair
             (Bcs.pair
                (Bcs.triple Bcs.bytes u256 sequence_number)
                (Bcs.triple u256 (Bcs.list withdrawal) hash32))
             (Bcs.pair
                (Bcs.triple output_digest (nat "blob gas used")
                   (nat "excess blob gas"))
                hash32))))

(* B5. Discriminated exactly as [Anchor.header] is: a genesis anchor is the one
   case where a parent exists and no header for it does. *)
let anchor =
  Bcs.sum
    [
      Bcs.case ~index:0
        (Bcs.triple keccak u256 (nat "anchor gas limit"))
        ~inject:(fun (hash, base_fee, gas_limit) ->
          Anchor.of_genesis ~hash ~base_fee ~gas_limit)
        ~project:(fun a ->
          Option.fold
            ~none:
              (Some (Anchor.hash a, Anchor.base_fee a, Anchor.gas_limit a))
            ~some:(fun (_ : Block_header_t.t) -> None)
            (Anchor.header a));
      Bcs.case ~index:1 block_header ~inject:Anchor.of_header
        ~project:Anchor.header;
    ]

let recent_hashes =
  Bcs.iso
    ~inject:(fun (newest, ancestors) ->
      Recent_hashes_t.of_genesis newest ~ancestors)
    ~project:(fun w ->
      (Recent_hashes_t.newest w, Recent_hashes_t.ancestors w))
    (Bcs.pair keccak (Bcs.list keccak))

let committee =
  Bcs.refine
    ~inject:(fun (epoch, authorities) ->
      Result.map_error Committee_t.error_to_string
        (Committee_t.create ~epoch authorities))
    ~project:(fun c -> (Committee_t.epoch c, Committee_t.authorities c))
    (Bcs.pair epoch (Bcs.list authority))

(* [n] increments rather than a field-wise producer, on purpose: the counter's
   own four operations stay its only writers. The cost is O(total leader count),
   which is the number of outputs the epoch has executed - the same order as the
   log replay the store already does at open - and the payload's body tag is
   checked before any of it runs, so a corrupt file cannot drive the fold. *)
let rec bump_n counter id n =
  match n <= 0 with
  | true -> counter
  | false -> bump_n (Rewards_counter.inc_leader_count counter id) id (n - 1)

let rewards_counter =
  Bcs.iso
    ~inject:(fun (committee, counts) ->
      List.fold_left
        (fun acc (id, n) -> bump_n acc id n)
        (Option.fold ~none:Rewards_counter.empty
           ~some:(Rewards_counter.set_committee Rewards_counter.empty)
           committee)
        counts)
    ~project:(fun r ->
      (Rewards_counter.committee r, Rewards_counter.leader_counts r))
    (Bcs.pair
       (Bcs.option committee)
       (Bcs.sorted_map authority_id Bcs.u32 ~compare:Authority_id.compare))

let phase =
  Bcs.sum
    [
      Bcs.case ~index:0 (Bcs.pair timestamp committee)
        ~inject:(fun (boundary, committee) ->
          Engine.Running { boundary; committee })
        ~project:(function
          | Engine.Running { boundary; committee } -> Some (boundary, committee)
          | Engine.Sealed _ -> None);
      Bcs.case ~index:1 (Bcs.pair timestamp committee)
        ~inject:(fun (closed_at, committee) ->
          Engine.Sealed { closed_at; committee })
        ~project:(function
          | Engine.Sealed { closed_at; committee } -> Some (closed_at, committee)
          | Engine.Running _ -> None);
    ]

let engine_persisted =
  Bcs.iso
    ~inject:(fun ((anchor, world, hashes), (rewards, phase)) ->
      { Engine.anchor; world; hashes; rewards; phase })
    ~project:(fun (p : Engine.persisted) ->
      ( (p.Engine.anchor, p.Engine.world, p.Engine.hashes),
        (p.Engine.rewards, p.Engine.phase) ))
    (Bcs.pair
       (Bcs.triple anchor world_state recent_hashes)
       (Bcs.pair rewards_counter phase))

(* B11. The decode side NAMES [Checkpoint.of_execution]: that is the whole
   reason this codec is not a plain pairing, and the window is handed over
   exactly as it was stored, never renormalised on the way through. *)
let checkpoint =
  Bcs.iso
    ~inject:(fun (engine, last_executed) ->
      Checkpoint.of_execution engine ~last_executed)
    ~project:(fun c -> (Checkpoint.engine c, Checkpoint.last_executed c))
    (Bcs.pair engine_persisted (Bcs.option Consensus_block.codec))
