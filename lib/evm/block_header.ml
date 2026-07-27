(* The execution-layer header. The record is private to this module and
   [assemble] is its only producer, so every field is either copied from a
   context the constructor already validated, read off an outcome, or a pinned
   constant. Nothing here recomputes a value another module owns. *)

module U256 = Tn_state.U256
module Digest = Tn_crypto.Digest
module Digests = Tn_types.Digests
module Units = Tn_types.Units
module Rlp = Tn_rlp.Rlp

type root_field =
  | State_root
  | Transactions_root
  | Receipts_root
  | Withdrawals_root

let root_field_to_string = function
  | State_root -> "state root"
  | Transactions_root -> "transactions root"
  | Receipts_root -> "receipts root"
  | Withdrawals_root -> "withdrawals root"

type error = Root_unrepresentable of root_field | Epoch_close_state_deferred

let error_to_string = function
  | Root_unrepresentable field ->
      Printf.sprintf "%s is not 32 bytes" (root_field_to_string field)
  | Epoch_close_state_deferred ->
      "the epoch-close state transitions are deferred, so a closing block's \
       state root is not yet computable"

(* The two pinned constants are decoded through [U256.of_hex] rather than
   through a second hand-rolled decoder: it already refuses anything but exactly
   sixty-four hex digits and collapses a single bad digit to [None]
   ([u256.ml:107-123]), and a [U256] is exactly thirty-two bytes wide, so
   [Hash32.of_bytes] below cannot fail on its output.

   [Hash32.of_bytes] is nevertheless the gate rather than an assumption, and the
   collapse to [Hash32.zero] is the honest limit the .mli states: a typo in a
   literal lands as thirty-two zero bytes, which is never a plausible constant
   and is loud in the pin test. *)
let hash32_of_hex hex =
  Option.value ~default:Hash32.zero
    (Option.bind (U256.of_hex hex) (fun word ->
         Hash32.of_bytes (U256.to_be_bytes word)))

let empty_requests_hash =
  hash32_of_hex
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

let empty_ommer_root =
  hash32_of_hex
    "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"

type t = {
  parent_hash : Tn_keccak.t;
  ommers_hash : Digests.Batch_digest.t;
  beneficiary : Units.Address.t;
  state_root : Hash32.t;
  transactions_root : Hash32.t;
  receipts_root : Hash32.t;
  logs_bloom : Bloom.t;
  position : Batch_position.t;
  number : int;
  gas_limit : int;
  gas_used : int;
  timestamp : int;
  extra_data : string;
  mix_hash : U256.t;
  nonce : Units.Sequence_number.t;
  base_fee_per_gas : U256.t;
  withdrawals : Withdrawal.t list;
  withdrawals_root : Hash32.t;
  parent_beacon_block_root : Digests.Output_digest.t;
  blob_gas_used : int;
  excess_blob_gas : int;
  requests_hash : Hash32.t;
}

let ( let* ) = Result.bind

(* The 32-byte gate. [Block_roots] and [Epoch_boundary] hand back plain strings
   because [block_roots.ml:5-10] collapses an unreachable [Duplicate_key] into
   an error STRING rather than a root; this is where that becomes a visible
   error instead of a header nobody else can reproduce. *)
let gate field root =
  Option.to_result ~none:(Root_unrepresentable field) (Hash32.of_bytes root)

let assemble ~context ~outcome =
  let boundary = Block_context.boundary context in
  match boundary with
  | Epoch_boundary.Closing _ -> Error Epoch_close_state_deferred
  | Epoch_boundary.Open ->
      let commitment = Epoch_boundary.commitment boundary in
      let block = Block_context.block context in
      let* state_root =
        gate State_root (Block_roots.state_root (Block_execution.world outcome))
      in
      let* transactions_root =
        gate Transactions_root
          (Block_roots.transactions_root_of
             (Block_execution.transactions outcome))
      in
      let* receipts_root =
        gate Receipts_root
          (Block_roots.receipts_root (Block_execution.receipts outcome))
      in
      let* withdrawals_root =
        gate Withdrawals_root (Epoch_boundary.withdrawals_root commitment)
      in
      Ok
        {
          parent_hash = Block_context.parent_hash context;
          ommers_hash = Block_context.batch_digest context;
          beneficiary = Env.Block.coinbase block;
          state_root;
          transactions_root;
          receipts_root;
          logs_bloom = Block_execution.logs_bloom outcome;
          position = Block_context.position context;
          number = Block_context.number context;
          gas_limit = Block_context.gas_limit context;
          gas_used = Block_execution.gas_used outcome;
          timestamp = Block_context.timestamp context;
          extra_data = Epoch_boundary.extra_data commitment;
          mix_hash = Env.Block.prevrandao block;
          nonce = Block_context.nonce context;
          base_fee_per_gas = Env.Block.basefee block;
          withdrawals = Epoch_boundary.withdrawals commitment;
          withdrawals_root;
          parent_beacon_block_root = Block_context.consensus_root context;
          blob_gas_used = 0;
          excess_blob_gas = 0;
          requests_hash = empty_requests_hash;
        }

let parent_hash t = t.parent_hash
let ommers_hash t = t.ommers_hash
let beneficiary t = t.beneficiary
let state_root t = t.state_root
let transactions_root t = t.transactions_root
let receipts_root t = t.receipts_root
let logs_bloom t = t.logs_bloom
let position t = t.position

(* Derived rather than stored, so the header's [difficulty] and the EIP-4788
   gate are two reads of one value. *)
let difficulty t = Batch_position.word t.position

let number t = t.number
let gas_limit t = t.gas_limit
let gas_used t = t.gas_used
let timestamp t = t.timestamp
let extra_data t = t.extra_data
let mix_hash t = t.mix_hash
let nonce t = t.nonce
let base_fee_per_gas t = t.base_fee_per_gas
let withdrawals t = t.withdrawals
let withdrawals_root t = t.withdrawals_root
let parent_beacon_block_root t = t.parent_beacon_block_root
let blob_gas_used t = t.blob_gas_used
let excess_blob_gas t = t.excess_blob_gas
let requests_hash t = t.requests_hash

(* Eight raw big-endian bytes, because the Rust field is a [B64] and not a
   scalar. A pure [String.init] gather like [secp256k1.ml:91]; the mask keeps
   [Char.chr] total. *)
let nonce_bytes n =
  let word = Units.Sequence_number.to_int64 n in
  String.init 8 (fun i ->
      Char.chr
        (Int64.to_int
           (Int64.logand (Int64.shift_right_logical word ((7 - i) * 8)) 0xffL)))

(* Twenty-one chunks in protocol-canonical order. [encode_list] takes
   ALREADY-ENCODED chunks and computes the header itself ([rlp.mli:88-93]), so
   each line below is the whole of that field's encoding and the byte-string
   rule versus the scalar rule is visible one line at a time. *)
let encode_rlp t =
  Rlp.encode_list
    [
      Rlp.encode_bytes (Tn_keccak.to_bytes t.parent_hash);
      Rlp.encode_bytes
        (Digest.to_bytes (Digests.Batch_digest.to_digest t.ommers_hash));
      Rlp.encode_bytes (Units.Address.to_bytes t.beneficiary);
      Rlp.encode_bytes (Hash32.to_bytes t.state_root);
      Rlp.encode_bytes (Hash32.to_bytes t.transactions_root);
      Rlp.encode_bytes (Hash32.to_bytes t.receipts_root);
      Rlp.encode_bytes (Bloom.to_bytes t.logs_bloom);
      Rlp.encode_scalar (U256.to_be_bytes (Batch_position.word t.position));
      Rlp.encode_nat t.number;
      Rlp.encode_nat t.gas_limit;
      Rlp.encode_nat t.gas_used;
      Rlp.encode_nat t.timestamp;
      Rlp.encode_bytes t.extra_data;
      Rlp.encode_bytes (U256.to_be_bytes t.mix_hash);
      Rlp.encode_bytes (nonce_bytes t.nonce);
      Rlp.encode_scalar (U256.to_be_bytes t.base_fee_per_gas);
      Rlp.encode_bytes (Hash32.to_bytes t.withdrawals_root);
      Rlp.encode_nat t.blob_gas_used;
      Rlp.encode_nat t.excess_blob_gas;
      Rlp.encode_bytes
        (Digest.to_bytes
           (Digests.Output_digest.to_digest t.parent_beacon_block_root));
      Rlp.encode_bytes (Hash32.to_bytes t.requests_hash);
    ]

let hash t = Tn_keccak.digest (encode_rlp t)

(* Every stored field, [withdrawals] included: the RLP does not commit to the
   list, so equality is the only place a silently dropped withdrawal shows
   up. *)
let equal a b =
  Tn_keccak.equal a.parent_hash b.parent_hash
  && Digests.Batch_digest.equal a.ommers_hash b.ommers_hash
  && Units.Address.equal a.beneficiary b.beneficiary
  && Hash32.equal a.state_root b.state_root
  && Hash32.equal a.transactions_root b.transactions_root
  && Hash32.equal a.receipts_root b.receipts_root
  && Bloom.equal a.logs_bloom b.logs_bloom
  && Batch_position.equal a.position b.position
  && a.number = b.number
  && a.gas_limit = b.gas_limit
  && a.gas_used = b.gas_used
  && a.timestamp = b.timestamp
  && String.equal a.extra_data b.extra_data
  && U256.equal a.mix_hash b.mix_hash
  && Units.Sequence_number.equal a.nonce b.nonce
  && U256.equal a.base_fee_per_gas b.base_fee_per_gas
  && List.equal Withdrawal.equal a.withdrawals b.withdrawals
  && Hash32.equal a.withdrawals_root b.withdrawals_root
  && Digests.Output_digest.equal a.parent_beacon_block_root
       b.parent_beacon_block_root
  && a.blob_gas_used = b.blob_gas_used
  && a.excess_blob_gas = b.excess_blob_gas
  && Hash32.equal a.requests_hash b.requests_hash
