(* Shared fixtures for the chunk-30 block-execution spine, in the same slot as
   tx_vectors.ml and trie_vectors.ml: a plain module NOT listed in test/dune's
   (names ...), so dune links it into every test binary.

   Two things here are worth reading before the tests that use them.

   (1) THE MINIATURE ASSEMBLER is test_creation.ml's and test_executor.ml's,
   extended with the three opcodes this chunk's fixtures need (CALL, LOG1 and a
   twenty-byte PUSH). Every fixture contract is spelled out opcode by opcode so
   the storage a test predicts can be read off the code.

   (2) THE SYNTHETIC SIGNER. The port carries no signing function on purpose:
   {!Tn_evm.Secp256k1} is recovery only. It does not need one. Recovery is a
   total function of the signing hash and the (r, s, parity) triple, so ANY
   triple that recovers at all IS a genuine signature by whatever address it
   recovers to. The fixtures therefore pick the triple and read the sender back
   with {!Tn_evm.Tx_recovery.recover_signer}, then seed that address. Varying
   [s] alone varies the sender while leaving the payload untouched, which is how
   a block gets several distinct senders each at nonce zero. *)

module U256 = Tn_state.U256
module Nonce = Tn_state.Nonce
module Account = Tn_state.Account
module World_state = Tn_state.World_state
module Units = Tn_types.Units
module Address = Tn_types.Units.Address
module Digest = Tn_crypto.Digest
module Digests = Tn_types.Digests
module Env = Tn_evm.Env
module Opcode = Tn_evm.Opcode
module Block_hashes = Tn_evm.Block_hashes
module Batch_position = Tn_evm.Batch_position
module Block_context = Tn_evm.Block_context
module Epoch_boundary = Tn_evm.Epoch_boundary
module Transaction = Tn_evm.Transaction
module Tx_envelope = Tn_evm.Tx_envelope
module Tx_payload = Tn_evm.Tx_payload
module Tx_signature = Tn_evm.Tx_signature
module Tx_recovery = Tn_evm.Tx_recovery

let get = function Some x -> x | None -> Alcotest.fail "expected Some"

let get_ok = function
  | Ok x -> x
  | Error _ -> Alcotest.fail "expected Ok"

let u n = get (U256.of_int n)
let nonce_of n = get (Nonce.of_int n)
let width_of n = get (Opcode.Push_bytes.of_int n)
let topics_of n = get (Tn_evm.Topic_count.of_int n)

let hex s =
  let digit c =
    match c with
    | '0' .. '9' -> Char.code c - Char.code '0'
    | 'a' .. 'f' -> Char.code c - Char.code 'a' + 10
    | 'A' .. 'F' -> Char.code c - Char.code 'A' + 10
    | _ -> 0
  in
  String.init
    (String.length s / 2)
    (fun i ->
      Char.chr ((digit (String.get s (2 * i)) lsl 4) lor digit (String.get s ((2 * i) + 1))))

let to_hex s =
  let buf = Buffer.create (2 * String.length s) in
  String.iter (fun c -> Buffer.add_string buf (Printf.sprintf "%02x" (Char.code c))) s;
  Buffer.contents buf

(* A twenty-byte address whose last byte is [n], distinct from the precompiles
   0x01..0x0a for any [n] outside that range and from the three system-contract
   addresses, none of which ends in a low byte with nineteen leading zeros. *)
let address_of n =
  get (Address.of_bytes (String.make (Address.length - 1) '\000' ^ String.make 1 (Char.chr n)))

(* ---------- the miniature assembler ---------- *)

let byte b = String.make 1 (Char.chr b)
let op o = byte (Opcode.to_byte o)
let bytes_of parts = String.concat "" parts
let push0 = op Opcode.Push0
let push1 n = op (Opcode.Push (width_of 1)) ^ byte n

let push_bytes s =
  op (Opcode.Push (width_of (String.length s))) ^ s

let push_int ~width n =
  push_bytes (String.init width (fun i -> Char.chr ((n lsr ((width - 1 - i) * 8)) land 0xff)))

(* ---------- fixture contracts ---------- *)

(* CALLER; PUSH0; SSTORE; STOP. SSTORE pops the key first, so slot 0 receives
   the caller's address as a word. *)
let caller_recorder = bytes_of [ op Opcode.Caller; push0; op Opcode.Sstore; op Opcode.Stop ]

(* PUSH1 v; PUSH1 k; SSTORE; STOP. Writes [v] into slot [k] of whatever account
   runs it. *)
let slot_writer ~slot ~value = bytes_of [ push1 value; push1 slot; op Opcode.Sstore; op Opcode.Stop ]

(* A zero-value CALL into [callee] with no calldata, then STOP. CALL pops
   gas, address, value, argsOffset, argsSize, retOffset, retSize with gas on
   top, so the pushes run in the reverse of that order. The forwarded gas is a
   flat 1_000_000, far above what the callee's single SSTORE costs. *)
let sub_caller ~callee =
  bytes_of
    [
      push0 (* retSize *);
      push0 (* retOffset *);
      push0 (* argsSize *);
      push0 (* argsOffset *);
      push0 (* value *);
      push_bytes (Address.to_bytes callee);
      push_int ~width:3 1_000_000;
      op Opcode.Call;
      op Opcode.Stop;
    ]

(* PUSH1 topic; PUSH0 size; PUSH0 offset; LOG1; STOP. LOG1 pops offset, size
   then the topic, so the topic is pushed first. A log from a system call is
   what the block-bloom test proves never reaches the header. *)
let log_emitter ~topic =
  bytes_of
    [ push1 topic; push0; push0; op (Opcode.Log (topics_of 1)); op Opcode.Stop ]

(* ---------- worlds ---------- *)

let account ~nonce ~balance = Account.make ~nonce:(nonce_of nonce) ~balance:(u balance)

let world_seed pairs =
  List.fold_left (fun w (address, acct) -> World_state.set_account w address acct) World_state.empty pairs

let with_code world address code =
  World_state.set_account world address
    (Account.with_code (Account.make ~nonce:Nonce.zero ~balance:U256.zero) code)

let present world address =
  List.exists (fun (a, _) -> Address.equal a address) (World_state.accounts world)

let slot world address key = World_state.storage world address (u key)

let slot_hex world address key = to_hex (U256.to_be_bytes (slot world address key))

let slots_set world address =
  Tn_state.Storage.bindings (Account.storage (World_state.account world address))
  |> List.filter (fun (_, value) -> not (U256.is_zero value))
  |> List.length

(* ---------- digests ---------- *)

let digest32 bytes = Digests.Output_digest.of_digest (get (Digest.of_bytes bytes))
let batch_digest32 bytes = Digests.Batch_digest.of_digest (get (Digest.of_bytes bytes))
let zero_output_digest = digest32 (String.make 32 '\000')

(* A distinct, nonzero, non-repeating consensus root and batch digest. *)
let consensus_root = digest32 (String.init 32 (fun i -> Char.chr (0x40 + i)))
let batch_digest = batch_digest32 (String.init 32 (fun i -> Char.chr (0x80 + i)))
let parent_hash = Tn_keccak.digest "chunk-30 parent block"

(* ---------- block environment and context ---------- *)

let coinbase = address_of 0xc3

let block_env ?(number = 1000) ?(timestamp = 1_700_000_000) ?(gas_limit = 30_000_000)
    ?(basefee = 0) ?(prevrandao = 0) () =
  Env.Block.make ~coinbase ~timestamp:(u timestamp) ~number:(u number) ~prevrandao:(u prevrandao)
    ~gas_limit:(u gas_limit) ~basefee:(u basefee) ~chain_id:(u 1) ~hashes:Block_hashes.empty

let position_of ~batch_index ~worker_id =
  get (Batch_position.of_batch ~batch_index ~worker_id:(get (Units.Worker_id.of_int worker_id)))

let sequence_number ~epoch ~round =
  Units.Sequence_number.of_epoch_round
    (get (Units.Epoch.of_int epoch))
    (get (Tn_types.Round.of_int round))

(* The context every spine test starts from. The defaults are a first batch of a
   non-genesis block on an open epoch boundary; each test overrides only what it
   is about. Construction failures are surfaced by the caller, so the two tests
   that are ABOUT a construction failure use [Block_context.make] directly. *)
let context ?(number = 1000) ?(timestamp = 1_700_000_000) ?(gas_limit = 30_000_000)
    ?(basefee = 0) ?(prevrandao = 0) ?(batch_index = 0) ?(worker_id = 0)
    ?(boundary = Epoch_boundary.Open) ?(consensus_root = consensus_root)
    ?(parent_hash = parent_hash) ?(batch_digest = batch_digest) ?(epoch = 7) ?(round = 9) () =
  get_ok
    (Block_context.make
       ~block:(block_env ~number ~timestamp ~gas_limit ~basefee ~prevrandao ())
       ~parent_hash ~consensus_root
       ~nonce:(sequence_number ~epoch ~round)
       ~batch_digest
       ~position:(position_of ~batch_index ~worker_id)
       ~boundary)

(* ---------- synthetic signed envelopes ---------- *)

(* The x coordinate of the secp256k1 generator: a point on the curve, so it is a
   valid [r] for every signing hash. *)
let curve_r = get (U256.of_hex "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

(* [signer] indexes the signature's [s], which is what varies the recovered
   address while leaving the payload alone. It must be at least one (a zero
   scalar does not recover) and stays far below secp256k1n/2, so the EIP-2
   low-s gate passes. *)
let sign ~signer payload =
  Tx_envelope.make ~payload ~signature:(Tx_signature.make ~parity:false ~r:curve_r ~s:(u signer))

let legacy_envelope ~signer ?(nonce = 0) ?(gas_price = 1) ?(value = 0) ?(data = "")
    ?(kind = Transaction.Call (address_of 0xb2)) ~gas_limit () =
  sign ~signer
    (Tx_payload.legacy ~nonce:(nonce_of nonce) ~gas_price:(u gas_price) ~gas_limit ~kind
       ~value:(u value) ~data ~chain_id:None)

let sender_of envelope =
  match Tx_recovery.recover_signer envelope with
  | Ok address -> address
  | Error e -> Alcotest.failf "fixture signature does not recover: %s" (Tx_recovery.error_to_string e)

(* Seat every envelope's recovered sender at the given nonce with a balance that
   covers any gas limit these fixtures use. *)
let fund world ?(nonce = 0) ?(balance = 1_000_000_000_000) envelopes =
  List.fold_left
    (fun w envelope -> World_state.set_account w (sender_of envelope) (account ~nonce ~balance))
    world envelopes
