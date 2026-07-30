(* The port of BatchValidator::validate_batch (validator.rs:39-82 at
   telcoin-network 5dbb764e). Everything here is pure: the three snapshot
   fields, the eight rules in Rust's order, and the peer-penalty map that
   makes the error identity observable. *)

module Units = Tn_types.Units
module Batch = Tn_types.Batch
module Digests = Tn_types.Digests

type penalty = Mild | Medium | Severe | Fatal

(* Rust declaration order (sealed_batch.rs:261-309), preserved arm for
   arm including the two dead variants, so the penalty match below stays
   structurally 1:1 with worker network/error.rs:83-103. *)
type error =
  | Invalid_digest
  | Canonical_chain of { block_hash : Tn_keccak.t }
  | Empty_batch
  | Header_max_gas_exceeds_gas_limit of
      { total_possible_gas : int64; gas_limit : int64 }
  | Calculate_max_possible_gas
  | Header_transaction_bytes_exceeds_max of int
  | Recover_transaction of
      { digest : Digests.Batch_digest.t; message : string }
  | Invalid_base_fee of
      { expected_base_fee : Units.Base_fee.t; base_fee : Units.Base_fee.t }
  | Invalid_worker_id of
      { expected_worker_id : Units.Worker_id.t; worker_id : Units.Worker_id.t }
  | Invalid_tx_4844 of Tn_keccak.t
  | Gas_overflow
  | Invalid_epoch of { expected : Units.Epoch.t; found : Units.Epoch.t }

(* Each arm mirrors the thiserror display string verbatim
   (sealed_batch.rs:261-309). Hashes render 0x-prefixed full hex (alloy
   FixedBytes Display, non-alternate); u64 payloads render unsigned. *)
let error_to_string e =
  match e with
  | Invalid_digest -> "Invalid digest for sealed batch."
  | Canonical_chain { block_hash } ->
      Printf.sprintf
        "Canonical chain header 0x%s can't be found for peer batch's parent"
        (Tn_keccak.to_hex block_hash)
  | Empty_batch -> "Batch contains no transactions"
  | Header_max_gas_exceeds_gas_limit { total_possible_gas; gas_limit } ->
      Printf.sprintf
        "Peer's batch total possible gas (%Lu) is greater than batch's gas \
         limit (%Lu)"
        total_possible_gas gas_limit
  | Calculate_max_possible_gas ->
      "Unable to reduce max possible gas limit for peer's batch"
  | Header_transaction_bytes_exceeds_max total ->
      Printf.sprintf "Peer's transactions exceed max byte size: %d" total
  | Recover_transaction { digest; message } ->
      Printf.sprintf "Failed to decode transaction for batch 0x%s: %s"
        (Digests.Batch_digest.to_hex digest)
        message
  | Invalid_base_fee { expected_base_fee; base_fee } ->
      Printf.sprintf "Invalid base fee, expected %s got %s"
        (Units.Base_fee.to_string expected_base_fee)
        (Units.Base_fee.to_string base_fee)
  | Invalid_worker_id { expected_worker_id; worker_id } ->
      Printf.sprintf "Invalid worker id, expected %d got %d"
        (Units.Worker_id.to_int expected_worker_id)
        (Units.Worker_id.to_int worker_id)
  | Invalid_tx_4844 tx_hash ->
      Printf.sprintf "Proposed batch contains blob transaction. Tx hash: 0x%s"
        (Tn_keccak.to_hex tx_hash)
  | Gas_overflow -> "Overflow calculating max possible gas."
  | Invalid_epoch { expected; found } ->
      Printf.sprintf "Invalid epoch, expected epoch %s got epoch %s"
        (Units.Epoch.to_string expected)
        (Units.Epoch.to_string found)

(* The exact map of worker network/error.rs:83-103, or-patterns and all.
   Exhaustive on purpose: a new variant must force a decision here. *)
let penalty e =
  match e with
  | Canonical_chain _ -> Mild
  | Invalid_epoch _ | Invalid_tx_4844 _ -> Medium
  | Recover_transaction _ -> Severe
  | Empty_batch | Invalid_base_fee _ | Invalid_worker_id _ | Invalid_digest
  | Gas_overflow | Calculate_max_possible_gas
  | Header_max_gas_exceeds_gas_limit _
  | Header_transaction_bytes_exceeds_max _ ->
      Fatal

let ( let* ) = Result.bind

module type TX_DECODER = sig
  type tx

  val decode_and_recover : string -> (tx, string) result
  val hash : tx -> Tn_keccak.t
  val is_eip4844 : tx -> bool
  val gas_limit : tx -> int64
end

module type S = sig
  module Valid : sig
    type t

    val batch : t -> Batch.t
    val digest : t -> Digests.Batch_digest.t
  end

  type t

  val make :
    worker_id:Units.Worker_id.t ->
    epoch:Units.Epoch.t ->
    base_fee_per_gas:Units.Base_fee.t ->
    t

  val validate : t -> Batch.Sealed.t -> (Valid.t, error) result
end

module Make (D : TX_DECODER) = struct
  module Valid = struct
    type t = { batch : Batch.t; digest : Digests.Batch_digest.t }

    let batch v = v.batch
    let digest v = v.digest
  end

  (* Rust BatchValidator's three pure fields (validator.rs:18-33);
     reth_env/tx_pool serve only the dead submit_txn_if_mine. *)
  type t = {
    worker_id : Units.Worker_id.t;
    epoch : Units.Epoch.t;
    base_fee : Units.Base_fee.t;
  }

  let make ~worker_id ~epoch ~base_fee_per_gas =
    { worker_id; epoch; base_fee = base_fee_per_gas }

  (* Rule 4 (validator.rs:67, 122-141): raw byte length, before any decode.
     The empty list errors EmptyBatch; equality at the cap passes ("allow
     txs that equal max tx bytes"). *)
  let validate_batch_size_bytes batch =
    let max_bytes = Batch.max_batch_size (Batch.epoch batch) in
    match Batch.transactions batch with
    | [] -> Error Empty_batch
    | _ :: _ as transactions ->
        let total_bytes =
          List.fold_left (fun total tx -> total + String.length tx) 0
            transactions
        in
        if total_bytes > max_bytes then
          Error (Header_transaction_bytes_exceeds_max total_bytes)
        else Ok ()

  (* Rule 5 (validator.rs:70, 147-156, 209-215): every tx must decode and
     recover. Rust rayon-folds into Result so WHICH failing tx's message
     surfaces is nondeterministic there; the port pins list order (the
     first Error wins, later ones never override it through the bind). *)
  let decode_transactions batch digest =
    Batch.transactions batch
    |> List.fold_left
         (fun acc tx ->
           Result.bind acc (fun decoded ->
               D.decode_and_recover tx
               |> Result.map (fun d -> d :: decoded)
               |> Result.map_error (fun message ->
                      Recover_transaction { digest; message })))
         (Ok [])
    |> Result.map List.rev

  (* Rule 6 (validator.rs:73, 198-206): the FIRST EIP-4844 tx fails the
     batch, identified by its own hash. *)
  let validate_no_blob_txs decoded =
    List.find_opt D.is_eip4844 decoded
    |> Option.fold ~none:(Ok ()) ~some:(fun blob_tx ->
           Error (Invalid_tx_4844 (D.hash blob_tx)))

  (* Rule 7 (validator.rs:77, 162-185): checked u64 sum of declared gas
     (unsigned wrap detection: a u64 add overflows iff the sum compares
     unsigned-below an addend), then the fork-blind cap; equality passes. *)
  let validate_batch_gas epoch decoded =
    let* total_possible_gas =
      List.fold_left
        (fun acc tx ->
          Result.bind acc (fun total ->
              let sum = Int64.add total (D.gas_limit tx) in
              if Int64.unsigned_compare sum total < 0 then Error Gas_overflow
              else Ok sum))
        (Ok 0L) decoded
    in
    let gas_limit = Batch.max_batch_gas epoch in
    if Int64.unsigned_compare total_possible_gas gas_limit > 0 then
      Error (Header_max_gas_exceeds_gas_limit { total_possible_gas; gas_limit })
    else Ok ()

  (* Rule 8 (validator.rs:80, 188-195): strict equality with the
     epoch-constant snapshot, not an ordering. *)
  let validate_basefee t batch =
    let base_fee = Batch.base_fee_per_gas batch in
    if Units.Base_fee.equal base_fee t.base_fee then Ok ()
    else Error (Invalid_base_fee { expected_base_fee = t.base_fee; base_fee })

  (* The eight rules, Rust's exact order (validator.rs:39-82), first
     failure short-circuiting through the binds. *)
  let validate t sealed =
    let batch, digest = Batch.Sealed.split sealed in
    (* Rule 1 (validator.rs:41-45): recompute the digest, compare the
       claim. *)
    let* () =
      if Digests.Batch_digest.equal digest (Batch.digest batch) then Ok ()
      else Error Invalid_digest
    in
    (* Rule 2 (validator.rs:47-53): a validator belongs to one worker. *)
    let* () =
      let worker_id = Batch.worker_id batch in
      if Units.Worker_id.equal worker_id t.worker_id then Ok ()
      else
        Error
          (Invalid_worker_id { expected_worker_id = t.worker_id; worker_id })
    in
    (* Rule 3 (validator.rs:55-60): one epoch. *)
    let* () =
      let found = Batch.epoch batch in
      if Units.Epoch.equal found t.epoch then Ok ()
      else Error (Invalid_epoch { expected = t.epoch; found })
    in
    let* () = validate_batch_size_bytes batch in
    let* decoded = decode_transactions batch digest in
    let* () = validate_no_blob_txs decoded in
    let* () = validate_batch_gas (Batch.epoch batch) decoded in
    let* () = validate_basefee t batch in
    Ok { Valid.batch; digest }
end

module Tx_shape_decoder = struct
  type tx = Tx_shape.t

  let decode_and_recover input =
    Tx_shape.decode_and_recover input
    |> Result.map_error Tx_shape.error_to_string

  let hash = Tx_shape.hash
  let is_eip4844 = Tx_shape.is_eip4844
  let gas_limit = Tx_shape.gas_limit
end

module Validator = Make (Tx_shape_decoder)
