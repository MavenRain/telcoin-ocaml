(* The batch-to-block mapping (payload_builder.rs:99-224, payload.rs:30-120
   at telcoin-network 5dbb764e) as pure data: one spec per flattened batch,
   plus the two empty-output behaviors. *)

module Units = Tn_types.Units
module Digests = Tn_types.Digests
module Batch = Tn_types.Batch
module Batch_position = Tn_evm.Batch_position
module Nonempty = Tn_std.Nonempty
module Bcs = Tn_codec.Bcs

module Spec = struct
  type t = {
    batch : Batch.t;
    epoch : Units.Epoch.t;
    batch_digest : Digests.Batch_digest.t;
    beneficiary : Units.Address.t;
    mix_hash : string;
    position : Batch_position.t;
    nonce : Units.Sequence_number.t;
    consensus_root : Digests.Output_digest.t;
    timestamp : Units.Timestamp.t;
    closes_epoch : bool;
  }

  let batch t = t.batch
  let batch_digest t = t.batch_digest
  let beneficiary t = t.beneficiary

  (* payload_builder.rs:170-171: the executed block's basefee is the
     batch's own field (the validator's rule 8 pinned it to the epoch
     constant). *)
  let base_fee t = Batch.base_fee_per_gas t.batch

  (* payload_builder.rs:41,172: always the fork-blind cap at the OUTPUT
     LEADER's epoch, never the batch's own epoch field (certified batches
     bypass rule 3, so the two can differ) and never the batch's gas
     sum. *)
  let gas_limit t = Batch.max_batch_gas t.epoch
  let mix_hash t = t.mix_hash
  let position t = t.position
  let nonce t = t.nonce
  let consensus_root t = t.consensus_root
  let timestamp t = t.timestamp
  let closes_epoch t = t.closes_epoch
end

module Close_spec = struct
  type t = {
    beneficiary : Units.Address.t;
    mix_hash : string;
    consensus_root : Digests.Output_digest.t;
    nonce : Units.Sequence_number.t;
    timestamp : Units.Timestamp.t;
  }

  let beneficiary t = t.beneficiary
  let mix_hash t = t.mix_hash
  let consensus_root t = t.consensus_root
  let nonce t = t.nonce
  let timestamp t = t.timestamp
end

type t =
  | Skip
  | Close_block of Close_spec.t
  | Batch_blocks of Spec.t Nonempty.t

type error = Position_out_of_range of { batch_index : int }

let error_to_string e =
  match e with
  | Position_out_of_range { batch_index } ->
      Printf.sprintf "batch position out of range at flat index %d" batch_index

let ( let* ) = Result.bind

(* payload_builder.rs:191-196: mix_hash = output_digest ^ batch_digest.
   Both operands are Digest.to_bytes of 32-byte digests, so map2 never
   truncates. Each xored byte goes back to a byte through the BCS u8
   writer, the port's total byte emitter (it masks to the low octet, and
   an lxor of two octets is an octet already). *)
let xor_bytes a b =
  Seq.map2
    (fun x y -> Bcs.encode Bcs.u8 (Char.code x lxor Char.code y))
    (String.to_seq a) (String.to_seq b)
  |> List.of_seq |> String.concat ""

(* Total zip: both lists come out of one Output walk, so the lengths are
   equal by construction (TN's ConsensusOutputUnevenBatches guard,
   discharged structurally); the fold simply stops at the shorter. *)
let zip_digests digests pairs =
  List.fold_left
    (fun (rev, rest) digest ->
      match rest with
      | pair :: tl -> ((digest, pair) :: rev, tl)
      | [] -> (rev, []))
    ([], pairs) digests
  |> fst |> List.rev

let plan output ~closes_epoch =
  let consensus_root = Output.output_digest output in
  let root_bytes =
    Tn_crypto.Digest.to_bytes (Digests.Output_digest.to_digest consensus_root)
  in
  let nonce = Output.nonce output in
  let timestamp = Output.committed_at output in
  let epoch = Output.leader_epoch output in
  let flat =
    Output.certified output
    |> List.concat_map (fun (address, batches) ->
           List.map (fun batch -> (address, batch)) batches)
    |> zip_digests (Output.batch_digests output)
  in
  match flat with
  | [] ->
      (* payload_builder.rs:99-160: an empty output executes nothing
         unless the epoch is closing, which produces exactly one empty
         block with the leader as beneficiary and the bare output digest
         as mix_hash. *)
      if closes_epoch then
        Ok
          (Close_block
             {
               Close_spec.beneficiary = Output.leader_address output;
               mix_hash = root_bytes;
               consensus_root;
               nonce;
               timestamp;
             })
      else Ok Skip
  | first :: rest ->
      let count = List.length flat in
      (* One spec per flattened batch (payload_builder.rs:163-224). The
         flag mirrors close_epoch_for_last_batch (output.rs:235-244):
         only the LAST spec of a closing output closes the epoch. *)
      let spec_at index (batch_digest, (beneficiary, batch)) =
        Batch_position.of_batch ~batch_index:index
          ~worker_id:(Batch.worker_id batch)
        |> Option.to_result ~none:(Position_out_of_range { batch_index = index })
        |> Result.map (fun position ->
               {
                 Spec.batch;
                 epoch;
                 batch_digest;
                 beneficiary;
                 mix_hash =
                   xor_bytes root_bytes
                     (Tn_crypto.Digest.to_bytes
                        (Digests.Batch_digest.to_digest batch_digest));
                 position;
                 nonce;
                 consensus_root;
                 timestamp;
                 closes_epoch = closes_epoch && Int.equal index (count - 1);
               })
      in
      let* head = spec_at 0 first in
      let* rev_tail =
        List.fold_left
          (fun acc pair ->
            let* index, rev = acc in
            spec_at index pair |> Result.map (fun s -> (index + 1, s :: rev)))
          (Ok (1, [])) rest
        |> Result.map snd
      in
      Ok (Batch_blocks (Nonempty.cons head (List.rev rev_tail)))
