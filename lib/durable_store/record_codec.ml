module Bcs = Tn_codec.Bcs
module Consensus_block = Tn_execution.Consensus_block
module Record = Tn_execution.Consensus_store.Record
module Digests = Tn_types.Digests
module Units = Tn_types.Units

type error =
  | Bcs of Bcs.error
  | Trailing of { left : int }
  | Rebuild of Record.error

let error_to_string = function
  | Bcs e -> "record payload: " ^ Bcs.error_to_string e
  | Trailing { left } ->
      Printf.sprintf "record payload: %d byte(s) left over after decoding" left
  | Rebuild e -> "record payload: " ^ Record.error_to_string e

(* Decode a whole payload: the wire shape must consume every byte, which is why
   this reads a prefix and then checks the remainder rather than leaning on
   [Bcs.decode]'s own trailing arm — the leftover count is worth naming. *)
let exactly codec bytes =
  Result.bind
    (Result.map_error (fun e -> Bcs e) (Bcs.decode_prefix codec bytes))
    (fun (value, consumed) ->
      let left = String.length bytes - consumed in
      if Int.equal left 0 then Ok value else Error (Trailing { left }))

let record_wire = Bcs.pair Consensus_block.codec (Bcs.list Tn_types.Batch.codec)
let encode_record record = Bcs.encode record_wire (Record.to_wire record)

let decode_record bytes =
  Result.bind (exactly record_wire bytes) (fun wire ->
      Result.map_error (fun e -> Rebuild e) (Record.of_wire wire))

module Meta = struct
  type t = {
    epoch : Units.Epoch.t;
    epoch_start : Consensus_block.Number.t;
    epoch_parent : Digests.Output_digest.t;
  }

  (* A wire u64 the host int cannot hold is refused rather than wrapped. *)
  let host_int_of_u64 v =
    if Int64.compare v 0L < 0 || Int64.compare v (Int64.of_int max_int) > 0 then
      None
    else Some (Int64.to_int v)

  (* The epoch is a u32 in the protocol but a u64 on this wire: every meta field
     is then 8-byte aligned, which keeps the payload readable in a hex dump. *)
  let epoch_codec =
    Bcs.refine
      ~inject:(fun v ->
        Option.to_result ~none:"meta: epoch out of range"
          (Option.bind (host_int_of_u64 v) Units.Epoch.of_int))
      ~project:(fun e -> Int64.of_int (Units.Epoch.to_int e))
      Bcs.u64

  let parent_codec =
    Bcs.iso
      ~inject:(fun raw ->
        Digests.Output_digest.of_digest
          (Option.value
             (Tn_crypto.Digest.of_bytes raw)
             ~default:Tn_crypto.Digest.zero))
      ~project:(fun d ->
        Tn_crypto.Digest.to_bytes (Digests.Output_digest.to_digest d))
      (Bcs.fixed_bytes Tn_crypto.Digest.length)

  let codec =
    Bcs.iso
      ~inject:(fun (epoch, epoch_start, epoch_parent) ->
        { epoch; epoch_start; epoch_parent })
      ~project:(fun m -> (m.epoch, m.epoch_start, m.epoch_parent))
      (Bcs.triple epoch_codec Consensus_block.Number.codec parent_codec)

  let encode m = Bcs.encode codec m
  let decode bytes = exactly codec bytes

  let equal a b =
    Units.Epoch.equal a.epoch b.epoch
    && Consensus_block.Number.equal a.epoch_start b.epoch_start
    && Digests.Output_digest.equal a.epoch_parent b.epoch_parent
end
