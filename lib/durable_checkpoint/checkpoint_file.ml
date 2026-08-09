(* The durable checkpoint. Everything physical is [Atomic_file]'s; what lives
   here is the payload codec and the two write-time cross-artefact refusals. *)

module Bcs = Tn_codec.Bcs
module Atomic_file = Tn_durable.Atomic_file
module Io = Tn_durable.Io
module Io_ops = Tn_durable.Io_ops
module Disk = Tn_durable_store.Consensus_store_disk
module Consensus_store = Tn_execution.Consensus_store
module Consensus_block = Tn_execution.Consensus_block
module Digests = Tn_types.Digests
module Checkpoint = Tn_driver.Checkpoint

type load =
  | Absent
  | Loaded of { checkpoint : Checkpoint.t; generation : int }

type error =
  | Io of Io.error
  | File of Atomic_file.error
  | Decode of Bcs.error
  | Trailing of { left : int }
  | Ahead of { watermark : int; durable_tip : int }
  | Unknown_block of { number : int }
  | Generation_regressed of { stored : int; offered : int }

let error_to_string = function
  | Io e -> Io.error_to_string e
  | File e -> Atomic_file.error_to_string e
  | Decode e -> "checkpoint payload: " ^ Bcs.error_to_string e
  | Trailing { left } ->
      Printf.sprintf "checkpoint payload: %d byte(s) left over after decoding"
        left
  | Ahead { watermark; durable_tip } ->
      Printf.sprintf
        "checkpoint: last executed %d is above the store's durable tip %d"
        watermark durable_tip
  | Unknown_block { number } ->
      Printf.sprintf
        "checkpoint: the store holds no such block at height %d" number
  | Generation_regressed { stored; offered } ->
      Printf.sprintf "checkpoint: generation %d does not advance on %d" offered
        stored

let name = "checkpoint"
let magic = "TNCKPT\x00\x00"
let format = 1

(* [Atomic_file] refuses a generation above its own u64be ceiling, so this is
   where "strictly increasing" runs out of room. Restated rather than exported:
   the container owns the constant, and a reader of this file should see the
   number that bounds the counter it is reading. *)
let generation_ceiling = (1 lsl 62) - 1

(* {2 The two write-time refusals} *)

(* A checkpoint that has executed nothing has watermark [genesis], and an empty
   store has no tip; both read as zero, so the fresh pair passes without a
   special case. *)
let durable_tip_of store =
  Option.fold ~none:0 ~some:Consensus_block.Number.to_int (Disk.durable_tip store)

let guard_ahead ~store checkpoint =
  let watermark =
    Consensus_block.Number.to_int (Checkpoint.watermark checkpoint)
  in
  let durable_tip = durable_tip_of store in
  match watermark > durable_tip with
  | true -> Error (Ahead { watermark; durable_tip })
  | false -> Ok ()

(* The height alone is not the question: a store from another run may well hold
   SOME block at that height. The digest is what makes the two artefacts one
   run's, so the record is fetched by height and its digest compared. *)
let guard_known ~store checkpoint =
  Option.fold ~none:(Ok ())
    ~some:(fun block ->
      let number = Consensus_block.number block in
      let refuse =
        Error (Unknown_block { number = Consensus_block.Number.to_int number })
      in
      Result.fold
        ~ok:(fun record ->
          match
            Digests.Output_digest.equal
              (Consensus_store.Record.digest record)
              (Consensus_block.digest block)
          with
          | true -> Ok ()
          | false -> refuse)
        ~error:(fun (_ : Consensus_store.miss) -> refuse)
        (Consensus_store.record_at (Disk.mirror store) number))
    (Checkpoint.last_executed checkpoint)

(* {2 Publish and read} *)

let stored_generation ~ops ~dir =
  Result.map
    (Option.fold ~none:0 ~some:fst)
    (Result.map_error
       (fun e -> File e)
       (Atomic_file.load ~ops ~dir ~name ~magic ~format))

let publish ~ops ~dir ~generation checkpoint =
  Result.map
    (fun () -> generation)
    (Result.map_error
       (fun e -> File e)
       (Atomic_file.save ~ops ~dir ~name ~magic ~format ~generation
          ~payload:(Bcs.encode Checkpoint_codec.checkpoint checkpoint)))

let save ?(ops = Io_ops.real) ~dir ~store checkpoint =
  Result.bind (guard_ahead ~store checkpoint) (fun () ->
      Result.bind (guard_known ~store checkpoint) (fun () ->
          Result.bind (stored_generation ~ops ~dir) (fun stored ->
              let offered =
                match stored < generation_ceiling with
                | true -> Stdlib.succ stored
                | false -> stored
              in
              match offered > stored with
              | false -> Error (Generation_regressed { stored; offered })
              | true -> publish ~ops ~dir ~generation:offered checkpoint)))

let decode payload generation =
  Result.bind
    (Result.map_error
       (fun e -> Decode e)
       (Bcs.decode_prefix Checkpoint_codec.checkpoint payload))
    (fun (checkpoint, consumed) ->
      let left = String.length payload - consumed in
      match Int.equal left 0 with
      | true -> Ok (Loaded { checkpoint; generation })
      | false -> Error (Trailing { left }))

(* The trailing [unit] is what erases [?ops]: every other argument is labelled,
   so without it the optional could never be defaulted. The same shape
   [Consensus_store_disk.open_] carries, for the same reason. *)
let load ?(ops = Io_ops.real) ~dir () =
  Result.bind
    (Result.map_error
       (fun e -> File e)
       (Atomic_file.load ~ops ~dir ~name ~magic ~format))
    (Option.fold ~none:(Ok Absent) ~some:(fun (generation, payload) ->
         decode payload generation))
