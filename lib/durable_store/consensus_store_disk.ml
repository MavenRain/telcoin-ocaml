(* The real durable backend.

   One ordering in this file is the entire crash argument, and it is the two
   lines of [advancing]: the advanced mirror is installed only inside the [Ok]
   arm of an append, and an append returns only after its flush has returned.
   Install it outside that arm and a record the device never took becomes
   observable through every read member.

   The second load-bearing choice is that nothing here decides what a valid
   chain is. Both the live write path and the replay call
   [Consensus_store.receive] and [Consensus_store.open_epoch], so acceptance has
   exactly one definition and no byte sequence can install a store the live path
   would have refused. *)

module Io = Tn_durable.Io
module Io_ops = Tn_durable.Io_ops
module Frame = Tn_durable.Frame
module Append_log = Tn_durable.Append_log
module Store_lock = Tn_durable.Store_lock
module Digests = Tn_types.Digests
module Units = Tn_types.Units
module Consensus_block = Tn_execution.Consensus_block
module Consensus_store = Tn_execution.Consensus_store
module Record = Tn_execution.Consensus_store.Record
module Meta = Record_codec.Meta

type origin = {
  dir : string;
  epoch : Units.Epoch.t;
  anchor : Consensus_block.Number.t;
  parent : Digests.Output_digest.t;
}

type t = {
  origin : origin;
      (* What [open_] was asked for, kept verbatim. NOT the store's current
         epoch facts, which move with every roll and are read off the mirror:
         these are the values the stored file header was validated against, and
         they are what a caller must hand back to open the same root again. *)
  log : Append_log.t;
  mirror : Consensus_store.t;
  last_meta : string option;
      (* The payload bytes of the most recent durable epoch-open frame, which is
         what [reopen_epoch] compares against. Rebuilt by the replay, so the
         restart path answers the same after a crash as before one. *)
  log_end_at_open : int;
  seq_at_open : int;
      (* The log's end offset and frame count the moment this handle opened.
         [fsyncs] and [bytes_appended] are deltas off the LOG, never off any
         process-wide tally, so IO by another [Tn_durable] handle in this
         process — a checkpoint save, a second root — cannot bleed into this
         handle's counts. *)
}

type fault =
  | Io of Io.error
  | Log of Append_log.error
  | Lock of Store_lock.error
  | Decode of { at : int; seq : int; error : Record_codec.error }
  | Meta_disagrees of { at : int; seq : int; field : string }
  | Replayed_refusal of { at : int; seq : int; cause : Consensus_store.error }

let where ~at ~seq = Printf.sprintf "frame %d at offset %d" seq at

let fault_to_string = function
  | Io e -> Io.error_to_string e
  | Log e -> Append_log.error_to_string e
  | Lock e -> Store_lock.error_to_string e
  | Decode { at; seq; error } ->
      Printf.sprintf "%s: %s" (where ~at ~seq)
        (Record_codec.error_to_string error)
  | Meta_disagrees { at; seq; field } ->
      Printf.sprintf
        "%s: the epoch frame states a %s the tip does not derive"
        (where ~at ~seq) field
  | Replayed_refusal { at; seq; cause } ->
      Printf.sprintf "%s: the chain rules refuse this record: %s"
        (where ~at ~seq)
        (Consensus_store.error_to_string cause)

type write_error = Refused of Consensus_store.error | Fault of fault

let write_error_to_string = function
  | Refused e -> Consensus_store.error_to_string e
  | Fault f -> fault_to_string f

type report = {
  heal : Append_log.heal;
  frames : int;
  created : bool;
  durability : [ `Fsync_no_fullsync ];
}

let log_name = "consensus.log"
let magic = "TNCSLOG\x00"
let format = 1
let header_size = 64

(* Big-endian throughout, so a hex dump reads in the same order the offsets do.
   Built by folding over a width rather than by indexing a buffer. *)
let be ~width v =
  let out = Buffer.create width in
  let () =
    List.iter
      (fun i -> Buffer.add_uint8 out ((v lsr ((width - 1 - i) * 8)) land 0xff))
      (List.init width Fun.id)
  in
  Buffer.contents out

(* The 64 bytes that say which chain, which epoch and which anchor this root
   belongs to. Written once at create and compared field by field at every
   adopt, which is how a foreign root is refused before a frame is parsed. *)
let file_header ~epoch ~anchor ~parent =
  String.concat ""
    [
      magic;
      be ~width:4 format;
      be ~width:4 header_size;
      be ~width:8 (Units.Epoch.to_int epoch);
      be ~width:8 (Consensus_block.Number.to_int anchor);
      Tn_crypto.Digest.to_bytes (Digests.Output_digest.to_digest parent);
    ]

(* The physical layer wraps contention in an arm of its own error; lifting it
   keeps single-writer contention one named thing at this layer too. *)
let of_log_error = function
  | Append_log.Lock e -> Lock e
  | ( Append_log.Io _ | Append_log.Corrupt _ | Append_log.Bad_magic _
    | Append_log.Bad_format _ | Append_log.Bad_header_len _
    | Append_log.Header_mismatch _ | Append_log.Bad_payload_len _ ) as e ->
      Log e

(* The three facts the reference itself states about the epoch it holds open.
   Taking them from the reference rather than restating them is what makes the
   frame a cross-check of a derivation rather than a second source of truth. *)
let meta_of store =
  {
    Meta.epoch = Consensus_store.epoch store;
    epoch_start = Consensus_store.epoch_start store;
    epoch_parent = Consensus_store.epoch_parent store;
  }

(* What a roll will derive off the current tip, computed exactly as the
   reference computes it: the next expected height, and the tip's digest or the
   open epoch's own anchor while nothing is retained. *)
let derived_start store = Consensus_store.expected_next store

let derived_parent store =
  Option.fold
    ~none:(Consensus_store.epoch_parent store)
    ~some:Record.digest
    (Consensus_store.latest_received store)

(* The first stated fact the tip does not agree with, named. The epoch itself
   has no tip-derived counterpart - it is the frame's own claim, and the
   reference's strict-advance guard is what adjudicates it - so the cross-check
   covers exactly the two facts a replay can recompute. *)
let meta_disagreement store meta =
  Option.map fst
    (List.find_opt
       (fun (_field, agrees) -> not agrees)
       [
         ( "epoch_start",
           Consensus_block.Number.equal meta.Meta.epoch_start
             (derived_start store) );
         ( "epoch_parent",
           Digests.Output_digest.equal meta.Meta.epoch_parent
             (derived_parent store) );
       ])

(* The replay's running state: the store so far, and where in the file the next
   frame begins, so every diagnosis carries an offset an operator can look at. *)
type walk = {
  store : Consensus_store.t;
  at : int;
  seq : int;
  last_meta : string option;
}

let step acc (kind, payload) =
  Result.bind acc (fun s ->
      let at = s.at in
      let seq = s.seq in
      let onward store last_meta =
        {
          store;
          at = at + Frame.frame_size ~payload_len:(String.length payload);
          seq = seq + 1;
          last_meta;
        }
      in
      match kind with
      | Frame.Record ->
          Result.bind
            (Result.map_error
               (fun error -> Decode { at; seq; error })
               (Record_codec.decode_record payload))
            (fun record ->
              Result.map
                (fun store -> onward store s.last_meta)
                (Result.map_error
                   (fun cause -> Replayed_refusal { at; seq; cause })
                   (Consensus_store.receive s.store record)))
      | Frame.Epoch_open ->
          Result.bind
            (Result.map_error
               (fun error -> Decode { at; seq; error })
               (Meta.decode payload))
            (fun meta ->
              Result.bind
                (Option.fold ~none:(Ok ())
                   ~some:(fun field -> Error (Meta_disagrees { at; seq; field }))
                   (meta_disagreement s.store meta))
                (fun () ->
                  Result.map
                    (fun store -> onward store (Some payload))
                    (Result.map_error
                       (fun cause -> Replayed_refusal { at; seq; cause })
                       (Consensus_store.open_epoch s.store
                          ~epoch:meta.Meta.epoch)))))

let replay ~epoch ~anchor ~parent payloads =
  List.fold_left step
    (Ok
       {
         store = Consensus_store.create ~epoch ~anchor ~parent;
         at = header_size;
         seq = 0;
         last_meta = None;
       })
    payloads

(* A refusal after the log is open gives the root back. A caller that repairs
   the cause and retries in this process would otherwise meet its own earlier
   handle rather than the fault it just fixed. *)
let closing log r =
  Result.fold ~ok:Result.ok
    ~error:(fun e ->
      let (_ : (unit, Append_log.error) result) = Append_log.close log in
      Error e)
    r

let open_ ?(ops = Io_ops.real) ~dir ~epoch ~anchor ~parent () =
  let path = Filename.concat dir log_name in
  Result.bind
    (Result.map_error (fun e -> Io e) (Io.exists ~ops ~path))
    (fun existed ->
      Result.bind
        (Result.map_error of_log_error
           (Append_log.open_ ~ops ~dir
              ~file_header:(file_header ~epoch ~anchor ~parent)))
        (fun opened ->
          closing opened.Append_log.log
            (Result.map
               (fun walked ->
                 ( {
                     origin = { dir; epoch; anchor; parent };
                     log = opened.Append_log.log;
                     mirror = walked.store;
                     last_meta = walked.last_meta;
                     log_end_at_open =
                       Append_log.end_offset opened.Append_log.log;
                     seq_at_open = Append_log.next_seq opened.Append_log.log;
                   },
                   {
                     heal = opened.Append_log.heal;
                     frames = opened.Append_log.frames;
                     created = not existed;
                     durability = `Fsync_no_fullsync;
                   } ))
               (replay ~epoch ~anchor ~parent opened.Append_log.payloads))))

let mirror t = t.mirror
let origin t = t.origin

(* D2, and the whole of it. *)
let advancing t ~advanced ~last_meta appended =
  Result.map
    (fun log -> { t with log; mirror = advanced; last_meta })
    (Result.map_error (fun e -> Fault (of_log_error e)) appended)

(* D4: the reference answers an already-held record with the store unchanged,
   and the mirror's own digest index tells that case apart from a fresh one
   without comparing two stores. Returning here is what makes a shell's retry
   after a partial crash cost zero bytes and zero flushes. *)
let already_durable t record =
  Option.is_some
    (Consensus_store.record_by_digest t.mirror (Record.digest record))

let receive t record =
  Result.bind
    (Result.map_error
       (fun e -> Refused e)
       (Consensus_store.receive t.mirror record))
    (fun advanced ->
      match already_durable t record with
      | true -> Ok t
      | false ->
          advancing t ~advanced ~last_meta:t.last_meta
            (Append_log.append t.log ~kind:Frame.Record
               ~payload:(Record_codec.encode_record record)))

let open_epoch t ~epoch =
  Result.bind
    (Result.map_error
       (fun e -> Refused e)
       (Consensus_store.open_epoch t.mirror ~epoch))
    (fun advanced ->
      let payload = Meta.encode (meta_of advanced) in
      advancing t ~advanced ~last_meta:(Some payload)
        (Append_log.append t.log ~kind:Frame.Epoch_open ~payload))

let reopen_epoch t ~epoch =
  let stated = Meta.encode (meta_of t.mirror) in
  match
    Units.Epoch.equal (Consensus_store.epoch t.mirror) epoch
    && Option.fold ~none:false ~some:(String.equal stated) t.last_meta
  with
  | true -> Ok t
  | false -> open_epoch t ~epoch

let durable_tip t =
  Option.map Record.number (Consensus_store.latest_received t.mirror)

(* Every flush after open is exactly one appended frame — the append path
   costs one flush and nothing else this handle does flushes — so the log's
   own counters ARE the handle's counters, and no other handle's IO can move
   them. *)
let fsyncs t = Append_log.next_seq t.log - t.seq_at_open
let bytes_appended t = Append_log.end_offset t.log - t.log_end_at_open
let close t = Result.map_error of_log_error (Append_log.close t.log)
