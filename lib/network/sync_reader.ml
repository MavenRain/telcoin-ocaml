(* The pure half of the four sync reassembly loops. Every rule here is a rule
   about the frame sequence alone, which is why the three readers differ only
   in what a [Data] frame means to them: the control-frame and abort rules are
   shared and written once. *)

open Tn_types
module Bcs = Tn_codec.Bcs

type opening =
  | Proceed
  | Denied of Sync_frame.deny_reason
  | Peer_error of Sync_frame.frame_error

type violation =
  | Unexpected_opening_frame
  | Control_frame_mid_stream
  | Peer_abort of Sync_frame.frame_error
  | Too_many_items of { got : int; requested : int }
  | Unexpected_digest of Digests.Batch_digest.t
  | Duplicate_digest of Digests.Batch_digest.t
  | Size_cap_exceeded of { cumulative : int; cap : int }
  | Decode of Bcs.error

let frame_error_name = function
  | Sync_frame.Internal -> "internal"
  | Sync_frame.Malformed -> "malformed"

let violation_to_string = function
  | Unexpected_opening_frame -> "sync reader: unexpected opening sync frame"
  | Control_frame_mid_stream -> "sync reader: unexpected sync frame mid stream"
  | Peer_abort e ->
      Printf.sprintf "sync reader: peer aborted the stream (%s)"
        (frame_error_name e)
  | Too_many_items { got; requested } ->
      Printf.sprintf "sync reader: peer sent %d items for %d requested" got
        requested
  | Unexpected_digest d ->
      Printf.sprintf "sync reader: peer sent unrequested batch %s"
        (Digests.Batch_digest.to_hex d)
  | Duplicate_digest d ->
      Printf.sprintf "sync reader: peer sent duplicate batch %s"
        (Digests.Batch_digest.to_hex d)
  | Size_cap_exceeded { cumulative; cap } ->
      Printf.sprintf "sync reader: response of %d bytes exceeds the %d cap"
        cumulative cap
  | Decode e -> "sync reader: " ^ Bcs.error_to_string e

let opening = function
  | Sync_frame.Ack -> Ok Proceed
  | Sync_frame.Deny reason -> Ok (Denied reason)
  | Sync_frame.Err e -> Ok (Peer_error e)
  | Sync_frame.Req _ | Sync_frame.Data _ | Sync_frame.End_ ->
      Error Unexpected_opening_frame

(* The body loop every reader shares. A frame list that runs out without an
   [End_] is not a violation: upstream that is a read timeout, and timeouts
   are runtime. [Result.bind]'s continuation runs only on [Ok], so the
   recursion is not evaluated on the rejecting branch. *)
let drive ~step ~finished ~output start frames =
  let rec go state rest =
    match rest with
    | [] -> Ok (output state, finished state)
    | frame :: tail ->
        if finished state then Ok (output state, true)
        else Result.bind (step state frame) (fun (state, _, _) -> go state tail)
  in
  go start frames

module Pack_reader = struct
  type t = { chunks : string list; done_ : bool }

  let start = { chunks = []; done_ = false }
  let finished t = t.done_
  let payload t = String.concat "" (List.rev t.chunks)

  let step t frame =
    match frame with
    | Sync_frame.Data bytes ->
        Ok ({ t with chunks = bytes :: t.chunks }, Some bytes, false)
    | Sync_frame.End_ -> Ok ({ t with done_ = true }, None, true)
    | Sync_frame.Err e -> Error (Peer_abort e)
    | Sync_frame.Req _ | Sync_frame.Ack | Sync_frame.Deny _ ->
        Error Control_frame_mid_stream

  let run frames = drive ~step ~finished ~output:payload start frames
end

module Cert_reader = struct
  type t = {
    accepted : Certificate_wire.t list;
    seen_bytes : int;
    cap : int;
    done_ : bool;
  }

  let start ~accept_cap =
    { accepted = []; seen_bytes = 0; cap = accept_cap; done_ = false }

  let finished t = t.done_
  let certificates t = List.rev t.accepted
  let cumulative t = t.seen_bytes
  let batch_codec = Bcs.list Certificate_wire.codec

  let step t frame =
    match frame with
    | Sync_frame.Data bytes ->
        let seen_bytes = t.seen_bytes + String.length bytes in
        if seen_bytes > t.cap then
          Error (Size_cap_exceeded { cumulative = seen_bytes; cap = t.cap })
        else
          Result.fold
            ~ok:(fun batch ->
              Ok
                ( {
                    t with
                    accepted = List.rev_append batch t.accepted;
                    seen_bytes;
                  },
                  Some batch,
                  false ))
            ~error:(fun e -> Error (Decode e))
            (Bcs.decode batch_codec bytes)
    | Sync_frame.End_ -> Ok ({ t with done_ = true }, None, true)
    | Sync_frame.Err e -> Error (Peer_abort e)
    | Sync_frame.Req _ | Sync_frame.Ack | Sync_frame.Deny _ ->
        Error Control_frame_mid_stream

  let run ~accept_cap frames =
    drive ~step ~finished ~output:certificates (start ~accept_cap) frames
end

module Batch_reader = struct
  type t = {
    requested : Digests.Batch_digest.t list;
    seen : Digests.Batch_digest.t list;
    accepted : Tn_types.Batch.t list;
    done_ : bool;
  }

  let start ~requested = { requested; seen = []; accepted = []; done_ = false }
  let finished t = t.done_
  let batches t = List.rev t.accepted
  let member d ds = List.exists (Digests.Batch_digest.equal d) ds

  (* handle.rs:464-486 applies three bounds in this order, and the order is
     observable: a peer that oversends duplicates of a requested digest is
     reported as sending too many, not as duplicating. *)
  let accept t bytes =
    let requested_len = List.length t.requested in
    let got = List.length t.accepted + 1 in
    Result.bind
      (if got > requested_len then
         Error (Too_many_items { got; requested = requested_len })
       else Ok ())
      (fun () ->
        Result.fold
          ~ok:(fun batch ->
            let digest = Tn_types.Batch.digest batch in
            match () with
            | () when not (member digest t.requested) ->
                Error (Unexpected_digest digest)
            | () when member digest t.seen -> Error (Duplicate_digest digest)
            | () ->
                Ok
                  ( {
                      t with
                      seen = digest :: t.seen;
                      accepted = batch :: t.accepted;
                    },
                    Some batch,
                    false ))
          ~error:(fun e -> Error (Decode e))
          (Bcs.decode Tn_types.Batch.codec bytes))

  let step t frame =
    match frame with
    | Sync_frame.Data bytes -> accept t bytes
    | Sync_frame.End_ -> Ok ({ t with done_ = true }, None, true)
    | Sync_frame.Err e -> Error (Peer_abort e)
    | Sync_frame.Req _ | Sync_frame.Ack | Sync_frame.Deny _ ->
        Error Control_frame_mid_stream

  let run ~requested frames =
    drive ~step ~finished ~output:batches (start ~requested) frames
end
