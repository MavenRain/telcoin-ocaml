(* The sender-side chunking policy of the bulk-sync streams. Every constant
   is a literal transcribed from the Rust line its .mli cites; nothing here
   derives a threshold from another, because upstream writes them out and a
   derived value would hide a drift in the one it was derived from. The two
   sums that ARE written as sums upstream (263168 and 67633152) are checked
   against their parts by a test row rather than computed here. *)

module Reader = Tn_snappy.Byte_reader

type error = Invalid_chunk_size of { chunk_size : int }

let error_to_string = function
  | Invalid_chunk_size { chunk_size } ->
      Printf.sprintf "sync chunking: chunk size %d is below one" chunk_size

let sync_pack_chunk_size = 262144
let sync_pack_frame_overhead = 1024
let max_sync_pack_frame_size = 263168
let sync_cert_batch_target_size = 262144
let max_sync_cert_frame_size = 524288
let batch_digests_read_chunk_size = 200
let max_sync_missing_certs_response_bytes = 67108864
let max_sync_missing_certs_accept_bytes = 67633152
let max_sync_request_frame_size = 4194304
let sync_frame_overhead = 1024
let max_pending_requests_per_peer = 2
let max_epoch_sync_probes = 3
let max_batch_request_retries = 3
let max_sync_frame_size ~max_batch_size = max_batch_size + sync_frame_overhead

(* Slicing goes through Tn_snappy.Byte_reader, whose [sub] is bounds checked
   and answers with an option, so this file holds no String.sub and no index
   syntax (byte_reader.mli, the Bcs.Reader discipline one library down). Both
   [Option.fold] arms are thunks: [~none] is eager, and the recursive step
   must not run on the exhausted branch. *)
let slices ~chunk_size s =
  let reader = Reader.of_string s in
  let total = Reader.length reader in
  let rec go pos acc =
    if pos >= total then List.rev acc
    else
      let remaining = total - pos in
      let len = if remaining < chunk_size then remaining else chunk_size in
      Option.fold
        ~none:(fun () -> List.rev acc)
        ~some:(fun chunk () -> go (pos + len) (chunk :: acc))
        (Reader.sub reader ~pos ~len)
        ()
  in
  go 0 []

let frames_of_slices parts =
  List.append (List.map (fun c -> Sync_frame.Data c) parts) [ Sync_frame.End_ ]

let pack_frames payload =
  frames_of_slices (slices ~chunk_size:sync_pack_chunk_size payload)

let pack_frames_with ~chunk_size payload =
  if chunk_size < 1 then Error (Invalid_chunk_size { chunk_size })
  else Ok (frames_of_slices (slices ~chunk_size payload))

(* The CertBatch fold. [sent] is the cumulative encoded size of everything
   emitted, which is what the honest responder cap watches; [current] is the
   batch being accumulated and [current_bytes] its size. An element is always
   appended BEFORE either threshold is tested, which is what makes the
   crossing element part of the response rather than the first casualty of
   the cap (GT:823). *)
let cert_batches_bounded ~encoded_size ~target_size ~response_cap items =
  let close current acc =
    match current with [] -> acc | _ :: _ -> List.rev current :: acc
  in
  let rec go rest ~sent ~current ~current_bytes acc =
    match rest with
    | [] -> List.rev (close current acc)
    | item :: tail ->
        let size = encoded_size item in
        let sent = sent + size in
        let current = item :: current in
        let current_bytes = current_bytes + size in
        let stop = sent >= response_cap in
        let flush = stop || current_bytes >= target_size in
        if flush then
          go
            (if stop then [] else tail)
            ~sent ~current:[] ~current_bytes:0
            (List.rev current :: acc)
        else go tail ~sent ~current ~current_bytes acc
  in
  go items ~sent:0 ~current:[] ~current_bytes:0 []

let cert_batches ~encoded_size items =
  cert_batches_bounded ~encoded_size ~target_size:sync_cert_batch_target_size
    ~response_cap:max_sync_missing_certs_response_bytes items

(* [split_at] and [group] are the list analogue of [slices]: no List.nth, no
   partial head, and tail recursive so a 200-element group costs no stack. *)
let split_at ~n items =
  let rec go k acc rest =
    if k <= 0 then (List.rev acc, rest)
    else
      match rest with
      | [] -> (List.rev acc, [])
      | x :: xs -> go (k - 1) (x :: acc) xs
  in
  go n [] items

let digest_chunks items =
  let rec go rest acc =
    match rest with
    | [] -> List.rev acc
    | _ :: _ ->
        let taken, remaining = split_at ~n:batch_digests_read_chunk_size rest in
        go remaining (taken :: acc)
  in
  go items []
