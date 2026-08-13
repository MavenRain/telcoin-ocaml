(** The sender-side chunking policy of the bulk-sync streams, as pure folds
    and pinned constants (GT RF sections 3, 5 and 6; design 1c lines 116-135).

    The frame layer ({!Sync_frame}) says what an envelope looks like; this
    module says how much goes in one. Upstream splits the policy across
    [consensus/primary/src/network/sync_codec.rs] and
    [consensus/worker/src/network/stream_codec.rs], where it is tangled with
    [AsyncWrite], timers and DB reads. Everything here is the part that is a
    function of the bytes alone: the thresholds, the frame-cap arithmetic, and
    the three folds that turn a payload or an item list into the [Data] frames
    a responder writes.

    What is NOT here, and is deferred with the rest of the runtime (design
    section 6): the writers themselves, every timeout, the DB lookups that
    feed [digest_chunks], and the admission-control machinery whose numeric
    caps nonetheless live here so the deferral list can say honestly that
    chunk 44 ships the constants. *)

type error =
  | Invalid_chunk_size of { chunk_size : int }
      (** {!pack_frames_with} was handed a chunk size below one, which no
          finite number of chunks could exhaust a payload at. *)

val error_to_string : error -> string
(** A one-line rendering, for test failure messages and shim logs. *)

(** {1 Pinned constants}

    Every value below is a literal from the Rust source cited on it, and each
    is pinned by its own test row so a silent drift shows up as a red case. *)

val sync_pack_chunk_size : int
(** 262144 = 256*1024: the fixed [Data] payload size the epoch-pack writer
    cuts its source into (sync_codec.rs:35, GT:815). *)

val sync_pack_frame_overhead : int
(** 1024, the slack a pack frame is allowed on top of its payload
    (sync_codec.rs:39, GT:815). *)

val max_sync_pack_frame_size : int
(** 263168 = {!sync_pack_chunk_size} + {!sync_pack_frame_overhead}, the frame
    cap of a [/tn-primary-sync] pack stream (sync_codec.rs:44, GT:815). *)

val sync_cert_batch_target_size : int
(** 262144: a certificate batch flushes as soon as its accumulated encoded
    bytes reach this (sync_codec.rs:56, GT:822). It is a target, not a cap;
    the element that crosses it is inside the batch that flushes. *)

val max_sync_cert_frame_size : int
(** 524288 = {!sync_cert_batch_target_size} * 2, the frame cap of a
    missing-certificates stream (sync_codec.rs:62, GT:822). *)

val batch_digests_read_chunk_size : int
(** 200: the worker responder looks its requested digests up in the store 200
    at a time (stream_codec.rs:25, GT:810). *)

val max_sync_missing_certs_response_bytes : int
(** 67108864 = 64 MiB, the cap an HONEST responder holds itself to. The
    element that crosses it is still sent and the stream then ends
    (sync_codec.rs:70, GT:823). *)

val max_sync_missing_certs_accept_bytes : int
(** 67633152 = {!max_sync_missing_certs_response_bytes} +
    {!max_sync_cert_frame_size}: what a REQUESTER accepts, one whole frame
    more than an honest responder sends, so an honest stream can never trip it
    (sync_codec.rs:82-83, GT:822). *)

val max_sync_request_frame_size : int
(** 4194304 = 4 MiB, the cap on control and request frames, which is what the
    opening [Req] frame is written under (primary/network/mod.rs:146,
    GT:843). *)

val sync_frame_overhead : int
(** 1024, the worker sync path's frame slack (worker handle.rs:41-55,
    GT:811). *)

val max_pending_requests_per_peer : int
(** 2. A responder that already holds this many in-flight requests from one
    peer answers [Deny At_capacity] (primary/network/mod.rs:101, GT:860). The
    admission RUNTIME is deferred; this is its number. *)

val max_epoch_sync_probes : int
(** 3: how many peers an epoch-pack fetch probes before giving up
    (primary/network/mod.rs:137, GT:839). The probing loop is deferred. *)

val max_batch_request_retries : int
(** 3: how many times a batch request is retried (GT:882). The retry loop is
    deferred. *)

val max_sync_frame_size : max_batch_size:int -> int
(** [max_sync_frame_size ~max_batch_size] is [max_batch_size +
    ]{!sync_frame_overhead}, the worker sync stream's frame cap
    (worker handle.rs:41-55, GT:811).

    This one is a FUNCTION and not a constant because the worker's cap tracks
    the epoch's maximum batch size, so a shim computes it per epoch and hands
    the result to {!Wire_frame} as its [max_message_size]. *)

(** {1 Pure chunking folds} *)

val pack_frames : string -> 'r Sync_frame.t list
(** [pack_frames payload] is the frame sequence an epoch-pack or
    consensus-output responder writes after its [Ack]: one [Data] frame per
    {!sync_pack_chunk_size} bytes, in order, then exactly one [End_]
    (sync_codec.rs:173-216, GT:816).

    An empty payload gives [\[End_\]], the [sync_pack_round_trip_empty]
    shape (GT:891). The result is generic in the request type because no
    frame it builds is a [Req]. *)

val pack_frames_with :
  chunk_size:int -> string -> ('r Sync_frame.t list, error) result
(** {!pack_frames} at a caller-chosen chunk size, so a property test can cross
    a chunk boundary without allocating a quarter megabyte per sample. A
    [chunk_size] below one is refused rather than clamped. *)

val cert_batches : encoded_size:('c -> int) -> 'c list -> 'c list list
(** [cert_batches ~encoded_size certs] is the [CertBatch] fold of
    sync_codec.rs:416-427 and 491-533 at the production constants: batches in
    stream order, each flushed as soon as its accumulated encoded bytes reach
    {!sync_cert_batch_target_size}, and the whole stream ended by the honest
    cap {!max_sync_missing_certs_response_bytes}.

    The cap INCLUDES the element that crosses it (GT:823): a certificate whose
    size takes the running total to or past the cap is sent, and nothing after
    it is. Excluding it would make an honest responder truncate one
    certificate early, which the requester cannot distinguish from a peer that
    simply has fewer. *)

val cert_batches_bounded :
  encoded_size:('c -> int) ->
  target_size:int ->
  response_cap:int ->
  'c list ->
  'c list list
(** {!cert_batches} with both thresholds supplied, which is what lets a test
    exhibit the crossing element at three-digit sizes instead of at 64 MiB.
    A non-positive [target_size] flushes one element per batch, and a
    non-positive [response_cap] stops after the first element; neither is a
    production configuration and neither can diverge. *)

val digest_chunks : 'a list -> 'a list list
(** [digest_chunks digests] cuts a requested-digest list into the
    {!batch_digests_read_chunk_size}-element groups the worker responder looks
    up one at a time (stream_codec.rs:92, GT:810). Order is preserved and the
    final group may be short; an empty list gives no groups. *)
