(** The requester-side reassembly validators of the bulk-sync streams, as pure
    state machines (GT:812, 818, 825, 844, 854-859; design 1c lines 137-150).

    Upstream these live inside [try_unfold]/[read_frame] loops wrapped in
    timeouts. What survives the removal of the IO is exactly the part that
    decides whether a peer is misbehaving: the classification of the opening
    frame, and, per exchange kind, a step function over the frames that
    follow. Timeouts, retries and peer scoring are deferred (design section
    6); a stalled peer is not a violation this module can name, because
    silence is not a frame.

    All three readers share one step shape,
    [state -> frame -> (state * output option * finished, violation) result],
    and one {!violation} sum, so a shim can drive any of them with the same
    loop. *)

open Tn_types

type opening =
  | Proceed  (** [Ack]: the responder is streaming, read the body. *)
  | Denied of Sync_frame.deny_reason
      (** [Deny]: retryable against another peer, not a fault (GT:844). *)
  | Peer_error of Sync_frame.frame_error
      (** [Err]: the responder failed on its own side. *)

type violation =
  | Unexpected_opening_frame
      (** [Req], [Data] or [End_] arrived first, where the handshake admits
          only [Ack], [Deny] or [Err] (GT:844). *)
  | Control_frame_mid_stream
      (** [Req], [Ack] or [Deny] arrived inside the body (GT:858). *)
  | Peer_abort of Sync_frame.frame_error
      (** An [Err] frame ended the stream abnormally (GT:859). The frame
          itself is well formed; it is the protocol-level abort signal. *)
  | Too_many_items of { got : int; requested : int }
      (** The worker responder sent more batches than were asked for
          (worker handle.rs:464-469, GT:854). *)
  | Unexpected_digest of Digests.Batch_digest.t
      (** A batch whose digest was never requested (handle.rs:476-480). *)
  | Duplicate_digest of Digests.Batch_digest.t
      (** The same requested digest arrived twice (handle.rs:482-486). *)
  | Size_cap_exceeded of { cumulative : int; cap : int }
      (** The certificate stream passed the requester's accept cap, counting
          the frame that crossed it (sync_codec.rs:606-609, GT:857). *)
  | Decode of Tn_codec.Bcs.error  (** A [Data] frame's payload did not parse. *)

val violation_to_string : violation -> string
(** A one-line rendering naming which rule fired. *)

val opening : 'r Sync_frame.t -> (opening, violation) result
(** Classify the FIRST frame of a stream. [Ack], [Deny] and [Err] are all
    legitimate answers and each has its own {!opening} constructor; anything
    else is {!Unexpected_opening_frame}. *)

(** The epoch-pack and consensus-output reader: [Data] frames concatenate into
    one contiguous payload (sync_codec.rs:270-304, GT:818). *)
module Pack_reader : sig
  type t
  (** The bytes accepted so far, plus whether [End_] has arrived. *)

  val start : t
  (** An empty, unfinished reader. *)

  val finished : t -> bool
  (** Whether [End_] has been seen. Frames after it are not consumed. *)

  val payload : t -> string
  (** The accepted [Data] payloads concatenated in arrival order. *)

  val step : t -> 'r Sync_frame.t -> (t * string option * bool, violation) result
  (** One frame. The [string option] is this frame's own payload chunk, so a
      shim can stream instead of accumulating; the [bool] is {!finished}. *)

  val run : 'r Sync_frame.t list -> (string * bool, violation) result
  (** Drive {!step} over a whole body. The [bool] reports whether the body
      ended with [End_]: a list that simply runs out is not a violation here,
      because upstream that case is a read timeout and timeouts are deferred. *)
end

(** The missing-certificates reader: each [Data] frame is a whole BCS
    [Vec<Certificate>] batch, and the requester holds the stream to a
    cumulative byte cap (sync_codec.rs:547-616, GT:825). *)
module Cert_reader : sig
  type t
  (** The certificates accepted so far, the cumulative frame bytes, and the
      cap they are held to. *)

  val start : accept_cap:int -> t
  (** A reader capped at [accept_cap] cumulative [Data] payload bytes. The
      production value is
      {!Sync_chunking.max_sync_missing_certs_accept_bytes}; it is an argument
      so a test can exhibit the cap without a 64 MiB stream. *)

  val finished : t -> bool
  (** Whether [End_] has been seen. *)

  val certificates : t -> Certificate_wire.t list
  (** Every certificate accepted, in arrival order across all batches. *)

  val cumulative : t -> int
  (** The [Data] payload bytes counted so far, INCLUDING the frame that
      crossed the cap when one did. *)

  val step :
    t ->
    'r Sync_frame.t ->
    (t * Certificate_wire.t list option * bool, violation) result
  (** One frame. The option carries just this frame's batch. The cap is tested
      AFTER the frame's bytes are counted, so the crossing frame is what
      reports the violation, exactly as sync_codec.rs:606-609 does. *)

  val run :
    accept_cap:int ->
    'r Sync_frame.t list ->
    (Certificate_wire.t list * bool, violation) result
  (** Drive {!step} over a whole body; the [bool] is {!finished}. *)
end

(** The worker batch-sync reader: one [Data] frame per whole [Batch], checked
    against the digest set that was requested (worker handle.rs:434-505,
    GT:812). *)
module Batch_reader : sig
  type t
  (** The requested digest set, the digests already seen, and the batches
      accepted. *)

  val start : requested:Digests.Batch_digest.t list -> t
  (** A reader that will accept a batch only if its RECOMPUTED digest is in
      [requested] and has not arrived before. *)

  val finished : t -> bool
  (** Whether [End_] has been seen. *)

  val batches : t -> Tn_types.Batch.t list
  (** The batches accepted, in arrival order. *)

  val step :
    t -> 'r Sync_frame.t -> (t * Tn_types.Batch.t option * bool, violation) result
  (** One frame, with the three bounds applied in the order handle.rs applies
      them: count first, then membership, then duplication. The digest is
      recomputed with [Tn_types.Batch.digest] from the decoded batch and never
      taken from the peer, so a peer cannot label a batch as one it was
      asked for. *)

  val run :
    requested:Digests.Batch_digest.t list ->
    'r Sync_frame.t list ->
    (Tn_types.Batch.t list * bool, violation) result
  (** Drive {!step} over a whole body; the [bool] is {!finished}. *)
end
