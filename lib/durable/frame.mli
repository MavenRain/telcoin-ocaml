(** The on-disk envelope: one frame per durable payload, self-identifying at
    both ends.

    Every redundant field earns its bytes. The head tag means a torn length
    cannot mis-size a read, so a partial write is undecodable rather than
    MIS-decodable. The body tag catches a full-length frame whose payload is
    damaged. The length echo and the end magic make the tail of a frame as
    self-identifying as its head, so a resync probe rejects a false positive
    cheaply. Sequence contiguity means a frame that is individually perfect but
    positionally wrong, which is what a spliced log looks like, is still
    refused.

    Nothing here touches the filesystem and nothing here references a port type,
    so the whole framing argument is testable as a pure function over strings.

    Layout, all integers big-endian:

    {v
    0x00        4  len        payload length L, 1 <= L <= max_payload
    0x04        1  kind       0x01 Record, 0x02 Epoch_open
    0x05        3  pad        zero
    0x08        8  seq        0-based, strictly contiguous
    0x10        8  head_tag   BLAKE2B(bytes 0x00 .. 0x0F)[0..8)
    0x18        L  payload
    0x18 + L    8  body_tag   BLAKE2B(payload)[0..8)
    0x20 + L    4  len_echo   L again
    0x24 + L    4  end_magic  "TNCE"
    v} *)

type kind =
  | Record  (** A consensus record, kind byte [0x01]. *)
  | Epoch_open  (** An epoch roll marker, kind byte [0x02]. *)

val max_payload : int
(** 16777216, that is 16 MiB. Upstream's own maximum record size, and the bound
    that makes every allocation in this module decidable before it happens. *)

val header_size : int
(** 24: length 4, kind 1, pad 3, sequence 8, head tag 8. *)

val trailer_size : int
(** 16: body tag 8, length echo 4, end magic 4. *)

val frame_size : payload_len:int -> int
(** [frame_size ~payload_len] is the whole on-disk size of a frame carrying
    [payload_len] bytes, that is [payload_len + 40]. *)

type head = {
  kind : kind;  (** What the payload is. *)
  seq : int;  (** The frame's own 0-based position in the log. *)
  payload_len : int;  (** The declared payload length, already bounds-checked. *)
}
(** What a frame's header says about itself, once the header has been
    validated. *)

type bad =
  | Short of { at : int; have : int; need : int }
      (** The buffer ends before the frame does. This is what every torn write
          looks like. *)
  | Bad_head_tag of { at : int }  (** The header does not match its own tag. *)
  | Bad_body_tag of { at : int }  (** The payload does not match its own tag. *)
  | Length_disagrees of { at : int; head : int; echo : int }
      (** The trailing length echo contradicts the header's length. *)
  | Missing_end_magic of { at : int }  (** The frame does not end in ["TNCE"]. *)
  | Bad_kind of { at : int; byte : int }
      (** The kind byte is neither [0x01] nor [0x02]. *)
  | Oversize of { at : int; len : int; cap : int }
      (** The declared length is outside [1 .. max_payload]. Checked BEFORE any
          allocation, so a damaged length can never drive one. *)
  | Seq_out_of_order of { at : int; expected : int; got : int }
      (** The frame is byte-perfect but sits at the wrong position in the log.
          A torn write cannot produce this. *)

val bad_to_string : bad -> string
(** A one-line rendering of a {!bad}, naming the offset it was found at. *)

val bad_offset : bad -> int
(** The offset the frame that failed starts at, for every arm of {!bad}. *)

val encode : kind:kind -> seq:int -> payload:string -> string
(** [encode ~kind ~seq ~payload] is the whole frame as bytes. Total by
    construction, and the inverse of {!decode_at} for every [payload] whose
    length is in [1 .. max_payload]. A payload outside that range still encodes,
    and {!decode_at} then refuses the result as {!Oversize}: the writer, not
    this function, is the place that bound is enforced. *)

val decode_at :
  buf:string -> at:int -> expect_seq:int -> (head * string * int, bad) result
(** [decode_at ~buf ~at ~expect_seq] reads one frame at [at]. The [int] in the
    success case is one past this frame, which is where the next one starts.

    The checks run in this order: the header is present, the declared length is
    in range, the kind byte is known, the head tag matches, the whole frame is
    present, the body tag matches, the length echo agrees, the end magic is
    there, and only last the sequence is the expected one. The order is
    load-bearing for diagnosis rather than for safety: it means a single damaged
    field names ITSELF, instead of every mutation collapsing into the one check
    that happens to run first. *)

type stop =
  | Clean of { at : int }
      (** The buffer ended exactly on a frame boundary, at [at]. *)
  | Torn of { at : int; why : bad }
      (** The damage at [at] has no correctly formed frame at or above it, so it
          is a tail tear: healable by truncation to [at]. *)
  | Corrupt of { at : int; why : bad; next_good : int }
      (** The damage at [at] has a correctly formed frame at [next_good], so
          committed data sits ABOVE the damage. Media failure or tampering,
          never a crash. Truncating here would discard history, so a caller
          refuses instead. *)

type scan = {
  frames : (head * string) list;  (** Every whole frame, in log order. *)
  stop : stop;  (** Why the walk stopped, and where. *)
}
(** The result of walking a buffer of frames. *)

val scan : buf:string -> from:int -> scan
(** [scan ~buf ~from] walks frames left to right from [from], expecting
    sequence 0 at [from].

    At the first frame that fails any check at offset [O], it resyncs: it probes
    every offset in [\[O, length buf)] for a frame that passes every structural
    check and carries a sequence no lower than the one expected at [O]. If one
    exists at [P] the damage is INTERIOR ({!Corrupt} with [next_good = P]),
    because appending at the end is the only mutation a crash can produce, so a
    hole with good data above it means media failure or tampering. If none
    exists the damage is a tail tear ({!Torn}) and is healable.

    The probe starts AT [O] rather than above it, and that is deliberate: when
    the failure at [O] is only positional, the bytes there are a perfectly
    formed frame, which no torn write can produce. A spliced log is therefore
    interior damage and is never truncated.

    Probing costs O(1) per offset, because the header check rejects almost
    everything, and a payload is hashed only once its header validates. *)
