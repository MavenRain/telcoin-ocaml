(** [SyncFrame<R>] (crates/network-libp2p/src/sync/frame.rs:26-44, GT:97-107),
    the envelope every bulk-sync stream speaks.

    The frame is generic in its request type, and so is this port: the codec
    takes the request codec as a parameter rather than living behind a
    functor, because the two instantiations differ only in that one argument
    (design line 98).

    The tag numbering is pinned upstream by the test [frame_tags_are_stable]
    (frame.rs:154-165), which asserts the exact bytes of every variant; that
    test is ported verbatim into test_network.ml. *)

type deny_reason =
  | At_capacity  (** index 0: the server is out of request slots. *)
  | Unavailable  (** index 1: the server does not have the data. *)

type frame_error =
  | Internal  (** index 0. *)
  | Malformed  (** index 1: the peer sent something unparseable. *)

type 'r t =
  | Req of 'r  (** index 0, the opening frame. *)
  | Ack  (** index 1, the server's go-ahead. *)
  | Deny of deny_reason  (** index 2. *)
  | Data of string  (** index 3, a body chunk as a length-prefixed byte seq. *)
  | End_  (** index 4, the normal terminator. *)
  | Err of frame_error  (** index 5, abnormal termination. *)

val deny_reason_codec : deny_reason Tn_codec.Bcs.t
val frame_error_codec : frame_error Tn_codec.Bcs.t

val codec : 'r Tn_codec.Bcs.t -> 'r t Tn_codec.Bcs.t
(** [codec request] is the frame codec for a stream whose requests are
    encoded by [request]. *)

val equal : ('r -> 'r -> bool) -> 'r t -> 'r t -> bool
val to_string : ('r -> string) -> 'r t -> string
(** A short rendering, for test failure messages. *)
