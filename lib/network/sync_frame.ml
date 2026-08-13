module Bcs = Tn_codec.Bcs

type deny_reason = At_capacity | Unavailable
type frame_error = Internal | Malformed

type 'r t =
  | Req of 'r
  | Ack
  | Deny of deny_reason
  | Data of string
  | End_
  | Err of frame_error

let deny_reason_codec : deny_reason Bcs.t =
  Bcs.sum
    [
      Bcs.case ~index:0 Bcs.unit
        ~inject:(fun () -> At_capacity)
        ~project:(function At_capacity -> Some () | Unavailable -> None);
      Bcs.case ~index:1 Bcs.unit
        ~inject:(fun () -> Unavailable)
        ~project:(function Unavailable -> Some () | At_capacity -> None);
    ]

let frame_error_codec : frame_error Bcs.t =
  Bcs.sum
    [
      Bcs.case ~index:0 Bcs.unit
        ~inject:(fun () -> Internal)
        ~project:(function Internal -> Some () | Malformed -> None);
      Bcs.case ~index:1 Bcs.unit
        ~inject:(fun () -> Malformed)
        ~project:(function Malformed -> Some () | Internal -> None);
    ]

let codec request_codec =
  Bcs.sum
    [
      Bcs.case ~index:0 request_codec
        ~inject:(fun r -> Req r)
        ~project:(function
          | Req r -> Some r
          | Ack | Deny _ | Data _ | End_ | Err _ -> None);
      Bcs.case ~index:1 Bcs.unit
        ~inject:(fun () -> Ack)
        ~project:(function
          | Ack -> Some ()
          | Req _ | Deny _ | Data _ | End_ | Err _ -> None);
      Bcs.case ~index:2 deny_reason_codec
        ~inject:(fun d -> Deny d)
        ~project:(function
          | Deny d -> Some d
          | Req _ | Ack | Data _ | End_ | Err _ -> None);
      Bcs.case ~index:3 Bcs.bytes
        ~inject:(fun b -> Data b)
        ~project:(function
          | Data b -> Some b
          | Req _ | Ack | Deny _ | End_ | Err _ -> None);
      Bcs.case ~index:4 Bcs.unit
        ~inject:(fun () -> End_)
        ~project:(function
          | End_ -> Some ()
          | Req _ | Ack | Deny _ | Data _ | Err _ -> None);
      Bcs.case ~index:5 frame_error_codec
        ~inject:(fun e -> Err e)
        ~project:(function
          | Err e -> Some e
          | Req _ | Ack | Deny _ | Data _ | End_ -> None);
    ]

let deny_equal a b =
  match (a, b) with
  | At_capacity, At_capacity -> true
  | Unavailable, Unavailable -> true
  | At_capacity, Unavailable -> false
  | Unavailable, At_capacity -> false

let frame_error_equal a b =
  match (a, b) with
  | Internal, Internal -> true
  | Malformed, Malformed -> true
  | Internal, Malformed -> false
  | Malformed, Internal -> false

(* The left side of the mismatch arm enumerates every variant, so a frame
   added upstream fails to compile here instead of comparing equal. *)
let equal req_equal a b =
  match (a, b) with
  | Req x, Req y -> req_equal x y
  | Ack, Ack -> true
  | Deny x, Deny y -> deny_equal x y
  | Data x, Data y -> String.equal x y
  | End_, End_ -> true
  | Err x, Err y -> frame_error_equal x y
  | (Req _ | Ack | Deny _ | Data _ | End_ | Err _), _ -> false

let to_string req_to_string = function
  | Req r -> "Req(" ^ req_to_string r ^ ")"
  | Ack -> "Ack"
  | Deny At_capacity -> "Deny(AtCapacity)"
  | Deny Unavailable -> "Deny(Unavailable)"
  | Data b -> Printf.sprintf "Data(%d bytes)" (String.length b)
  | End_ -> "End"
  | Err Internal -> "Err(Internal)"
  | Err Malformed -> "Err(Malformed)"
