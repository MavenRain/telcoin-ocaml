open Tn_types
module Bcs = Tn_codec.Bcs

type request =
  | Wreq_report_batch of Batch.Sealed.t
  | Wreq_peer_exchange of Peer_exchange.t

type response =
  | Wres_report_batch of unit
  | Wres_peer_exchange of Peer_exchange.t
  | Wres_error of string
  | Wres_recoverable_error of string

type gossip =
  | Wgossip_batch of { epoch : Units.Epoch.t; block_hash : Digests.Batch_digest.t }

let request_codec : request Bcs.t =
  Bcs.sum
    [
      Bcs.case ~index:0 Batch.Sealed.codec
        ~inject:(fun b -> Wreq_report_batch b)
        ~project:(function
          | Wreq_report_batch b -> Some b
          | Wreq_peer_exchange _ -> None);
      Bcs.case ~index:1 Peer_exchange.codec
        ~inject:(fun p -> Wreq_peer_exchange p)
        ~project:(function
          | Wreq_peer_exchange p -> Some p
          | Wreq_report_batch _ -> None);
    ]

let response_codec : response Bcs.t =
  Bcs.sum
    [
      Bcs.case ~index:0 Bcs.unit
        ~inject:(fun () -> Wres_report_batch ())
        ~project:(function
          | Wres_report_batch () -> Some ()
          | Wres_peer_exchange _ | Wres_error _ | Wres_recoverable_error _ ->
              None);
      Bcs.case ~index:1 Peer_exchange.codec
        ~inject:(fun p -> Wres_peer_exchange p)
        ~project:(function
          | Wres_peer_exchange p -> Some p
          | Wres_report_batch _ | Wres_error _ | Wres_recoverable_error _ -> None);
      Bcs.case ~index:2 Bcs.string_utf8
        ~inject:(fun m -> Wres_error m)
        ~project:(function
          | Wres_error m -> Some m
          | Wres_report_batch _ | Wres_peer_exchange _ | Wres_recoverable_error _
            ->
              None);
      Bcs.case ~index:3 Bcs.string_utf8
        ~inject:(fun m -> Wres_recoverable_error m)
        ~project:(function
          | Wres_recoverable_error m -> Some m
          | Wres_report_batch _ | Wres_peer_exchange _ | Wres_error _ -> None);
    ]

let gossip_codec : gossip Bcs.t =
  Bcs.sum
    [
      Bcs.case ~index:0
        (Bcs.pair Wire_scalar.epoch Wire_scalar.batch_digest)
        ~inject:(fun (epoch, block_hash) -> Wgossip_batch { epoch; block_hash })
        ~project:(function Wgossip_batch b -> Some (b.epoch, b.block_hash));
    ]

let request_equal a b =
  match (a, b) with
  | Wreq_report_batch x, Wreq_report_batch y -> Batch.Sealed.equal x y
  | Wreq_peer_exchange x, Wreq_peer_exchange y -> Peer_exchange.equal x y
  | (Wreq_report_batch _ | Wreq_peer_exchange _), _ -> false

let response_equal a b =
  match (a, b) with
  | Wres_report_batch (), Wres_report_batch () -> true
  | Wres_peer_exchange x, Wres_peer_exchange y -> Peer_exchange.equal x y
  | Wres_error x, Wres_error y -> String.equal x y
  | Wres_recoverable_error x, Wres_recoverable_error y -> String.equal x y
  | ( ( Wres_report_batch _ | Wres_peer_exchange _ | Wres_error _
      | Wres_recoverable_error _ ),
      _ ) ->
      false

let gossip_equal a b =
  match (a, b) with
  | Wgossip_batch x, Wgossip_batch y ->
      Units.Epoch.equal x.epoch y.epoch
      && Digests.Batch_digest.equal x.block_hash y.block_hash
