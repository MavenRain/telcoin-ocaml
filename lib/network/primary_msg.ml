open Tn_types
module Bcs = Tn_codec.Bcs

type request =
  | Req_vote of { header : Tn_vertex.Header.t; parents : Certificate_wire.t list }
  | Req_peer_exchange of Peer_exchange.t
  | Req_epoch_record of {
      epoch : Units.Epoch.t option;
      hash : Tn_crypto.Digest.t option;
    }

type response =
  | Res_vote of Vote_wire.t
  | Res_missing_parents of Digests.Header_digest.t list
  | Res_epoch_record of {
      record : Epoch_record.t;
      certificate : Epoch_certificate.t;
    }
  | Res_peer_exchange of Peer_exchange.t
  | Res_error of string
  | Res_recoverable_error of string

type gossip =
  | Gossip_certificate of Certificate_wire.t
  | Gossip_consensus of Consensus_result.t
  | Gossip_epoch_vote of Epoch_vote.t

type missing_certificates_request = {
  exclusive_lower_bound : Round.t;
  skip_rounds : (Authority_id.t * string) list;
  max_response_size : int64;
}

let make_missing_certificates_request ~exclusive_lower_bound ~skip_rounds
    ~max_response_size =
  { exclusive_lower_bound; skip_rounds; max_response_size }

let parents_codec : Certificate_wire.t list Bcs.t =
  Bcs.list Certificate_wire.codec

let request_codec : request Bcs.t =
  Bcs.sum
    [
      Bcs.case ~index:0
        (Bcs.pair Tn_vertex.Header.codec parents_codec)
        ~inject:(fun (header, parents) -> Req_vote { header; parents })
        ~project:(function
          | Req_vote v -> Some (v.header, v.parents)
          | Req_peer_exchange _ | Req_epoch_record _ -> None);
      Bcs.case ~index:1 Peer_exchange.codec
        ~inject:(fun peers -> Req_peer_exchange peers)
        ~project:(function
          | Req_peer_exchange p -> Some p
          | Req_vote _ | Req_epoch_record _ -> None);
      Bcs.case ~index:2
        (Bcs.pair
           (Bcs.option Wire_scalar.epoch)
           (Bcs.option Wire_scalar.digest))
        ~inject:(fun (epoch, hash) -> Req_epoch_record { epoch; hash })
        ~project:(function
          | Req_epoch_record e -> Some (e.epoch, e.hash)
          | Req_vote _ | Req_peer_exchange _ -> None);
    ]

let response_codec : response Bcs.t =
  Bcs.sum
    [
      Bcs.case ~index:0 Vote_wire.codec
        ~inject:(fun v -> Res_vote v)
        ~project:(function
          | Res_vote v -> Some v
          | Res_missing_parents _ | Res_epoch_record _ | Res_peer_exchange _
          | Res_error _ | Res_recoverable_error _ ->
              None);
      Bcs.case ~index:1
        (Bcs.list Wire_scalar.header_digest)
        ~inject:(fun ds -> Res_missing_parents ds)
        ~project:(function
          | Res_missing_parents ds -> Some ds
          | Res_vote _ | Res_epoch_record _ | Res_peer_exchange _ | Res_error _
          | Res_recoverable_error _ ->
              None);
      Bcs.case ~index:2
        (Bcs.pair Epoch_record.codec Epoch_certificate.codec)
        ~inject:(fun (record, certificate) ->
          Res_epoch_record { record; certificate })
        ~project:(function
          | Res_epoch_record e -> Some (e.record, e.certificate)
          | Res_vote _ | Res_missing_parents _ | Res_peer_exchange _
          | Res_error _ | Res_recoverable_error _ ->
              None);
      Bcs.case ~index:3 Peer_exchange.codec
        ~inject:(fun p -> Res_peer_exchange p)
        ~project:(function
          | Res_peer_exchange p -> Some p
          | Res_vote _ | Res_missing_parents _ | Res_epoch_record _
          | Res_error _ | Res_recoverable_error _ ->
              None);
      Bcs.case ~index:4 Bcs.string_utf8
        ~inject:(fun m -> Res_error m)
        ~project:(function
          | Res_error m -> Some m
          | Res_vote _ | Res_missing_parents _ | Res_epoch_record _
          | Res_peer_exchange _ | Res_recoverable_error _ ->
              None);
      Bcs.case ~index:5 Bcs.string_utf8
        ~inject:(fun m -> Res_recoverable_error m)
        ~project:(function
          | Res_recoverable_error m -> Some m
          | Res_vote _ | Res_missing_parents _ | Res_epoch_record _
          | Res_peer_exchange _ | Res_error _ ->
              None);
    ]

let gossip_codec : gossip Bcs.t =
  Bcs.sum
    [
      Bcs.case ~index:0 Certificate_wire.codec
        ~inject:(fun c -> Gossip_certificate c)
        ~project:(function
          | Gossip_certificate c -> Some c
          | Gossip_consensus _ | Gossip_epoch_vote _ -> None);
      Bcs.case ~index:1 Consensus_result.codec
        ~inject:(fun c -> Gossip_consensus c)
        ~project:(function
          | Gossip_consensus c -> Some c
          | Gossip_certificate _ | Gossip_epoch_vote _ -> None);
      Bcs.case ~index:2 Epoch_vote.codec
        ~inject:(fun v -> Gossip_epoch_vote v)
        ~project:(function
          | Gossip_epoch_vote v -> Some v
          | Gossip_certificate _ | Gossip_consensus _ -> None);
    ]

let ( let* ) = Result.bind

let missing_certificates_request_codec : missing_certificates_request Bcs.t =
  Bcs.make
    ~write:(fun w m ->
      Bcs.write Wire_scalar.round w m.exclusive_lower_bound;
      Bcs.write
        (Bcs.list (Bcs.pair Wire_scalar.authority_id Bcs.bytes))
        w m.skip_rounds;
      Bcs.Writer.u64 w m.max_response_size)
    ~read:(fun r ->
      let* exclusive_lower_bound = Bcs.read Wire_scalar.round r in
      let* skip_rounds =
        Bcs.read (Bcs.list (Bcs.pair Wire_scalar.authority_id Bcs.bytes)) r
      in
      let* max_response_size = Bcs.Reader.u64 r in
      Ok { exclusive_lower_bound; skip_rounds; max_response_size })

let request_equal a b =
  match (a, b) with
  | Req_vote x, Req_vote y ->
      Tn_vertex.Header.equal x.header y.header
      && List.equal Certificate_wire.equal x.parents y.parents
  | Req_peer_exchange x, Req_peer_exchange y -> Peer_exchange.equal x y
  | Req_epoch_record x, Req_epoch_record y ->
      Option.equal Units.Epoch.equal x.epoch y.epoch
      && Option.equal Tn_crypto.Digest.equal x.hash y.hash
  | (Req_vote _ | Req_peer_exchange _ | Req_epoch_record _), _ -> false

let response_equal a b =
  match (a, b) with
  | Res_vote x, Res_vote y -> Vote_wire.equal x y
  | Res_missing_parents x, Res_missing_parents y ->
      List.equal Digests.Header_digest.equal x y
  | Res_epoch_record x, Res_epoch_record y ->
      Epoch_record.equal x.record y.record
      && Epoch_certificate.equal x.certificate y.certificate
  | Res_peer_exchange x, Res_peer_exchange y -> Peer_exchange.equal x y
  | Res_error x, Res_error y -> String.equal x y
  | Res_recoverable_error x, Res_recoverable_error y -> String.equal x y
  | ( ( Res_vote _ | Res_missing_parents _ | Res_epoch_record _
      | Res_peer_exchange _ | Res_error _ | Res_recoverable_error _ ),
      _ ) ->
      false

let gossip_equal a b =
  match (a, b) with
  | Gossip_certificate x, Gossip_certificate y -> Certificate_wire.equal x y
  | Gossip_consensus x, Gossip_consensus y -> Consensus_result.equal x y
  | Gossip_epoch_vote x, Gossip_epoch_vote y -> Epoch_vote.equal x y
  | (Gossip_certificate _ | Gossip_consensus _ | Gossip_epoch_vote _), _ -> false
