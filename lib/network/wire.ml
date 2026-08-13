(* The translation table between the wire messages and Tn_consensus.Node.
   Nothing here decides anything: every function is a total mapping from one
   message to the actions or the event it stands for, so the shim that owns
   the sockets owns no protocol knowledge beyond routing. *)

open Tn_types
module Bcs = Tn_codec.Bcs
module Node = Tn_consensus.Node

type outbound =
  | Publish of { topic : string; payload : string }
  | Request of { to_ : Authority_id.t; request : Primary_msg.request }
  | Response of { response : Primary_msg.response }
  | Local

type unmapped =
  | Peer_exchange_request
  | Epoch_record_request
  | Missing_parents_response
  | Epoch_record_response
  | Peer_exchange_response
  | Rpc_error_response
  | Recoverable_rpc_error_response
  | Consensus_gossip
  | Epoch_vote_gossip
  | Worker_batch_gossip

type inbound_verdict =
  | Event of Node.event
  | Not_a_node_event of unmapped

type error =
  | Vote_ingress of Vote_wire.error
  | Certificate_ingress of Certificate_wire.error
  | Gossip_decode of Gossip.error

let error_to_string = function
  | Vote_ingress e -> "wire: " ^ Vote_wire.error_to_string e
  | Certificate_ingress e -> "wire: " ^ Certificate_wire.error_to_string e
  | Gossip_decode e -> "wire: " ^ Gossip.error_to_string e

(* Tail-recursive traversal of a fallible mapping: the first refusal is the
   answer, and [Result.bind]'s continuation is not evaluated on it. *)
let traverse f items =
  let rec go acc rest =
    match rest with
    | [] -> Ok (List.rev acc)
    | x :: xs -> Result.bind (f x) (fun y -> go (y :: acc) xs)
  in
  go [] items

let retry_vote_request ~header ~parents = Primary_msg.Req_vote { header; parents }

let outbound_of_command ~committee ~chain_id command =
  match command with
  | Node.Broadcast_header header ->
      (* One request per committee member, in committee order: the fan-out
         node.mli's single command does not carry (GT:494). Parents are empty
         on the first leg and attach only on the retry. *)
      Ok
        (List.map
           (fun authority ->
             Request
               {
                 to_ = Authority.id authority;
                 request = Primary_msg.Req_vote { header; parents = [] };
               })
           (Committee.authorities committee))
  | Node.Send_vote { to_ = _; vote } ->
      Result.fold
        ~ok:(fun wire -> Ok [ Response { response = Primary_msg.Res_vote wire } ])
        ~error:(fun e -> Error (Vote_ingress e))
        (Vote_wire.of_vote vote)
  | Node.Send_missing_parents { to_ = _; digests } ->
      (* The same request-response channel as the vote it answers, which is
         why it is a Response and not a Request (GT:496). *)
      Ok [ Response { response = Primary_msg.Res_missing_parents digests } ]
  | Node.Broadcast_certificate certificate ->
      Result.fold
        ~ok:(fun wire ->
          Ok
            [
              Publish
                {
                  topic = Gossip.primary_topic ~chain_id;
                  payload =
                    Bcs.encode Primary_msg.gossip_codec
                      (Primary_msg.Gossip_certificate wire);
                };
            ])
        ~error:(fun e -> Error (Certificate_ingress e))
        (Certificate_wire.of_certificate committee certificate)
  | Node.Arm_timer { kind = _; after = _; gen = _ } -> Ok [ Local ]
  | Node.Emit_committed _ -> Ok [ Local ]

let checked_parents ~committee parents =
  traverse
    (fun parent ->
      Result.map_error
        (fun e -> Certificate_ingress e)
        (Certificate_wire.to_checked committee parent))
    parents

let event_of_request ~committee ~from_ request =
  match request with
  | Primary_msg.Req_vote { header; parents } ->
      Result.map
        (fun parents -> Event (Node.Vote_request { from_; header; parents }))
        (checked_parents ~committee parents)
  | Primary_msg.Req_peer_exchange _ -> Ok (Not_a_node_event Peer_exchange_request)
  | Primary_msg.Req_epoch_record _ -> Ok (Not_a_node_event Epoch_record_request)

let event_of_response response =
  match response with
  | Primary_msg.Res_vote wire ->
      Result.fold
        ~ok:(fun vote -> Ok (Event (Node.Vote_received vote)))
        ~error:(fun e -> Error (Vote_ingress e))
        (Vote_wire.to_vote wire)
  | Primary_msg.Res_missing_parents _ ->
      Ok (Not_a_node_event Missing_parents_response)
  | Primary_msg.Res_epoch_record { record = _; certificate = _ } ->
      Ok (Not_a_node_event Epoch_record_response)
  | Primary_msg.Res_peer_exchange _ -> Ok (Not_a_node_event Peer_exchange_response)
  | Primary_msg.Res_error _ -> Ok (Not_a_node_event Rpc_error_response)
  | Primary_msg.Res_recoverable_error _ ->
      Ok (Not_a_node_event Recoverable_rpc_error_response)

let verdict_of_payload ~committee payload =
  match payload with
  | Gossip.Primary_payload (Primary_msg.Gossip_certificate wire) ->
      Result.fold
        ~ok:(fun certificate -> Ok (Event (Node.Certificate_received certificate)))
        ~error:(fun e -> Error (Certificate_ingress e))
        (Certificate_wire.to_checked committee wire)
  | Gossip.Primary_payload (Primary_msg.Gossip_consensus _) ->
      Ok (Not_a_node_event Consensus_gossip)
  | Gossip.Primary_payload (Primary_msg.Gossip_epoch_vote _) ->
      Ok (Not_a_node_event Epoch_vote_gossip)
  | Gossip.Worker_payload (Worker_msg.Wgossip_batch _) ->
      Ok (Not_a_node_event Worker_batch_gossip)

let event_of_gossip ~committee ~chain_id ~topic bytes =
  Result.bind
    (Result.map_error (fun e -> Gossip_decode e)
       (Gossip.decode ~chain_id ~topic bytes))
    (verdict_of_payload ~committee)
