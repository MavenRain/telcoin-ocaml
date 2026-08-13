module Bcs = Tn_codec.Bcs

let max_gossip_message_size = 12_000
let primary_topic ~chain_id = Printf.sprintf "tn-primary-%d" chain_id

let consensus_output_topic ~chain_id =
  Printf.sprintf "tn-consensus-output-%d" chain_id

let epoch_vote_topic ~chain_id = Printf.sprintf "tn-epoch-vote-%d" chain_id
let worker_batch_topic ~chain_id = Printf.sprintf "tn-worker-%d" chain_id

type topic_kind =
  | Primary_certificate
  | Consensus_output
  | Epoch_vote
  | Worker_batch

let topic_of_kind ~chain_id = function
  | Primary_certificate -> primary_topic ~chain_id
  | Consensus_output -> consensus_output_topic ~chain_id
  | Epoch_vote -> epoch_vote_topic ~chain_id
  | Worker_batch -> worker_batch_topic ~chain_id

let all_kinds = [ Primary_certificate; Consensus_output; Epoch_vote; Worker_batch ]

let topic_kind ~chain_id topic =
  List.find_opt
    (fun kind -> String.equal (topic_of_kind ~chain_id kind) topic)
    all_kinds

type payload =
  | Primary_payload of Primary_msg.gossip
  | Worker_payload of Worker_msg.gossip

type error = Unknown_topic of { topic : string } | Bcs of Bcs.error

let error_to_string = function
  | Unknown_topic { topic } -> Printf.sprintf "gossip: unknown topic %S" topic
  | Bcs e -> "gossip: " ^ Bcs.error_to_string e

let decode_kind kind bytes =
  let wrap codec inject =
    Result.fold
      ~ok:(fun v -> Ok (inject v))
      ~error:(fun e -> Error (Bcs e))
      (Bcs.decode codec bytes)
  in
  match kind with
  | Primary_certificate ->
      wrap Primary_msg.gossip_codec (fun g -> Primary_payload g)
  | Consensus_output -> wrap Primary_msg.gossip_codec (fun g -> Primary_payload g)
  | Epoch_vote -> wrap Primary_msg.gossip_codec (fun g -> Primary_payload g)
  | Worker_batch -> wrap Worker_msg.gossip_codec (fun g -> Worker_payload g)

let decode ~chain_id ~topic bytes =
  Option.fold
    ~none:(Error (Unknown_topic { topic }))
    ~some:(fun kind -> decode_kind kind bytes)
    (topic_kind ~chain_id topic)

(* PeerId::from_bytes(&[0, 1, 0]), the source libp2p substitutes when a
   message carries none (config.rs:518-531). *)
let fallback_source = "\x00\x01\x00"

let message_id ~source ~sequence_number =
  (* [%Lu] is the UNSIGNED rendering of an Int64; [%Ld] would print a
     negative number for every sequence number at or above 2^63 and diverge
     from every Rust peer. *)
  Base58.encode (Option.value ~default:fallback_source source)
  ^ Printf.sprintf "%Lu" (Option.value ~default:0L sequence_number)

type publishers = Open | Restricted of Bls_public_key.t list

(* consensus.rs:1595-1600 wraps the whole allowlist rule in
   [gossip.source.is_some_and(..)], so the OUTERMOST condition is that the
   message carries a source at all: one with none is unauthorized whatever the
   topic entry says, an Open topic included. The BLS key is a second, separate
   resolution of that source, which only a {!Restricted} topic consults. *)
let topic_allows ~author = function
  | Open -> true
  | Restricted keys ->
      Option.fold ~none:false
        ~some:(fun key -> List.exists (Bls_public_key.equal key) keys)
        author

let publisher_allowed ~authorized ~topic ~source ~author =
  Option.fold ~none:false
    ~some:(fun (_ : string) ->
      Option.fold ~none:false
        ~some:(topic_allows ~author)
        (List.assoc_opt topic authorized))
    source

type reject_reason = Too_large | Unauthorized_author
type acceptance = Accept | Reject of reject_reason
type penalty_target = Fatal_relayer | Fatal_author | Skip

(* consensus.rs:1584-1604: the size test runs first and the allowlist second,
   so an oversized message never reaches the author check and is charged to
   the relayer even when its author would also have failed. *)
let verify ~data_len ~topic ~source ~author ~authorized =
  if data_len > max_gossip_message_size then Reject Too_large
  else if publisher_allowed ~authorized ~topic ~source ~author then Accept
  else Reject Unauthorized_author

let penalty reason ~relayer_resolved ~author_resolved =
  match reason with
  | Too_large -> if relayer_resolved then Fatal_relayer else Skip
  | Unauthorized_author -> if author_resolved then Fatal_author else Skip
