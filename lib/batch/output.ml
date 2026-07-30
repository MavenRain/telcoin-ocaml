(* ConsensusOutput's payload attachment (output.rs:42-64,
   subscriber.rs:430-551 at telcoin-network 5dbb764e) made pure. The
   subscriber's worker fetch is the [lookup] dependency and the authority
   execution-address table is [address_of]; everything else is a fold over
   the sub-DAG's headers in commit order (leader last). *)

module Units = Tn_types.Units
module Digests = Tn_types.Digests
module Authority_id = Tn_types.Authority_id
module Batch = Tn_types.Batch
module Sub_dag = Tn_consensus.Sub_dag
module Header = Tn_vertex.Header
module Consensus_block = Tn_execution.Consensus_block

type error =
  | Missing_batch of Digests.Batch_digest.t
  | Unknown_authority of Authority_id.t

let error_to_string e =
  match e with
  | Missing_batch digest ->
      Printf.sprintf "missing fetched batch 0x%s"
        (Digests.Batch_digest.to_hex digest)
  | Unknown_authority id ->
      Printf.sprintf "unknown authority %s" (Authority_id.to_hex id)

(* One certificate's worth of attached payload: the CertifiedBatch image
   (output.rs:31-40). Digests are kept beside their batches so the flat
   digest list and the certified batches can never go uneven: TN's
   ConsensusOutputUnevenBatches guard (payload_builder.rs:60-86) is
   discharged by construction. *)
type entry = {
  address : Units.Address.t;
  resolved : (Digests.Batch_digest.t * Batch.t) list;
}

type t = {
  consensus : Consensus_block.t;
  entries : entry list;
  leader_address : Units.Address.t;
}

let ( let* ) = Result.bind

(* Resolve one header: its author's execution address, then every payload
   digest in payload order. A duplicate digest (across headers) resolves
   again, mirroring the subscriber's clone (subscriber.rs:480-509). *)
let resolve_entry ~lookup ~address_of header =
  let* address =
    address_of (Header.author header)
    |> Option.to_result ~none:(Unknown_authority (Header.author header))
  in
  Header.payload header
  |> List.fold_left
       (fun acc (digest, _worker_id) ->
         let* rev = acc in
         lookup digest
         |> Option.to_result ~none:(Missing_batch digest)
         |> Result.map (fun batch -> (digest, batch) :: rev))
       (Ok [])
  |> Result.map (fun rev -> { address; resolved = List.rev rev })

let attach ~consensus ~lookup ~address_of =
  let sub_dag = Consensus_block.sub_dag consensus in
  let* entries =
    Sub_dag.headers sub_dag |> Tn_std.Nonempty.to_list
    |> List.fold_left
         (fun acc header ->
           let* rev = acc in
           resolve_entry ~lookup ~address_of header
           |> Result.map (fun entry -> entry :: rev))
         (Ok [])
    |> Result.map List.rev
  in
  (* The leader is the last header (Sub_dag's leader-last invariant), so
     this re-resolves an address the fold above already accepted; kept as
     its own lookup so the close-block beneficiary has one clear source. *)
  let leader = Sub_dag.leader sub_dag in
  let* leader_address =
    address_of (Header.author leader)
    |> Option.to_result ~none:(Unknown_authority (Header.author leader))
  in
  Ok { consensus; entries; leader_address }

let consensus t = t.consensus
let output_digest t = Consensus_block.digest t.consensus

let batch_digests t =
  List.concat_map (fun entry -> List.map fst entry.resolved) t.entries

let certified t =
  List.map (fun entry -> (entry.address, List.map snd entry.resolved)) t.entries

let leader_address t = t.leader_address

let leader_epoch t = Sub_dag.leader_epoch (Consensus_block.sub_dag t.consensus)

let committed_at t =
  Sub_dag.commit_timestamp (Consensus_block.sub_dag t.consensus)

let nonce t = Sub_dag.sequence_number (Consensus_block.sub_dag t.consensus)

let closes_epoch t ~epoch_boundary =
  Units.Timestamp.compare (committed_at t) epoch_boundary >= 0
