open Tn_types
module Bcs = Tn_codec.Bcs

type worker =
  | Batches of {
      batch_digests : Digests.Batch_digest.t list;
      epoch : Units.Epoch.t;
    }

type primary =
  | Epoch_pack of { epoch : Units.Epoch.t }
  | Missing_certificates of {
      exclusive_lower_bound : Round.t;
      skip_rounds : (Authority_id.t * string) list;
    }
  | Epoch_pack_partial of { epoch : Units.Epoch.t; last_consensus_number : int64 }
  | Consensus_output of { number : int64 }

(* Ordered by ENCODED bytes, the order bcs would sort a map key by and the
   order a Rust BTreeSet iterates a uniform 32-byte digest in. *)
let digest_set : Digests.Batch_digest.t list Bcs.t =
  Bcs.btree_set Wire_scalar.batch_digest
    ~compare:(Bcs.encoded_compare Wire_scalar.batch_digest)

let skip_rounds_codec : (Authority_id.t * string) list Bcs.t =
  Bcs.list (Bcs.pair Wire_scalar.authority_id Bcs.bytes)

let worker_codec : worker Bcs.t =
  Bcs.sum
    [
      Bcs.case ~index:0
        (Bcs.pair digest_set Wire_scalar.epoch)
        ~inject:(fun (batch_digests, epoch) -> Batches { batch_digests; epoch })
        ~project:(function
          | Batches b -> Some (b.batch_digests, b.epoch));
    ]

let primary_codec : primary Bcs.t =
  Bcs.sum
    [
      Bcs.case ~index:0 Wire_scalar.epoch
        ~inject:(fun epoch -> Epoch_pack { epoch })
        ~project:(function
          | Epoch_pack p -> Some p.epoch
          | Missing_certificates _ | Epoch_pack_partial _ | Consensus_output _ ->
              None);
      Bcs.case ~index:1
        (Bcs.pair Wire_scalar.round skip_rounds_codec)
        ~inject:(fun (exclusive_lower_bound, skip_rounds) ->
          Missing_certificates { exclusive_lower_bound; skip_rounds })
        ~project:(function
          | Missing_certificates m ->
              Some (m.exclusive_lower_bound, m.skip_rounds)
          | Epoch_pack _ | Epoch_pack_partial _ | Consensus_output _ -> None);
      Bcs.case ~index:2
        (Bcs.pair Wire_scalar.epoch Bcs.u64)
        ~inject:(fun (epoch, last_consensus_number) ->
          Epoch_pack_partial { epoch; last_consensus_number })
        ~project:(function
          | Epoch_pack_partial p -> Some (p.epoch, p.last_consensus_number)
          | Epoch_pack _ | Missing_certificates _ | Consensus_output _ -> None);
      Bcs.case ~index:3 Bcs.u64
        ~inject:(fun number -> Consensus_output { number })
        ~project:(function
          | Consensus_output c -> Some c.number
          | Epoch_pack _ | Missing_certificates _ | Epoch_pack_partial _ -> None);
    ]

let worker_equal a b =
  match (a, b) with
  | Batches x, Batches y ->
      List.equal Digests.Batch_digest.equal x.batch_digests y.batch_digests
      && Units.Epoch.equal x.epoch y.epoch

let skip_equal (a_id, a_blob) (b_id, b_blob) =
  Authority_id.equal a_id b_id && String.equal a_blob b_blob

let primary_equal a b =
  match (a, b) with
  | Epoch_pack x, Epoch_pack y -> Units.Epoch.equal x.epoch y.epoch
  | Missing_certificates x, Missing_certificates y ->
      Round.equal x.exclusive_lower_bound y.exclusive_lower_bound
      && List.equal skip_equal x.skip_rounds y.skip_rounds
  | Epoch_pack_partial x, Epoch_pack_partial y ->
      Units.Epoch.equal x.epoch y.epoch
      && Int64.equal x.last_consensus_number y.last_consensus_number
  | Consensus_output x, Consensus_output y -> Int64.equal x.number y.number
  | ( ( Epoch_pack _ | Missing_certificates _ | Epoch_pack_partial _
      | Consensus_output _ ),
      _ ) ->
      false
