open Tn_types
module Bcs = Tn_codec.Bcs

type consensus_num_hash = { number : int64; hash : Tn_crypto.Digest.t }

type t = {
  epoch : Units.Epoch.t;
  committee : Bls_public_key.t list;
  next_committee : Bls_public_key.t list;
  parent_hash : Tn_crypto.Digest.t;
  final_state : Block_num_hash.t;
  final_consensus : consensus_num_hash;
}

let make_consensus_num_hash ~number ~hash = { number; hash }

let make ~epoch ~committee ~next_committee ~parent_hash ~final_state
    ~final_consensus =
  { epoch; committee; next_committee; parent_hash; final_state; final_consensus }

let ( let* ) = Result.bind

let consensus_num_hash_codec : consensus_num_hash Bcs.t =
  Bcs.make
    ~write:(fun w c ->
      Bcs.Writer.u64 w c.number;
      Bcs.write Wire_scalar.digest w c.hash)
    ~read:(fun r ->
      let* number = Bcs.Reader.u64 r in
      let* hash = Bcs.read Wire_scalar.digest r in
      Ok { number; hash })

let key_list : Bls_public_key.t list Bcs.t = Bcs.list Bls_public_key.codec

let codec : t Bcs.t =
  Bcs.make
    ~write:(fun w t ->
      Bcs.write Wire_scalar.epoch w t.epoch;
      Bcs.write key_list w t.committee;
      Bcs.write key_list w t.next_committee;
      Bcs.write Wire_scalar.digest w t.parent_hash;
      Bcs.write Block_num_hash.codec w t.final_state;
      Bcs.write consensus_num_hash_codec w t.final_consensus)
    ~read:(fun r ->
      let* epoch = Bcs.read Wire_scalar.epoch r in
      let* committee = Bcs.read key_list r in
      let* next_committee = Bcs.read key_list r in
      let* parent_hash = Bcs.read Wire_scalar.digest r in
      let* final_state = Bcs.read Block_num_hash.codec r in
      let* final_consensus = Bcs.read consensus_num_hash_codec r in
      Ok
        {
          epoch;
          committee;
          next_committee;
          parent_hash;
          final_state;
          final_consensus;
        })

let equal a b =
  Units.Epoch.equal a.epoch b.epoch
  && List.equal Bls_public_key.equal a.committee b.committee
  && List.equal Bls_public_key.equal a.next_committee b.next_committee
  && Tn_crypto.Digest.equal a.parent_hash b.parent_hash
  && Block_num_hash.equal a.final_state b.final_state
  && Int64.equal a.final_consensus.number b.final_consensus.number
  && Tn_crypto.Digest.equal a.final_consensus.hash b.final_consensus.hash
