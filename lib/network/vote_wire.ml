open Tn_types
module Bcs = Tn_codec.Bcs
module Vote = Tn_vertex.Vote

type t = {
  header_digest : Digests.Header_digest.t;
  round : Round.t;
  epoch : Units.Epoch.t;
  origin : Authority_id.t;
  author : Authority_id.t;
  signature : Bls_signature.t;
}

type error = Signature_rejected | Does_not_verify

let error_to_string = function
  | Signature_rejected -> "vote: the crypto seam refused the signature"
  | Does_not_verify -> "vote: signature does not verify"

let make ~header_digest ~round ~epoch ~origin ~author ~signature =
  { header_digest; round; epoch; origin; author; signature }

let header_digest t = t.header_digest
let round t = t.round
let epoch t = t.epoch
let origin t = t.origin
let author t = t.author
let signature t = t.signature
let ( let* ) = Result.bind

let codec : t Bcs.t =
  Bcs.make
    ~write:(fun w t ->
      Bcs.write Wire_scalar.header_digest w t.header_digest;
      Bcs.write Wire_scalar.round w t.round;
      Bcs.write Wire_scalar.epoch w t.epoch;
      Bcs.write Wire_scalar.authority_id w t.origin;
      Bcs.write Wire_scalar.authority_id w t.author;
      Bcs.write Bls_signature.codec w t.signature)
    ~read:(fun r ->
      let* header_digest = Bcs.read Wire_scalar.header_digest r in
      let* round = Bcs.read Wire_scalar.round r in
      let* epoch = Bcs.read Wire_scalar.epoch r in
      let* origin = Bcs.read Wire_scalar.authority_id r in
      let* author = Bcs.read Wire_scalar.authority_id r in
      let* signature = Bcs.read Bls_signature.codec r in
      Ok { header_digest; round; epoch; origin; author; signature })

let to_vote t =
  Option.to_result ~none:Signature_rejected
    (Vote.claim ~header_digest:t.header_digest ~round:t.round ~epoch:t.epoch
       ~origin:t.origin ~author:t.author
       ~signature:(Bls_signature.to_bytes t.signature))

let to_verified public_key t =
  let* vote = to_vote t in
  if Vote.verify public_key vote then Ok vote else Error Does_not_verify

let of_vote vote =
  Result.map
    (fun signature ->
      {
        header_digest = Vote.header_digest vote;
        round = Vote.round vote;
        epoch = Vote.epoch vote;
        origin = Vote.origin vote;
        author = Vote.author vote;
        signature;
      })
    (Option.to_result ~none:Signature_rejected
       (Bls_signature.of_bytes (Tn_crypto.Signature.to_bytes (Vote.signature vote))))

let equal a b =
  Digests.Header_digest.equal a.header_digest b.header_digest
  && Round.equal a.round b.round
  && Units.Epoch.equal a.epoch b.epoch
  && Authority_id.equal a.origin b.origin
  && Authority_id.equal a.author b.author
  && Bls_signature.equal a.signature b.signature
