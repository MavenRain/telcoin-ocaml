open Tn_types
module Bcs = Tn_codec.Bcs

type t = {
  epoch : Units.Epoch.t;
  epoch_hash : Tn_crypto.Digest.t;
  public_key : Bls_public_key.t;
  signature : Bls_signature.t;
}

let make ~epoch ~epoch_hash ~public_key ~signature =
  { epoch; epoch_hash; public_key; signature }

let ( let* ) = Result.bind

let codec : t Bcs.t =
  Bcs.make
    ~write:(fun w t ->
      Bcs.write Wire_scalar.epoch w t.epoch;
      Bcs.write Wire_scalar.digest w t.epoch_hash;
      Bcs.write Bls_public_key.codec w t.public_key;
      Bcs.write Bls_signature.codec w t.signature)
    ~read:(fun r ->
      let* epoch = Bcs.read Wire_scalar.epoch r in
      let* epoch_hash = Bcs.read Wire_scalar.digest r in
      let* public_key = Bcs.read Bls_public_key.codec r in
      let* signature = Bcs.read Bls_signature.codec r in
      Ok { epoch; epoch_hash; public_key; signature })

let equal a b =
  Units.Epoch.equal a.epoch b.epoch
  && Tn_crypto.Digest.equal a.epoch_hash b.epoch_hash
  && Bls_public_key.equal a.public_key b.public_key
  && Bls_signature.equal a.signature b.signature
