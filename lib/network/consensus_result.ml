open Tn_types
module Bcs = Tn_codec.Bcs

type t = {
  epoch : Units.Epoch.t;
  round : Round.t;
  number : int64;
  hash : Tn_crypto.Digest.t;
  validator : Bls_public_key.t;
  signature : Bls_signature.t;
}

let make ~epoch ~round ~number ~hash ~validator ~signature =
  { epoch; round; number; hash; validator; signature }

let ( let* ) = Result.bind

let codec : t Bcs.t =
  Bcs.make
    ~write:(fun w t ->
      Bcs.write Wire_scalar.epoch w t.epoch;
      Bcs.write Wire_scalar.round w t.round;
      Bcs.Writer.u64 w t.number;
      Bcs.write Wire_scalar.digest w t.hash;
      Bcs.write Bls_public_key.codec w t.validator;
      Bcs.write Bls_signature.codec w t.signature)
    ~read:(fun r ->
      let* epoch = Bcs.read Wire_scalar.epoch r in
      let* round = Bcs.read Wire_scalar.round r in
      let* number = Bcs.Reader.u64 r in
      let* hash = Bcs.read Wire_scalar.digest r in
      let* validator = Bcs.read Bls_public_key.codec r in
      let* signature = Bcs.read Bls_signature.codec r in
      Ok { epoch; round; number; hash; validator; signature })

let equal a b =
  Units.Epoch.equal a.epoch b.epoch
  && Round.equal a.round b.round
  && Int64.equal a.number b.number
  && Tn_crypto.Digest.equal a.hash b.hash
  && Bls_public_key.equal a.validator b.validator
  && Bls_signature.equal a.signature b.signature
