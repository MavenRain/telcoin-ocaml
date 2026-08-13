module Bcs = Tn_codec.Bcs

type t = {
  epoch_hash : Tn_crypto.Digest.t;
  signature : Bls_signature.t;
  signed_authorities : Roaring.t;
}

let make ~epoch_hash ~signature ~signed_authorities =
  { epoch_hash; signature; signed_authorities }

let ( let* ) = Result.bind

let codec : t Bcs.t =
  Bcs.make
    ~write:(fun w t ->
      Bcs.write Wire_scalar.digest w t.epoch_hash;
      Bcs.write Bls_signature.codec w t.signature;
      Bcs.write Roaring.codec w t.signed_authorities)
    ~read:(fun r ->
      let* epoch_hash = Bcs.read Wire_scalar.digest r in
      let* signature = Bcs.read Bls_signature.codec r in
      let* signed_authorities = Bcs.read Roaring.codec r in
      Ok { epoch_hash; signature; signed_authorities })

let equal a b =
  Tn_crypto.Digest.equal a.epoch_hash b.epoch_hash
  && Bls_signature.equal a.signature b.signature
  && Roaring.equal a.signed_authorities b.signed_authorities
