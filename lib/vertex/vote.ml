open Tn_types
module D = Tn_crypto.Digest

type t = {
  header_digest : Digests.Header_digest.t;
  round : Round.t;
  epoch : Units.Epoch.t;
  origin : Authority_id.t;
  author : Authority_id.t;
  signature : Tn_crypto.Signature.t;
}

let signing_message hd =
  Intent.wrap Intent.Consensus_vote (D.to_bytes (Digests.Header_digest.to_digest hd))

let sign sk ~voter header =
  let hd = Header.digest header in
  {
    header_digest = hd;
    round = Header.round header;
    epoch = Header.epoch header;
    origin = Header.author header;
    author = voter;
    signature = Tn_crypto.sign sk (signing_message hd);
  }

let header_digest t = t.header_digest
let round t = t.round
let epoch t = t.epoch
let origin t = t.origin
let author t = t.author
let signature t = t.signature
let verify pk t = Tn_crypto.verify pk (signing_message t.header_digest) t.signature
