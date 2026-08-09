open Tn_std
open Tn_types
open Tn_vertex
module Bcs = Tn_codec.Bcs
module Hash32 = Tn_hash32.Hash32

type t = {
  sequence : Header.t Nonempty.t; (* commit order: ascending round, leader last *)
  scores : Reputation_scores.t;
  stored : Units.Timestamp.t; (* the raw clamped value that feeds the digest *)
  randomness : Hash32.t; (* keccak256, NOT the Tn_crypto seam *)
  digest : Digests.Sub_dag_digest.t; (* computed once in create and cached *)
}

(* [BlsSignature::default().to_bytes()]: the compressed point at infinity on
   G1, so byte 0 is 0xc0 (the compressed flag or the infinity flag) and the
   remaining 47 bytes are zero. Rust's [CommittedSubDag::new] falls back to
   exactly these bytes when the leader carries no aggregate signature
   (primary/output.rs:378-382), so the fallback pre-image is this constant and
   never the empty string. *)
let default_signature_bytes = "\xc0" ^ String.make 47 '\000'

let default_randomness =
  Hash32.of_keccak (Tn_keccak.digest default_signature_bytes)

let headers t = t.sequence

(* Commit order, duplicates kept: the same flatten [Tn_batch.Output.attach]
   performs, minus the per-certificate grouping it needs and this does not. *)
let payload_digests t =
  Nonempty.to_list t.sequence
  |> List.concat_map (fun header -> List.map fst (Header.payload header))

let leader t = Nonempty.last t.sequence
let leader_round t = Header.round (leader t)
let leader_author t = Header.author (leader t)
let leader_epoch t = Header.epoch (leader t)
let scores t = t.scores
let stored_timestamp t = t.stored
let randomness t = t.randomness
let digest t = t.digest

let sequence_number t =
  Units.Sequence_number.of_epoch_round (Header.epoch (leader t)) (Header.round (leader t))

(* Rust reads [previous.commit_timestamp] — the raw stored field, not the
   fallback getter — so the previous read here is [stored_timestamp]. The
   accessor view below diverges from it only when the stored value is zero. *)
let commit_timestamp t =
  if Units.Timestamp.equal t.stored Units.Timestamp.zero then Header.created_at (leader t)
  else t.stored

let header_digest_bytes sequence =
  let buf = Buffer.create (Tn_crypto.Digest.length * Nonempty.length sequence) in
  Nonempty.iter
    (fun h ->
      Buffer.add_string buf
        (Tn_crypto.Digest.to_bytes (Digests.Header_digest.to_digest (Header.digest h))))
    sequence;
  Buffer.contents buf

(* The frozen pre-image: header digests in sequence order, BCS scores, 8-byte
   LE stored timestamp, raw randomness, with no separators between them. The
   scores section is {!Reputation_scores.codec} itself, not a second copy of
   its shape: Rust hashes [bcs(inner.reputation_scores)] (output.rs:466), the
   very bytes the wire carries, so sharing the codec makes the agreement
   structural instead of a comment. *)
let preimage_bytes ~sequence ~scores ~stored ~randomness =
  header_digest_bytes sequence
  ^ Bcs.encode Reputation_scores.codec scores
  ^ Bcs.encode Bcs.u64 (Units.Timestamp.to_sec stored)
  ^ Hash32.to_bytes randomness

let preimage t =
  preimage_bytes ~sequence:t.sequence ~scores:t.scores ~stored:t.stored
    ~randomness:t.randomness

(* The only place the cached digest is computed, shared by [create] and by the
   storage decoder so the two can never drift. *)
let of_persisted ~headers ~scores ~stored ~randomness =
  let pre = preimage_bytes ~sequence:headers ~scores ~stored ~randomness in
  (* The BARE pre-image, no tag: Rust's [CommittedSubDag::digest] feeds the four
     parts straight into the hasher (primary/output.rs:457-471). *)
  let digest = Digests.Sub_dag_digest.of_digest (Tn_crypto.Digest.hash pre) in
  { sequence = headers; scores; stored; randomness; digest }

let create ~sequence ~scores ~previous =
  let leader_cert = Nonempty.last sequence in
  let leader_header = Certificate.header leader_cert in
  let headers = Nonempty.map Certificate.header sequence in
  let stored =
    Units.Timestamp.max
      (previous |> Option.fold ~none:Units.Timestamp.zero ~some:stored_timestamp)
      (Header.created_at leader_header)
  in
  (* keccak256 of the leader's aggregate signature bytes, with the default
     signature standing in when the leader carries none — Rust's
     [CommittedSubDag::new] (primary/output.rs:378-382). Keccak is a fixed fact
     of the protocol, not a seam choice, so this does not route through
     {!Tn_crypto}. *)
  let signature_bytes =
    Certificate.aggregate_signature leader_cert
    |> Option.fold ~none:default_signature_bytes ~some:Tn_crypto.Aggregate.to_bytes
  in
  let randomness = Hash32.of_keccak (Tn_keccak.digest signature_bytes) in
  of_persisted ~headers ~scores ~stored ~randomness

(* A whole-second timestamp beyond the representable range is refused, not
   clamped: a clamped value would hash to a digest the writer never wrote. *)
let timestamp_codec =
  Bcs.refine
    ~inject:(fun secs ->
      Option.to_result ~none:"sub-DAG: stored timestamp out of range"
        (Units.Timestamp.of_sec secs))
    ~project:Units.Timestamp.to_sec Bcs.u64

(* [pfx32], not the pre-image's bare 32: Rust's [randomness: B256] serialises
   through alloy's [serialize_bytes], which bcs always length-prefixes, so the
   wire carries 0x20 then the 32 bytes while {!preimage} carries them bare
   (output.rs:470). The two classes are deliberately different here; unifying
   them breaks one side or the other. [sized_bytes] fixes the width at the
   codec, so [of_bytes] cannot miss and the eager default is a constant. *)
let randomness_codec =
  Bcs.iso
    ~inject:(fun raw -> Option.value (Hash32.of_bytes raw) ~default:Hash32.zero)
    ~project:Hash32.to_bytes
    (Bcs.sized_bytes Hash32.length)

(* Non-emptiness survives the wire as a refusal, never as a repaired value. *)
let sequence_codec =
  Bcs.refine
    ~inject:(fun headers ->
      Option.to_result ~none:"sub-DAG: the committed sequence is never empty"
        (Nonempty.of_list headers))
    ~project:Nonempty.to_list (Bcs.list Header.codec)

let codec : t Bcs.t =
  Bcs.iso
    ~inject:(fun ((headers, scores, stored), randomness) ->
      of_persisted ~headers ~scores ~stored ~randomness)
    ~project:(fun t -> ((t.sequence, t.scores, t.stored), t.randomness))
    (Bcs.pair
       (Bcs.triple sequence_codec Reputation_scores.codec timestamp_codec)
       randomness_codec)

let equal a b = Digests.Sub_dag_digest.equal a.digest b.digest
let compare a b = Digests.Sub_dag_digest.compare a.digest b.digest
