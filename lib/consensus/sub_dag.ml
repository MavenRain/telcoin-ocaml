open Tn_std
open Tn_types
open Tn_vertex
module Bcs = Tn_codec.Bcs

type t = {
  sequence : Header.t Nonempty.t; (* commit order: ascending round, leader last *)
  scores : Reputation_scores.t;
  stored : Units.Timestamp.t; (* the raw clamped value that feeds the digest *)
  randomness : Tn_crypto.Digest.t;
  digest : Digests.Sub_dag_digest.t; (* computed once in create and cached *)
}

let headers t = t.sequence
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

(* BCS shape of the scores, matching Rust exactly: a ULEB128-counted map with
   32-byte keys ascending bytewise and u64 little-endian values, followed by the
   final-of-schedule bool. [Reputation_scores.bindings] is already ascending id
   (= ascending bytes), which [sorted_map] re-checks. *)
let scores_codec =
  Bcs.pair (Bcs.sorted_map (Bcs.fixed_bytes 32) Bcs.u64 ~compare:String.compare) Bcs.bool

let scores_value scores =
  ( List.map
      (fun (id, s) -> (Authority_id.to_bytes id, Int64.of_int s))
      (Reputation_scores.bindings scores),
    Reputation_scores.is_final scores )

let header_digest_bytes sequence =
  let buf = Buffer.create (Tn_crypto.Digest.length * Nonempty.length sequence) in
  Nonempty.iter
    (fun h ->
      Buffer.add_string buf
        (Tn_crypto.Digest.to_bytes (Digests.Header_digest.to_digest (Header.digest h))))
    sequence;
  Buffer.contents buf

(* The frozen pre-image: header digests in sequence order, BCS scores, 8-byte
   LE stored timestamp, raw randomness — no domain tag, no separators. *)
let preimage_bytes ~sequence ~scores ~stored ~randomness =
  header_digest_bytes sequence
  ^ Bcs.encode scores_codec (scores_value scores)
  ^ Bcs.encode Bcs.u64 (Units.Timestamp.to_sec stored)
  ^ Tn_crypto.Digest.to_bytes randomness

let preimage t =
  preimage_bytes ~sequence:t.sequence ~scores:t.scores ~stored:t.stored
    ~randomness:t.randomness

let create ~sequence ~scores ~previous =
  let leader_cert = Nonempty.last sequence in
  let leader_header = Certificate.header leader_cert in
  let sequence = Nonempty.map Certificate.header sequence in
  let stored =
    Units.Timestamp.max
      (previous |> Option.fold ~none:Units.Timestamp.zero ~some:stored_timestamp)
      (Header.created_at leader_header)
  in
  (* Divergence: Rust derives randomness with keccak256 of the aggregate BLS
     signature bytes and falls back to [BlsSignature::default().to_bytes()] on
     the (leader-unreachable) missing-signature case; this port routes the same
     bytes through the {!Tn_crypto} seam and hashes empty bytes on that dead
     branch. Deterministic either way; aligning the concrete hash and the
     fallback constant is deferred to the codec/crypto chunk. *)
  let randomness =
    Certificate.aggregate_signature leader_cert
    |> Option.fold ~none:"" ~some:Tn_crypto.Aggregate.to_bytes
    |> Tn_crypto.Digest.hash
  in
  let pre = preimage_bytes ~sequence ~scores ~stored ~randomness in
  let digest =
    Digests.Sub_dag_digest.of_digest
      (Tn_crypto.Digest.hash (Digests.Sub_dag_digest.domain ^ pre))
  in
  { sequence; scores; stored; randomness; digest }

let equal a b = Digests.Sub_dag_digest.equal a.digest b.digest
let compare a b = Digests.Sub_dag_digest.compare a.digest b.digest
