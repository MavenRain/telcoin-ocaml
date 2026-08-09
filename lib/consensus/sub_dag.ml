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

(* The only place the cached digest is computed, shared by [create] and by the
   storage decoder so the two can never drift. *)
let of_persisted ~headers ~scores ~stored ~randomness =
  let pre = preimage_bytes ~sequence:headers ~scores ~stored ~randomness in
  let digest =
    Digests.Sub_dag_digest.of_digest
      (Tn_crypto.Digest.hash (Digests.Sub_dag_digest.domain ^ pre))
  in
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
  of_persisted ~headers ~scores ~stored ~randomness

(* A whole-second timestamp beyond the representable range is refused, not
   clamped: a clamped value would hash to a digest the writer never wrote. *)
let timestamp_codec =
  Bcs.refine
    ~inject:(fun secs ->
      Option.to_result ~none:"sub-DAG: stored timestamp out of range"
        (Units.Timestamp.of_sec secs))
    ~project:Units.Timestamp.to_sec Bcs.u64

let randomness_codec =
  Bcs.iso
    ~inject:(fun raw ->
      Option.value (Tn_crypto.Digest.of_bytes raw) ~default:Tn_crypto.Digest.zero)
    ~project:Tn_crypto.Digest.to_bytes
    (Bcs.fixed_bytes Tn_crypto.Digest.length)

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
