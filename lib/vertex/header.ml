open Tn_types
module Bcs = Tn_codec.Bcs
module D = Tn_crypto.Digest

(* Semantic fields, separated from the cached digest so the digest is never
   part of its own pre-image. Field order is Rust's HeaderInner declaration
   order (primary/header.rs:13-39), which is also the BCS field order. *)
type fields = {
  author : Authority_id.t;
  round : Round.t;
  epoch : Units.Epoch.t;
  created_at : Units.Timestamp.t;
  payload : (Digests.Batch_digest.t * Units.Worker_id.t) list;
  parents : Digests.Header_digest.t list; (* sorted, de-duplicated *)
  latest_execution_block : Block_num_hash.t;
}

type t = { fields : fields; digest : Digests.Header_digest.t }

let canonical_parents ps = List.sort_uniq Digests.Header_digest.compare ps

(* Rust's payload is an [IndexMap<BlockHash, WorkerId>] read through
   [indexmap::map::serde_seq] (primary/header.rs:22-24), whose visitor inserts
   the decoded pairs one by one. [IndexMap::insert] on a key already present
   keeps that key in its FIRST position and overwrites its value with the LAST
   one seen, so a repeated batch digest collapses to a single entry. The port's
   payload is a list, which would keep the repeat, so the same collapse is
   applied here: otherwise identical wire bytes give the two nodes different
   header digests, since Rust digests the map it decoded. *)
let canonical_payload entries =
  let insert acc (key, wid) =
    let seen = List.exists (fun (k, _) -> Digests.Batch_digest.equal k key) acc in
    if seen then
      List.map
        (fun (k, v) ->
          if Digests.Batch_digest.equal k key then (k, wid) else (k, v))
        acc
    else (key, wid) :: acc
  in
  List.rev (List.fold_left insert [] entries)

let ( let* ) = Result.bind
let ok = Result.ok

(* Every 32-byte digest in this struct is a Rust [Digest<32>] or a [BlockHash],
   and both reach bcs through [serialize_bytes], so each is LENGTH-PREFIXED:
   0x20 then the 32 bytes. Only the author escapes that, being an
   [AuthorityIdentifier] whose serde is an array (committee.rs:307-319) and so a
   bare 32. Decoding through [sized_bytes] refuses a bare 32-byte digest at its
   own offset instead of re-reading the first byte as a length. *)
let digest32 : string Bcs.t = Bcs.sized_bytes D.length

(* A whole-second timestamp outside this port's representable range is REFUSED,
   never clamped: Rust's [created_at] is a plain u64 (primary/header.rs:21) and
   [Header::deserialize] recomputes the digest over the value it actually read
   (header.rs:193-203), so a substituted default would hash a header the writer
   never wrote and split one wire header into two digests. The sub-DAG's stored
   timestamp refuses the same field for the same reason. Values at or above
   2^63 seconds are far past any real clock, so the refusal costs no honest
   header. *)
let timestamp_codec : Units.Timestamp.t Bcs.t =
  Bcs.refine
    ~inject:(fun secs ->
      Option.to_result ~none:"header: created_at out of range"
        (Units.Timestamp.of_sec secs))
    ~project:Units.Timestamp.to_sec Bcs.u64

(* Write the fields as a BCS struct: fields in declaration order, no tags,
   sequences with a ULEB128 count. *)
let write_fields (w : Bcs.Writer.t) (f : fields) =
  Bcs.Writer.raw w (Authority_id.to_bytes f.author);
  Bcs.Writer.u32 w (Round.to_int f.round);
  Bcs.Writer.u32 w (Units.Epoch.to_int f.epoch);
  Bcs.write timestamp_codec w f.created_at;
  Bcs.Writer.uleb128 w (List.length f.payload);
  List.iter
    (fun (bd, wid) ->
      Bcs.write digest32 w (D.to_bytes (Digests.Batch_digest.to_digest bd));
      Bcs.Writer.u16 w (Units.Worker_id.to_int wid))
    f.payload;
  Bcs.Writer.uleb128 w (List.length f.parents);
  List.iter
    (fun p -> Bcs.write digest32 w (D.to_bytes (Digests.Header_digest.to_digest p)))
    f.parents;
  Bcs.write Block_num_hash.codec w f.latest_execution_block

(* Totalise a 32-byte read into a digest newtype; [digest32] guarantees the
   width, so the default is unreachable. *)
let to_digest s = D.of_bytes s |> Option.value ~default:(D.hash "")

let read_list read_elt (r : Bcs.Reader.t) =
  let* n = Bcs.Reader.uleb128 r in
  let rec go i acc =
    if i = 0 then ok (List.rev acc)
    else
      let* e = read_elt r in
      go (i - 1) (e :: acc)
  in
  go n []

let read_batch (r : Bcs.Reader.t) =
  let* raw = Bcs.read digest32 r in
  let* wid_i = Bcs.Reader.u16 r in
  let wid =
    Units.Worker_id.of_int wid_i |> Option.value ~default:Units.Worker_id.zero
  in
  ok (Digests.Batch_digest.of_digest (to_digest raw), wid)

let read_parent (r : Bcs.Reader.t) =
  Result.map
    (fun s -> Digests.Header_digest.of_digest (to_digest s))
    (Bcs.read digest32 r)

let read_fields (r : Bcs.Reader.t) =
  let* author_b = Bcs.Reader.raw r 32 in
  let* round_i = Bcs.Reader.u32 r in
  let* epoch_i = Bcs.Reader.u32 r in
  let* created_at = Bcs.read timestamp_codec r in
  let* payload_raw = read_list read_batch r in
  let* parents_raw = read_list read_parent r in
  let* latest_execution_block = Bcs.read Block_num_hash.codec r in
  let author =
    Authority_id.of_bytes author_b |> Option.value ~default:Authority_id.zero
  in
  let round = Round.of_int round_i |> Option.value ~default:Round.genesis in
  let epoch = Units.Epoch.of_int epoch_i |> Option.value ~default:Units.Epoch.zero in
  ok
    {
      author;
      round;
      epoch;
      created_at;
      payload = canonical_payload payload_raw;
      parents = canonical_parents parents_raw;
      latest_execution_block;
    }

let fields_codec : fields Bcs.t = Bcs.make ~write:write_fields ~read:read_fields

(* The BARE pre-image, no tag and no prefix, exactly Rust's
   [blake3(bcs(HeaderInner))] (primary/header.rs:349-356). *)
let compute_digest (f : fields) =
  Digests.Header_digest.of_digest (D.hash (Bcs.encode fields_codec f))

let of_fields f =
  let f =
    {
      f with
      payload = canonical_payload f.payload;
      parents = canonical_parents f.parents;
    }
  in
  { fields = f; digest = compute_digest f }

let make ~author ~round ~epoch ~created_at ~payload ~parents
    ~latest_execution_block =
  of_fields
    { author; round; epoch; created_at; payload; parents; latest_execution_block }

let digest t = t.digest
let author t = t.fields.author
let round t = t.fields.round
let epoch t = t.fields.epoch
let created_at t = t.fields.created_at
let payload t = t.fields.payload
let parents t = t.fields.parents
let latest_execution_block t = t.fields.latest_execution_block

let codec : t Bcs.t =
  Bcs.make
    ~write:(fun w t -> write_fields w t.fields)
    ~read:(fun r -> Result.map of_fields (read_fields r))

let equal a b = Digests.Header_digest.equal a.digest b.digest
let compare a b = Digests.Header_digest.compare a.digest b.digest

type error = Wrong_epoch | Author_not_in_committee | Empty_parents_after_genesis

let error_to_string = function
  | Wrong_epoch -> "header epoch does not match committee epoch"
  | Author_not_in_committee -> "header author is not a committee member"
  | Empty_parents_after_genesis -> "non-genesis header has no parents"

let validate committee t =
  if not (Units.Epoch.equal (epoch t) (Committee.epoch committee)) then
    Error Wrong_epoch
  else if not (Committee.contains committee (author t)) then
    Error Author_not_in_committee
  else if Round.compare (round t) Round.genesis > 0 && parents t = [] then
    Error Empty_parents_after_genesis
  else Ok ()
