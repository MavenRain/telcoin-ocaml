open Tn_types
module Bcs = Tn_codec.Bcs
module D = Tn_crypto.Digest

(* Semantic fields, separated from the cached digest so the digest is never
   part of its own pre-image. *)
type fields = {
  author : Authority_id.t;
  round : Round.t;
  epoch : Units.Epoch.t;
  created_at : Units.Timestamp.t;
  payload : (Digests.Batch_digest.t * Units.Worker_id.t) list;
  parents : Digests.Header_digest.t list; (* sorted, de-duplicated *)
}

type t = { fields : fields; digest : Digests.Header_digest.t }

let canonical_parents ps = List.sort_uniq Digests.Header_digest.compare ps

(* Write the fields as a BCS struct: fields in declaration order, fixed 32-byte
   digests with no length prefix, sequences with a ULEB128 count. *)
let write_fields (w : Bcs.Writer.t) (f : fields) =
  Bcs.Writer.raw w (Authority_id.to_bytes f.author);
  Bcs.Writer.u32 w (Round.to_int f.round);
  Bcs.Writer.u32 w (Units.Epoch.to_int f.epoch);
  Bcs.Writer.u64 w (Units.Timestamp.to_sec f.created_at);
  Bcs.Writer.uleb128 w (List.length f.payload);
  List.iter
    (fun (bd, wid) ->
      Bcs.Writer.raw w (D.to_bytes (Digests.Batch_digest.to_digest bd));
      Bcs.Writer.u16 w (Units.Worker_id.to_int wid))
    f.payload;
  Bcs.Writer.uleb128 w (List.length f.parents);
  List.iter
    (fun p -> Bcs.Writer.raw w (D.to_bytes (Digests.Header_digest.to_digest p)))
    f.parents

let ( let* ) = Result.bind
let ok = Result.ok

(* Totalise a 32-byte read into a domain digest; fixed_bytes 32 guarantees the
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
  let* raw = Bcs.Reader.raw r 32 in
  let* wid_i = Bcs.Reader.u16 r in
  let wid =
    Units.Worker_id.of_int wid_i |> Option.value ~default:Units.Worker_id.zero
  in
  ok (Digests.Batch_digest.of_digest (to_digest raw), wid)

let read_parent (r : Bcs.Reader.t) =
  Result.map
    (fun s -> Digests.Header_digest.of_digest (to_digest s))
    (Bcs.Reader.raw r 32)

let read_fields (r : Bcs.Reader.t) =
  let* author_b = Bcs.Reader.raw r 32 in
  let* round_i = Bcs.Reader.u32 r in
  let* epoch_i = Bcs.Reader.u32 r in
  let* ts = Bcs.Reader.u64 r in
  let* payload = read_list read_batch r in
  let* parents_raw = read_list read_parent r in
  let author =
    Authority_id.of_bytes author_b |> Option.value ~default:Authority_id.zero
  in
  let round = Round.of_int round_i |> Option.value ~default:Round.genesis in
  let epoch = Units.Epoch.of_int epoch_i |> Option.value ~default:Units.Epoch.zero in
  let created_at =
    Units.Timestamp.of_sec ts |> Option.value ~default:Units.Timestamp.zero
  in
  ok
    {
      author;
      round;
      epoch;
      created_at;
      payload;
      parents = canonical_parents parents_raw;
    }

let fields_codec : fields Bcs.t = Bcs.make ~write:write_fields ~read:read_fields
let domain = Digests.Header_digest.domain

let compute_digest (f : fields) =
  Digests.Header_digest.of_digest (D.hash (domain ^ Bcs.encode fields_codec f))

let of_fields f =
  let f = { f with parents = canonical_parents f.parents } in
  { fields = f; digest = compute_digest f }

let make ~author ~round ~epoch ~created_at ~payload ~parents =
  of_fields { author; round; epoch; created_at; payload; parents }

let digest t = t.digest
let author t = t.fields.author
let round t = t.fields.round
let epoch t = t.fields.epoch
let created_at t = t.fields.created_at
let payload t = t.fields.payload
let parents t = t.fields.parents

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
