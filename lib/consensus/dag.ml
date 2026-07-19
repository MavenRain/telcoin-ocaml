open Tn_types
open Tn_vertex

(* The digest-keyed secondary index. Header digests are a valid map key because
   Digests.Header_digest supplies [compare]; this gives parent-existence checks
   and the later commit traversal a log-time digest lookup instead of a scan. *)
module Digest_map = Map.Make (Digests.Header_digest)

type t = {
  gc_depth : int;
  committed_round : Round.t;
  gc_round : Round.t;
  (* Highest committed round per author; a certificate at or below its author's
     entry has already been ordered and so is not newly relevant. *)
  last_committed : Round.t Authority_id.Map.t;
  (* round -> author -> certificate: the primary DAG store. *)
  certs : Certificate.t Authority_id.Map.t Round.Map.t;
  (* header digest -> certificate: the secondary index over the same set. *)
  by_digest : Certificate.t Digest_map.t;
}

type error =
  | Equivocation of Round.t * Authority_id.t
  | Missing_parent of Digests.Header_digest.t
  | Missing_parent_round of Round.t

let error_to_string = function
  | Equivocation (round, author) ->
      Printf.sprintf "certificate equivocates an existing one at round %s for %s"
        (Round.to_string round) (Authority_id.to_hex author)
  | Missing_parent digest ->
      Printf.sprintf "parent %s is not present at the previous round"
        (Digests.Header_digest.to_hex digest)
  | Missing_parent_round round ->
      Printf.sprintf "previous round %s is absent from the dag" (Round.to_string round)

let ( let* ) = Result.bind

let create ~gc_depth =
  {
    gc_depth;
    committed_round = Round.genesis;
    gc_round = Round.genesis;
    last_committed = Authority_id.Map.empty;
    certs = Round.Map.empty;
    by_digest = Digest_map.empty;
  }

(* Every parent a certificate names must be stored at the round below it. The
   genesis band (round <= gc_round + 1) is skipped: round-1 certificates point
   at genesis certificates, which are never stored. *)
let check_parents t certificate =
  let round = Certificate.round certificate in
  if Round.compare round (Round.succ t.gc_round) <= 0 then Ok ()
  else
    let prev = Round.sub_saturating round 1 in
    (* The previous round must exist as a whole, and then every named parent must
       resolve, through the digest index, to a certificate stored at that round.
       A parent found at some other round counts as missing, matching Rust, which
       only consults [dag[round - 1]]. *)
    let* _prev_table =
      Round.Map.find_opt prev t.certs |> Option.to_result ~none:(Missing_parent_round prev)
    in
    let present digest =
      Digest_map.find_opt digest t.by_digest
      |> Option.map (fun c -> Round.equal (Certificate.round c) prev)
      |> Option.value ~default:false
    in
    Header.parents (Certificate.header certificate)
    |> List.find_opt (fun digest -> not (present digest))
    |> Option.fold ~none:(Ok ()) ~some:(fun missing -> Error (Missing_parent missing))

let try_insert t certificate =
  let round = Certificate.round certificate in
  let origin = Certificate.origin certificate in
  (* Below the GC horizon the certificate can never be part of a future commit,
     so it is dropped without error. *)
  if Round.compare round t.gc_round <= 0 then Ok (t, false)
  else
    let* () = check_parents t certificate in
    let table =
      Round.Map.find_opt round t.certs
      |> Option.value ~default:Authority_id.Map.empty
    in
    match Authority_id.Map.find_opt origin table with
    | Some existing when not (Certificate.equal existing certificate) ->
        (* Keep the first certificate stored and reject the equivocating one.
           Rust overwrites the slot with the new certificate and then returns the
           error, leaving the equivocator in the dag; keeping the original is the
           safer choice and the caller stops on the error either way. *)
        Error (Equivocation (round, origin))
    | _ ->
        let table = Authority_id.Map.add origin certificate table in
        let certs = Round.Map.add round table t.certs in
        let by_digest =
          Digest_map.add (Certificate.digest certificate) certificate t.by_digest
        in
        (* Newly relevant iff strictly beyond this author's last committed round;
           the certificate is stored regardless, so parents of later rounds can
           still be verified against it. *)
        let last =
          Authority_id.Map.find_opt origin t.last_committed
          |> Option.value ~default:Round.genesis
        in
        Ok ({ t with certs; by_digest }, Round.compare round last > 0)

let update t certificate =
  let origin = Certificate.origin certificate in
  let round = Certificate.round certificate in
  let keep_max existing = if Round.compare round existing > 0 then round else existing in
  let last_committed =
    Authority_id.Map.update origin
      (fun existing -> Some (Option.fold ~none:round ~some:keep_max existing))
      t.last_committed
  in
  let committed_round = keep_max t.committed_round in
  let gc_round = Round.sub_saturating committed_round t.gc_depth in
  let above_gc r = Round.compare r gc_round > 0 in
  let certs = Round.Map.filter (fun r _ -> above_gc r) t.certs in
  let by_digest = Digest_map.filter (fun _ c -> above_gc (Certificate.round c)) t.by_digest in
  { t with last_committed; committed_round; gc_round; certs; by_digest }

let get t round origin =
  Option.bind (Round.Map.find_opt round t.certs) (Authority_id.Map.find_opt origin)

let get_by_digest t digest = Digest_map.find_opt digest t.by_digest
let contains_digest t digest = Digest_map.mem digest t.by_digest

let round_certificates t round =
  Round.Map.find_opt round t.certs
  |> Option.fold ~none:[] ~some:(fun table ->
         List.map snd (Authority_id.Map.bindings table))

let rounds t = List.map fst (Round.Map.bindings t.certs)
let committed_round t = t.committed_round
let gc_round t = t.gc_round
