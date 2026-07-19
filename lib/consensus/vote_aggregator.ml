open Tn_types
open Tn_vertex

type t = {
  (* Every author whose vote has been seen, accepted or not. A second vote from
     any of these is a duplicate. This set is the equivocation guard and mirrors
     the Rust authorities_seen, which is updated before the vote is validated. *)
  seen : Authority_id.Set.t;
  (* Authors whose votes were accepted; only these count toward quorum. *)
  voters : Authority_id.Set.t;
  (* Accepted votes, newest first; order is irrelevant to the certificate. *)
  votes : Vote.t list;
}

let empty =
  { seen = Authority_id.Set.empty; voters = Authority_id.Set.empty; votes = [] }

let voters t = t.voters

(* Validate one vote against the header being certified. The checks and their
   order mirror the Rust aggregator: a vote for the wrong header, then a
   non-member, then a bad signature. The repeat-author check is handled by the
   caller, before the author's slot is claimed. *)
let ( let* ) = Result.bind

let validate committee header vote =
  if not (Digests.Header_digest.equal (Vote.header_digest vote) (Header.digest header))
  then Error Certificate.Wrong_header
  else
    let* authority =
      Committee.authority committee (Vote.author vote)
      |> Option.to_result ~none:Certificate.Unknown_voter
    in
    if Vote.verify (Authority.protocol_key authority) vote then Ok ()
    else Error Certificate.Bad_signature

let add t committee header vote =
  let author = Vote.author vote in
  if Authority_id.Set.mem author t.seen then (t, Error Certificate.Duplicate_voter)
  else
    (* Claim the author's slot on first sight, before validating, exactly as the
       Rust aggregator does: a later valid vote from a peer whose first vote was
       rejected is refused as a duplicate. *)
    let t = { t with seen = Authority_id.Set.add author t.seen } in
    validate committee header vote
    |> Result.fold
         ~error:(fun e -> (t, Error e))
         ~ok:(fun () ->
           let voters = Authority_id.Set.add author t.voters in
           let votes = vote :: t.votes in
           let t = { t with voters; votes } in
           (* Once the counted signers reach quorum, assemble the certificate.
              Every vote in [votes] has already passed the same checks
              Certificate.assemble applies, so this step succeeds; propagating
              its result keeps the certificate verified-by-construction rather
              than trusting a bypass. *)
           let output =
             if Committee.reaches_quorum committee (Committee.stake_of committee voters)
             then Result.map Option.some (Certificate.assemble committee header votes)
             else Ok None
           in
           (t, output))
