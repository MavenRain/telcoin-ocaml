(* The verification state is reduced to the one distinction the protocol
   actually needs downstream — genesis vs a real aggregate — because every
   other Rust state (Unsigned/Unverified/VerifiedDirectly/VerifiedIndirectly)
   describes a certificate that either is not yet valid (so is not a value of
   this type) or is valid (so is indistinguishable here). *)
open Tn_types

type verification = Genesis | Aggregated of Tn_crypto.Aggregate.t

type t = {
  header : Header.t;
  signers : Authority_id.Set.t;
  verification : verification;
}

type error =
  | Empty
  | Wrong_header
  | Unknown_voter
  | Duplicate_voter
  | Bad_signature
  | Not_enough_stake

let error_to_string = function
  | Empty -> "no votes supplied"
  | Wrong_header -> "vote references a different header"
  | Unknown_voter -> "voter is not a committee member"
  | Duplicate_voter -> "duplicate vote from one authority"
  | Bad_signature -> "vote signature does not verify"
  | Not_enough_stake -> "signers do not reach the quorum threshold"

let ( let* ) = Result.bind

(* Validate one vote against the header being certified and the running signer
   set, returning the voter's public key and signature on success. *)
let check_vote committee header signers vote =
  if not (Digests.Header_digest.equal (Vote.header_digest vote) (Header.digest header))
  then Error Wrong_header
  else
    match Committee.authority committee (Vote.author vote) with
    | None -> Error Unknown_voter
    | Some authority ->
        let id = Vote.author vote in
        if Authority_id.Set.mem id signers then Error Duplicate_voter
        else
          let pk = Authority.protocol_key authority in
          if not (Vote.verify pk vote) then Error Bad_signature
          else Ok (pk, Vote.signature vote)

let assemble committee header votes =
  match votes with
  | [] -> Error Empty
  | _ ->
      (* Fold the votes, accumulating the signer set and per-signer signatures;
         the first invalid vote aborts the whole assembly. *)
      let step acc vote =
        let* signers, sigs = acc in
        let* _pk, signature = check_vote committee header signers vote in
        Ok (Authority_id.Set.add (Vote.author vote) signers, signature :: sigs)
      in
      let* signers, sigs =
        List.fold_left step (Ok (Authority_id.Set.empty, [])) votes
      in
      if not (Committee.reaches_quorum committee (Committee.stake_of committee signers))
      then Error Not_enough_stake
      else
        Ok
          {
            header;
            signers;
            verification = Aggregated (Tn_crypto.aggregate sigs);
          }

let genesis committee =
  List.map
    (fun authority ->
      let header =
        Header.make ~author:(Authority.id authority) ~round:Round.genesis
          ~epoch:(Committee.epoch committee) ~created_at:Units.Timestamp.zero
          ~payload:[] ~parents:[]
      in
      { header; signers = Authority_id.Set.empty; verification = Genesis })
    (Committee.authorities committee)

(* Resolve a signer set to committee public keys, failing if any signer is not
   a member (a certificate whose bitmap names a non-member). *)
let public_keys committee signers =
  Authority_id.Set.fold
    (fun id acc ->
      let* keys = acc in
      match Committee.authority committee id with
      | None -> Error Unknown_voter
      | Some a -> Ok (Authority.protocol_key a :: keys))
    signers (Ok [])

let check committee t =
  match t.verification with
  | Genesis -> Ok ()
  | Aggregated agg ->
      let* pks = public_keys committee t.signers in
      if not (Committee.reaches_quorum committee (Committee.stake_of committee t.signers))
      then Error Not_enough_stake
      else
        let msg = Vote.signing_message (Header.digest t.header) in
        if Tn_crypto.verify_aggregate pks msg agg then Ok () else Error Bad_signature

let header t = t.header
let digest t = Header.digest t.header
let round t = Header.round t.header
let epoch t = Header.epoch t.header
let origin t = Header.author t.header
let signers t = t.signers

let aggregate_signature t =
  (* An exhaustive match on this module's own two-constructor sum, not on an
     Option/Result. A committed leader sits at an even round >= 2 so its
     certificate is never genesis; the [None] arm exists for totality. *)
  match t.verification with Genesis -> None | Aggregated a -> Some a

let is_genesis t = match t.verification with Genesis -> true | Aggregated _ -> false
let equal a b = Digests.Header_digest.equal (digest a) (digest b)
let compare a b = Digests.Header_digest.compare (digest a) (digest b)
