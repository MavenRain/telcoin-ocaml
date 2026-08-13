open Tn_types
module Bcs = Tn_codec.Bcs
module Certificate = Tn_vertex.Certificate
module Header = Tn_vertex.Header

type sig_state =
  | Unsigned of Bls_signature.t
  | Unverified of Bls_signature.t
  | Verified_directly of Bls_signature.t
  | Verified_indirectly of Bls_signature.t
  | Genesis

type t = { header : Header.t; state : sig_state; signed_authorities : Roaring.t }

type error =
  | Unknown_signer_index of { index : int }
  | Signer_not_in_committee
  | Signature_rejected
  | Not_checked of Certificate.error

let error_to_string = function
  | Unknown_signer_index { index } ->
      Printf.sprintf "certificate: bitmap names committee position %d" index
  | Signer_not_in_committee -> "certificate: signer outside the committee"
  | Signature_rejected -> "certificate: the crypto seam refused the aggregate"
  | Not_checked e -> "certificate: " ^ Certificate.error_to_string e

let make ~header ~state ~signed_authorities =
  { header; state; signed_authorities }

let header t = t.header
let state t = t.state
let signed_authorities t = t.signed_authorities

(* The four signed states all become the port's single [Aggregated] state;
   every match below enumerates all five, so a variant added upstream breaks
   the build rather than falling into a catch-all. *)
let state_signature = function
  | Unsigned s -> Some s
  | Unverified s -> Some s
  | Verified_directly s -> Some s
  | Verified_indirectly s -> Some s
  | Genesis -> None

let state_index = function
  | Unsigned _ -> 0
  | Unverified _ -> 1
  | Verified_directly _ -> 2
  | Verified_indirectly _ -> 3
  | Genesis -> 4

(* The five variants of certificate.rs:431-449, in index order. Each signed
   state carries one 48-byte signature; Genesis carries nothing, so its
   encoding is the bare tag. *)
let state_codec : sig_state Bcs.t =
  Bcs.sum
    [
      Bcs.case ~index:0 Bls_signature.codec
        ~inject:(fun s -> Unsigned s)
        ~project:(function
          | Unsigned s -> Some s
          | Unverified _ | Verified_directly _ | Verified_indirectly _ | Genesis
            ->
              None);
      Bcs.case ~index:1 Bls_signature.codec
        ~inject:(fun s -> Unverified s)
        ~project:(function
          | Unverified s -> Some s
          | Unsigned _ | Verified_directly _ | Verified_indirectly _ | Genesis ->
              None);
      Bcs.case ~index:2 Bls_signature.codec
        ~inject:(fun s -> Verified_directly s)
        ~project:(function
          | Verified_directly s -> Some s
          | Unsigned _ | Unverified _ | Verified_indirectly _ | Genesis -> None);
      Bcs.case ~index:3 Bls_signature.codec
        ~inject:(fun s -> Verified_indirectly s)
        ~project:(function
          | Verified_indirectly s -> Some s
          | Unsigned _ | Unverified _ | Verified_directly _ | Genesis -> None);
      Bcs.case ~index:4 Bcs.unit
        ~inject:(fun () -> Genesis)
        ~project:(function
          | Genesis -> Some ()
          | Unsigned _ | Unverified _ | Verified_directly _
          | Verified_indirectly _ ->
              None);
    ]

let ( let* ) = Result.bind

let codec : t Bcs.t =
  Bcs.make
    ~write:(fun w t ->
      Bcs.write Header.codec w t.header;
      Bcs.write state_codec w t.state;
      Bcs.write Roaring.codec w t.signed_authorities)
    ~read:(fun r ->
      let* header = Bcs.read Header.codec r in
      let* state = Bcs.read state_codec r in
      let* signed_authorities = Bcs.read Roaring.codec r in
      Ok { header; state; signed_authorities })

let signer_set committee t =
  List.fold_left
    (fun acc index ->
      let* set = acc in
      Option.fold
        ~none:(Error (Unknown_signer_index { index }))
        ~some:(fun a -> Ok (Authority_id.Set.add (Authority.id a) set))
        (Committee.nth committee index))
    (Ok Authority_id.Set.empty)
    (Roaring.to_list t.signed_authorities)

let to_checked committee t =
  let* signers = signer_set committee t in
  let aggregate = Option.map Bls_signature.to_bytes (state_signature t.state) in
  let* certificate =
    Option.to_result ~none:Signature_rejected
      (Certificate.claim ~header:t.header ~signers ~aggregate)
  in
  Result.fold
    ~ok:(fun () -> Ok certificate)
    ~error:(fun e -> Error (Not_checked e))
    (Certificate.check committee certificate)

let of_certificate committee certificate =
  let* indices =
    Authority_id.Set.fold
      (fun id acc ->
        let* acc = acc in
        Option.fold ~none:(Error Signer_not_in_committee)
          ~some:(fun index -> Ok (index :: acc))
          (Committee.index_of committee id))
      (Certificate.signers certificate)
      (Ok [])
  in
  let* signed_authorities =
    Result.map_error
      (fun (_ : Roaring.error) -> Signature_rejected)
      (Roaring.of_list indices)
  in
  let* state =
    Option.fold ~none:(Ok Genesis)
      ~some:(fun agg ->
        Option.fold ~none:(Error Signature_rejected)
          ~some:(fun s -> Ok (Verified_directly s))
          (Bls_signature.of_bytes (Tn_crypto.Aggregate.to_bytes agg)))
      (Certificate.aggregate_signature certificate)
  in
  Ok { header = Certificate.header certificate; state; signed_authorities }

let state_equal a b =
  Int.equal (state_index a) (state_index b)
  && Option.equal Bls_signature.equal (state_signature a) (state_signature b)

let equal a b =
  Header.equal a.header b.header
  && state_equal a.state b.state
  && Roaring.equal a.signed_authorities b.signed_authorities
