(* Vertex-layer tests. The certificate matrix is the important part: it pins
   that a Certificate.t cannot be assembled from sub-quorum, duplicate,
   wrong-header, unknown-voter, or badly-signed votes. *)

open Tn_types
open Tn_vertex

let get = function Some x -> x | None -> Alcotest.fail "expected Some"
let first = function x :: _ -> x | [] -> Alcotest.fail "expected non-empty list"
let nth l i = get (List.nth_opt l i)

let err =
  Alcotest.testable
    (fun ppf e -> Format.pp_print_string ppf (Certificate.error_to_string e))
    ( = )

(* The Ok side of assemble's result is a Certificate.t we never expect in the
   rejection tests; this testable exists only to satisfy [result]. *)
let reject =
  Alcotest.testable (fun ppf _ -> Format.pp_print_string ppf "<cert>") ( == )

(* A fixed committee of n validators plus their secret keys, keyed by id. *)
let setup n =
  let sks = List.init n (fun i -> Tn_crypto.Secret_key.derive (Int64.of_int i)) in
  let authorities =
    List.map
      (fun sk ->
        Authority.make
          ~protocol_key:(Tn_crypto.Secret_key.public_key sk)
          ~execution_address:Units.Address.zero)
      sks
  in
  let committee =
    match Committee.create ~epoch:Units.Epoch.zero authorities with
    | Ok c -> c
    | Error e -> Alcotest.failf "committee: %s" (Committee.error_to_string e)
  in
  (* map each authority id to its secret key *)
  let sk_of id =
    List.find_map
      (fun sk ->
        let a_id = Authority_id.of_public_key (Tn_crypto.Secret_key.public_key sk) in
        if Authority_id.equal a_id id then Some sk else None)
      sks
    |> get
  in
  (committee, sk_of)

let a_header committee ~author ~round =
  let r = get (Round.of_int round) in
  let parents =
    if round = 0 then []
    else
      (* one dummy parent so validate passes; content irrelevant to signing *)
      [ Digests.Header_digest.of_digest (Tn_crypto.Digest.hash "parent") ]
  in
  Header.make ~author ~round:r ~epoch:(Committee.epoch committee)
    ~created_at:Units.Timestamp.zero ~payload:[] ~parents

let ids committee = List.map Authority.id (Committee.authorities committee)

(* votes from the first k authorities on a header *)
let votes_from committee sk_of header k =
  List.filteri (fun i _ -> i < k) (ids committee)
  |> List.map (fun id -> Vote.sign (sk_of id) ~voter:id header)

(* ---- header ---- *)

let test_header_digest_changes () =
  let committee, _ = setup 4 in
  let author = first (ids committee) in
  let h1 = a_header committee ~author ~round:2 in
  let h2 =
    Header.make ~author ~round:(get (Round.of_int 4))
      ~epoch:(Committee.epoch committee) ~created_at:Units.Timestamp.zero
      ~payload:[] ~parents:(Header.parents h1)
  in
  Alcotest.(check bool) "different round -> different digest" false
    (Digests.Header_digest.equal (Header.digest h1) (Header.digest h2))

let test_header_codec_roundtrip () =
  let committee, _ = setup 4 in
  let h = a_header committee ~author:(first (ids committee)) ~round:2 in
  match Tn_codec.Bcs.decode Header.codec (Tn_codec.Bcs.encode Header.codec h) with
  | Ok h' -> Alcotest.(check bool) "roundtrip preserves digest" true (Header.equal h h')
  | Error e -> Alcotest.failf "decode: %s" (Tn_codec.Bcs.error_to_string e)

(* ---- certificate matrix ---- *)

let test_assemble_ok () =
  let committee, sk_of = setup 4 in
  let h = a_header committee ~author:(first (ids committee)) ~round:2 in
  let votes = votes_from committee sk_of h 3 (* quorum = 3 *) in
  match Certificate.assemble committee h votes with
  | Ok cert ->
      Alcotest.(check bool) "cert digest = header digest" true
        (Digests.Header_digest.equal (Certificate.digest cert) (Header.digest h));
      Alcotest.(check (result unit err)) "check re-verifies" (Ok ())
        (Certificate.check committee cert)
  | Error e -> Alcotest.failf "assemble should succeed: %s" (Certificate.error_to_string e)

let test_assemble_subquorum () =
  let committee, sk_of = setup 4 in
  let h = a_header committee ~author:(first (ids committee)) ~round:2 in
  let votes = votes_from committee sk_of h 2 (* below quorum 3 *) in
  Alcotest.(check (result reject err)) "sub-quorum rejected"
    (Error Certificate.Not_enough_stake)
    (Certificate.assemble committee h votes)

let test_assemble_duplicate () =
  let committee, sk_of = setup 4 in
  let h = a_header committee ~author:(first (ids committee)) ~round:2 in
  let id0 = first (ids committee) in
  let v = Vote.sign (sk_of id0) ~voter:id0 h in
  let votes = [ v; v; v ] in
  Alcotest.(check (result reject err)) "duplicate voter rejected"
    (Error Certificate.Duplicate_voter)
    (Certificate.assemble committee h votes)

let test_assemble_wrong_header () =
  let committee, sk_of = setup 4 in
  let h = a_header committee ~author:(first (ids committee)) ~round:2 in
  let other = a_header committee ~author:(first (ids committee)) ~round:4 in
  (* votes are for `other`, but we assemble for `h` *)
  let votes = votes_from committee sk_of other 3 in
  Alcotest.(check (result reject err)) "wrong header rejected"
    (Error Certificate.Wrong_header)
    (Certificate.assemble committee h votes)

let test_assemble_unknown_voter () =
  let committee, _ = setup 4 in
  let h = a_header committee ~author:(first (ids committee)) ~round:2 in
  (* an outsider not in the committee *)
  let outsider_sk = Tn_crypto.Secret_key.derive 999L in
  let outsider_id =
    Authority_id.of_public_key (Tn_crypto.Secret_key.public_key outsider_sk)
  in
  let v = Vote.sign outsider_sk ~voter:outsider_id h in
  Alcotest.(check (result reject err)) "unknown voter rejected"
    (Error Certificate.Unknown_voter)
    (Certificate.assemble committee h [ v ])

let test_assemble_bad_signature () =
  let committee, sk_of = setup 4 in
  let h = a_header committee ~author:(first (ids committee)) ~round:2 in
  let id0 = first (ids committee) in
  let id1 = nth (ids committee) 1 in
  (* id1 signs but we claim the vote is from id0: signature will not verify
     under id0's key *)
  let good = Vote.sign (sk_of id1) ~voter:id1 h in
  let forged = Vote.sign (sk_of id1) ~voter:id0 h in
  Alcotest.(check (result reject err)) "bad signature rejected"
    (Error Certificate.Bad_signature)
    (Certificate.assemble committee h [ good; forged ])

let test_genesis () =
  let committee, _ = setup 4 in
  let g = Certificate.genesis committee in
  Alcotest.(check int) "one genesis cert per authority" 4 (List.length g);
  Alcotest.(check bool) "all are genesis" true (List.for_all Certificate.is_genesis g);
  Alcotest.(check bool) "all at round 0" true
    (List.for_all (fun c -> Round.equal (Certificate.round c) Round.genesis) g);
  Alcotest.(check bool) "genesis passes check" true
    (List.for_all (fun c -> Result.is_ok (Certificate.check committee c)) g)

let () =
  Alcotest.run "tn_vertex"
    [
      ( "header",
        [
          Alcotest.test_case "digest changes with fields" `Quick test_header_digest_changes;
          Alcotest.test_case "codec roundtrip" `Quick test_header_codec_roundtrip;
        ] );
      ( "certificate",
        [
          Alcotest.test_case "assemble ok + check" `Quick test_assemble_ok;
          Alcotest.test_case "sub-quorum" `Quick test_assemble_subquorum;
          Alcotest.test_case "duplicate voter" `Quick test_assemble_duplicate;
          Alcotest.test_case "wrong header" `Quick test_assemble_wrong_header;
          Alcotest.test_case "unknown voter" `Quick test_assemble_unknown_voter;
          Alcotest.test_case "bad signature" `Quick test_assemble_bad_signature;
          Alcotest.test_case "genesis" `Quick test_genesis;
        ] );
    ]
