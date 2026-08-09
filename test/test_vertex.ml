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
  Header.make ~latest_execution_block:Tn_types.Block_num_hash.zero ~author ~round:r ~epoch:(Committee.epoch committee)
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
    Header.make ~latest_execution_block:Tn_types.Block_num_hash.zero ~author ~round:(get (Round.of_int 4))
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

(* ---- chunk-41 S2: the Rust-oracle header rows ----

   Every expected value below is the oracle's own hex (header_vectors.ml),
   never a value this port computed for itself, so a green row is wire
   evidence. The rows here assert the BCS PRE-IMAGE, which is seam-independent
   and therefore assertable in this executable; the digest column of the same
   rows belongs to test/crypto_blst, where the Tn_crypto seam is real
   BLAKE3. *)

module HV = Header_vectors

(* The six positive rows are built in {!Oracle_headers}, because chunk-41 S3's
   sub-DAG and consensus-block rows are built OVER the same headers and two
   hand-typed copies could drift apart while both stayed green. Aliased here so
   the row bodies below read exactly as they did when they were local. *)
let of_hex = Oracle_headers.of_hex
let anchor = Oracle_headers.anchor
let repeat32 = Oracle_headers.repeat32
let h1 = Oracle_headers.h1
let h2 = Oracle_headers.h2
let h3 = Oracle_headers.h3
let h4 = Oracle_headers.h4
let h5 = Oracle_headers.h5
let h6 = Oracle_headers.h6
let encoded h = Hex_bytes.encode (Tn_codec.Bcs.encode Header.codec h)

let test_header_vectors_preimage () =
  Alcotest.(check string) "H1 = Header::default()" HV.h1_bcs (encoded (h1 ()));
  Alcotest.(check string) "H2 varies author and round" HV.h2_bcs
    (encoded (h2 ()));
  Alcotest.(check string) "H3 varies epoch, created_at, payload" HV.h3_bcs
    (encoded (h3 ()));
  Alcotest.(check string) "H4 varies payload length, worker id, parents"
    HV.h4_bcs (encoded (h4 ()));
  Alcotest.(check string) "H5 varies both anchor sub-fields" HV.h5_bcs
    (encoded (h5 ()));
  Alcotest.(check string) "H6 canonicalises descending parents" HV.h6_bcs
    (encoded (h6 ()))

(* The oracle states H6 = H4; asserting it here keeps the canonicalisation
   claim from resting on the two rows happening to be typed alike. *)
let test_header_vectors_parent_order () =
  Alcotest.(check string) "the oracle's own H6 and H4 rows agree" HV.h4_bcs
    HV.h6_bcs;
  Alcotest.(check bool) "H6 digest = H4 digest" true
    (Digests.Header_digest.equal (Header.digest (h6 ())) (Header.digest (h4 ())))

(* Field 7 is projected, not dropped: H5 shares fields 1-6 with H4 and must
   still differ. Without this a port that ignored the anchor would pass every
   row whose anchor is zero. *)
let test_header_vectors_field_seven_is_live () =
  Alcotest.(check bool) "H5 bytes differ from H4" false
    (String.equal HV.h4_bcs HV.h5_bcs);
  Alcotest.(check bool) "H5 digest differs from H4" false
    (Digests.Header_digest.equal (Header.digest (h5 ())) (Header.digest (h4 ())));
  Alcotest.(check bool) "the decoded anchor survives the round trip" true
    (Tn_codec.Bcs.decode Header.codec (of_hex "H5 bcs" HV.h5_bcs)
    |> Result.map (fun h ->
           Block_num_hash.equal
             (Header.latest_execution_block h)
             (anchor "H5 anchor" ~number:0x0102030405060708L
                ~hash:(repeat32 "cc")))
    |> Result.value ~default:false)

let test_header_vectors_roundtrip () =
  let row name hex =
    Tn_codec.Bcs.decode Header.codec (of_hex name hex)
    |> Result.map (fun h -> encoded h)
    |> Result.fold
         ~ok:(fun re ->
           Alcotest.(check string) (name ^ " re-encodes to its own bytes") hex re)
         ~error:(fun e ->
           Alcotest.failf "%s: %s" name (Tn_codec.Bcs.error_to_string e))
  in
  List.iter
    (fun (name, hex) -> row name hex)
    [
      ("H1", HV.h1_bcs);
      ("H2", HV.h2_bcs);
      ("H3", HV.h3_bcs);
      ("H4", HV.h4_bcs);
      ("H5", HV.h5_bcs);
    ]

(* H_NEG_A is H4 with the payload keys and parents written BARE, the shape this
   port used before the fix. It must not decode: the first byte of a key (0xaa)
   is not the length 32, so the read is refused at that offset instead of being
   re-framed. *)
let test_header_vector_neg_bare_digests () =
  Alcotest.(check bool) "H_NEG_A differs from H4" false
    (String.equal HV.h_neg_a_bcs HV.h4_bcs);
  Alcotest.(check bool) "a bare-digest header is refused, not accepted" false
    (Result.is_ok
       (Tn_codec.Bcs.decode Header.codec (of_hex "H_NEG_A" HV.h_neg_a_bcs)))

(* H_NEG_B is H5 with field 7 absent, the six-field shape this port used before
   the fix. It must not decode either: the anchor's 41 bytes are missing. *)
let test_header_vector_neg_missing_field_seven () =
  Alcotest.(check bool) "H_NEG_B differs from H5" false
    (String.equal HV.h_neg_b_bcs HV.h5_bcs);
  Alcotest.(check bool) "a six-field header is refused, not accepted" false
    (Result.is_ok
       (Tn_codec.Bcs.decode Header.codec (of_hex "H_NEG_B" HV.h_neg_b_bcs)))

(* Drop [count] characters at [index], by filtering the indexed sequence, so no
   partial accessor is involved and a bad index yields a shorter string rather
   than a raised exception. *)
let drop_at s ~index ~count =
  String.to_seqi s
  |> Seq.filter (fun (i, (_ : char)) -> i < index || i >= index + count)
  |> Seq.map snd |> String.of_seq

(* The anchor hash is the third corrected site and the oracle has no row for it,
   so this row is DERIVED from H5's oracle bytes by deleting the "20" length
   byte in front of the hash. It asserts only a REFUSAL, so it cannot launder a
   wrong value: the last 66 hex characters of H5 are that prefix byte followed
   by the 32-byte hash. *)
let test_header_vector_neg_bare_anchor_hash () =
  let bare =
    drop_at HV.h5_bcs ~index:(String.length HV.h5_bcs - 66) ~count:2
  in
  Alcotest.(check int) "the derived row is one byte shorter than H5"
    (String.length HV.h5_bcs - 2)
    (String.length bare);
  Alcotest.(check bool) "H5 with a bare anchor hash is refused" false
    (Result.is_ok (Tn_codec.Bcs.decode Header.codec (of_hex "bare anchor" bare)))

(* H_DUP is H4's wire with the payload key repeated. Rust's payload is an
   IndexMap read through serde_seq, so the repeat collapses to one entry that
   keeps the FIRST position and the LAST worker id; the oracle prints
   H_DUP_decoded_entries = 1 for exactly these bytes. This port must reach the
   same single entry, or the same wire header would carry two digests. *)
let test_header_vector_dup_payload_key () =
  Alcotest.(check bool) "H_DUP differs from H4" false
    (String.equal HV.h_dup_wire_bcs HV.h4_bcs);
  Alcotest.(check bool) "the wire is not already the collapsed form" false
    (String.equal HV.h_dup_wire_bcs HV.h_dup_bcs);
  Tn_codec.Bcs.decode Header.codec (of_hex "H_DUP" HV.h_dup_wire_bcs)
  |> Result.fold
       ~ok:(fun h ->
         Alcotest.(check int) "the repeated key collapses to one entry" 1
           (List.length (Header.payload h));
         Alcotest.(check (list (pair string int)))
           "the surviving entry keeps the key and takes the LAST worker id"
           [ (Oracle_headers.repeat32 "aa", 3) ]
           (List.map
              (fun (k, w) ->
                (Digests.Batch_digest.to_hex k, Units.Worker_id.to_int w))
              (Header.payload h));
         Alcotest.(check string) "it re-encodes to the oracle's collapsed bytes"
           HV.h_dup_bcs (encoded h))
       ~error:(fun e ->
         Alcotest.failf "H_DUP: %s" (Tn_codec.Bcs.error_to_string e))

(* H_TS is H3 with created_at = u64::MAX. Rust accepts it (a plain u64 field)
   and digests it; this port's timestamp domain stops at 2^63 - 1, so the codec
   REFUSES the row rather than substituting a default and digesting a header
   the writer never wrote. The refusal is the assertion; the oracle's digest for
   the row is recorded in header_vectors.ml as the documented divergence. *)
let test_header_vector_neg_created_at_top_bit () =
  Alcotest.(check bool) "H_TS differs from H3" false
    (String.equal HV.h_ts_bcs HV.h3_bcs);
  Alcotest.(check bool) "a top-bit created_at is refused, not zeroed" false
    (Result.is_ok (Tn_codec.Bcs.decode Header.codec (of_hex "H_TS" HV.h_ts_bcs)));
  (* The refusal must be the timestamp's, not a length accident: H3, which
     differs only in those eight bytes, still decodes. *)
  Alcotest.(check bool) "H3 with an in-range created_at still decodes" true
    (Result.is_ok (Tn_codec.Bcs.decode Header.codec (of_hex "H3" HV.h3_bcs)))

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

(* ---- chunk-41 S4: the Rust-oracle vote and certificate rows ----

   Every expected value below is the oracle's own hex or int
   (vote_vectors.ml). VO1..VO3 and VO_DIGEST are seam-independent: the digest
   bytes they start from are supplied directly, via
   {!Oracle_headers.header_digest}, not computed by hashing anything, so
   {!Vote.signing_message} -- which only wraps and length-prefixes -- is
   assertable here whatever the {!Tn_crypto} seam is. *)

module VV = Vote_vectors

let vote_signing_message_hex hd = Hex_bytes.encode (Vote.signing_message hd)

let test_vote_signing_message_rows () =
  let hd hex = Oracle_headers.header_digest "vote header digest" hex in
  Alcotest.(check string) "VO1: the 36-byte message for H1's digest"
    VV.vo1_signing_message
    (vote_signing_message_hex (hd VV.vo1_digest));
  Alcotest.(check string) "VO2: the 36-byte message for H4's digest"
    VV.vo2_signing_message
    (vote_signing_message_hex (hd VV.vo2_digest));
  Alcotest.(check string) "VO3: the 36-byte message for H5's digest"
    VV.vo3_signing_message
    (vote_signing_message_hex (hd VV.vo3_digest))

(* VO_DIGEST: a signed vote's [header_digest] field is bit-for-bit the
   header's own digest -- the relabel Rust performs with [.into()], never an
   independent hash. Signed for real, so the check exercises {!Vote.sign}
   rather than constructing the field by hand. *)
let test_vote_digest_identity () =
  let committee, sk_of = setup 4 in
  let id0 = first (ids committee) in
  let h = a_header committee ~author:id0 ~round:2 in
  let v = Vote.sign (sk_of id0) ~voter:id0 h in
  Alcotest.(check bool) "the vote's header_digest is the header's digest" true
    (Digests.Header_digest.equal (Vote.header_digest v) (Header.digest h));
  Alcotest.(check string)
    "and the oracle's own VO_DIGEST row names the same digest as VO2"
    VV.vo_digest_header_digest VV.vo2_digest

(* VO_NEG is the 35-byte message this port produced before the fix: the raw
   digest with no length prefix. It must differ from VO2, be exactly one byte
   short, and -- the assertion that actually exercises the fix -- this port's
   own {!Vote.signing_message}, the code under test rather than the oracle
   row, must not produce it either. *)
let test_vote_neg_no_length_prefix () =
  Alcotest.(check int) "VO_NEG is 35 bytes" VV.vo_neg_length
    (String.length VV.vo_neg_message / 2);
  Alcotest.(check bool) "VO_NEG differs from VO2" false
    (String.equal VV.vo_neg_message VV.vo2_signing_message);
  let produced =
    vote_signing_message_hex
      (Oracle_headers.header_digest "VO2 digest" VV.vo2_digest)
  in
  Alcotest.(check bool) "this port's message is not the 35-byte shape" false
    (String.equal produced VV.vo_neg_message);
  Alcotest.(check string) "this port's message is the oracle's 36-byte one"
    VV.vo2_signing_message produced

(* ---- certificate oracle rows ----

   Certificate.digest is [Header.digest t.header], not an independent hash
   (certificate.ml:108), so C1..C3 are the oracle's own two columns agreeing:
   its certificate-digest column for H1/H4/H5 is byte-identical to its
   header-digest column for the same headers. *)
let test_certificate_oracle_rows_match_header_digests () =
  Alcotest.(check string) "C1 = H1's digest" VV.c1_certificate_digest
    HV.h1_digest;
  Alcotest.(check string) "C2 = H4's digest" VV.c2_certificate_digest
    HV.h4_digest;
  Alcotest.(check string) "C3 = H5's digest" VV.c3_certificate_digest
    HV.h5_digest;
  Alcotest.(check string) "C_NEG's own certificate leg is H4's digest"
    VV.c_neg_over_h4_digest HV.h4_digest;
  Alcotest.(check string) "C_NEG's comparison leg is H5's digest"
    VV.c_neg_compared_to_h5_digest HV.h5_digest;
  Alcotest.(check bool) "and the two legs differ" false
    (String.equal VV.c_neg_over_h4_digest VV.c_neg_compared_to_h5_digest)

(* The identity itself, proven by this port's code over THREE distinct
   assembled certificates so it cannot pass on a constant: each certificate's
   digest matches its own header, and a certificate assembled over one
   header's digest does not match a different header's digest (C-NEG). *)
let test_certificate_digest_identity_is_non_vacuous () =
  let committee, sk_of = setup 4 in
  let id0 = first (ids committee) in
  let cert_over round =
    let h = a_header committee ~author:id0 ~round in
    let votes = votes_from committee sk_of h 3 (* quorum = 3 of 4 *) in
    Certificate.assemble committee h votes
    |> Result.fold
         ~ok:(fun c -> (h, c))
         ~error:(fun e ->
           Alcotest.failf "assemble round %d: %s" round
             (Certificate.error_to_string e))
  in
  let h1, c1 = cert_over 2 in
  let h2, c2 = cert_over 3 in
  let h3, c3 = cert_over 4 in
  Alcotest.(check bool) "cert 1 digest = its own header digest" true
    (Digests.Header_digest.equal (Certificate.digest c1) (Header.digest h1));
  Alcotest.(check bool) "cert 2 digest = its own header digest" true
    (Digests.Header_digest.equal (Certificate.digest c2) (Header.digest h2));
  Alcotest.(check bool) "cert 3 digest = its own header digest" true
    (Digests.Header_digest.equal (Certificate.digest c3) (Header.digest h3));
  Alcotest.(check bool) "the three headers have pairwise different digests"
    true
    (not (Digests.Header_digest.equal (Header.digest h1) (Header.digest h2))
    && not (Digests.Header_digest.equal (Header.digest h2) (Header.digest h3))
    );
  Alcotest.(check bool) "C-NEG: cert 1's digest does not match header 2's"
    false
    (Digests.Header_digest.equal (Certificate.digest c1) (Header.digest h2))

let () =
  Alcotest.run "tn_vertex"
    [
      ( "header",
        [
          Alcotest.test_case "digest changes with fields" `Quick test_header_digest_changes;
          Alcotest.test_case "codec roundtrip" `Quick test_header_codec_roundtrip;
        ] );
      ( "header oracle vectors",
        [
          Alcotest.test_case "H1-H6 BCS pre-image = oracle hex" `Quick
            test_header_vectors_preimage;
          Alcotest.test_case "H6 = H4: parents canonicalise" `Quick
            test_header_vectors_parent_order;
          Alcotest.test_case "field 7 is in the pre-image" `Quick
            test_header_vectors_field_seven_is_live;
          Alcotest.test_case "every row round-trips" `Quick
            test_header_vectors_roundtrip;
          Alcotest.test_case "H_NEG_A bare digests refused" `Quick
            test_header_vector_neg_bare_digests;
          Alcotest.test_case "H_NEG_B six-field header refused" `Quick
            test_header_vector_neg_missing_field_seven;
          Alcotest.test_case "bare anchor hash refused" `Quick
            test_header_vector_neg_bare_anchor_hash;
          Alcotest.test_case "H_DUP repeated payload key collapses" `Quick
            test_header_vector_dup_payload_key;
          Alcotest.test_case "H_TS top-bit created_at refused" `Quick
            test_header_vector_neg_created_at_top_bit;
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
      ( "vote oracle vectors",
        [
          Alcotest.test_case "VO1-VO3 signing message = oracle bytes" `Quick
            test_vote_signing_message_rows;
          Alcotest.test_case "VO_DIGEST: header_digest is the relabel" `Quick
            test_vote_digest_identity;
          Alcotest.test_case "VO_NEG: no bare 35-byte message" `Quick
            test_vote_neg_no_length_prefix;
        ] );
      ( "certificate oracle vectors",
        [
          Alcotest.test_case "C1-C3/C_NEG = the oracle's own header digests"
            `Quick test_certificate_oracle_rows_match_header_digests;
          Alcotest.test_case "the identity holds over three distinct certs"
            `Quick test_certificate_digest_identity_is_non_vacuous;
        ] );
    ]
