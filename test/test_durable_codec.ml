(* Chunk 40, stage S3: the Tier-A codecs.

   Nothing here touches a filesystem. That is the point: every rule about what a
   reader may trust from a byte string is settled before a descriptor exists.

   Three disciplines run through the file. Every round trip is checked through
   every public projection of the type AND through its own [equal], because a
   value compared only by digest hides a field that failed to survive, and a
   value compared only field-wise hides a digest that was never recomputed. Every
   re-derived field is checked to be ABSENT from the wire, not merely correct on
   the way back, since a decoder that trusts a cached digest still round-trips a
   value it encoded itself. And every negative case names the arm it expects, so
   a check that stopped working cannot hide behind a neighbouring one. *)

open Tn_types
open Tn_vertex
open Tn_consensus
module Bcs = Tn_codec.Bcs
module Cb = Tn_execution.Consensus_block
module Chain = Tn_execution.Consensus_chain
module Record = Tn_execution.Consensus_store.Record
module Rc = Tn_durable_store.Record_codec
module Nonempty = Tn_std.Nonempty

(* Totalise an option under a named expectation; [Result.fold] keeps both arms
   lazy, where [Option.fold]'s [~none] is eager. *)
let get what o =
  Result.fold ~ok:Fun.id ~error:(fun msg -> Alcotest.fail msg)
    (Option.to_result ~none:what o)

let nth what l n = get what (List.nth_opt l n)

(* Byte handling for the test side, total by the same rule the library uses: a
   span running off either end is clamped rather than raising. *)
let sub_at s ~off ~len =
  let bound = String.length s in
  let start = min (max 0 off) bound in
  let stop = min (max start (off + max 0 len)) bound in
  String.sub s start (stop - start) (* @total-accessor *)

(* Overwrite [bytes] at [at], leaving the total length unchanged. *)
let splice s ~at ~bytes =
  let width = String.length bytes in
  String.concat ""
    [
      sub_at s ~off:0 ~len:at;
      bytes;
      sub_at s ~off:(at + width) ~len:(String.length s - at - width);
    ]

(* Flip the low bit of one byte. The byte is read by folding a one-character
   span, so no index and no [Char.chr] appear, and it is written back through
   the codec's own [u8] writer. *)
let flip s ~at =
  let byte = String.fold_left (fun _acc c -> Char.code c) 0 (sub_at s ~off:at ~len:1) in
  splice s ~at ~bytes:(Bcs.encode Bcs.u8 (byte lxor 0x01))

(* Substring search as a total fold: no unchecked span, no index arithmetic
   outside the clamp above. *)
let contains ~needle haystack =
  let n = String.length needle in
  List.exists
    (fun start -> String.equal needle (sub_at haystack ~off:start ~len:n))
    (List.init (max 0 (String.length haystack - n + 1)) Fun.id)

(* {1 Fixtures} *)

(* Four validators, exactly the shape test_consensus_store.ml uses. *)
let committee, sk_of =
  let sks = List.init 4 (fun i -> Tn_crypto.Secret_key.derive (Int64.of_int i)) in
  let authorities =
    List.map
      (fun sk ->
        Authority.make
          ~protocol_key:(Tn_crypto.Secret_key.public_key sk)
          ~execution_address:Units.Address.zero)
      sks
  in
  let committee =
    Result.fold ~ok:Fun.id
      ~error:(fun e ->
        Alcotest.failf "committee: %s" (Committee.error_to_string e))
      (Committee.create ~epoch:Units.Epoch.zero authorities)
  in
  let sk_of id =
    get "secret key"
      (List.find_opt
         (fun sk ->
           Authority_id.equal
             (Authority_id.of_public_key (Tn_crypto.Secret_key.public_key sk))
             id)
         sks)
  in
  (committee, sk_of)

let ids = List.map Authority.id (Committee.authorities committee)
let id0 = nth "id0" ids 0
let id1 = nth "id1" ids 1
let id2 = nth "id2" ids 2
let id3 = nth "id3" ids 3

let certify header =
  let votes = List.map (fun id -> Vote.sign (sk_of id) ~voter:id header) ids in
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "certify: %s" (Certificate.error_to_string e))
    (Certificate.assemble committee header votes)

let mk_header ~author ~r ~payload =
  Header.make ~author
    ~round:(get "round" (Round.of_int r))
    ~epoch:Units.Epoch.zero
    ~created_at:(get "timestamp" (Units.Timestamp.of_sec (Int64.of_int (50 + r))))
    ~payload
    ~parents:(List.map Certificate.digest (Certificate.genesis committee))

let worker n = get "worker id" (Units.Worker_id.of_int n)

let mk_batch ~txs ~worker_n ~fee =
  Batch.make ~transactions:txs ~epoch:Units.Epoch.zero
    ~beneficiary:Units.Address.zero
    ~base_fee_per_gas:(Units.Base_fee.of_int64 fee)
    ~worker_id:(worker worker_n)

(* Every oracle-signed row chunk 34 minted, carried as one batch's transaction
   list, so the widest batch fixture the suite already owns is on this wire: the
   1000-byte F3, the 4844 envelope F6 and the high-s twin F8 included. *)
let fixture_txs =
  [
    Batch_fixtures.f1_encoded;
    Batch_fixtures.f2_encoded;
    Batch_fixtures.f3_encoded;
    Batch_fixtures.f4a_encoded;
    Batch_fixtures.f4b_encoded;
    Batch_fixtures.f5_encoded;
    Batch_fixtures.f6_encoded;
    Batch_fixtures.f8_encoded;
  ]

let ba = mk_batch ~txs:[ "\x0a" ] ~worker_n:0 ~fee:7L
let bb = mk_batch ~txs:[ "\x0b"; "\x0b\x0b" ] ~worker_n:1 ~fee:11L
let bc = mk_batch ~txs:fixture_txs ~worker_n:2 ~fee:13L
let bd = Batch.default
let bodies_pool = [ ba; bb; bc; bd ]
let dg body = Batch.digest body
let da = dg ba
let db = dg bb
let dc = dg bc
let dd = dg bd
let scores_fresh = Reputation_scores.fresh committee

let scores_bumped =
  List.fold_left Reputation_scores.bump scores_fresh [ id0; id0; id1; id3 ]

let scores_final = Reputation_scores.with_final true scores_bumped

let sub_dag_of ~cells ~scores =
  let certs =
    List.map
      (fun (r, author, payload) -> certify (mk_header ~author ~r ~payload))
      cells
  in
  Sub_dag.create
    ~sequence:(get "non-empty sequence" (Nonempty.of_list certs))
    ~scores ~previous:None

(* A commit that carried no payload still consumes a height. *)
let sd_plain = sub_dag_of ~cells:[ (1, id0, []) ] ~scores:scores_fresh

let sd_payload =
  sub_dag_of
    ~cells:[ (2, id1, [ (da, worker 0); (db, worker 1) ]) ]
    ~scores:scores_bumped

(* Three headers, and [da] under two of them: one body resolved twice. *)
let sd_dup =
  sub_dag_of
    ~cells:
      [
        (1, id0, [ (da, worker 0) ]);
        (2, id1, [ (db, worker 1); (da, worker 0) ]);
        (3, id2, [ (dc, worker 2); (dd, worker 0) ]);
      ]
    ~scores:scores_bumped

(* The only fixture whose scores are FINAL: what a dropped [is_final] breaks. *)
let sd_final =
  sub_dag_of ~cells:[ (4, id3, [ (dc, worker 2) ]) ] ~scores:scores_final

let sub_dags = [ sd_plain; sd_payload; sd_dup; sd_final ]

(* A real chain, minted by the fold the driver uses, so the links are real. *)
let blocks =
  let _, rev =
    List.fold_left
      (fun (c, acc) sd ->
        let c', b = Chain.append c sd in
        (c', b :: acc))
      (Chain.genesis, []) sub_dags
  in
  List.rev rev

(* Height zero, which the chain fold never produces: the anchor's own number has
   to survive the wire too. *)
let block_at_genesis =
  Cb.create ~parent_hash:Cb.genesis_parent ~sub_dag:sd_plain
    ~number:Cb.Number.genesis

let all_blocks = block_at_genesis :: blocks

let lookup d =
  List.find_opt (fun body -> Digests.Batch_digest.equal (dg body) d) bodies_pool

let record_of what block =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "%s: %s" what (Record.error_to_string e))
    (Record.create ~consensus:block ~lookup)

let records =
  List.mapi (fun i b -> record_of (Printf.sprintf "record %d" i) b) all_blocks

(* {1 Projection-wise comparison} *)

let check_scores what a b =
  let hexed s =
    List.map
      (fun (id, v) -> (Authority_id.to_hex id, v))
      (Reputation_scores.bindings s)
  in
  let desc s =
    List.map
      (fun (id, v) -> (Authority_id.to_hex id, v))
      (Reputation_scores.by_score_desc s)
  in
  let pairs = Alcotest.(list (pair string int)) in
  Alcotest.check pairs (what ^ ": bindings") (hexed a) (hexed b);
  Alcotest.check pairs (what ^ ": by_score_desc") (desc a) (desc b);
  Alcotest.(check bool)
    (what ^ ": is_final")
    (Reputation_scores.is_final a) (Reputation_scores.is_final b);
  Alcotest.(check int)
    (what ^ ": total_authorities")
    (Reputation_scores.total_authorities a)
    (Reputation_scores.total_authorities b);
  Alcotest.(check bool)
    (what ^ ": all_zero")
    (Reputation_scores.all_zero a) (Reputation_scores.all_zero b);
  Alcotest.(check (list int))
    (what ^ ": get per id")
    (List.map (Reputation_scores.get a) ids)
    (List.map (Reputation_scores.get b) ids);
  Alcotest.(check bool) (what ^ ": equal") true (Reputation_scores.equal a b)

let check_sub_dag what a b =
  let digests sd =
    List.map Digests.Batch_digest.to_hex (Sub_dag.payload_digests sd)
  in
  let headers sd =
    List.map
      (fun h -> Digests.Header_digest.to_hex (Header.digest h))
      (Nonempty.to_list (Sub_dag.headers sd))
  in
  Alcotest.(check (list string)) (what ^ ": headers") (headers a) (headers b);
  Alcotest.(check (list string))
    (what ^ ": payload_digests")
    (digests a) (digests b);
  Alcotest.(check bool) (what ^ ": leader") true
    (Header.equal (Sub_dag.leader a) (Sub_dag.leader b));
  Alcotest.(check int)
    (what ^ ": leader_round")
    (Round.to_int (Sub_dag.leader_round a))
    (Round.to_int (Sub_dag.leader_round b));
  Alcotest.(check string)
    (what ^ ": leader_author")
    (Authority_id.to_hex (Sub_dag.leader_author a))
    (Authority_id.to_hex (Sub_dag.leader_author b));
  Alcotest.(check int)
    (what ^ ": leader_epoch")
    (Units.Epoch.to_int (Sub_dag.leader_epoch a))
    (Units.Epoch.to_int (Sub_dag.leader_epoch b));
  Alcotest.(check string)
    (what ^ ": sequence_number")
    (Int64.to_string (Units.Sequence_number.to_int64 (Sub_dag.sequence_number a)))
    (Int64.to_string (Units.Sequence_number.to_int64 (Sub_dag.sequence_number b)));
  check_scores (what ^ " scores") (Sub_dag.scores a) (Sub_dag.scores b);
  Alcotest.(check string)
    (what ^ ": stored_timestamp")
    (Units.Timestamp.to_string (Sub_dag.stored_timestamp a))
    (Units.Timestamp.to_string (Sub_dag.stored_timestamp b));
  Alcotest.(check string)
    (what ^ ": commit_timestamp")
    (Units.Timestamp.to_string (Sub_dag.commit_timestamp a))
    (Units.Timestamp.to_string (Sub_dag.commit_timestamp b));
  Alcotest.(check string)
    (what ^ ": randomness")
    (Tn_crypto.Digest.to_hex (Sub_dag.randomness a))
    (Tn_crypto.Digest.to_hex (Sub_dag.randomness b));
  Alcotest.(check string)
    (what ^ ": preimage")
    (Sub_dag.preimage a) (Sub_dag.preimage b);
  Alcotest.(check string)
    (what ^ ": digest")
    (Digests.Sub_dag_digest.to_hex (Sub_dag.digest a))
    (Digests.Sub_dag_digest.to_hex (Sub_dag.digest b));
  Alcotest.(check bool) (what ^ ": equal") true (Sub_dag.equal a b)

let check_block what a b =
  Alcotest.(check string)
    (what ^ ": parent_hash")
    (Digests.Output_digest.to_hex (Cb.parent_hash a))
    (Digests.Output_digest.to_hex (Cb.parent_hash b));
  Alcotest.(check int)
    (what ^ ": number")
    (Cb.Number.to_int (Cb.number a))
    (Cb.Number.to_int (Cb.number b));
  check_sub_dag (what ^ " sub_dag") (Cb.sub_dag a) (Cb.sub_dag b);
  Alcotest.(check string) (what ^ ": preimage") (Cb.preimage a) (Cb.preimage b);
  Alcotest.(check string)
    (what ^ ": digest")
    (Digests.Output_digest.to_hex (Cb.digest a))
    (Digests.Output_digest.to_hex (Cb.digest b));
  Alcotest.(check bool) (what ^ ": equal") true (Cb.equal a b)

let check_batch what a b =
  Alcotest.(check (list string))
    (what ^ ": transactions")
    (Batch.transactions a) (Batch.transactions b);
  Alcotest.(check int)
    (what ^ ": epoch")
    (Units.Epoch.to_int (Batch.epoch a))
    (Units.Epoch.to_int (Batch.epoch b));
  Alcotest.(check string)
    (what ^ ": beneficiary")
    (Units.Address.to_bytes (Batch.beneficiary a))
    (Units.Address.to_bytes (Batch.beneficiary b));
  Alcotest.(check string)
    (what ^ ": base_fee_per_gas")
    (Units.Base_fee.to_string (Batch.base_fee_per_gas a))
    (Units.Base_fee.to_string (Batch.base_fee_per_gas b));
  Alcotest.(check int)
    (what ^ ": worker_id")
    (Units.Worker_id.to_int (Batch.worker_id a))
    (Units.Worker_id.to_int (Batch.worker_id b));
  let stamp t =
    Option.fold ~none:"absent" ~some:Units.Timestamp.to_string (Batch.received_at t)
  in
  Alcotest.(check string) (what ^ ": received_at") (stamp a) (stamp b);
  Alcotest.(check string)
    (what ^ ": digest")
    (Digests.Batch_digest.to_hex (Batch.digest a))
    (Digests.Batch_digest.to_hex (Batch.digest b));
  Alcotest.(check bool) (what ^ ": equal") true (Batch.equal a b)

let check_record what a b =
  check_block (what ^ " consensus") (Record.consensus a) (Record.consensus b);
  check_sub_dag (what ^ " sub_dag") (Record.sub_dag a) (Record.sub_dag b);
  Alcotest.(check int)
    (what ^ ": number")
    (Cb.Number.to_int (Record.number a))
    (Cb.Number.to_int (Record.number b));
  Alcotest.(check string)
    (what ^ ": digest")
    (Digests.Output_digest.to_hex (Record.digest a))
    (Digests.Output_digest.to_hex (Record.digest b));
  Alcotest.(check string)
    (what ^ ": parent_hash")
    (Digests.Output_digest.to_hex (Record.parent_hash a))
    (Digests.Output_digest.to_hex (Record.parent_hash b));
  Alcotest.(check int)
    (what ^ ": epoch")
    (Units.Epoch.to_int (Record.epoch a))
    (Units.Epoch.to_int (Record.epoch b));
  Alcotest.(check int)
    (what ^ ": body count")
    (List.length (Record.bodies a))
    (List.length (Record.bodies b));
  List.iteri
    (fun i x ->
      let label = Printf.sprintf "%s body %d" what i in
      check_batch label x (nth (label ^ ": absent") (Record.bodies b) i))
    (Record.bodies a)

(* {1 Named expectations over the two error surfaces} *)

let decoded what codec bytes =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "%s: %s" what (Bcs.error_to_string e))
    (Bcs.decode codec bytes)

let refused what codec bytes =
  Result.fold
    ~ok:(fun _ -> Alcotest.failf "%s: expected a refusal, got a value" what)
    ~error:Fun.id (Bcs.decode codec bytes)

let record_ok what bytes =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "%s: %s" what (Rc.error_to_string e))
    (Rc.decode_record bytes)

let record_error what bytes =
  Result.fold
    ~ok:(fun _ -> Alcotest.failf "%s: expected a refusal, got a record" what)
    ~error:Fun.id (Rc.decode_record bytes)

let expect_trailing what bytes =
  let e = record_error what bytes in
  match e with
  | Rc.Trailing { left } -> left
  | Rc.Bcs _ | Rc.Rebuild _ ->
      Alcotest.failf "%s: expected Trailing, got %s" what (Rc.error_to_string e)

let expect_bcs what bytes =
  let e = record_error what bytes in
  match e with
  | Rc.Bcs _ -> ()
  | Rc.Trailing _ | Rc.Rebuild _ ->
      Alcotest.failf "%s: expected a codec error, got %s" what
        (Rc.error_to_string e)

let expect_missing_body what bytes =
  let e = record_error what bytes in
  match e with
  | Rc.Rebuild (Record.Missing_body d) -> d
  | Rc.Bcs _ | Rc.Trailing _ ->
      Alcotest.failf "%s: expected Missing_body, got %s" what
        (Rc.error_to_string e)

(* The record wire, rebuilt from its two public halves, so a case can hand the
   decoder a body list the encoder would never have produced. *)
let wire_codec = Bcs.pair Cb.codec (Bcs.list Batch.codec)
let wire block bodies = Bcs.encode wire_codec (block, bodies)

(* {1 Number} *)

let test_of_int_refuses_below_genesis () =
  Alcotest.(check bool) "of_int (-1)" true (Option.is_none (Cb.Number.of_int (-1)));
  Alcotest.(check bool)
    "of_int (-4096)" true
    (Option.is_none (Cb.Number.of_int (-4096)));
  Alcotest.(check int) "of_int 0 is genesis"
    (Cb.Number.to_int Cb.Number.genesis)
    (Cb.Number.to_int (get "of_int 0" (Cb.Number.of_int 0)))

let test_number_round_trips () =
  List.iter
    (fun n ->
      let value = get "of_int" (Cb.Number.of_int n) in
      let bytes = Bcs.encode Cb.Number.codec value in
      Alcotest.(check int) "eight little-endian bytes" 8 (String.length bytes);
      Alcotest.(check string) "the same field the pre-image carries"
        (Bcs.encode Bcs.u64 (Cb.Number.to_int64 value))
        bytes;
      let back = decoded "number" Cb.Number.codec bytes in
      Alcotest.(check int) "to_int" n (Cb.Number.to_int back);
      Alcotest.(check bool) "equal" true (Cb.Number.equal value back))
    [ 0; 1; 2; 7; 255; 4096; 1_000_000; max_int ]

let test_number_refuses_an_out_of_range_height () =
  let all_ones = refused "u64 all ones" Cb.Number.codec (Bcs.encode Bcs.u64 (-1L)) in
  Alcotest.(check bool) "renders" true (String.length (Bcs.error_to_string all_ones) > 0);
  let too_big =
    refused "above max_int" Cb.Number.codec (Bcs.encode Bcs.u64 Int64.max_int)
  in
  Alcotest.(check bool) "renders" true (String.length (Bcs.error_to_string too_big) > 0)

(* {1 Reputation scores} *)

let test_scores_round_trip () =
  List.iter
    (fun (what, s) ->
      let back =
        decoded what Reputation_scores.codec (Bcs.encode Reputation_scores.codec s)
      in
      check_scores what s back)
    [ ("fresh", scores_fresh); ("bumped", scores_bumped); ("final", scores_final) ]

let test_scores_finality_is_on_the_wire () =
  let final =
    decoded "final" Reputation_scores.codec
      (Bcs.encode Reputation_scores.codec scores_final)
  in
  let plain =
    decoded "bumped" Reputation_scores.codec
      (Bcs.encode Reputation_scores.codec scores_bumped)
  in
  Alcotest.(check bool) "a final set decodes final" true (Reputation_scores.is_final final);
  Alcotest.(check bool) "a non-final set decodes non-final" false
    (Reputation_scores.is_final plain);
  Alcotest.(check bool) "the two encodings differ" false
    (String.equal
       (Bcs.encode Reputation_scores.codec scores_final)
       (Bcs.encode Reputation_scores.codec scores_bumped))

let test_scores_reject_a_disagreeing_count () =
  let bytes = Bcs.encode Reputation_scores.codec scores_bumped in
  let at = String.length bytes - 4 in
  let total = Reputation_scores.total_authorities scores_bumped in
  Alcotest.(check string) "the tail is the declared count"
    (Bcs.encode Bcs.u32 total) (sub_at bytes ~off:at ~len:4);
  let doctored = splice bytes ~at ~bytes:(Bcs.encode Bcs.u32 (total + 1)) in
  let e = refused "count off by one" Reputation_scores.codec doctored in
  Alcotest.(check bool) "renders" true (String.length (Bcs.error_to_string e) > 0)

let test_scores_reject_a_non_ascending_map () =
  let bytes = Bcs.encode Reputation_scores.codec scores_bumped in
  (* Four entries behind a one-byte ULEB128 count, each 32 + 8 bytes wide. *)
  let key i = sub_at bytes ~off:(1 + (40 * i)) ~len:32 in
  let swapped = splice (splice bytes ~at:1 ~bytes:(key 1)) ~at:41 ~bytes:(key 0) in
  Alcotest.(check bool) "the swap changed the bytes" false (String.equal bytes swapped);
  let e = refused "descending keys" Reputation_scores.codec swapped in
  Alcotest.(check bool) "renders" true (String.length (Bcs.error_to_string e) > 0)

(* {1 Sub-DAG} *)

let test_sub_dag_round_trips () =
  List.iteri
    (fun i sd ->
      let what = Printf.sprintf "sub-DAG %d" i in
      check_sub_dag what sd (decoded what Sub_dag.codec (Bcs.encode Sub_dag.codec sd)))
    sub_dags

let test_sub_dag_encoding_is_byte_stable () =
  List.iteri
    (fun i sd ->
      let once = Bcs.encode Sub_dag.codec sd in
      let twice = Bcs.encode Sub_dag.codec (decoded "round" Sub_dag.codec once) in
      Alcotest.(check string)
        (Printf.sprintf "sub-DAG %d re-encodes identically" i)
        once twice)
    sub_dags

(* The section widths, so a digest cannot be hiding in the payload. *)
let sub_dag_sections sd =
  let headers =
    Bcs.encode (Bcs.list Header.codec) (Nonempty.to_list (Sub_dag.headers sd))
  in
  let scores = Bcs.encode Reputation_scores.codec (Sub_dag.scores sd) in
  (String.length headers, String.length scores)

let test_the_cached_digest_is_not_on_the_wire () =
  List.iteri
    (fun i sd ->
      let bytes = Bcs.encode Sub_dag.codec sd in
      let headers_len, scores_len = sub_dag_sections sd in
      Alcotest.(check int)
        (Printf.sprintf "sub-DAG %d: four sections and no fifth" i)
        (headers_len + scores_len + 8 + Tn_crypto.Digest.length)
        (String.length bytes);
      Alcotest.(check bool)
        (Printf.sprintf "sub-DAG %d: the digest bytes are absent" i)
        false
        (contains bytes
           ~needle:
             (Tn_crypto.Digest.to_bytes
                (Digests.Sub_dag_digest.to_digest (Sub_dag.digest sd)))))
    sub_dags

let test_tampering_moves_the_digest () =
  let sd = sd_dup in
  let headers_len, scores_len = sub_dag_sections sd in
  let bytes = Bcs.encode Sub_dag.codec sd in
  let back =
    decoded "tampered randomness" Sub_dag.codec
      (flip bytes ~at:(headers_len + scores_len + 8))
  in
  let expected =
    Sub_dag.of_persisted ~headers:(Sub_dag.headers sd) ~scores:(Sub_dag.scores sd)
      ~stored:(Sub_dag.stored_timestamp sd)
      ~randomness:(Sub_dag.randomness back)
  in
  Alcotest.(check bool) "the randomness really changed" false
    (Tn_crypto.Digest.equal (Sub_dag.randomness sd) (Sub_dag.randomness back));
  Alcotest.(check string) "the digest is RECOMPUTED over the tampered fields"
    (Digests.Sub_dag_digest.to_hex (Sub_dag.digest expected))
    (Digests.Sub_dag_digest.to_hex (Sub_dag.digest back));
  Alcotest.(check bool) "so it is no longer the digest the writer held" false
    (Digests.Sub_dag_digest.equal (Sub_dag.digest sd) (Sub_dag.digest back))

let test_of_persisted_agrees_with_create () =
  List.iteri
    (fun i sd ->
      let rebuilt =
        Sub_dag.of_persisted ~headers:(Sub_dag.headers sd)
          ~scores:(Sub_dag.scores sd) ~stored:(Sub_dag.stored_timestamp sd)
          ~randomness:(Sub_dag.randomness sd)
      in
      check_sub_dag (Printf.sprintf "sub-DAG %d rebuilt" i) sd rebuilt)
    sub_dags

let test_an_empty_sequence_is_refused () =
  let bytes = Bcs.encode Sub_dag.codec sd_plain in
  Alcotest.(check string) "one header in the fixture" "\x01" (sub_at bytes ~off:0 ~len:1);
  let e = refused "zero headers" Sub_dag.codec (splice bytes ~at:0 ~bytes:"\x00") in
  Alcotest.(check bool) "renders" true (String.length (Bcs.error_to_string e) > 0)

let test_a_negative_timestamp_is_refused () =
  let sd = sd_payload in
  let headers_len, scores_len = sub_dag_sections sd in
  let bytes = Bcs.encode Sub_dag.codec sd in
  let doctored =
    splice bytes ~at:(headers_len + scores_len) ~bytes:(Bcs.encode Bcs.u64 (-1L))
  in
  let e = refused "u64 all ones as a timestamp" Sub_dag.codec doctored in
  Alcotest.(check bool) "renders" true (String.length (Bcs.error_to_string e) > 0)

(* {1 Consensus block} *)

let test_block_round_trips () =
  List.iteri
    (fun i b ->
      let what = Printf.sprintf "block %d" i in
      check_block what b (decoded what Cb.codec (Bcs.encode Cb.codec b)))
    all_blocks

let test_block_wire_omits_the_digest_and_the_extra_field () =
  List.iteri
    (fun i b ->
      let bytes = Bcs.encode Cb.codec b in
      Alcotest.(check int)
        (Printf.sprintf "block %d: parent, sub-DAG, number and nothing else" i)
        (Tn_crypto.Digest.length
        + String.length (Bcs.encode Sub_dag.codec (Cb.sub_dag b))
        + 8)
        (String.length bytes);
      Alcotest.(check bool)
        (Printf.sprintf "block %d: the digest bytes are absent" i)
        false
        (contains bytes
           ~needle:
             (Tn_crypto.Digest.to_bytes
                (Digests.Output_digest.to_digest (Cb.digest b)))))
    all_blocks

let test_a_block_height_below_genesis_is_refused () =
  let b = nth "block" all_blocks 1 in
  let bytes = Bcs.encode Cb.codec b in
  let at = String.length bytes - 8 in
  Alcotest.(check string) "the tail is the height"
    (Bcs.encode Bcs.u64 (Cb.Number.to_int64 (Cb.number b)))
    (sub_at bytes ~off:at ~len:8);
  let e =
    refused "u64 all ones as a height" Cb.codec
      (splice bytes ~at ~bytes:(Bcs.encode Bcs.u64 (-1L)))
  in
  Alcotest.(check bool) "renders" true (String.length (Bcs.error_to_string e) > 0)

(* {1 Record payloads} *)

let test_record_round_trips () =
  List.iteri
    (fun i r ->
      let what = Printf.sprintf "record %d" i in
      check_record what r (record_ok what (Rc.encode_record r)))
    records

let test_record_encoding_is_byte_stable () =
  List.iteri
    (fun i r ->
      let once = Rc.encode_record r in
      let twice = Rc.encode_record (record_ok "round" once) in
      Alcotest.(check string)
        (Printf.sprintf "record %d re-encodes identically" i)
        once twice)
    records

let test_a_payload_must_be_consumed_exactly () =
  let bytes = Rc.encode_record (nth "record" records 3) in
  Alcotest.(check int) "one byte over" 1 (expect_trailing "one byte over" (bytes ^ "\x00"));
  Alcotest.(check int) "sixteen bytes over" 16
    (expect_trailing "sixteen bytes over" (bytes ^ String.make 16 '\xff'));
  expect_bcs "truncated" (sub_at bytes ~off:0 ~len:(String.length bytes - 1));
  expect_bcs "empty" ""

let test_a_short_body_list_is_missing_body () =
  let r = nth "record with bodies" records 3 in
  let block = Record.consensus r in
  let dropped =
    List.filter
      (fun body -> not (Digests.Batch_digest.equal (dg body) db))
      (Record.bodies r)
  in
  let missing = expect_missing_body "the dropped body is named" (wire block dropped) in
  Alcotest.(check string) "and it is the one that was dropped"
    (Digests.Batch_digest.to_hex db)
    (Digests.Batch_digest.to_hex missing);
  let none_at_all = expect_missing_body "no bodies at all" (wire block []) in
  Alcotest.(check string) "the first payload digest is named"
    (Digests.Batch_digest.to_hex
       (nth "first digest" (Sub_dag.payload_digests (Cb.sub_dag block)) 0))
    (Digests.Batch_digest.to_hex none_at_all)

let test_a_reordered_body_list_is_re_derived () =
  let r = nth "record with bodies" records 3 in
  let block = Record.consensus r in
  let reordered = List.rev (Record.bodies r) in
  Alcotest.(check bool) "the fixture really was reordered" false
    (List.equal Batch.equal reordered (Record.bodies r));
  let back = record_ok "reordered" (wire block reordered) in
  Alcotest.(check (list string)) "the bodies come back in the HEADER's order"
    (List.map Digests.Batch_digest.to_hex
       (Sub_dag.payload_digests (Cb.sub_dag block)))
    (List.map (fun body -> Digests.Batch_digest.to_hex (dg body)) (Record.bodies back));
  check_record "reordered" r back;
  Alcotest.(check string) "and it re-encodes to the canonical payload"
    (Rc.encode_record r) (Rc.encode_record back)

let test_a_deduplicated_body_list_re_expands () =
  let r = nth "record with a repeated digest" records 3 in
  let block = Record.consensus r in
  let payload = Sub_dag.payload_digests (Cb.sub_dag block) in
  let occurrences d = List.length (List.filter (Digests.Batch_digest.equal d) payload) in
  Alcotest.(check int) "the fixture declares [da] twice" 2 (occurrences da);
  let deduped =
    List.rev
      (List.fold_left
         (fun kept body ->
           if List.exists (fun other -> Digests.Batch_digest.equal (dg other) (dg body)) kept
           then kept
           else body :: kept)
         [] (Record.bodies r))
  in
  Alcotest.(check int) "the wire carries each body once"
    (List.length (List.sort_uniq Digests.Batch_digest.compare payload))
    (List.length deduped);
  let back = record_ok "deduplicated" (wire block deduped) in
  Alcotest.(check int) "the record comes back at full multiplicity"
    (List.length payload)
    (List.length (Record.bodies back));
  check_record "deduplicated" r back

let test_a_payloadless_record_has_no_bodies () =
  let r = nth "record 0" records 0 in
  Alcotest.(check int) "no payload declared, no body stored" 0
    (List.length (Record.bodies r));
  check_record "empty body list" r (record_ok "empty" (Rc.encode_record r))

let test_received_at_is_not_on_the_wire () =
  let stamped = Batch.with_received_at ba (get "timestamp" (Units.Timestamp.of_sec 99L)) in
  Alcotest.(check bool) "the fixture really is stamped" true
    (Option.is_some (Batch.received_at stamped));
  Alcotest.(check string) "a stamp does not move the digest"
    (Digests.Batch_digest.to_hex (dg ba))
    (Digests.Batch_digest.to_hex (dg stamped));
  Alcotest.(check string) "nor the bytes"
    (Bcs.encode Batch.codec ba)
    (Bcs.encode Batch.codec stamped);
  let back = decoded "batch" Batch.codec (Bcs.encode Batch.codec stamped) in
  Alcotest.(check bool) "and it does not survive the wire" true
    (Option.is_none (Batch.received_at back))

let test_error_rendering () =
  let bytes = Rc.encode_record (nth "record" records 1) in
  let rendered =
    List.map Rc.error_to_string
      [
        record_error "trailing" (bytes ^ "\x00");
        record_error "truncated" (sub_at bytes ~off:0 ~len:4);
        record_error "missing body" (wire (Record.consensus (nth "record" records 3)) []);
      ]
  in
  Alcotest.(check int) "three distinct renderings" 3
    (List.length (List.sort_uniq String.compare rendered));
  List.iter
    (fun s -> Alcotest.(check bool) "non-empty" true (String.length s > 0))
    rendered

(* {1 Epoch meta} *)

let metas =
  [
    Rc.Meta.
      {
        epoch = Units.Epoch.zero;
        epoch_start = Cb.Number.genesis;
        epoch_parent = Cb.genesis_parent;
      };
    Rc.Meta.
      {
        epoch = get "epoch 7" (Units.Epoch.of_int 7);
        epoch_start = get "height 4096" (Cb.Number.of_int 4096);
        epoch_parent = Cb.digest (nth "block" all_blocks 2);
      };
  ]

let meta_ok what bytes =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "%s: %s" what (Rc.error_to_string e))
    (Rc.Meta.decode bytes)

let meta_error what bytes =
  Result.fold
    ~ok:(fun _ -> Alcotest.failf "%s: expected a refusal, got a meta" what)
    ~error:Fun.id (Rc.Meta.decode bytes)

let test_meta_round_trips () =
  List.iteri
    (fun i m ->
      let what = Printf.sprintf "meta %d" i in
      let back = meta_ok what (Rc.Meta.encode m) in
      Alcotest.(check int)
        (what ^ ": epoch")
        (Units.Epoch.to_int m.Rc.Meta.epoch)
        (Units.Epoch.to_int back.Rc.Meta.epoch);
      Alcotest.(check int)
        (what ^ ": epoch_start")
        (Cb.Number.to_int m.Rc.Meta.epoch_start)
        (Cb.Number.to_int back.Rc.Meta.epoch_start);
      Alcotest.(check string)
        (what ^ ": epoch_parent")
        (Digests.Output_digest.to_hex m.Rc.Meta.epoch_parent)
        (Digests.Output_digest.to_hex back.Rc.Meta.epoch_parent);
      Alcotest.(check bool) (what ^ ": equal") true (Rc.Meta.equal m back);
      Alcotest.(check int) (what ^ ": fixed width") 48 (String.length (Rc.Meta.encode m)))
    metas

let test_meta_distinguishes_its_fields () =
  let a = nth "meta 0" metas 0 and b = nth "meta 1" metas 1 in
  Alcotest.(check bool) "two different metas are not equal" false (Rc.Meta.equal a b);
  Alcotest.(check bool) "nor do they encode alike" false
    (String.equal (Rc.Meta.encode a) (Rc.Meta.encode b))

let test_meta_refuses_a_damaged_payload () =
  let bytes = Rc.Meta.encode (nth "meta 1" metas 1) in
  let trailing = meta_error "one byte over" (bytes ^ "\x00") in
  let left =
    match trailing with
    | Rc.Trailing { left } -> left
    | Rc.Bcs _ | Rc.Rebuild _ ->
        Alcotest.failf "expected Trailing, got %s" (Rc.error_to_string trailing)
  in
  Alcotest.(check int) "one byte over" 1 left;
  let short = meta_error "truncated" (sub_at bytes ~off:0 ~len:7) in
  (match short with
  | Rc.Bcs _ -> ()
  | Rc.Trailing _ | Rc.Rebuild _ ->
      Alcotest.failf "expected a codec error, got %s" (Rc.error_to_string short));
  let bad_epoch =
    meta_error "epoch out of range"
      (splice bytes ~at:0 ~bytes:(Bcs.encode Bcs.u64 (-1L)))
  in
  Alcotest.(check bool) "an out-of-range epoch renders" true
    (String.length (Rc.error_to_string bad_epoch) > 0)

let () =
  Alcotest.run "durable codec"
    [
      ( "consensus block numbers",
        [
          Alcotest.test_case "below genesis is None" `Quick
            test_of_int_refuses_below_genesis;
          Alcotest.test_case "heights round-trip as eight LE bytes" `Quick
            test_number_round_trips;
          Alcotest.test_case "an unrepresentable height is refused" `Quick
            test_number_refuses_an_out_of_range_height;
        ] );
      ( "reputation scores",
        [
          Alcotest.test_case "every projection round-trips" `Quick
            test_scores_round_trip;
          Alcotest.test_case "finality survives the wire" `Quick
            test_scores_finality_is_on_the_wire;
          Alcotest.test_case "a disagreeing authority count is refused" `Quick
            test_scores_reject_a_disagreeing_count;
          Alcotest.test_case "a non-ascending map is refused" `Quick
            test_scores_reject_a_non_ascending_map;
        ] );
      ( "sub-DAGs",
        [
          Alcotest.test_case "every projection round-trips" `Quick
            test_sub_dag_round_trips;
          Alcotest.test_case "re-encoding is byte-stable" `Quick
            test_sub_dag_encoding_is_byte_stable;
          Alcotest.test_case "the cached digest is not on the wire" `Quick
            test_the_cached_digest_is_not_on_the_wire;
          Alcotest.test_case "tampering moves the recomputed digest" `Quick
            test_tampering_moves_the_digest;
          Alcotest.test_case "of_persisted agrees with create" `Quick
            test_of_persisted_agrees_with_create;
          Alcotest.test_case "an empty sequence is refused" `Quick
            test_an_empty_sequence_is_refused;
          Alcotest.test_case "an out-of-range timestamp is refused" `Quick
            test_a_negative_timestamp_is_refused;
        ] );
      ( "consensus blocks",
        [
          Alcotest.test_case "every projection round-trips" `Quick
            test_block_round_trips;
          Alcotest.test_case "the wire omits the digest and the extra field" `Quick
            test_block_wire_omits_the_digest_and_the_extra_field;
          Alcotest.test_case "a height below genesis is refused" `Quick
            test_a_block_height_below_genesis_is_refused;
        ] );
      ( "record payloads",
        [
          Alcotest.test_case "every projection round-trips" `Quick
            test_record_round_trips;
          Alcotest.test_case "re-encoding is byte-stable" `Quick
            test_record_encoding_is_byte_stable;
          Alcotest.test_case "the payload is consumed exactly" `Quick
            test_a_payload_must_be_consumed_exactly;
          Alcotest.test_case "a short body list names the missing body" `Quick
            test_a_short_body_list_is_missing_body;
          Alcotest.test_case "a reordered body list is re-derived" `Quick
            test_a_reordered_body_list_is_re_derived;
          Alcotest.test_case "a deduplicated body list re-expands" `Quick
            test_a_deduplicated_body_list_re_expands;
          Alcotest.test_case "a payloadless record has no bodies" `Quick
            test_a_payloadless_record_has_no_bodies;
          Alcotest.test_case "received_at is not on the wire" `Quick
            test_received_at_is_not_on_the_wire;
          Alcotest.test_case "the three refusals render distinctly" `Quick
            test_error_rendering;
        ] );
      ( "epoch meta",
        [
          Alcotest.test_case "round-trips at a fixed width" `Quick
            test_meta_round_trips;
          Alcotest.test_case "two metas are distinguishable" `Quick
            test_meta_distinguishes_its_fields;
          Alcotest.test_case "a damaged payload is refused" `Quick
            test_meta_refuses_a_damaged_payload;
        ] );
    ]
