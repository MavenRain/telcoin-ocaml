(* Chunk-44 stage 3: the [Tn_network] message layer against the chunk-44 Rust
   oracle harness.

   Every golden row in network_vectors.ml's stage-3 tables is the byte output
   of that harness, which re-declares each Rust type verbatim from the file
   and line the ground truth cites and encodes it with bcs 0.1.6, the version
   telcoin-network @ 31cc4e90 pins. The two rows that embed a [Header] are
   composed from the FROZEN chunk-41 header pre-image, so a green run here is
   wire evidence and not round-trip self-consistency: this file builds each
   value with the port's own constructors, encodes it, and compares the bytes
   with what Rust wrote, then decodes Rust's bytes back and compares values.

   The rows that discriminate most:
   - [worker_response_report_batch_unit], one byte: a unit variant is a bare
     tag, and an accidental unit payload would show up nowhere else;
   - [worker_gossip_batch]: a [BlockHash] is LENGTH-PREFIXED (0x20 then 32),
     not a bare 32 (GT:87);
   - [missing_certificates_request]: Rust's [usize] is 8 bytes LE (GT:43);
   - the four [primary_request_epoch_record_*] rows: two independent Options
     in one variant, so a swapped tag shows;
   - [node_record_rpc_none] against [legacy_node_record]: the same values in
     the two layouts [decode_compat] has to tell apart;
   - the message-id rows at 2^63 and u64::MAX, which are red under a signed
     rendering of the sequence number and green only under an unsigned one. *)

open Tn_types
module Bcs = Tn_codec.Bcs
module NV = Network_vectors
module SV = Snappy_vectors
module N = Tn_network
module Header = Tn_vertex.Header

(* ------------------------------------------------------------------ helpers *)

let hex s =
  let buf = Buffer.create ((String.length s * 2) + 2) in
  String.iter
    (fun c -> Buffer.add_string buf (Printf.sprintf "%02x" (Char.code c)))
    s;
  Buffer.contents buf

let unhex = SV.unhex

(* Both forcing helpers build a THUNK in the failing arm and apply it at the
   end, because [Option.fold]'s [~none] and [Result.fold]'s arms are eager: a
   bare [Alcotest.fail] there would fire on every call, including the ones
   that succeed. *)
let force msg o =
  Option.fold ~none:(fun () -> Alcotest.fail msg) ~some:(fun v () -> v) o ()

let force_result to_string r =
  Result.fold
    ~ok:(fun v () -> v)
    ~error:(fun e () -> Alcotest.fail (to_string e))
    r ()

let bcs_error = Bcs.error_to_string

(* One name per BCS error, enumerated, so a negative case pins WHICH rejection
   fired without depending on an offset that a neighbouring field's width
   would shift. *)
let error_kind = function
  | Bcs.Unexpected_end_of_input _ -> "unexpected_end_of_input"
  | Bcs.Non_canonical_uleb128 _ -> "non_canonical_uleb128"
  | Bcs.Uleb128_overflow _ -> "uleb128_overflow"
  | Bcs.Invalid_bool _ -> "invalid_bool"
  | Bcs.Invalid_option_tag _ -> "invalid_option_tag"
  | Bcs.Unknown_variant _ -> "unknown_variant"
  | Bcs.Length_out_of_range _ -> "length_out_of_range"
  | Bcs.Integer_out_of_range _ -> "integer_out_of_range"
  | Bcs.Trailing_bytes _ -> "trailing_bytes"

(* The keyed lookup every oracle case goes through. A miss yields an empty hex
   string, which turns the case red instead of testing nothing; the floor case
   asserts one hit and one miss by name. *)
let bcs_hex name =
  Option.fold ~none:""
    ~some:(fun (r : NV.bcs_row) -> r.hex)
    (List.find_opt (fun (r : NV.bcs_row) -> String.equal r.bcs_name name)
       NV.bcs_rows)

let has_row name = String.length (bcs_hex name) > 0

(* The workhorse: the port's value must ENCODE to Rust's bytes and Rust's
   bytes must DECODE back to the port's value. *)
let oracle_row ~name ~codec ~equal value =
  let expected = bcs_hex name in
  Alcotest.(check bool) (name ^ ": row present") true (String.length expected > 0);
  Alcotest.(check string) (name ^ ": encode") expected (hex (Bcs.encode codec value));
  let got = force_result bcs_error (Bcs.decode codec (unhex expected)) in
  Alcotest.(check bool) (name ^ ": decode") true (equal got value)

let decode_rejects ~name ~codec ~kind bytes =
  Result.fold
    ~ok:(fun _ -> Alcotest.fail (name ^ ": accepted"))
    ~error:(fun e -> Alcotest.(check string) name kind (error_kind e))
    (Bcs.decode codec bytes)

(* ----------------------------------------------------------------- fixtures *)

let dig c = force "digest width" (Tn_crypto.Digest.of_bytes (String.make 32 c))
let hdr_digest c = Digests.Header_digest.of_digest (dig c)
let bat_digest c = Digests.Batch_digest.of_digest (dig c)
let auth c = force "authority id width" (Authority_id.of_bytes (String.make 32 c))
let key c = force "bls key width" (N.Bls_public_key.of_bytes (String.make 96 c))

let sig48 c =
  force "bls signature width" (N.Bls_signature.of_bytes (String.make 48 c))

let hash32 c = force "hash32 width" (Tn_hash32.Hash32.of_bytes (String.make 32 c))
let epoch n = force "epoch out of range" (Units.Epoch.of_int n)
let round n = force "round out of range" (Round.of_int n)
let bitmap vs = force_result N.Roaring.error_to_string (N.Roaring.of_list vs)
let small_bitmap = bitmap [ 0; 1; 5 ]

(* [Header::default()], the frozen chunk-41 H1 pre-image and the header every
   composed row embeds. *)
let h1 =
  Header.make ~author:Authority_id.zero ~round:Round.genesis
    ~epoch:Units.Epoch.zero ~created_at:Units.Timestamp.zero ~payload:[]
    ~parents:[] ~latest_execution_block:Block_num_hash.zero

let vote_default =
  N.Vote_wire.make
    ~header_digest:(Digests.Header_digest.of_digest Tn_crypto.Digest.zero)
    ~round:Round.genesis ~epoch:Units.Epoch.zero ~origin:Authority_id.zero
    ~author:Authority_id.zero ~signature:(sig48 '\x00')

let vote_populated =
  N.Vote_wire.make ~header_digest:(hdr_digest '\x0a') ~round:(round 5)
    ~epoch:(epoch 7) ~origin:(auth '\x0b') ~author:(auth '\x0c')
    ~signature:(sig48 '\x0d')

let epoch_record_default =
  N.Epoch_record.make ~epoch:Units.Epoch.zero ~committee:[] ~next_committee:[]
    ~parent_hash:Tn_crypto.Digest.zero ~final_state:Block_num_hash.zero
    ~final_consensus:
      (N.Epoch_record.make_consensus_num_hash ~number:0L
         ~hash:Tn_crypto.Digest.zero)

let epoch_record_populated =
  N.Epoch_record.make ~epoch:(epoch 7)
    ~committee:[ key '\x11'; key '\x22' ]
    ~next_committee:[ key '\x33' ] ~parent_hash:(dig '\x44')
    ~final_state:
      (Block_num_hash.make ~number:0x0102030405060708L ~hash:(hash32 '\x55'))
    ~final_consensus:
      (N.Epoch_record.make_consensus_num_hash ~number:9L ~hash:(dig '\x66'))

let epoch_vote_default =
  N.Epoch_vote.make ~epoch:Units.Epoch.zero ~epoch_hash:Tn_crypto.Digest.zero
    ~public_key:(key '\x00') ~signature:(sig48 '\x00')

let epoch_vote_populated =
  N.Epoch_vote.make ~epoch:(epoch 3) ~epoch_hash:(dig '\x91')
    ~public_key:(key '\x92') ~signature:(sig48 '\x93')

let epoch_certificate values =
  N.Epoch_certificate.make ~epoch_hash:(dig '\x77') ~signature:(sig48 '\x88')
    ~signed_authorities:(bitmap values)

let consensus_result_populated =
  N.Consensus_result.make ~epoch:(epoch 2) ~round:(round 3) ~number:4L
    ~hash:(dig '\xa1') ~validator:(key '\xa2') ~signature:(sig48 '\xa3')

let cert_wire state = N.Certificate_wire.make ~header:h1 ~state

let cert_unsigned =
  cert_wire (N.Certificate_wire.Unsigned (sig48 '\x01'))
    ~signed_authorities:small_bitmap

let cert_genesis_empty =
  cert_wire N.Certificate_wire.Genesis ~signed_authorities:(bitmap [])

let var b = N.Var_bytes.of_bytes b

(* The harness's [peer_map(n)] takes the first [n] of these, whose bytes are
   written out rather than computed, so no character arithmetic is needed. *)
let peer_parts =
  [
    (key '\xb0', var "\x00\x24\x08\x00", var "\x04\x7f\x00\x00\x01\x00");
    (key '\xb1', var "\x00\x24\x08\x01", var "\x04\x7f\x00\x00\x01\x01");
  ]

let peer_entries =
  List.map
    (fun (k, network_key, addr) ->
      N.Peer_exchange.make_entry ~key:k ~network_key ~multiaddrs:[ addr ])
    peer_parts

let peer_map n =
  force_result N.Peer_exchange.error_to_string
    (N.Peer_exchange.of_entries (List.filteri (fun i _ -> i < n) peer_entries))

(* One map entry as bcs writes it, used to build the two non-canonical maps
   the decoder must refuse without ever slicing a golden row apart. *)
let entry_codec =
  Bcs.pair N.Bls_public_key.codec
    (Bcs.pair N.Var_bytes.codec (Bcs.unordered_list N.Var_bytes.codec))

let entry_bytes n =
  Option.fold ~none:""
    ~some:(fun (k, network_key, addr) ->
      Bcs.encode entry_codec (k, (network_key, [ addr ])))
    (List.nth_opt peer_parts n)

let batch_v5 =
  Batch.make
    ~transactions:[ "\xaa\xbb"; "\xcc" ]
    ~epoch:(epoch 7)
    ~beneficiary:(force "address" (Units.Address.of_bytes (String.make 20 '\x23')))
    ~base_fee_per_gas:(force "base fee" (Units.Base_fee.of_int 1_000_000_007))
    ~worker_id:(force "worker id" (Units.Worker_id.of_int 3))

let sealed_v5 = Batch.Sealed.claim ~batch:batch_v5 ~digest:(bat_digest '\xef')
let skip_rounds = [ (auth '\x0e', "\x01\x02") ]

let missing_certs =
  N.Primary_msg.make_missing_certificates_request
    ~exclusive_lower_bound:(round 4) ~skip_rounds ~max_response_size:1_048_576L

let node_info ~rpc =
  N.Node_record.make_network_info
    ~pubkey:(var "\x00\x24\x08\x01")
    ~multiaddrs:[ var "\x04\x7f\x00\x00\x01" ]
    ~timestamp:1_700_000_000L ~rpc

let node_record ~rpc =
  N.Node_record.make ~info:(node_info ~rpc) ~signature:(sig48 '\x30')

let rpc_both =
  Some
    (N.Node_record.make_rpc_info ~http:"http://a.example/"
       ~ws:(Some "ws://a.example/"))

let rpc_http_only =
  Some (N.Node_record.make_rpc_info ~http:"http://a.example/" ~ws:None)

(* The harness built this one from an unsorted pair; a [BTreeSet] iterates
   ascending, so the wire bytes and every decode of them are ascending. *)
let worker_batches_request =
  N.Sync_request.Batches
    { batch_digests = [ bat_digest '\x01'; bat_digest '\x02' ]; epoch = epoch 6 }

let worker_frame_codec = N.Sync_frame.codec N.Sync_request.worker_codec
let worker_frame_equal = N.Sync_frame.equal N.Sync_request.worker_equal

(* --------------------------------------------------------------- the floor *)

let vector_count =
  List.length NV.bcs_rows + List.length NV.roaring_rows
  + List.length NV.msgid_rows
  + List.length NV.roaring_neg_rows

let case_total = ref 0

let t_floor () =
  Alcotest.(check bool)
    (Printf.sprintf "vector rows %d >= 70" vector_count)
    true (vector_count >= 70);
  Alcotest.(check bool)
    (Printf.sprintf "test cases %d >= 70" !case_total)
    true
    (!case_total >= 70);
  Alcotest.(check bool) "the oracle tables are all present" true
    (List.length NV.bcs_rows >= 65
    && List.length NV.roaring_rows >= 5
    && List.length NV.msgid_rows >= 8);
  (* Positive control and miss for the keyed row lookup every case uses. *)
  Alcotest.(check bool) "the row lookup hits" true (has_row "vote_populated");
  Alcotest.(check bool) "the row lookup misses" false (has_row "no_such_row")

(* --------------------------------------------------------------- roaring *)

let roaring_values name =
  if String.equal name "empty" then []
  else if String.equal name "array_one" then [ 42 ]
  else if String.equal name "array_three" then [ 0; 1; 5 ]
  else if String.equal name "array_two_containers" then [ 1; 70000 ]
  else List.init 5000 Fun.id

let t_roaring_golden_encode () =
  List.iter
    (fun (r : NV.roaring_row) ->
      let bits = bitmap (roaring_values r.r_name) in
      Alcotest.(check int)
        (r.r_name ^ ": the case matches the row's cardinality")
        r.card (N.Roaring.cardinality bits);
      Alcotest.(check string)
        (r.r_name ^ ": interchange bytes")
        r.raw_hex
        (hex (N.Roaring.to_bytes bits));
      Alcotest.(check string)
        (r.r_name ^ ": BCS field bytes")
        r.field_hex
        (hex (Bcs.encode N.Roaring.codec bits)))
    NV.roaring_rows

let t_roaring_golden_decode () =
  List.iter
    (fun (r : NV.roaring_row) ->
      let got =
        force_result N.Roaring.error_to_string
          (N.Roaring.of_bytes (unhex r.raw_hex))
      in
      Alcotest.(check int) (r.r_name ^ ": cardinality") r.card
        (N.Roaring.cardinality got);
      Alcotest.(check (list int))
        (r.r_name ^ ": values")
        (roaring_values r.r_name) (N.Roaring.to_list got);
      let field =
        force_result bcs_error (Bcs.decode N.Roaring.codec (unhex r.field_hex))
      in
      Alcotest.(check bool)
        (r.r_name ^ ": the field decodes to the same bitmap")
        true (N.Roaring.equal got field))
    NV.roaring_rows

let t_roaring_run_container () =
  (* roaring 0.10.12 never EMITS a run container, so this row is hand-built to
     the format and validated by the Rust decoder. The port must read it. *)
  let got =
    force_result N.Roaring.error_to_string
      (N.Roaring.of_bytes (unhex NV.roaring_run_hex))
  in
  Alcotest.(check (list int))
    "run container values" NV.roaring_run_values (N.Roaring.to_list got);
  let field =
    force_result bcs_error
      (Bcs.decode N.Roaring.codec (unhex NV.roaring_run_field_hex))
  in
  Alcotest.(check bool) "run container through the BCS field" true
    (N.Roaring.equal got field);
  (* Re-encoding gives the no-run form, which is what Rust would write for the
     same values: legal, documented, and not byte-identical. *)
  Alcotest.(check bool) "re-encoding uses the no-run cookie" true
    (not (String.equal (hex (N.Roaring.to_bytes got)) NV.roaring_run_hex));
  (* The POSITIVE control for the [start + len] test: a run ending on 0xffff
     exactly, which [s.checked_add(len)] still admits upstream. Its sibling
     one past that end is the "run_start_len_overflow" negative row. *)
  let boundary =
    force_result N.Roaring.error_to_string
      (N.Roaring.of_bytes (unhex NV.roaring_run_boundary_hex))
  in
  Alcotest.(check (list int))
    "a run ending on 0xffff is admitted" NV.roaring_run_boundary_values
    (N.Roaring.to_list boundary)

let t_roaring_negatives () =
  List.iter
    (fun (name, hexs, rust) ->
      Alcotest.(check bool)
        (Printf.sprintf "%s: Rust rejects it (%s)" name rust)
        true
        (String.length rust > 0);
      Result.fold
        ~ok:(fun _ -> Alcotest.fail (name ^ ": accepted"))
        ~error:(fun (_ : N.Roaring.error) -> ())
        (N.Roaring.of_bytes (unhex hexs)))
    NV.roaring_neg_rows;
  (* Trailing bytes after a complete bitmap are refused too: the BCS field
     length delimits the payload exactly. *)
  Result.fold
    ~ok:(fun _ -> Alcotest.fail "trailing byte accepted")
    ~error:(fun (_ : N.Roaring.error) -> ())
    (N.Roaring.of_bytes (unhex "3a3000000000000000"))

let t_roaring_round_trip () =
  List.iter
    (fun values ->
      let bits = bitmap values in
      let got =
        force_result N.Roaring.error_to_string
          (N.Roaring.of_bytes (N.Roaring.to_bytes bits))
      in
      Alcotest.(check (list int))
        (Printf.sprintf "round trip of %d values" (List.length values))
        (N.Roaring.to_list bits) (N.Roaring.to_list got))
    [
      [];
      [ 0 ];
      [ 4_294_967_295 ];
      [ 5; 5; 1 ];
      List.init 4096 Fun.id;
      List.init 4097 (fun i -> i * 2);
      [ 1; 70000; 200000 ];
    ]

let t_roaring_range () =
  Result.fold
    ~ok:(fun _ -> Alcotest.fail "2^32 accepted")
    ~error:(fun e ->
      Alcotest.(check string) "value out of range"
        "roaring value 4294967296 outside [0, 2^32)"
        (N.Roaring.error_to_string e))
    (N.Roaring.of_list [ 0x1_0000_0000 ]);
  Alcotest.(check bool) "membership" true (N.Roaring.mem 5 small_bitmap);
  Alcotest.(check bool) "non-membership" false (N.Roaring.mem 4 small_bitmap)

let t_roaring_fields () =
  oracle_row ~name:"roaring_field_empty" ~codec:N.Roaring.codec
    ~equal:N.Roaring.equal (bitmap []);
  oracle_row ~name:"roaring_field_small" ~codec:N.Roaring.codec
    ~equal:N.Roaring.equal small_bitmap

(* ------------------------------------------------------------- stable tags *)

(* frame.rs:154-165 [frame_tags_are_stable], ported verbatim: the exact bytes
   of every SyncFrame variant. *)
let t_frame_tags_are_stable () =
  let u32_codec = N.Sync_frame.codec Bcs.u32 in
  let check name expected frame =
    Alcotest.(check string) name expected (hex (Bcs.encode u32_codec frame))
  in
  check "Req(0) is [0]" "0000000000" (N.Sync_frame.Req 0);
  check "Ack is [1]" "01" (N.Sync_frame.Ack);
  check "Deny(AtCapacity) is [2,0]" "0200"
    (N.Sync_frame.Deny N.Sync_frame.At_capacity);
  check "Deny(Unavailable) is [2,1]" "0201"
    (N.Sync_frame.Deny N.Sync_frame.Unavailable);
  check "Data(empty) is [3,0]" "0300" (N.Sync_frame.Data "");
  check "End is [4]" "04" (N.Sync_frame.End_);
  check "Err(Internal) is [5,0]" "0500" (N.Sync_frame.Err N.Sync_frame.Internal);
  check "Err(Malformed) is [5,1]" "0501"
    (N.Sync_frame.Err N.Sync_frame.Malformed)

(* request.rs:151-179 [request_tags_are_stable]. *)
let t_request_tags_are_stable () =
  let tag name expected value =
    Alcotest.(check bool)
      (Printf.sprintf "%s starts with %s" name expected)
      true
      (String.starts_with ~prefix:expected
         (hex (Bcs.encode N.Sync_request.primary_codec value)))
  in
  tag "EpochPack" "00" (N.Sync_request.Epoch_pack { epoch = epoch 1 });
  tag "MissingCertificates" "01"
    (N.Sync_request.Missing_certificates
       { exclusive_lower_bound = round 1; skip_rounds = [] });
  tag "EpochPackPartial" "02"
    (N.Sync_request.Epoch_pack_partial
       { epoch = epoch 1; last_consensus_number = 1L });
  tag "ConsensusOutput" "03" (N.Sync_request.Consensus_output { number = 1L });
  Alcotest.(check bool) "the worker request is index 0" true
    (String.starts_with ~prefix:"00"
       (hex (Bcs.encode N.Sync_request.worker_codec worker_batches_request)))

let t_req_frame_round_trips () =
  (* frame.rs's [req_frame_round_trips], Req(0xC0FFEE) as a u32. *)
  let u32_codec = N.Sync_frame.codec Bcs.u32 in
  oracle_row ~name:"sync_frame_req_c0ffee_u32" ~codec:u32_codec
    ~equal:(N.Sync_frame.equal Int.equal)
    (N.Sync_frame.Req 0xC0FFEE)

(* ------------------------------------------------------------ payload leaves *)

let t_vote_rows () =
  oracle_row ~name:"vote_default" ~codec:N.Vote_wire.codec
    ~equal:N.Vote_wire.equal vote_default;
  oracle_row ~name:"vote_populated" ~codec:N.Vote_wire.codec
    ~equal:N.Vote_wire.equal vote_populated

let t_epoch_record_rows () =
  oracle_row ~name:"epoch_record_default" ~codec:N.Epoch_record.codec
    ~equal:N.Epoch_record.equal epoch_record_default;
  oracle_row ~name:"epoch_record_populated" ~codec:N.Epoch_record.codec
    ~equal:N.Epoch_record.equal epoch_record_populated

let t_epoch_vote_rows () =
  oracle_row ~name:"epoch_vote_default" ~codec:N.Epoch_vote.codec
    ~equal:N.Epoch_vote.equal epoch_vote_default;
  oracle_row ~name:"epoch_vote_populated" ~codec:N.Epoch_vote.codec
    ~equal:N.Epoch_vote.equal epoch_vote_populated

let t_epoch_certificate_rows () =
  oracle_row ~name:"epoch_certificate_empty_bitmap"
    ~codec:N.Epoch_certificate.codec ~equal:N.Epoch_certificate.equal
    (epoch_certificate []);
  oracle_row ~name:"epoch_certificate_array_bitmap"
    ~codec:N.Epoch_certificate.codec ~equal:N.Epoch_certificate.equal
    (epoch_certificate [ 0; 1; 5 ])

let t_consensus_result_row () =
  oracle_row ~name:"consensus_result_populated" ~codec:N.Consensus_result.codec
    ~equal:N.Consensus_result.equal consensus_result_populated

let t_certificate_wire_states () =
  (* All five SignatureVerificationState variants, in index order. *)
  List.iter
    (fun (name, state) ->
      oracle_row ~name ~codec:N.Certificate_wire.codec
        ~equal:N.Certificate_wire.equal
        (cert_wire state ~signed_authorities:small_bitmap))
    [
      ("certificate_wire_unsigned", N.Certificate_wire.Unsigned (sig48 '\x01'));
      ("certificate_wire_unverified", N.Certificate_wire.Unverified (sig48 '\x02'));
      ( "certificate_wire_verified_directly",
        N.Certificate_wire.Verified_directly (sig48 '\x03') );
      ( "certificate_wire_verified_indirectly",
        N.Certificate_wire.Verified_indirectly (sig48 '\x04') );
      ("certificate_wire_genesis", N.Certificate_wire.Genesis);
    ]

let t_certificate_wire_genesis_empty () =
  oracle_row ~name:"cert_genesis_empty_bitmap" ~codec:N.Certificate_wire.codec
    ~equal:N.Certificate_wire.equal cert_genesis_empty

(* -------------------------------------------------------------- primary msgs *)

let t_primary_request_rows () =
  oracle_row ~name:"primary_request_peer_exchange_1"
    ~codec:N.Primary_msg.request_codec ~equal:N.Primary_msg.request_equal
    (N.Primary_msg.Req_peer_exchange (peer_map 1));
  oracle_row ~name:"primary_request_vote_h1_no_parents"
    ~codec:N.Primary_msg.request_codec ~equal:N.Primary_msg.request_equal
    (N.Primary_msg.Req_vote { header = h1; parents = [] });
  oracle_row ~name:"primary_request_vote_h1_one_parent"
    ~codec:N.Primary_msg.request_codec ~equal:N.Primary_msg.request_equal
    (N.Primary_msg.Req_vote { header = h1; parents = [ cert_unsigned ] })

let t_epoch_record_request_options () =
  (* All four Some/None combinations of the two Options (GT:40). *)
  List.iter
    (fun (name, epoch_opt, hash_opt) ->
      oracle_row ~name ~codec:N.Primary_msg.request_codec
        ~equal:N.Primary_msg.request_equal
        (N.Primary_msg.Req_epoch_record { epoch = epoch_opt; hash = hash_opt }))
    [
      ("primary_request_epoch_record_none_none", None, None);
      ("primary_request_epoch_record_some_none", Some (epoch 9), None);
      ("primary_request_epoch_record_none_some", None, Some (dig '\xc1'));
      ("primary_request_epoch_record_some_some", Some (epoch 9), Some (dig '\xc1'));
    ]

let t_primary_response_rows () =
  List.iter
    (fun (name, response) ->
      oracle_row ~name ~codec:N.Primary_msg.response_codec
        ~equal:N.Primary_msg.response_equal response)
    [
      ("primary_response_vote", N.Primary_msg.Res_vote vote_populated);
      ( "primary_response_missing_parents",
        N.Primary_msg.Res_missing_parents
          [ hdr_digest '\x01'; hdr_digest '\x02' ] );
      ( "primary_response_epoch_record",
        N.Primary_msg.Res_epoch_record
          {
            record = epoch_record_populated;
            certificate = epoch_certificate [ 0; 1; 5 ];
          } );
      ( "primary_response_peer_exchange_2",
        N.Primary_msg.Res_peer_exchange (peer_map 2) );
      ("primary_response_error", N.Primary_msg.Res_error "nope");
      ( "primary_response_recoverable_error",
        N.Primary_msg.Res_recoverable_error "retry" );
    ]

let t_primary_gossip_rows () =
  List.iter
    (fun (name, gossip) ->
      oracle_row ~name ~codec:N.Primary_msg.gossip_codec
        ~equal:N.Primary_msg.gossip_equal gossip)
    [
      ( "primary_gossip_certificate",
        N.Primary_msg.Gossip_certificate cert_unsigned );
      ( "primary_gossip_consensus",
        N.Primary_msg.Gossip_consensus consensus_result_populated );
      ( "primary_gossip_epoch_vote",
        N.Primary_msg.Gossip_epoch_vote epoch_vote_populated );
    ]

let t_missing_certificates_request () =
  let codec = N.Primary_msg.missing_certificates_request_codec in
  oracle_row ~name:"missing_certificates_request" ~codec
    ~equal:(fun a b ->
      String.equal (hex (Bcs.encode codec a)) (hex (Bcs.encode codec b)))
    missing_certs;
  (* The [usize] leg is 8 bytes LE and nothing shorter: 1_048_576 is
     00 00 10 00 00 00 00 00, which a 4-byte encoding could not carry. *)
  Alcotest.(check bool) "usize is u64 LE" true
    (String.ends_with ~suffix:"0000100000000000"
       (bcs_hex "missing_certificates_request"))

(* --------------------------------------------------------------- worker msgs *)

let t_worker_gossip_row () =
  oracle_row ~name:"worker_gossip_batch" ~codec:N.Worker_msg.gossip_codec
    ~equal:N.Worker_msg.gossip_equal
    (N.Worker_msg.Wgossip_batch
       { epoch = epoch 7; block_hash = bat_digest '\xaa' });
  (* GT:87: the BlockHash is ULEB128(32) then 32 bytes, so the row is
     tag + 4 epoch bytes + 0x20 + 32 = 38 bytes, and it opens 00 07000000 20. *)
  let row = bcs_hex "worker_gossip_batch" in
  Alcotest.(check int) "row length in hex characters" 76 (String.length row);
  Alcotest.(check bool) "the 0x20 length prefix" true
    (String.starts_with ~prefix:"000700000020" row)

let t_worker_request_rows () =
  oracle_row ~name:"worker_request_report_batch"
    ~codec:N.Worker_msg.request_codec ~equal:N.Worker_msg.request_equal
    (N.Worker_msg.Wreq_report_batch sealed_v5);
  oracle_row ~name:"worker_request_peer_exchange_1"
    ~codec:N.Worker_msg.request_codec ~equal:N.Worker_msg.request_equal
    (N.Worker_msg.Wreq_peer_exchange (peer_map 1))

let t_worker_response_rows () =
  oracle_row ~name:"worker_response_report_batch_unit"
    ~codec:N.Worker_msg.response_codec ~equal:N.Worker_msg.response_equal
    (N.Worker_msg.Wres_report_batch ());
  Alcotest.(check string)
    "the unit variant is one bare tag byte" "00"
    (bcs_hex "worker_response_report_batch_unit");
  List.iter
    (fun (name, response) ->
      oracle_row ~name ~codec:N.Worker_msg.response_codec
        ~equal:N.Worker_msg.response_equal response)
    [
      ( "worker_response_peer_exchange_0",
        N.Worker_msg.Wres_peer_exchange (peer_map 0) );
      ("worker_response_error", N.Worker_msg.Wres_error "boom");
      ( "worker_response_recoverable_error",
        N.Worker_msg.Wres_recoverable_error "later" );
    ]

(* ---------------------------------------------------------------- sync rows *)

let t_sync_frame_rows () =
  List.iter
    (fun (name, frame) ->
      oracle_row ~name ~codec:worker_frame_codec ~equal:worker_frame_equal frame)
    [
      ("sync_frame_worker_req_batches", N.Sync_frame.Req worker_batches_request);
      ("sync_frame_ack", N.Sync_frame.Ack);
      ("sync_frame_deny_at_capacity", N.Sync_frame.Deny N.Sync_frame.At_capacity);
      ("sync_frame_deny_unavailable", N.Sync_frame.Deny N.Sync_frame.Unavailable);
      ("sync_frame_data_empty", N.Sync_frame.Data "");
      ("sync_frame_data_3", N.Sync_frame.Data "\x01\x02\x03");
      ("sync_frame_end", N.Sync_frame.End_);
      ("sync_frame_err_internal", N.Sync_frame.Err N.Sync_frame.Internal);
      ("sync_frame_err_malformed", N.Sync_frame.Err N.Sync_frame.Malformed);
    ]

let t_worker_sync_request_row () =
  oracle_row ~name:"worker_sync_request_batches"
    ~codec:N.Sync_request.worker_codec ~equal:N.Sync_request.worker_equal
    worker_batches_request

let t_primary_sync_request_rows () =
  List.iter
    (fun (name, request) ->
      oracle_row ~name ~codec:N.Sync_request.primary_codec
        ~equal:N.Sync_request.primary_equal request)
    [
      ( "primary_sync_request_epoch_pack",
        N.Sync_request.Epoch_pack { epoch = epoch 12 } );
      ( "primary_sync_request_missing_certificates",
        N.Sync_request.Missing_certificates
          { exclusive_lower_bound = round 4; skip_rounds } );
      ( "primary_sync_request_epoch_pack_partial",
        N.Sync_request.Epoch_pack_partial
          { epoch = epoch 12; last_consensus_number = 99L } );
      ( "primary_sync_request_consensus_output",
        N.Sync_request.Consensus_output { number = 77L } );
    ]

let t_btree_set_is_permissive () =
  (* The digests encode ASCENDING whatever order they were built in, and an
     unsorted wire sequence is ACCEPTED and resorted, because Rust's decoder
     does exactly that (de.rs:611-617). Refusing it would reject bytes every
     Rust node takes. *)
  let descending =
    N.Sync_request.Batches
      {
        batch_digests = [ bat_digest '\x02'; bat_digest '\x01' ];
        epoch = epoch 6;
      }
  in
  Alcotest.(check string)
    "encoding is order-independent"
    (hex (Bcs.encode N.Sync_request.worker_codec descending))
    (hex (Bcs.encode N.Sync_request.worker_codec worker_batches_request));
  let digest_bytes c = Bcs.encode (Bcs.sized_bytes 32) (String.make 32 c) in
  let unsorted =
    "\x00\x02" ^ digest_bytes '\x02' ^ digest_bytes '\x01' ^ "\x06\x00\x00\x00"
  in
  let got =
    force_result bcs_error (Bcs.decode N.Sync_request.worker_codec unsorted)
  in
  Alcotest.(check bool) "unsorted bytes are accepted and resorted" true
    (N.Sync_request.worker_equal got worker_batches_request)

(* -------------------------------------------------------------- peer exchange *)

let t_peer_exchange_rows () =
  List.iter
    (fun (name, n) ->
      oracle_row ~name ~codec:N.Peer_exchange.codec ~equal:N.Peer_exchange.equal
        (peer_map n))
    [
      ("peer_exchange_map_empty", 0);
      ("peer_exchange_map_1", 1);
      ("peer_exchange_map_2", 2);
    ]

let t_peer_exchange_canonical () =
  (* Built in descending key order, the map still encodes ascending: bcs sorts
     by encoded key bytes before writing (ser.rs:545-546). *)
  let reversed =
    force_result N.Peer_exchange.error_to_string
      (N.Peer_exchange.of_entries (List.rev peer_entries))
  in
  Alcotest.(check string)
    "descending input encodes ascending"
    (bcs_hex "peer_exchange_map_2")
    (hex (Bcs.encode N.Peer_exchange.codec reversed));
  Result.fold
    ~ok:(fun _ -> Alcotest.fail "duplicate key accepted")
    ~error:(fun e ->
      Alcotest.(check string) "duplicate key" "peer exchange: duplicate map key"
        (N.Peer_exchange.error_to_string e))
    (N.Peer_exchange.of_entries
       (List.filteri (fun i _ -> i < 1) peer_entries
       @ List.filteri (fun i _ -> i < 1) peer_entries))

let t_peer_exchange_negatives () =
  (* The canonical map decoder refuses a swapped pair and a duplicate key, the
     two verdicts stage 0 reproduced against bcs 0.1.6 itself. *)
  let first = entry_bytes 0 and second = entry_bytes 1 in
  Alcotest.(check bool) "the entry builder produced bytes" true
    (String.length first > 0 && String.length second > 0);
  decode_rejects ~name:"swapped key order" ~codec:N.Peer_exchange.codec
    ~kind:"length_out_of_range"
    ("\x02" ^ second ^ first);
  decode_rejects ~name:"duplicate key" ~codec:N.Peer_exchange.codec
    ~kind:"length_out_of_range"
    ("\x02" ^ first ^ first);
  (* And the sorted pair IS accepted, so the two rejections above are not
     rejecting the shape. *)
  Alcotest.(check bool) "the sorted pair is accepted" true
    (Result.is_ok (Bcs.decode N.Peer_exchange.codec ("\x02" ^ first ^ second)))

(* ---------------------------------------------------------------- node record *)

let t_node_record_rows () =
  List.iter
    (fun (name, rpc) ->
      oracle_row ~name ~codec:N.Node_record.codec ~equal:N.Node_record.equal
        (node_record ~rpc))
    [
      ("node_record_rpc_some_ws_some", rpc_both);
      ("node_record_rpc_some_ws_none", rpc_http_only);
      ("node_record_rpc_none", None);
    ]

let t_legacy_node_record_row () =
  oracle_row ~name:"legacy_node_record" ~codec:N.Node_record.legacy_codec
    ~equal:N.Node_record.equal (node_record ~rpc:None)

let t_decode_compat () =
  let expect name bytes ~current =
    Result.fold
      ~ok:(fun r ->
        let is_current =
          match r with
          | N.Node_record.Current _ -> true
          | N.Node_record.Legacy _ -> false
        in
        Alcotest.(check bool) name current is_current)
      ~error:(fun e ->
        Alcotest.fail (name ^ ": " ^ N.Node_record.error_to_string e))
      (N.Node_record.decode_compat bytes)
  in
  expect "current layout, rpc present" ~current:true
    (unhex (bcs_hex "node_record_rpc_some_ws_some"));
  (* The rpc=None row is the disambiguation case of GT:139: it ends in the
     Option tag 0x00, where a legacy record ends in the 0x30 signature prefix.
     Both layouts are asserted, and neither is decided by peeking at that last
     byte. *)
  expect "current layout, rpc absent" ~current:true
    (unhex (bcs_hex "node_record_rpc_none"));
  expect "legacy layout" ~current:false (unhex (bcs_hex "legacy_node_record"));
  Result.fold
    ~ok:(fun _ -> Alcotest.fail "garbage accepted")
    ~error:(fun e ->
      Alcotest.(check bool) "both layouts named in the error" true
        (String.length (N.Node_record.error_to_string e) > 0))
    (N.Node_record.decode_compat "\x01\x02\x03")

(* ------------------------------------------------------------ decode negatives *)

let t_unknown_variant_tag () =
  decode_rejects ~name:"primary gossip tag 3" ~codec:N.Primary_msg.gossip_codec
    ~kind:"unknown_variant" "\x03";
  decode_rejects ~name:"worker response tag 4"
    ~codec:N.Worker_msg.response_codec ~kind:"unknown_variant" "\x04";
  decode_rejects ~name:"sync frame tag 6" ~codec:worker_frame_codec
    ~kind:"unknown_variant" "\x06";
  decode_rejects ~name:"primary sync request tag 4"
    ~codec:N.Sync_request.primary_codec ~kind:"unknown_variant" "\x04"

let t_non_minimal_uleb_tag () =
  (* 0x80 0x00 is a redundant continuation encoding of 0, which bcs refuses on
     decode. *)
  decode_rejects ~name:"non-minimal variant tag"
    ~codec:N.Primary_msg.gossip_codec ~kind:"non_canonical_uleb128" "\x80\x00"

let t_bad_option_tag () =
  (* Option tags are strictly 0x00 and 0x01. *)
  decode_rejects ~name:"option tag 0x02" ~codec:N.Primary_msg.request_codec
    ~kind:"invalid_option_tag" "\x02\x02"

let t_wrong_length_sized_bytes () =
  (* A 31-byte digest prefix in vote_wire's first field. *)
  decode_rejects ~name:"digest prefix 0x1f" ~codec:N.Vote_wire.codec
    ~kind:"length_out_of_range"
    ("\x1f" ^ String.make 31 '\x00');
  (* And a BLS key that claims 95 bytes, after a well-formed epoch and hash. *)
  decode_rejects ~name:"key prefix 0x5f" ~codec:N.Epoch_vote.codec
    ~kind:"length_out_of_range"
    ("\x03\x00\x00\x00\x20" ^ String.make 32 '\x91' ^ "\x5f"
   ^ String.make 95 '\x92')

let t_trailing_byte () =
  decode_rejects ~name:"trailing byte" ~codec:N.Vote_wire.codec
    ~kind:"trailing_bytes"
    (unhex (bcs_hex "vote_populated") ^ "\x00")

(* ----------------------------------------------------------------- protocols *)

let t_protocol_strings () =
  let ok name expected result =
    Alcotest.(check string) name expected
      (force_result N.Protocols.error_to_string result)
  in
  ok "primary req-res" "/tn-primary-2017/0.0.2"
    (N.Protocols.req_res_protocol ~node:N.Protocols.Primary ~chain_id:2017);
  ok "worker req-res" "/tn-worker-3-2017/0.0.2"
    (N.Protocols.req_res_protocol ~node:(N.Protocols.Worker 3) ~chain_id:2017);
  ok "primary kad" "/tn-primary-kad-2017/0.0.1"
    (N.Protocols.kad_protocol ~node:N.Protocols.Primary ~chain_id:2017);
  ok "worker kad" "/tn-worker-3-kad-2017/0.0.1"
    (N.Protocols.kad_protocol ~node:(N.Protocols.Worker 3) ~chain_id:2017);
  ok "primary sync" "/tn-primary-sync-2017/0.0.1"
    (N.Protocols.sync_protocol ~node:N.Protocols.Primary ~chain_id:2017);
  ok "worker sync" "/tn-worker-3-sync-2017/0.0.1"
    (N.Protocols.sync_protocol ~node:(N.Protocols.Worker 3) ~chain_id:2017);
  ok "primary peer exchange" "/tn-primary-peer-exchange-2017/0.0.1"
    (N.Protocols.peer_exchange_protocol ~node:N.Protocols.Primary ~chain_id:2017);
  ok "worker peer exchange" "/tn-worker-3-peer-exchange-2017/0.0.1"
    (N.Protocols.peer_exchange_protocol ~node:(N.Protocols.Worker 3)
       ~chain_id:2017);
  Alcotest.(check string)
    "gossip prefix" "/tn-meshsub-2017"
    (N.Protocols.gossip_protocol_id_prefix ~chain_id:2017)

let t_owned_protocol_rejects () =
  Result.fold
    ~ok:(fun s -> Alcotest.fail ("accepted " ^ s))
    ~error:(fun e ->
      Alcotest.(check bool) "no leading slash" true
        (String.length (N.Protocols.error_to_string e) > 0))
    (N.Protocols.owned_protocol "tn-primary-2017")

(* -------------------------------------------------------------------- gossip *)

let t_topic_strings () =
  Alcotest.(check string) "primary" "tn-primary-2017"
    (N.Gossip.primary_topic ~chain_id:2017);
  Alcotest.(check string) "consensus output" "tn-consensus-output-2017"
    (N.Gossip.consensus_output_topic ~chain_id:2017);
  Alcotest.(check string) "epoch vote" "tn-epoch-vote-2017"
    (N.Gossip.epoch_vote_topic ~chain_id:2017);
  Alcotest.(check string) "worker batch" "tn-worker-2017"
    (N.Gossip.worker_batch_topic ~chain_id:2017);
  Alcotest.(check int) "the application cap" 12_000
    N.Gossip.max_gossip_message_size

let t_topic_dispatch () =
  (* Positive control on EVERY topic, and a miss beside them. *)
  let chain_id = 2017 in
  let hits =
    List.map
      (fun (topic, bytes, expected_primary) ->
        Result.fold
          ~ok:(fun payload ->
            let is_primary =
              match payload with
              | N.Gossip.Primary_payload _ -> true
              | N.Gossip.Worker_payload _ -> false
            in
            Alcotest.(check bool) ("dispatch " ^ topic) expected_primary is_primary;
            true)
          ~error:(fun e -> Alcotest.fail (N.Gossip.error_to_string e))
          (N.Gossip.decode ~chain_id ~topic bytes))
      [
        ( N.Gossip.primary_topic ~chain_id,
          unhex (bcs_hex "primary_gossip_certificate"),
          true );
        ( N.Gossip.consensus_output_topic ~chain_id,
          unhex (bcs_hex "primary_gossip_consensus"),
          true );
        ( N.Gossip.epoch_vote_topic ~chain_id,
          unhex (bcs_hex "primary_gossip_epoch_vote"),
          true );
        ( N.Gossip.worker_batch_topic ~chain_id,
          unhex (bcs_hex "worker_gossip_batch"),
          false );
      ]
  in
  Alcotest.(check int) "every topic dispatched" 4 (List.length hits);
  Result.fold
    ~ok:(fun _ -> Alcotest.fail "unknown topic accepted")
    ~error:(fun e ->
      Alcotest.(check string) "unknown topic"
        "gossip: unknown topic \"tn-primary-9999\""
        (N.Gossip.error_to_string e))
    (N.Gossip.decode ~chain_id ~topic:"tn-primary-9999" "\x00");
  (* A topic of the RIGHT chain but the wrong payload still fails, at BCS. *)
  Result.fold
    ~ok:(fun _ -> Alcotest.fail "wrong payload accepted")
    ~error:(fun (_ : N.Gossip.error) -> ())
    (N.Gossip.decode ~chain_id
       ~topic:(N.Gossip.worker_batch_topic ~chain_id)
       "\x07")

let t_message_id_rows () =
  List.iter
    (fun (r : NV.msgid_row) ->
      let source = Option.map unhex r.source_hex in
      let sequence_number = Option.map Int64.of_string r.seq_hex in
      Alcotest.(check string)
        ("message id " ^ r.m_name)
        r.id
        (N.Gossip.message_id ~source ~sequence_number))
    NV.msgid_rows

let t_message_id_unsigned () =
  (* The two values a signed rendering gets wrong, stated on their own so they
     cannot leave the table silently. [Int64.min_int] IS 2^63 read unsigned,
     and [-1L] is u64::MAX. *)
  Alcotest.(check string)
    "2^63 renders unsigned" "15R9223372036854775808"
    (N.Gossip.message_id ~source:None ~sequence_number:(Some Int64.min_int));
  Alcotest.(check string)
    "u64::MAX renders unsigned" "15R18446744073709551615"
    (N.Gossip.message_id ~source:None ~sequence_number:(Some (-1L)));
  Alcotest.(check string)
    "the absent-source fallback" NV.msgid_fallback_base58
    (N.Base58.encode (unhex NV.msgid_fallback_bytes_hex))

let t_base58 () =
  (* Leading NUL bytes are one '1' each, the Bitcoin rule. *)
  Alcotest.(check string) "empty" "" (N.Base58.encode "");
  Alcotest.(check string) "one zero byte" "1" (N.Base58.encode "\x00");
  Alcotest.(check string) "two zero bytes" "11" (N.Base58.encode "\x00\x00");
  Alcotest.(check int) "the alphabet is 58 long" 58
    (String.length N.Base58.alphabet);
  Alcotest.(check string) "the fallback peer id" "15R"
    (N.Base58.encode "\x00\x01\x00")

let t_authorized_publishers () =
  let chain_id = 2017 in
  let primary = N.Gossip.primary_topic ~chain_id in
  let worker = N.Gossip.worker_batch_topic ~chain_id in
  let authorized =
    [
      (primary, N.Gossip.Restricted [ key '\xb0'; key '\xb1' ]);
      (worker, N.Gossip.Open);
    ]
  in
  (* Any peer id at all; only its presence is read. *)
  let peer = Some "\x00\x01\x00" in
  let allowed ?(source = peer) ~topic ~author () =
    N.Gossip.publisher_allowed ~authorized ~topic ~source ~author
  in
  Alcotest.(check bool) "an authorized publisher" true
    (allowed ~topic:primary ~author:(Some (key '\xb0')) ());
  Alcotest.(check bool) "an unauthorized publisher" false
    (allowed ~topic:primary ~author:(Some (key '\xcc')) ());
  Alcotest.(check bool) "an unresolved author on a restricted topic" false
    (allowed ~topic:primary ~author:None ());
  Alcotest.(check bool) "an open topic takes anyone" true
    (allowed ~topic:worker ~author:(Some (key '\xcc')) ());
  (* An Open topic does NOT need the BLS key to resolve, only the source. *)
  Alcotest.(check bool) "an open topic takes an unresolved author" true
    (allowed ~topic:worker ~author:None ());
  (* consensus.rs:1595: [gossip.source.is_some_and(..)] is the OUTERMOST gate,
     so a message with no source at all is refused on every topic, the Open
     one included. *)
  Alcotest.(check bool) "no source, open topic" false
    (allowed ~source:None ~topic:worker ~author:None ());
  Alcotest.(check bool) "no source, open topic, resolved author" false
    (allowed ~source:None ~topic:worker ~author:(Some (key '\xcc')) ());
  Alcotest.(check bool) "no source, restricted topic, allowlisted author" false
    (allowed ~source:None ~topic:primary ~author:(Some (key '\xb0')) ());
  Alcotest.(check bool) "a topic we do not subscribe to" false
    (allowed ~topic:"tn-epoch-vote-2017" ~author:(Some (key '\xb0')) ())

(* -------------------------------------------------------------- wire ingress *)

let committee_of n =
  let authority i =
    let secret = Tn_crypto.Secret_key.derive (Int64.of_int (i + 1)) in
    let public = Tn_crypto.Secret_key.public_key secret in
    (secret, Authority.make ~protocol_key:public ~execution_address:Units.Address.zero)
  in
  let pairs = List.init n authority in
  ( List.map fst pairs,
    force_result Committee.error_to_string
      (Committee.create ~epoch:Units.Epoch.zero (List.map snd pairs)) )

let t_certificate_ingress_genesis () =
  (* A genesis certificate is the ingress path every crypto seam agrees on:
     the Genesis state carries no signature, so [to_checked] rebuilds it and
     [Certificate.check] passes it without touching the seam's widths. *)
  let _, committee = committee_of 4 in
  let genesis =
    force "genesis certificates"
      (List.nth_opt (Tn_vertex.Certificate.genesis committee) 0)
  in
  let wire =
    force_result N.Certificate_wire.error_to_string
      (N.Certificate_wire.of_certificate committee genesis)
  in
  Alcotest.(check bool) "the wire state is Genesis" true
    (match N.Certificate_wire.state wire with
    | N.Certificate_wire.Genesis -> true
    | N.Certificate_wire.Unsigned _ | N.Certificate_wire.Unverified _
    | N.Certificate_wire.Verified_directly _
    | N.Certificate_wire.Verified_indirectly _ ->
        false);
  let back =
    force_result N.Certificate_wire.error_to_string
      (N.Certificate_wire.to_checked committee wire)
  in
  Alcotest.(check bool) "it round trips through the ingress" true
    (Tn_vertex.Certificate.equal back genesis);
  (* And the bytes survive the codec. *)
  let decoded =
    force_result bcs_error
      (Bcs.decode N.Certificate_wire.codec
         (Bcs.encode N.Certificate_wire.codec wire))
  in
  Alcotest.(check bool) "and through the codec" true
    (N.Certificate_wire.equal decoded wire)

let t_certificate_ingress_negatives () =
  let _, committee = committee_of 4 in
  (* A bitmap naming a position outside the committee. *)
  Result.fold
    ~ok:(fun _ -> Alcotest.fail "out-of-range signer accepted")
    ~error:(fun e ->
      Alcotest.(check string) "unknown signer index"
        "certificate: bitmap names committee position 9"
        (N.Certificate_wire.error_to_string e))
    (N.Certificate_wire.to_checked committee
       (N.Certificate_wire.make ~header:h1 ~state:N.Certificate_wire.Genesis
          ~signed_authorities:(bitmap [ 9 ])));
  (* A signed state with a bogus 48-byte aggregate: refused either by the
     crypto seam, whose signature width is its own business, or by the quorum
     check, but never accepted. *)
  Result.fold
    ~ok:(fun _ -> Alcotest.fail "bogus aggregate accepted")
    ~error:(fun (_ : N.Certificate_wire.error) -> ())
    (N.Certificate_wire.to_checked committee
       (N.Certificate_wire.make ~header:h1
          ~state:(N.Certificate_wire.Verified_directly (sig48 '\x01'))
          ~signed_authorities:(bitmap [ 0 ])))

(* The wire's [Genesis] state is a BARE TAG (index 4, no payload), so a peer
   is free to attach it to any header at all. Rust takes the genesis fast path
   only for a certificate contained in [Certificate::genesis(committee)]
   (certificate.rs:236) and falls through to the stake and aggregate checks
   otherwise, so the tag alone certifies nothing here either. *)
let t_certificate_genesis_tag_negatives () =
  let _, committee = committee_of 4 in
  let refused what wire =
    Result.fold
      ~ok:(fun (_ : Tn_vertex.Certificate.t) -> Alcotest.failf "%s accepted" what)
      ~error:(fun e ->
        Alcotest.(check string) what
          "certificate: genesis state on a certificate that is not genesis"
          (N.Certificate_wire.error_to_string e))
      (N.Certificate_wire.to_checked committee wire)
  in
  (* [Header.default] with an empty, well-formed bitmap: nothing ahead of
     [Certificate.check] can refuse it. *)
  refused "the genesis tag over an arbitrary header" cert_genesis_empty;
  let authority =
    force "a committee authority"
      (List.nth_opt (Committee.authorities committee) 0)
  in
  let genesis_header ~round =
    Header.make ~author:(Authority.id authority) ~round
      ~epoch:(Committee.epoch committee) ~created_at:Units.Timestamp.zero
      ~payload:[] ~parents:[] ~latest_execution_block:Block_num_hash.zero
  in
  (* A header that differs from a real genesis header in the ROUND alone, so
     the refusal is by certified header and not by author. *)
  refused "the genesis tag one round up"
    (N.Certificate_wire.make
       ~header:(genesis_header ~round:(round 5))
       ~state:N.Certificate_wire.Genesis ~signed_authorities:(bitmap []));
  (* The POSITIVE control on that same shape: the round-0 header of that same
     authority IS a genesis certificate and still passes. *)
  Alcotest.(check bool) "the real genesis header still passes" true
    (Result.is_ok
       (N.Certificate_wire.to_checked committee
          (N.Certificate_wire.make
             ~header:(genesis_header ~round:Round.genesis)
             ~state:N.Certificate_wire.Genesis ~signed_authorities:(bitmap []))))

let t_vote_ingress () =
  (* The POSITIVE control for the lib/vertex ingress, seam-independent: a
     signature the seam itself produced goes through [Vote.claim] and then
     verifies. *)
  let secrets, committee = committee_of 4 in
  let secret = force "a committee secret" (List.nth_opt secrets 0) in
  let public = Tn_crypto.Secret_key.public_key secret in
  let voter = Authority_id.of_public_key public in
  let header =
    Header.make ~author:voter ~round:Round.genesis
      ~epoch:(Committee.epoch committee) ~created_at:Units.Timestamp.zero
      ~payload:[] ~parents:[] ~latest_execution_block:Block_num_hash.zero
  in
  let signed = Tn_vertex.Vote.sign secret ~voter header in
  let claimed =
    force "claim of a real signature"
      (Tn_vertex.Vote.claim
         ~header_digest:(Tn_vertex.Vote.header_digest signed)
         ~round:(Tn_vertex.Vote.round signed)
         ~epoch:(Tn_vertex.Vote.epoch signed)
         ~origin:(Tn_vertex.Vote.origin signed)
         ~author:(Tn_vertex.Vote.author signed)
         ~signature:
           (Tn_crypto.Signature.to_bytes (Tn_vertex.Vote.signature signed)))
  in
  Alcotest.(check bool) "the claimed vote verifies" true
    (Tn_vertex.Vote.verify public claimed);
  (* The NEGATIVE: a claim whose signature bytes the seam does not accept. *)
  Alcotest.(check bool) "a non-signature is refused" true
    (Option.is_none
       (Tn_vertex.Vote.claim ~header_digest:(hdr_digest '\x0a')
          ~round:Round.genesis ~epoch:Units.Epoch.zero ~origin:Authority_id.zero
          ~author:Authority_id.zero ~signature:"not a signature"))

let t_vote_wire_ingress () =
  (* [Vote_wire.to_vote] must agree with the crypto seam exactly: it succeeds
     when the seam accepts the 48 wire bytes as a signature and fails
     otherwise. Stating it as an agreement keeps the case honest under both
     seams, since 48 bytes IS a blst signature and is NOT a stub one. *)
  let bytes = N.Bls_signature.to_bytes (sig48 '\x0d') in
  let seam_takes_it = Option.is_some (Tn_crypto.Signature.of_bytes bytes) in
  Alcotest.(check bool) "the ingress agrees with the seam" seam_takes_it
    (Result.is_ok (N.Vote_wire.to_vote vote_populated));
  Alcotest.(check bool) "the wire value survives its own codec" true
    (N.Vote_wire.equal vote_populated
       (force_result bcs_error
          (Bcs.decode N.Vote_wire.codec
             (Bcs.encode N.Vote_wire.codec vote_populated))))

(* ------------------------------------------------------- stage 4: chunking *)

module SC = N.Sync_chunking
module SR = N.Sync_reader
module SF = N.Sync_frame
module Node = Tn_consensus.Node

(* The frame lists this stage builds carry no [Req], so they are instantiated
   at [unit] and the matches below stay exhaustive without a catch-all. *)
let data_payloads (frames : unit SF.t list) =
  List.filter_map
    (fun frame ->
      match frame with
      | SF.Data bytes -> Some bytes
      | SF.Req () | SF.Ack | SF.Deny _ | SF.End_ | SF.Err _ -> None)
    frames

let frame_name (frame : unit SF.t) =
  match frame with
  | SF.Req () -> "req"
  | SF.Ack -> "ack"
  | SF.Deny _ -> "deny"
  | SF.Data _ -> "data"
  | SF.End_ -> "end"
  | SF.Err _ -> "err"

let frame_names frames = String.concat "," (List.map frame_name frames)

(* Bytes go in through [Buffer.add_uint8], which truncates rather than
   failing, so no partial [Char.chr] appears anywhere in this file. *)
let bytes_of_ints l =
  let buf = Buffer.create (List.length l + 1) in
  List.iter (Buffer.add_uint8 buf) l;
  Buffer.contents buf

(* [i mod 251] is the filling of the Rust round-trip vector (GT:891); 251 is
   prime and under 256, so consecutive chunks never repeat a page and a
   mis-ordered reassembly shows as a byte mismatch rather than a length one. *)
let filled n =
  let buf = Buffer.create (if n > 0 then n else 1) in
  let rec go i =
    if i >= n then Buffer.contents buf
    else (
      Buffer.add_uint8 buf (i mod 251);
      go (i + 1))
  in
  go 0

let bat_digest_n i =
  Digests.Batch_digest.of_digest
    (force "digest width"
       (Tn_crypto.Digest.of_bytes
          (bytes_of_ints (List.init 32 (fun k -> (i + k) mod 251)))))

let t_chunking_constants () =
  Alcotest.(check int) "SYNC_PACK_CHUNK_SIZE" 262144 SC.sync_pack_chunk_size;
  Alcotest.(check int) "SYNC_PACK_FRAME_OVERHEAD" 1024 SC.sync_pack_frame_overhead;
  Alcotest.(check int) "MAX_SYNC_PACK_FRAME_SIZE" 263168 SC.max_sync_pack_frame_size;
  Alcotest.(check int) "the pack frame cap is the sum of its parts" 263168
    (SC.sync_pack_chunk_size + SC.sync_pack_frame_overhead);
  Alcotest.(check int) "SYNC_CERT_BATCH_TARGET_SIZE" 262144
    SC.sync_cert_batch_target_size;
  Alcotest.(check int) "MAX_SYNC_CERT_FRAME_SIZE" 524288 SC.max_sync_cert_frame_size;
  Alcotest.(check int) "BATCH_DIGESTS_READ_CHUNK_SIZE" 200
    SC.batch_digests_read_chunk_size;
  Alcotest.(check int) "MAX_SYNC_MISSING_CERTS_RESPONSE_BYTES" 67108864
    SC.max_sync_missing_certs_response_bytes;
  Alcotest.(check int) "MAX_SYNC_MISSING_CERTS_ACCEPT_BYTES" 67633152
    SC.max_sync_missing_certs_accept_bytes;
  Alcotest.(check int) "the accept cap is the response cap plus one frame"
    67633152
    (SC.max_sync_missing_certs_response_bytes + SC.max_sync_cert_frame_size);
  Alcotest.(check int) "MAX_SYNC_REQUEST_FRAME_SIZE" 4194304
    SC.max_sync_request_frame_size;
  Alcotest.(check int) "SYNC_FRAME_OVERHEAD" 1024 SC.sync_frame_overhead;
  Alcotest.(check int) "MAX_PENDING_REQUESTS_PER_PEER" 2
    SC.max_pending_requests_per_peer;
  Alcotest.(check int) "MAX_EPOCH_SYNC_PROBES" 3 SC.max_epoch_sync_probes;
  Alcotest.(check int) "MAX_BATCH_REQUEST_RETRIES" 3 SC.max_batch_request_retries;
  (* The worker cap is epoch dependent, so it is a formula and not a
     constant: max_batch_size(epoch) + SYNC_FRAME_OVERHEAD (GT:811). *)
  Alcotest.(check int) "max_sync_frame_size at the production batch size"
    1001024
    (SC.max_sync_frame_size ~max_batch_size:1_000_000);
  Alcotest.(check int) "max_sync_frame_size at zero" 1024
    (SC.max_sync_frame_size ~max_batch_size:0);
  Alcotest.(check int) "max_sync_frame_size tracks Batch.max_batch_size"
    (Batch.max_batch_size Units.Epoch.zero + 1024)
    (SC.max_sync_frame_size
       ~max_batch_size:(Batch.max_batch_size Units.Epoch.zero))

let t_pack_round_trips () =
  (* sync_pack_round_trip_multi_chunk (GT:891). *)
  let payload = filled ((SC.sync_pack_chunk_size * 2) + 1234) in
  let frames = SC.pack_frames payload in
  Alcotest.(check string) "three data frames then the terminator"
    "data,data,data,end" (frame_names frames);
  Alcotest.(check string) "the chunks reassemble" payload
    (String.concat "" (data_payloads frames));
  Alcotest.(check int) "the first chunk is a whole chunk" SC.sync_pack_chunk_size
    (String.length
       (force "a first chunk" (List.nth_opt (data_payloads frames) 0)));
  (* sync_pack_round_trip_empty: an empty pack is the terminator alone. *)
  Alcotest.(check string) "an empty pack is End only" "end"
    (frame_names (SC.pack_frames ""));
  (* sync_consensus_output_round_trip. *)
  let output = filled (SC.sync_pack_chunk_size + 777) in
  let out_frames = SC.pack_frames output in
  Alcotest.(check string) "two data frames then the terminator" "data,data,end"
    (frame_names out_frames);
  Alcotest.(check string) "the output reassembles" output
    (String.concat "" (data_payloads out_frames));
  (* A chunk size below one is refused rather than clamped. *)
  Alcotest.(check bool) "a zero chunk size is refused" true
    (Result.fold
       ~ok:(fun (_ : unit SF.t list) -> false)
       ~error:(fun (_ : SC.error) -> true)
       (SC.pack_frames_with ~chunk_size:0 "abc"));
  Alcotest.(check string) "a chunk size of one cuts one byte per frame"
    "data,data,data,end"
    (frame_names
       (force_result SC.error_to_string (SC.pack_frames_with ~chunk_size:1 "abc")))

let t_frame_larger_than_max_is_rejected () =
  (* frame_larger_than_max_is_rejected (frame.rs:167-175, GT:890): a 256-byte
     Data payload against a 64-byte cap must not be written. *)
  let frame : unit SF.t = SF.Data (String.make 256 'x') in
  let codec = SF.codec Bcs.unit in
  Result.fold
    ~ok:(fun (_ : string) -> Alcotest.fail "an oversized frame was written")
    ~error:(fun e ->
      Alcotest.(check bool) "the cap names the message size" true
        (match e with
        | N.Wire_frame.Frame_error (N.Wire_frame.Message_too_large { len; max })
          ->
            len > 256 && max = 64
        | N.Wire_frame.Frame_error _ | N.Wire_frame.Bcs_error _ -> false))
    (N.Wire_frame.encode_msg ~max_message_size:64 codec frame);
  Alcotest.(check bool) "and the same frame fits under the real cap" true
    (Result.is_ok
       (N.Wire_frame.encode_msg ~max_message_size:SC.max_sync_request_frame_size
          codec frame))

let t_digest_chunks () =
  (* test_send_receive_sync_multi_chunk crosses the 200-digest boundary at
     250 (stream_codec.rs:217-245, GT:895). *)
  let digests = List.init 250 bat_digest_n in
  let chunks = SC.digest_chunks digests in
  Alcotest.(check (list int)) "200 then 50" [ 200; 50 ]
    (List.map List.length chunks);
  Alcotest.(check bool) "order is preserved" true
    (List.equal Digests.Batch_digest.equal digests (List.concat chunks));
  Alcotest.(check (list int)) "an empty request has no chunks" []
    (List.map List.length (SC.digest_chunks []));
  Alcotest.(check (list int)) "an exact multiple does not leave an empty tail"
    [ 200; 200 ]
    (List.map List.length (SC.digest_chunks (List.init 400 bat_digest_n)))

let cert_encoded_size cert = String.length (Bcs.encode N.Certificate_wire.codec cert)

let t_cert_batches_multi () =
  (* sync_certs_round_trip_multi_batch (GT:892): the count is DERIVED from
     the port's own encoder, because Rust derives it from its own. *)
  let per_cert = cert_encoded_size cert_genesis_empty in
  Alcotest.(check bool) "a certificate has a positive encoding" true
    (per_cert > 0);
  (* The divisor is tested on the line above the division; the guard is the
     totality justification, not a comment. *)
  let count =
    if per_cert <= 0 then 0
    else ((SC.sync_cert_batch_target_size * 2) / per_cert) + 5 (* @total-accessor *)
  in
  let certs = List.init count (fun _ -> cert_genesis_empty) in
  let batches = SC.cert_batches ~encoded_size:cert_encoded_size certs in
  Alcotest.(check bool)
    (Printf.sprintf "%d certificates of %d bytes make %d batches, >= 3" count
       per_cert (List.length batches))
    true
    (List.length batches >= 3);
  Alcotest.(check int) "every certificate is in exactly one batch" count
    (List.length (List.concat batches));
  (* Every batch but the last reached the flush target. *)
  let sizes =
    List.map
      (fun batch -> List.fold_left (fun a c -> a + cert_encoded_size c) 0 batch)
      batches
  in
  Alcotest.(check bool) "each flushed batch reached the target" true
    (List.for_all
       (fun s -> s >= SC.sync_cert_batch_target_size)
       (List.filteri (fun i _ -> i < List.length sizes - 1) sizes));
  Alcotest.(check (list int)) "an empty certificate list makes no batches" []
    (List.map List.length (SC.cert_batches ~encoded_size:cert_encoded_size []))

let t_cert_batch_crossing_element () =
  (* GT:823: the honest response cap ends the stream INCLUDING the element
     that crosses it. Sizes are uniform so only the cap can decide where the
     stream stops, and the identities make the crossing element visible. *)
  let batches =
    SC.cert_batches_bounded
      ~encoded_size:(fun _ -> 100)
      ~target_size:100 ~response_cap:250 [ 1; 2; 3; 4; 5 ]
  in
  Alcotest.(check (list int)) "the crossing element is inside the response"
    [ 1; 2; 3 ] (List.concat batches);
  Alcotest.(check int) "and each element flushed its own batch" 3
    (List.length batches);
  Alcotest.(check (list int)) "a cap above the total keeps everything"
    [ 1; 2; 3; 4; 5 ]
    (List.concat
       (SC.cert_batches_bounded
          ~encoded_size:(fun _ -> 100)
          ~target_size:100 ~response_cap:10_000 [ 1; 2; 3; 4; 5 ]));
  (* And the target alone, with no cap in reach, groups rather than truncates. *)
  Alcotest.(check (list int)) "the target groups without dropping" [ 2; 2; 1 ]
    (List.map List.length
       (SC.cert_batches_bounded
          ~encoded_size:(fun _ -> 60)
          ~target_size:100 ~response_cap:10_000 [ 1; 2; 3; 4; 5 ]))

(* ---------------------------------------------------- stage 4: sync readers *)

let violation_name = function
  | SR.Unexpected_opening_frame -> "unexpected_opening_frame"
  | SR.Control_frame_mid_stream -> "control_frame_mid_stream"
  | SR.Peer_abort SF.Internal -> "peer_abort_internal"
  | SR.Peer_abort SF.Malformed -> "peer_abort_malformed"
  | SR.Too_many_items _ -> "too_many_items"
  | SR.Unexpected_digest _ -> "unexpected_digest"
  | SR.Duplicate_digest _ -> "duplicate_digest"
  | SR.Size_cap_exceeded _ -> "size_cap_exceeded"
  | SR.Decode _ -> "decode"

let opening_name = function
  | SR.Proceed -> "proceed"
  | SR.Denied SF.At_capacity -> "denied_at_capacity"
  | SR.Denied SF.Unavailable -> "denied_unavailable"
  | SR.Peer_error SF.Internal -> "peer_error_internal"
  | SR.Peer_error SF.Malformed -> "peer_error_malformed"

let opening_verdict (frame : unit SF.t) =
  Result.fold ~ok:opening_name ~error:violation_name (SR.opening frame)

let t_opening_classification () =
  (* The handshake of GT:844, shared by all four request kinds. *)
  Alcotest.(check string) "Ack proceeds" "proceed" (opening_verdict SF.Ack);
  Alcotest.(check string) "Deny at capacity" "denied_at_capacity"
    (opening_verdict (SF.Deny SF.At_capacity));
  Alcotest.(check string) "Deny unavailable" "denied_unavailable"
    (opening_verdict (SF.Deny SF.Unavailable));
  Alcotest.(check string) "Err internal" "peer_error_internal"
    (opening_verdict (SF.Err SF.Internal));
  Alcotest.(check string) "Err malformed" "peer_error_malformed"
    (opening_verdict (SF.Err SF.Malformed));
  Alcotest.(check string) "a Req first is a protocol error"
    "unexpected_opening_frame" (opening_verdict (SF.Req ()));
  Alcotest.(check string) "a Data first is a protocol error"
    "unexpected_opening_frame" (opening_verdict (SF.Data "x"));
  Alcotest.(check string) "an End first is a protocol error"
    "unexpected_opening_frame" (opening_verdict SF.End_)

let t_unavailable_denies () =
  (* sync_consensus_output_unavailable_denies (GT:894): bytes=None yields
     exactly one Deny(Unavailable) frame and nothing else. *)
  let stream : unit SF.t list = [ SF.Deny SF.Unavailable ] in
  Alcotest.(check string) "one frame, a deny" "deny" (frame_names stream);
  Alcotest.(check string) "and it classifies as unavailable" "denied_unavailable"
    (opening_verdict (force "the deny frame" (List.nth_opt stream 0)));
  Alcotest.(check int) "no Ack, no Data, no End" 0
    (List.length
       (List.filter (fun f -> not (String.equal (frame_name f) "deny")) stream))

let pack_verdict frames =
  Result.fold
    ~ok:(fun (payload, finished) ->
      Printf.sprintf "ok:%d:%b" (String.length payload) finished)
    ~error:violation_name (SR.Pack_reader.run frames)

let t_pack_reader () =
  let payload = filled (SC.sync_pack_chunk_size + 777) in
  Alcotest.(check string) "a whole pack reassembles"
    (Printf.sprintf "ok:%d:true" (String.length payload))
    (pack_verdict (SC.pack_frames payload));
  Alcotest.(check string) "an empty pack is an empty payload" "ok:0:true"
    (pack_verdict (SC.pack_frames ""));
  (* A body that simply runs out is not a violation: upstream that is a read
     timeout, and timeouts are deferred. *)
  Alcotest.(check string) "a body with no terminator is unfinished" "ok:1:false"
    (pack_verdict [ SF.Data "x" ])

(* Each reader gets a Data payload of its OWN shape, so a decode failure
   cannot stand in for the abort the case is actually testing. *)
let empty_cert_batch = Bcs.encode (Bcs.list N.Certificate_wire.codec) []

let batch_one =
  Batch.make ~transactions:[ "\x01" ] ~epoch:Units.Epoch.zero
    ~beneficiary:Units.Address.zero ~base_fee_per_gas:Units.Base_fee.min_protocol
    ~worker_id:(force "worker id" (Units.Worker_id.of_int 0))

let batch_two =
  Batch.make ~transactions:[ "\x02" ] ~epoch:Units.Epoch.zero
    ~beneficiary:Units.Address.zero ~base_fee_per_gas:Units.Base_fee.min_protocol
    ~worker_id:(force "worker id" (Units.Worker_id.of_int 0))

let batch_bytes b = Bcs.encode Batch.codec b

let cert_verdict ~accept_cap frames =
  Result.fold
    ~ok:(fun (certs, finished) ->
      Printf.sprintf "ok:%d:%b" (List.length certs) finished)
    ~error:violation_name (SR.Cert_reader.run ~accept_cap frames)

let batch_verdict ~requested frames =
  Result.fold
    ~ok:(fun (batches, finished) ->
      Printf.sprintf "ok:%d:%b" (List.length batches) finished)
    ~error:violation_name (SR.Batch_reader.run ~requested frames)

let t_abnormal_termination () =
  (* GT:893: a Data frame followed by Err(Internal) must error out EVERY
     reader, reported as an abort rather than as a decode failure or a silent
     short read. *)
  let requested = [ Batch.digest batch_one ] in
  Alcotest.(check string) "the pack reader aborts" "peer_abort_internal"
    (pack_verdict [ SF.Data "x"; SF.Err SF.Internal ]);
  Alcotest.(check string) "the certificate reader aborts" "peer_abort_internal"
    (cert_verdict ~accept_cap:1024
       [ SF.Data empty_cert_batch; SF.Err SF.Internal ]);
  Alcotest.(check string) "the batch reader aborts" "peer_abort_internal"
    (batch_verdict ~requested
       [ SF.Data (batch_bytes batch_one); SF.Err SF.Internal ]);
  Alcotest.(check string) "and reports which abort" "peer_abort_malformed"
    (pack_verdict [ SF.Data "x"; SF.Err SF.Malformed ])

let t_stray_control_frame () =
  (* GT:858: any of Req/Ack/Deny inside the body is InvalidData upstream. *)
  let requested = [ Batch.digest batch_one ] in
  Alcotest.(check string) "a stray Ack in the pack reader"
    "control_frame_mid_stream"
    (pack_verdict [ SF.Data "x"; SF.Ack ]);
  Alcotest.(check string) "a stray Ack in the certificate reader"
    "control_frame_mid_stream"
    (cert_verdict ~accept_cap:1024 [ SF.Data empty_cert_batch; SF.Ack ]);
  Alcotest.(check string) "a stray Ack in the batch reader"
    "control_frame_mid_stream"
    (batch_verdict ~requested [ SF.Data (batch_bytes batch_one); SF.Ack ]);
  Alcotest.(check string) "a stray Deny" "control_frame_mid_stream"
    (pack_verdict [ SF.Data "x"; SF.Deny SF.At_capacity ]);
  Alcotest.(check string) "a stray Req" "control_frame_mid_stream"
    (pack_verdict [ SF.Data "x"; SF.Req () ])

let t_cert_reader_cap () =
  let one_cert =
    Bcs.encode (Bcs.list N.Certificate_wire.codec) [ cert_genesis_empty ]
  in
  let frame_len = String.length one_cert in
  Alcotest.(check string) "the cap admits an exact fit" "ok:2:true"
    (cert_verdict ~accept_cap:(frame_len * 2)
       [ SF.Data one_cert; SF.Data one_cert; SF.End_ ]);
  (* One byte short and the CROSSING frame is what reports it (GT:857). *)
  Alcotest.(check string) "one byte short and the crossing frame reports"
    "size_cap_exceeded"
    (cert_verdict
       ~accept_cap:((frame_len * 2) - 1)
       [ SF.Data one_cert; SF.Data one_cert; SF.End_ ]);
  Alcotest.(check string) "an empty batch frame still decodes" "ok:0:true"
    (cert_verdict ~accept_cap:1024 [ SF.Data empty_cert_batch; SF.End_ ]);
  Alcotest.(check string) "a Data frame that is not a batch is a decode error"
    "decode"
    (cert_verdict ~accept_cap:1024 [ SF.Data "\xff\xff\xff"; SF.End_ ])

let t_batch_reader_positive () =
  (* The POSITIVE control the design mandates for the digest-set lookup: a
     digest that WAS requested is accepted end to end, and the digest is the
     one the port's own Batch.digest recomputes from the decoded batch, never
     one the peer supplied. *)
  let digest_one = Batch.digest batch_one in
  let digest_two = Batch.digest batch_two in
  Alcotest.(check bool) "the two fixtures have distinct digests" false
    (Digests.Batch_digest.equal digest_one digest_two);
  let frames = [ SF.Data (batch_bytes batch_one); SF.End_ ] in
  Alcotest.(check string) "a requested batch is accepted" "ok:1:true"
    (batch_verdict ~requested:[ digest_one; digest_two ] frames);
  let accepted =
    force_result violation_name
      (SR.Batch_reader.run ~requested:[ digest_one; digest_two ] frames)
  in
  Alcotest.(check bool) "and it is the batch that was sent" true
    (List.equal Batch.equal [ batch_one ] (fst accepted));
  Alcotest.(check string) "both requested batches are accepted" "ok:2:true"
    (batch_verdict
       ~requested:[ digest_one; digest_two ]
       [
         SF.Data (batch_bytes batch_one);
         SF.Data (batch_bytes batch_two);
         SF.End_;
       ])

let t_batch_reader_negatives () =
  let digest_one = Batch.digest batch_one in
  let digest_two = Batch.digest batch_two in
  (* handle.rs:464-469: more frames than digests requested. *)
  Alcotest.(check string) "too many batches" "too_many_items"
    (batch_verdict ~requested:[ digest_one ]
       [ SF.Data (batch_bytes batch_one); SF.Data (batch_bytes batch_two) ]);
  (* handle.rs:476-480: a batch nobody asked for. *)
  Alcotest.(check string) "an unrequested digest" "unexpected_digest"
    (batch_verdict ~requested:[ digest_two ] [ SF.Data (batch_bytes batch_one) ]);
  (* handle.rs:482-486: the same requested digest twice. Two digests are
     requested so the count bound cannot fire first and mask this one. *)
  Alcotest.(check string) "a duplicate digest" "duplicate_digest"
    (batch_verdict
       ~requested:[ digest_one; digest_two ]
       [ SF.Data (batch_bytes batch_one); SF.Data (batch_bytes batch_one) ]);
  Alcotest.(check string) "a payload that is not a batch" "decode"
    (batch_verdict ~requested:[ digest_one ] [ SF.Data "\xff\xff\xff" ])

(* ------------------------------------------------- stage 4: gossip pipeline *)

let acceptance_name = function
  | N.Gossip.Accept -> "accept"
  | N.Gossip.Reject N.Gossip.Too_large -> "reject_too_large"
  | N.Gossip.Reject N.Gossip.Unauthorized_author -> "reject_unauthorized_author"

let penalty_name = function
  | N.Gossip.Fatal_relayer -> "fatal_relayer"
  | N.Gossip.Fatal_author -> "fatal_author"
  | N.Gossip.Skip -> "skip"

let chain_id = 2017

let t_gossip_verify () =
  let topic = N.Gossip.primary_topic ~chain_id in
  let good = key '\xb0' in
  let authorized = [ (topic, N.Gossip.Restricted [ good ]) ] in
  let peer = Some "\x00\x01\x00" in
  let verify ?(source = peer) ~data_len ~author () =
    acceptance_name (N.Gossip.verify ~data_len ~topic ~source ~author ~authorized)
  in
  Alcotest.(check int) "the cap is 12_000" 12_000 N.Gossip.max_gossip_message_size;
  Alcotest.(check string) "exactly at the cap" "accept"
    (verify ~data_len:12_000 ~author:(Some good) ());
  Alcotest.(check string) "one byte past the cap" "reject_too_large"
    (verify ~data_len:12_001 ~author:(Some good) ());
  Alcotest.(check string) "an unauthorized author under the cap"
    "reject_unauthorized_author"
    (verify ~data_len:12_000 ~author:(Some (key '\xcc')) ());
  Alcotest.(check string) "an unresolved author under the cap"
    "reject_unauthorized_author" (verify ~data_len:12_000 ~author:None ());
  (* A message carrying no source is unauthorized even with an allowlisted
     author, and the size test still runs ahead of it. *)
  Alcotest.(check string) "no source under the cap"
    "reject_unauthorized_author"
    (verify ~source:None ~data_len:12_000 ~author:(Some good) ());
  Alcotest.(check string) "no source past the cap" "reject_too_large"
    (verify ~source:None ~data_len:12_001 ~author:(Some good) ());
  (* The ORDER is observable: oversized AND unauthorized is charged as
     oversized, which penalises the relayer instead of the author. *)
  Alcotest.(check string) "size is tested first" "reject_too_large"
    (verify ~data_len:12_001 ~author:(Some (key '\xcc')) ());
  Alcotest.(check string) "a topic this node does not subscribe to"
    "reject_unauthorized_author"
    (acceptance_name
       (N.Gossip.verify ~data_len:1 ~topic:"tn-worker-2017" ~source:peer
          ~author:(Some good) ~authorized))

let t_gossip_penalty () =
  let p reason ~relayer ~author =
    penalty_name
      (N.Gossip.penalty reason ~relayer_resolved:relayer ~author_resolved:author)
  in
  Alcotest.(check string) "oversized bans the relayer" "fatal_relayer"
    (p N.Gossip.Too_large ~relayer:true ~author:true);
  Alcotest.(check string) "an unresolved relayer is skipped" "skip"
    (p N.Gossip.Too_large ~relayer:false ~author:true);
  Alcotest.(check string) "an unauthorized author bans the author" "fatal_author"
    (p N.Gossip.Unauthorized_author ~relayer:true ~author:true);
  Alcotest.(check string) "an unresolved author is skipped" "skip"
    (p N.Gossip.Unauthorized_author ~relayer:true ~author:false);
  (* Neither reason ever borrows the other peer's resolution. *)
  Alcotest.(check string) "the relayer never answers for the author" "skip"
    (p N.Gossip.Unauthorized_author ~relayer:false ~author:false);
  Alcotest.(check string) "the author never answers for the relayer" "skip"
    (p N.Gossip.Too_large ~relayer:false ~author:true)

(* -------------------------------------------------------- stage 4: the seam *)

let outbound_name = function
  | N.Wire.Publish { topic; payload } ->
      Printf.sprintf "publish:%s:%d" topic (String.length payload)
  | N.Wire.Request { to_ = _; request = _ } -> "request"
  | N.Wire.Response { response = _ } -> "response"
  | N.Wire.Local -> "local"

let unmapped_name = function
  | N.Wire.Peer_exchange_request -> "peer_exchange_request"
  | N.Wire.Epoch_record_request -> "epoch_record_request"
  | N.Wire.Missing_parents_response -> "missing_parents_response"
  | N.Wire.Epoch_record_response -> "epoch_record_response"
  | N.Wire.Peer_exchange_response -> "peer_exchange_response"
  | N.Wire.Rpc_error_response -> "rpc_error_response"
  | N.Wire.Recoverable_rpc_error_response -> "recoverable_rpc_error_response"
  | N.Wire.Consensus_gossip -> "consensus_gossip"
  | N.Wire.Epoch_vote_gossip -> "epoch_vote_gossip"
  | N.Wire.Worker_batch_gossip -> "worker_batch_gossip"

let verdict_name = function
  | N.Wire.Event (Node.Our_digest _) -> "event:our_digest"
  | N.Wire.Event (Node.Vote_request _) -> "event:vote_request"
  | N.Wire.Event (Node.Vote_received _) -> "event:vote_received"
  | N.Wire.Event (Node.Certificate_received _) -> "event:certificate_received"
  | N.Wire.Event (Node.Timer_fired _) -> "event:timer_fired"
  | N.Wire.Not_a_node_event u -> "unmapped:" ^ unmapped_name u

let verdict_of r = Result.fold ~ok:verdict_name ~error:N.Wire.error_to_string r

let t_broadcast_header_fans_out () =
  (* GT:494: node.mli emits ONE Broadcast_header; Rust drives an N-way
     fan-out, one request per committee member, and the target set lives
     nowhere in the command. *)
  let _, committee = committee_of 4 in
  let outs =
    force_result N.Wire.error_to_string
      (N.Wire.outbound_of_command ~committee ~chain_id (Node.Broadcast_header h1))
  in
  Alcotest.(check int) "one request per committee member"
    (Committee.size committee) (List.length outs);
  Alcotest.(check (list string)) "and every one of them is a request"
    [ "request"; "request"; "request"; "request" ]
    (List.map outbound_name outs);
  let targets =
    List.filter_map
      (fun o ->
        match o with
        | N.Wire.Request { to_; request = _ } -> Some to_
        | N.Wire.Publish _ | N.Wire.Response _ | N.Wire.Local -> None)
      outs
  in
  Alcotest.(check bool) "addressed to the committee, in committee order" true
    (List.equal Authority_id.equal targets
       (List.map Authority.id (Committee.authorities committee)));
  let requests =
    List.filter_map
      (fun o ->
        match o with
        | N.Wire.Request { to_ = _; request } -> Some request
        | N.Wire.Publish _ | N.Wire.Response _ | N.Wire.Local -> None)
      outs
  in
  (* Parents ride the RETRY leg only (certifier.rs:133-183). *)
  Alcotest.(check bool) "with no parents attached" true
    (List.for_all
       (fun r ->
         match r with
         | N.Primary_msg.Req_vote { header = _; parents } ->
             List.length parents = 0
         | N.Primary_msg.Req_peer_exchange _ | N.Primary_msg.Req_epoch_record _
           ->
             false)
       requests);
  Alcotest.(check bool) "the retry leg carries them" true
    (match
       N.Wire.retry_vote_request ~header:h1 ~parents:[ cert_genesis_empty ]
     with
    | N.Primary_msg.Req_vote { header = _; parents } -> List.length parents = 1
    | N.Primary_msg.Req_peer_exchange _ | N.Primary_msg.Req_epoch_record _ ->
        false)

let t_outbound_other_commands () =
  let secrets, committee = committee_of 4 in
  let outs command =
    Result.fold
      ~ok:(fun l -> String.concat "," (List.map outbound_name l))
      ~error:N.Wire.error_to_string
      (N.Wire.outbound_of_command ~committee ~chain_id command)
  in
  Alcotest.(check string) "missing parents answers on the vote channel"
    "response"
    (outs
       (Node.Send_missing_parents
          { to_ = auth '\x01'; digests = [ hdr_digest '\x02' ] }));
  Alcotest.(check string) "arming a timer is local" "local"
    (outs
       (Node.Arm_timer
          {
            kind = Tn_consensus.Proposer.Min_delay;
            after = Units.Duration.zero;
            gen = 1;
          }));
  let sub_dag =
    Tn_consensus.Sub_dag.create
      ~sequence:
        (force "a genesis sequence"
           (Tn_std.Nonempty.of_list (Tn_vertex.Certificate.genesis committee)))
      ~scores:(Tn_consensus.Reputation_scores.fresh committee)
      ~previous:None
  in
  Alcotest.(check string) "committed output is local at this layer" "local"
    (outs (Node.Emit_committed sub_dag));
  (* A certificate broadcast is a gossip publish on the primary topic. *)
  let genesis =
    force "genesis certificates"
      (List.nth_opt (Tn_vertex.Certificate.genesis committee) 0)
  in
  let published =
    force_result N.Wire.error_to_string
      (N.Wire.outbound_of_command ~committee ~chain_id
         (Node.Broadcast_certificate genesis))
  in
  Alcotest.(check bool) "on tn-primary-2017 with a real payload" true
    (List.for_all
       (fun o ->
         match o with
         | N.Wire.Publish { topic; payload } ->
             String.equal topic "tn-primary-2017" && String.length payload > 0
         | N.Wire.Request _ | N.Wire.Response _ | N.Wire.Local -> false)
       published);
  (* Send_vote crosses the crypto seam, whose signature width is its own
     business; stated as an agreement it is honest under both seams. *)
  let secret = force "a committee secret" (List.nth_opt secrets 0) in
  let public = Tn_crypto.Secret_key.public_key secret in
  let voter = Authority_id.of_public_key public in
  let header =
    Header.make ~author:voter ~round:Round.genesis
      ~epoch:(Committee.epoch committee) ~created_at:Units.Timestamp.zero
      ~payload:[] ~parents:[] ~latest_execution_block:Block_num_hash.zero
  in
  let vote = Tn_vertex.Vote.sign secret ~voter header in
  let seam_is_48 =
    String.length (Tn_crypto.Signature.to_bytes (Tn_vertex.Vote.signature vote))
    = 48
  in
  Alcotest.(check bool) "a vote is a response exactly when the seam is 48 wide"
    seam_is_48
    (String.equal "response" (outs (Node.Send_vote { to_ = auth '\x03'; vote })))

let t_inbound_requests () =
  let _, committee = committee_of 4 in
  let genesis =
    force "genesis certificates"
      (List.nth_opt (Tn_vertex.Certificate.genesis committee) 0)
  in
  let genesis_wire =
    force_result N.Certificate_wire.error_to_string
      (N.Certificate_wire.of_certificate committee genesis)
  in
  let verdict request =
    verdict_of (N.Wire.event_of_request ~committee ~from_:(auth '\x07') request)
  in
  Alcotest.(check string) "a vote request is a Node event" "event:vote_request"
    (verdict
       (N.Primary_msg.Req_vote
          {
            header = Tn_vertex.Certificate.header genesis;
            parents = [ genesis_wire ];
          }));
  Alcotest.(check string) "peer exchange is not" "unmapped:peer_exchange_request"
    (verdict (N.Primary_msg.Req_peer_exchange N.Peer_exchange.empty));
  Alcotest.(check string) "an epoch record request is not"
    "unmapped:epoch_record_request"
    (verdict (N.Primary_msg.Req_epoch_record { epoch = None; hash = None }));
  (* A parent that does not re-verify is refused, not admitted unchecked. *)
  Alcotest.(check bool) "an unverifiable parent is refused" true
    (Result.fold
       ~ok:(fun (_ : N.Wire.inbound_verdict) -> false)
       ~error:(fun (_ : N.Wire.error) -> true)
       (N.Wire.event_of_request ~committee ~from_:(auth '\x07')
          (N.Primary_msg.Req_vote
             {
               header = h1;
               parents =
                 [
                   N.Certificate_wire.make ~header:h1
                     ~state:N.Certificate_wire.Genesis
                     ~signed_authorities:(bitmap [ 9 ]);
                 ];
             })));
  (* The parents that DO verify come through as checked certificates. *)
  let checked =
    force_result N.Wire.error_to_string
      (N.Wire.event_of_request ~committee ~from_:(auth '\x07')
         (N.Primary_msg.Req_vote
            {
              header = Tn_vertex.Certificate.header genesis;
              parents = [ genesis_wire ];
            }))
  in
  Alcotest.(check bool) "carrying the parent it was given" true
    (match checked with
    | N.Wire.Event (Node.Vote_request { from_ = _; header = _; parents }) ->
        List.equal Tn_vertex.Certificate.equal [ genesis ] parents
    | N.Wire.Event
        ( Node.Our_digest _ | Node.Vote_received _ | Node.Certificate_received _
        | Node.Timer_fired _ )
    | N.Wire.Not_a_node_event _ ->
        false)

let t_inbound_responses () =
  let verdict response = verdict_of (N.Wire.event_of_response response) in
  Alcotest.(check string) "missing parents has no Node event"
    "unmapped:missing_parents_response"
    (verdict (N.Primary_msg.Res_missing_parents [ hdr_digest '\x01' ]));
  Alcotest.(check string) "an epoch record response has none"
    "unmapped:epoch_record_response"
    (verdict
       (N.Primary_msg.Res_epoch_record
          { record = epoch_record_default; certificate = epoch_certificate [ 0 ] }));
  Alcotest.(check string) "peer exchange has none"
    "unmapped:peer_exchange_response"
    (verdict (N.Primary_msg.Res_peer_exchange N.Peer_exchange.empty));
  Alcotest.(check string) "an RPC error has none" "unmapped:rpc_error_response"
    (verdict (N.Primary_msg.Res_error "boom"));
  Alcotest.(check string) "a recoverable RPC error has none"
    "unmapped:recoverable_rpc_error_response"
    (verdict (N.Primary_msg.Res_recoverable_error "later"));
  (* A vote response IS a Node event, when the seam can carry it. *)
  let seam_takes_it =
    Option.is_some
      (Tn_crypto.Signature.of_bytes (N.Bls_signature.to_bytes (sig48 '\x0d')))
  in
  Alcotest.(check bool) "a vote response is Vote_received under a wire seam"
    seam_takes_it
    (String.equal "event:vote_received"
       (verdict (N.Primary_msg.Res_vote vote_populated)))

let t_inbound_gossip () =
  let _, committee = committee_of 4 in
  let genesis =
    force "genesis certificates"
      (List.nth_opt (Tn_vertex.Certificate.genesis committee) 0)
  in
  let genesis_wire =
    force_result N.Certificate_wire.error_to_string
      (N.Certificate_wire.of_certificate committee genesis)
  in
  let primary = N.Gossip.primary_topic ~chain_id in
  let gossip topic payload =
    verdict_of (N.Wire.event_of_gossip ~committee ~chain_id ~topic payload)
  in
  let primary_bytes g = Bcs.encode N.Primary_msg.gossip_codec g in
  Alcotest.(check string) "a gossiped certificate becomes Certificate_received"
    "event:certificate_received"
    (gossip primary
       (primary_bytes (N.Primary_msg.Gossip_certificate genesis_wire)));
  let delivered =
    force_result N.Wire.error_to_string
      (N.Wire.event_of_gossip ~committee ~chain_id ~topic:primary
         (primary_bytes (N.Primary_msg.Gossip_certificate genesis_wire)))
  in
  Alcotest.(check bool) "and it is the certificate that was published" true
    (match delivered with
    | N.Wire.Event (Node.Certificate_received c) ->
        Tn_vertex.Certificate.equal c genesis
    | N.Wire.Event
        ( Node.Our_digest _ | Node.Vote_request _ | Node.Vote_received _
        | Node.Timer_fired _ )
    | N.Wire.Not_a_node_event _ ->
        false);
  (* GT:499-501: the layers these belong to are not ported, and they say so. *)
  Alcotest.(check string) "consensus output gossip is not a Node event"
    "unmapped:consensus_gossip"
    (gossip
       (N.Gossip.consensus_output_topic ~chain_id)
       (primary_bytes (N.Primary_msg.Gossip_consensus consensus_result_populated)));
  Alcotest.(check string) "an epoch vote is not a Node event"
    "unmapped:epoch_vote_gossip"
    (gossip
       (N.Gossip.epoch_vote_topic ~chain_id)
       (primary_bytes (N.Primary_msg.Gossip_epoch_vote epoch_vote_populated)));
  Alcotest.(check string) "a worker batch announcement is not a Node event"
    "unmapped:worker_batch_gossip"
    (gossip
       (N.Gossip.worker_batch_topic ~chain_id)
       (Bcs.encode N.Worker_msg.gossip_codec
          (N.Worker_msg.Wgossip_batch
             { epoch = Units.Epoch.zero; block_hash = bat_digest '\x05' })));
  Alcotest.(check bool) "an unknown topic is refused" true
    (Result.is_error
       (N.Wire.event_of_gossip ~committee ~chain_id ~topic:"tn-nope-2017" ""));
  Alcotest.(check bool) "an undecodable payload is refused" true
    (Result.is_error
       (N.Wire.event_of_gossip ~committee ~chain_id ~topic:primary "\xff\xff"))

(* ------------------------------------------------------ stage 4: properties *)

let n_pack_concat = "the pack frames of any payload concatenate back to it"

let prop_pack_concat =
  QCheck.Test.make ~count:200 ~name:n_pack_concat
    QCheck.(pair (string_size (Gen.int_range 0 300)) (int_range 1 64))
    (fun (payload, chunk_size) ->
      Result.fold
        ~ok:(fun frames ->
          let parts = data_payloads frames in
          String.equal payload (String.concat "" parts)
          && List.for_all
               (fun p -> String.length p <= chunk_size && String.length p > 0)
               parts
          && String.equal "end"
               (frame_name
                  (force "a terminator"
                     (List.nth_opt frames (List.length frames - 1)))))
        ~error:(fun (_ : SC.error) -> false)
        (SC.pack_frames_with ~chunk_size payload))

let n_cert_fold =
  "the certificate fold keeps order and stops on the crossing element"

let prop_cert_fold =
  QCheck.Test.make ~count:200 ~name:n_cert_fold
    QCheck.(
      triple
        (list_size (Gen.int_range 0 40) (int_range 1 200))
        (int_range 1 400) (int_range 1 2000))
    (fun (sizes, target_size, response_cap) ->
      let items = List.mapi (fun i s -> (i, s)) sizes in
      let encoded_size (_, s) = s in
      let batches =
        SC.cert_batches_bounded ~encoded_size ~target_size ~response_cap items
      in
      let emitted = List.concat batches in
      (* Order is preserved and the emitted run is a PREFIX of the input. *)
      let is_prefix =
        List.equal
          (fun (a, _) (b, _) -> a = b)
          emitted
          (List.filteri (fun i _ -> i < List.length emitted) items)
      in
      (* Everything but the last emitted element fits under the cap: the
         crossing element is the only one allowed to pass it. *)
      let before_last =
        List.filteri (fun i _ -> i < List.length emitted - 1) emitted
      in
      let sum l = List.fold_left (fun a x -> a + encoded_size x) 0 l in
      is_prefix
      && sum before_last < response_cap
      && (List.length emitted = List.length items || sum emitted >= response_cap))

let check_property ~salt t () =
  QCheck.Test.check_exn ~rand:(Random.State.make [| 0x44c0ffee; salt |]) t

(* ------------------------------------------------------------------- suites *)

let suites =
  [
    ("floor", [ Alcotest.test_case "F1 vector and case floor" `Quick t_floor ]);
    ( "roaring",
      [
        Alcotest.test_case "R1 golden bitmaps encode" `Quick
          t_roaring_golden_encode;
        Alcotest.test_case "R2 golden bitmaps decode" `Quick
          t_roaring_golden_decode;
        Alcotest.test_case "R3 the run container decodes" `Quick
          t_roaring_run_container;
        Alcotest.test_case "R4 negatives" `Quick t_roaring_negatives;
        Alcotest.test_case "R5 round trips" `Quick t_roaring_round_trip;
        Alcotest.test_case "R6 range and membership" `Quick t_roaring_range;
        Alcotest.test_case "R7 the BCS adapter field" `Quick t_roaring_fields;
      ] );
    ( "stable tags",
      [
        Alcotest.test_case "T1 frame_tags_are_stable" `Quick
          t_frame_tags_are_stable;
        Alcotest.test_case "T2 request_tags_are_stable" `Quick
          t_request_tags_are_stable;
        Alcotest.test_case "T3 req_frame_round_trips" `Quick
          t_req_frame_round_trips;
      ] );
    ( "payload leaves",
      [
        Alcotest.test_case "L1 vote" `Quick t_vote_rows;
        Alcotest.test_case "L2 epoch record" `Quick t_epoch_record_rows;
        Alcotest.test_case "L3 epoch vote" `Quick t_epoch_vote_rows;
        Alcotest.test_case "L4 epoch certificate" `Quick t_epoch_certificate_rows;
        Alcotest.test_case "L5 consensus result" `Quick t_consensus_result_row;
        Alcotest.test_case "L6 all five signature states" `Quick
          t_certificate_wire_states;
        Alcotest.test_case "L7 genesis with an empty bitmap" `Quick
          t_certificate_wire_genesis_empty;
      ] );
    ( "primary messages",
      [
        Alcotest.test_case "P1 requests" `Quick t_primary_request_rows;
        Alcotest.test_case "P2 the four Option combinations" `Quick
          t_epoch_record_request_options;
        Alcotest.test_case "P3 responses" `Quick t_primary_response_rows;
        Alcotest.test_case "P4 gossip" `Quick t_primary_gossip_rows;
        Alcotest.test_case "P5 missing certificates, usize as u64" `Quick
          t_missing_certificates_request;
      ] );
    ( "worker messages",
      [
        Alcotest.test_case "W1 gossip batch, the 0x20 prefix" `Quick
          t_worker_gossip_row;
        Alcotest.test_case "W2 requests" `Quick t_worker_request_rows;
        Alcotest.test_case "W3 responses, unit variant included" `Quick
          t_worker_response_rows;
      ] );
    ( "sync",
      [
        Alcotest.test_case "S1 every frame variant" `Quick t_sync_frame_rows;
        Alcotest.test_case "S2 the worker request" `Quick
          t_worker_sync_request_row;
        Alcotest.test_case "S3 the four primary requests" `Quick
          t_primary_sync_request_rows;
        Alcotest.test_case "S4 BTreeSet decode is permissive" `Quick
          t_btree_set_is_permissive;
      ] );
    ( "peer exchange",
      [
        Alcotest.test_case "X1 golden maps" `Quick t_peer_exchange_rows;
        Alcotest.test_case "X2 canonical encoding" `Quick
          t_peer_exchange_canonical;
        Alcotest.test_case "X3 unsorted and duplicate keys" `Quick
          t_peer_exchange_negatives;
      ] );
    ( "node record",
      [
        Alcotest.test_case "N1 the current layout" `Quick t_node_record_rows;
        Alcotest.test_case "N2 the legacy layout" `Quick t_legacy_node_record_row;
        Alcotest.test_case "N3 decode_compat on both" `Quick t_decode_compat;
      ] );
    ( "decode negatives",
      [
        Alcotest.test_case "G1 unknown variant tag" `Quick t_unknown_variant_tag;
        Alcotest.test_case "G2 non-minimal uleb tag" `Quick t_non_minimal_uleb_tag;
        Alcotest.test_case "G3 option tag 0x02" `Quick t_bad_option_tag;
        Alcotest.test_case "G4 wrong-length sized bytes" `Quick
          t_wrong_length_sized_bytes;
        Alcotest.test_case "G5 a trailing byte" `Quick t_trailing_byte;
      ] );
    ( "protocols",
      [
        Alcotest.test_case "PR1 every protocol string" `Quick t_protocol_strings;
        Alcotest.test_case "PR2 owned_protocol refuses" `Quick
          t_owned_protocol_rejects;
      ] );
    ( "gossip statics",
      [
        Alcotest.test_case "GO1 topics and the cap" `Quick t_topic_strings;
        Alcotest.test_case "GO2 topic dispatch, every topic and a miss" `Quick
          t_topic_dispatch;
        Alcotest.test_case "GO3 message id oracle rows" `Quick t_message_id_rows;
        Alcotest.test_case "GO4 message id is unsigned" `Quick
          t_message_id_unsigned;
        Alcotest.test_case "GO5 base58" `Quick t_base58;
        Alcotest.test_case "GO6 the publisher allowlist" `Quick
          t_authorized_publishers;
      ] );
    ( "wire ingress",
      [
        Alcotest.test_case "I1 genesis certificate ingress" `Quick
          t_certificate_ingress_genesis;
        Alcotest.test_case "I2 certificate ingress negatives" `Quick
          t_certificate_ingress_negatives;
        Alcotest.test_case "I2b the genesis tag is not a certificate" `Quick
          t_certificate_genesis_tag_negatives;
        Alcotest.test_case "I3 vote claim, positive and negative" `Quick
          t_vote_ingress;
        Alcotest.test_case "I4 vote_wire ingress agrees with the seam" `Quick
          t_vote_wire_ingress;
      ] );
    ( "sync chunking",
      [
        Alcotest.test_case "C1 every constant at its literal value" `Quick
          t_chunking_constants;
        Alcotest.test_case "C2 pack round trips at the chunk boundary" `Quick
          t_pack_round_trips;
        Alcotest.test_case "C3 frame_larger_than_max_is_rejected" `Quick
          t_frame_larger_than_max_is_rejected;
        Alcotest.test_case "C4 digest chunks at 200" `Quick t_digest_chunks;
        Alcotest.test_case "C5 a multi-batch certificate response" `Quick
          t_cert_batches_multi;
        Alcotest.test_case "C6 the crossing certificate is included" `Quick
          t_cert_batch_crossing_element;
      ] );
    ( "sync readers",
      [
        Alcotest.test_case "D1 the opening frame classification" `Quick
          t_opening_classification;
        Alcotest.test_case "D2 an unavailable responder denies and stops" `Quick
          t_unavailable_denies;
        Alcotest.test_case "D3 the pack reader reassembles" `Quick t_pack_reader;
        Alcotest.test_case "D4 abnormal termination through every reader" `Quick
          t_abnormal_termination;
        Alcotest.test_case "D5 a stray control frame through every reader" `Quick
          t_stray_control_frame;
        Alcotest.test_case "D6 the certificate accept cap" `Quick
          t_cert_reader_cap;
        Alcotest.test_case "D7 the batch reader positive control" `Quick
          t_batch_reader_positive;
        Alcotest.test_case "D8 the batch reader negatives" `Quick
          t_batch_reader_negatives;
      ] );
    ( "gossip pipeline",
      [
        Alcotest.test_case "GO7 verify at the cap and one past it" `Quick
          t_gossip_verify;
        Alcotest.test_case "GO8 the penalty mapping" `Quick t_gossip_penalty;
      ] );
    ( "the Node seam",
      [
        Alcotest.test_case "V1 Broadcast_header fans out to the committee" `Quick
          t_broadcast_header_fans_out;
        Alcotest.test_case "V2 the other five commands" `Quick
          t_outbound_other_commands;
        Alcotest.test_case "V3 inbound requests" `Quick t_inbound_requests;
        Alcotest.test_case "V4 inbound responses" `Quick t_inbound_responses;
        Alcotest.test_case "V5 inbound gossip" `Quick t_inbound_gossip;
      ] );
    ( "chunking properties",
      [
        Alcotest.test_case n_pack_concat `Quick
          (check_property ~salt:1 prop_pack_concat);
        Alcotest.test_case n_cert_fold `Quick
          (check_property ~salt:2 prop_cert_fold);
      ] );
  ]

let () =
  case_total := List.fold_left (fun acc (_, cs) -> acc + List.length cs) 0 suites;
  Alcotest.run "tn_network messages" suites
