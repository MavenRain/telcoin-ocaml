(* Chunk 41, stage S3: the Rust-oracle rows for the sub-DAG, the consensus
   block and the leader-swap RNG.

   Every expected value here is the oracle's own constant (sub_dag_vectors.ml,
   consensus_block_vectors.ml, chacha_vectors.ml), never a value this port
   computed for itself, so a green row is cross-implementation evidence rather
   than a self-consistency check.

   WHAT IS ASSERTED HERE AND WHAT IS NOT. The {!Tn_crypto} seam is BLAKE2s in
   this executable and BLAKE3 in test/crypto_blst, so a row is assertable here
   exactly when it does not depend on the protocol hash:

   - the sub-DAG and consensus-block WIRE encodings are seam-independent, since
     every 32-byte field in them is data fed in from the oracle file and the
     headers they contain are ENCODED, not digested;
   - the randomness is keccak256, which is a fixed fact of the protocol and not
     a seam choice, so those rows are assertable anywhere;
   - the ChaCha12 draws touch no hash at all;
   - the sub-DAG and consensus-block DIGEST and PRE-IMAGE columns are NOT
     assertable here, because a sub-DAG pre-image is built out of header
     digests. Those columns are pinned structurally below (lengths, field
     order, inequalities) and belong to test/crypto_blst by hex. *)

open Tn_std
open Tn_types
open Tn_vertex
open Tn_consensus
module Bcs = Tn_codec.Bcs
module Cb = Tn_execution.Consensus_block
module Hash32 = Tn_hash32.Hash32
module OH = Oracle_headers
module SDV = Sub_dag_vectors
module CBV = Consensus_block_vectors
module CHV = Chacha_vectors
module Std_rng = Tn_rand.Std_rng

(* A clamped span, total by the rule the rest of the suite uses: a span running
   off either end yields the overlap rather than raising. *)
let span s ~off ~len =
  String.to_seqi s
  |> Seq.filter (fun (i, (_ : char)) -> i >= off && i < off + len)
  |> Seq.map snd |> String.of_seq

let hex = Hex_bytes.encode
let nonempty label l = OH.force label (Nonempty.of_list l)

(* {1 Sub-DAG rows} *)

let scores_of bindings ~final =
  Reputation_scores.of_persisted
    ~bindings:
      (List.map (fun (id, s) -> (OH.author_of "score authority" id, s)) bindings)
    ~final

let stored_of secs = OH.force "stored timestamp" (Units.Timestamp.of_sec secs)

(* SD1: Rust's default sub-DAG shape — one default header, empty non-final
   scores, a stored timestamp of zero, zero randomness. *)
let sd1 () =
  Sub_dag.of_persisted
    ~headers:(nonempty "SD1 sequence" [ OH.h1 () ])
    ~scores:(scores_of [] ~final:false)
    ~stored:Units.Timestamp.zero
    ~randomness:(OH.hash32_of "SD1 randomness" OH.zeros32)

let sd2_scores () =
  scores_of [ (OH.repeat32 "01", 5); (OH.repeat32 "02", 9) ] ~final:true

(* SD2 varies every field at once: three headers in sequence order, two
   authorities with different scores, the final flag set, a non-zero timestamp
   and a real keccak randomness. *)
let sd2 () =
  Sub_dag.of_persisted
    ~headers:(nonempty "SD2 sequence" [ OH.h2 (); OH.h4 (); OH.h5 () ])
    ~scores:(sd2_scores ())
    ~stored:(stored_of 1_700_000_001L)
    ~randomness:(OH.hash32_of "SD2 randomness" SDV.sd_rand1_keccak256)

(* SD3 is SD2 with the flag cleared and the timestamp zeroed, so dropping
   either field from the pre-image shows as its own digest. *)
let sd3 () =
  Sub_dag.of_persisted
    ~headers:(nonempty "SD3 sequence" [ OH.h2 (); OH.h4 (); OH.h5 () ])
    ~scores:(scores_of [ (OH.repeat32 "01", 5); (OH.repeat32 "02", 9) ] ~final:false)
    ~stored:Units.Timestamp.zero
    ~randomness:(OH.hash32_of "SD3 randomness" SDV.sd_rand1_keccak256)

let test_sub_dag_codec_rows () =
  Alcotest.(check string) "SD-CODEC1 = the oracle's bytes" SDV.sd_codec1
    (hex (Bcs.encode Sub_dag.codec (sd1 ())));
  Alcotest.(check string) "SD-CODEC2 = the oracle's bytes" SDV.sd_codec2
    (hex (Bcs.encode Sub_dag.codec (sd2 ())))

let test_sub_dag_codec_rows_round_trip () =
  let row name h =
    Bcs.decode Sub_dag.codec (OH.of_hex name h)
    |> Result.fold
         ~ok:(fun sd ->
           Alcotest.(check string)
             (name ^ " re-encodes to its own bytes")
             h
             (hex (Bcs.encode Sub_dag.codec sd)))
         ~error:(fun e ->
           Alcotest.failf "%s: %s" name (Bcs.error_to_string e))
  in
  row "SD-CODEC1" SDV.sd_codec1;
  row "SD-CODEC2" SDV.sd_codec2

(* The asymmetry the chunk is most likely to get wrong: the SAME 32 randomness
   bytes are written bare into the digest pre-image and LENGTH-PREFIXED onto
   the wire. Asserting one without the other would let a port unify them and
   still pass. *)
let test_sub_dag_randomness_is_bare_in_the_preimage_and_prefixed_on_the_wire () =
  let sd = sd2 () in
  let raw = Hash32.to_bytes (Sub_dag.randomness sd) in
  let pre = Sub_dag.preimage sd in
  let wire = Bcs.encode Sub_dag.codec sd in
  Alcotest.(check string) "the pre-image ends with the BARE 32 bytes" (hex raw)
    (hex (span pre ~off:(String.length pre - 32) ~len:32));
  Alcotest.(check string) "the wire ends with 0x20 then the same 32 bytes"
    (hex ("\x20" ^ raw))
    (hex (span wire ~off:(String.length wire - 33) ~len:33))

(* A bare 32-byte randomness leg is the shape this port wrote before the fix.
   It must be REFUSED, not re-framed: the row is derived from the oracle's own
   SD-CODEC1 by deleting the 0x20 length byte, so it cannot launder a wrong
   value — it asserts only a refusal. *)
let test_sub_dag_neg_bare_randomness_is_refused () =
  let bytes = OH.of_hex "SD-CODEC1" SDV.sd_codec1 in
  let at = String.length bytes - 33 in
  Alcotest.(check string) "the deleted byte really is the length prefix" "20"
    (hex (span bytes ~off:at ~len:1));
  let bare = span bytes ~off:0 ~len:at ^ span bytes ~off:(at + 1) ~len:32 in
  Alcotest.(check int) "the derived row is one byte shorter"
    (String.length bytes - 1) (String.length bare);
  Alcotest.(check bool) "a bare randomness leg is refused" false
    (Result.is_ok (Bcs.decode Sub_dag.codec bare))

(* SD-RAND1: the randomness rule itself, keccak256 of the leader's aggregate
   signature bytes. *)
let test_sub_dag_randomness_is_keccak_of_the_aggregate () =
  let agg = OH.of_hex "SD-RAND1 aggregate" SDV.sd_rand1_agg_sig in
  Alcotest.(check string) "keccak256(aggregate) = the oracle's row"
    SDV.sd_rand1_keccak256
    (Hash32.to_hex (Hash32.of_keccak (Tn_keccak.digest agg)));
  Alcotest.(check string) "and it is SD2's randomness" SDV.sd_rand1_keccak256
    (Hash32.to_hex (Sub_dag.randomness (sd2 ())))

(* SD-RAND2: the missing-signature branch. The two inequalities are what make
   the row non-vacuous — the empty-string fallback this port used before the
   fix, and the blake3 a port that routed keccak through the {!Tn_crypto} seam
   would produce, are both named and both rejected. *)
let test_sub_dag_default_randomness () =
  Alcotest.(check string) "the pinned default signature bytes"
    SDV.bls_default_signature
    (hex Sub_dag.default_signature_bytes);
  Alcotest.(check int) "which are a 48-byte compressed G1 point" 48
    (String.length Sub_dag.default_signature_bytes);
  Alcotest.(check string) "keccak256 of them = the oracle's row" SDV.sd_rand2
    (Hash32.to_hex Sub_dag.default_randomness);
  Alcotest.(check string) "the oracle's own two rows agree" SDV.sd_rand2
    SDV.bls_default_signature_keccak256;
  (* Positive control on the value the fallback must NOT be: keccak256("") is
     computed here, not merely quoted, so the inequality below cannot pass on a
     mistyped constant. *)
  Alcotest.(check string) "keccak256(\"\") is the row the oracle names"
    SDV.sd_rand2_not_keccak256_empty
    (Hash32.to_hex (Hash32.of_keccak (Tn_keccak.digest "")));
  Alcotest.(check bool) "the fallback is NOT keccak256(\"\")" false
    (String.equal SDV.sd_rand2 SDV.sd_rand2_not_keccak256_empty);
  Alcotest.(check bool) "and NOT blake3 of the same bytes" false
    (String.equal SDV.sd_rand2 SDV.sd_rand2_not_blake3_default_sig)

(* The pre-image column belongs to test/crypto_blst, but its SHAPE does not
   depend on the seam: the byte count is four fixed sections plus the scores,
   so a dropped field shortens it here whatever the hash is. *)
let test_sub_dag_preimage_shape () =
  let row name sd oracle_hex =
    Alcotest.(check int)
      (name ^ ": the pre-image is the oracle's length")
      (String.length oracle_hex / 2)
      (String.length (Sub_dag.preimage sd))
  in
  row "SD1" (sd1 ()) SDV.sd1_preimage;
  row "SD2" (sd2 ()) SDV.sd2_preimage;
  row "SD3" (sd3 ()) SDV.sd3_preimage;
  Alcotest.(check bool) "SD3 differs from SD2 in the oracle's own rows" false
    (String.equal SDV.sd2_preimage SDV.sd3_preimage);
  Alcotest.(check bool) "and in this port's bytes" false
    (String.equal (Sub_dag.preimage (sd2 ())) (Sub_dag.preimage (sd3 ())))

(* SD-NEG is SD2's digest under the old "tn:subdag" domain tag. The oracle rows
   must differ, and this port's pre-image must not begin with the tag. *)
let test_sub_dag_neg_domain_tag () =
  Alcotest.(check bool) "the tagged digest differs from SD2's" false
    (String.equal SDV.sd_neg_digest SDV.sd2_digest);
  Alcotest.(check bool) "the pre-image carries no domain tag" false
    (String.equal
       (span (Sub_dag.preimage (sd2 ())) ~off:0
          ~len:(String.length SDV.sd_neg_domain_tag))
       SDV.sd_neg_domain_tag)

(* {1 Consensus-block rows} *)

let output_digest label h =
  Digests.Output_digest.of_digest (OH.crypto_digest label h)

let number_of n = OH.force "block number" (Cb.Number.of_int n)

let cb1 () =
  Cb.of_persisted
    ~parent_hash:(output_digest "CB1 parent" CBV.cb1_parent_hash)
    ~sub_dag:(sd1 ()) ~number:Cb.Number.genesis
    ~extra:(OH.hash32_of "CB1 extra" CBV.cb1_extra)

let cb2 () =
  Cb.of_persisted
    ~parent_hash:(output_digest "CB2 parent" CBV.cb2_parent_hash)
    ~sub_dag:(sd2 ()) ~number:(number_of 1)
    ~extra:(OH.hash32_of "CB2 extra" CBV.cb2_extra)

(* CB3 is CB2 with a loud [extra]. *)
let cb3 () =
  Cb.of_persisted
    ~parent_hash:(output_digest "CB3 parent" CBV.cb2_parent_hash)
    ~sub_dag:(sd2 ()) ~number:(number_of 1)
    ~extra:(OH.hash32_of "CB3 extra" CBV.cb3_extra)

let test_consensus_block_wire_rows () =
  Alcotest.(check string) "CB1 = the oracle's bytes" CBV.cb1_wire
    (hex (Bcs.encode Cb.codec (cb1 ())));
  Alcotest.(check string) "CB2 = the oracle's bytes" CBV.cb2_wire
    (hex (Bcs.encode Cb.codec (cb2 ())));
  Alcotest.(check string) "CB3 = the oracle's bytes" CBV.cb3_wire
    (hex (Bcs.encode Cb.codec (cb3 ())))

let test_consensus_block_rows_round_trip () =
  let row name h =
    Bcs.decode Cb.codec (OH.of_hex name h)
    |> Result.fold
         ~ok:(fun b ->
           Alcotest.(check string)
             (name ^ " re-encodes to its own bytes")
             h
             (hex (Bcs.encode Cb.codec b)))
         ~error:(fun e -> Alcotest.failf "%s: %s" name (Bcs.error_to_string e))
  in
  row "CB1" CBV.cb1_wire;
  row "CB2" CBV.cb2_wire;
  row "CB3" CBV.cb3_wire

(* CB3 is the positive control for [extra] being carried at all: same digest,
   different bytes. Without it a port that dropped the field entirely would
   pass every other row. *)
let test_extra_is_on_the_wire_and_off_the_digest () =
  Alcotest.(check bool) "the oracle's CB3 and CB2 wires differ" false
    (String.equal CBV.cb2_wire CBV.cb3_wire);
  Alcotest.(check string) "the oracle's CB3 and CB2 digests agree" CBV.cb2_digest
    CBV.cb3_digest;
  Alcotest.(check bool) "this port's CB3 and CB2 wires differ" false
    (String.equal
       (hex (Bcs.encode Cb.codec (cb2 ())))
       (hex (Bcs.encode Cb.codec (cb3 ()))));
  Alcotest.(check string) "and its digests agree"
    (Digests.Output_digest.to_hex (Cb.digest (cb2 ())))
    (Digests.Output_digest.to_hex (Cb.digest (cb3 ())));
  Alcotest.(check string) "CB3's extra survives the round trip" CBV.cb3_extra
    (Hash32.to_hex (Cb.extra (cb3 ())))

(* CB-NEG is CB2's digest over a THREE-field pre-image. The hex belongs to the
   blst executable; what is seam-independent, and asserted here, is that the
   trailing 32 zero bytes are present whatever [extra] holds and that dropping
   them moves the hash. *)
let test_consensus_block_neg_three_field_preimage () =
  Alcotest.(check bool) "the oracle's CB-NEG differs from CB2" false
    (String.equal CBV.cb_neg_digest CBV.cb2_digest);
  let pre = Cb.preimage (cb3 ()) in
  Alcotest.(check int) "the pre-image is 32 + 32 + 8 + 32 bytes" 104
    (String.length pre);
  Alcotest.(check string) "its last 32 bytes are zero, not the loud extra"
    (hex (String.make 32 '\000'))
    (hex (span pre ~off:72 ~len:32));
  Alcotest.(check bool) "dropping them moves the hash" false
    (String.equal
       (Tn_crypto.Digest.to_hex (Tn_crypto.Digest.hash pre))
       (Tn_crypto.Digest.to_hex
          (Tn_crypto.Digest.hash (span pre ~off:0 ~len:72))))

(* The genesis anchor. Its hex is a blake3 value and this port COMPUTES the
   anchor through the seam, so the hex row belongs to the blst executable. What
   is asserted here is the structure Rust fixes: the anchor is the digest of a
   block over a zero parent, the default sub-DAG and number zero — and it is no
   longer the hash of an empty pre-image, which is what this port used before
   the anchor became computed. *)
let default_sub_dag () =
  Sub_dag.of_persisted
    ~headers:(nonempty "genesis sequence" [ OH.h1 () ])
    ~scores:(scores_of [] ~final:false)
    ~stored:Units.Timestamp.zero ~randomness:Sub_dag.default_randomness

let test_genesis_anchor_is_computed_from_the_default_header () =
  let genesis =
    Cb.of_persisted
      ~parent_hash:(output_digest "genesis parent" OH.zeros32)
      ~sub_dag:(default_sub_dag ()) ~number:Cb.Number.genesis
      ~extra:(OH.hash32_of "genesis extra" OH.zeros32)
  in
  Alcotest.(check string) "the anchor is that block's digest"
    (Digests.Output_digest.to_hex (Cb.digest genesis))
    (Digests.Output_digest.to_hex Cb.genesis_parent);
  Alcotest.(check string) "whose sub-DAG randomness is the default-signature one"
    SDV.sd_rand2
    (Hash32.to_hex (Sub_dag.randomness (default_sub_dag ())));
  Alcotest.(check bool) "the anchor is no longer the hash of an empty pre-image"
    false
    (Digests.Output_digest.equal Cb.genesis_parent
       (Digests.Output_digest.of_digest (Tn_crypto.Digest.hash "")));
  (* Non-vacuity: the genesis sub-DAG is NOT SD1. They share every field but
     the randomness, so a port that kept the zero randomness would pass the
     structural row above and fail here. *)
  Alcotest.(check bool) "the genesis sub-DAG differs from SD1" false
    (Digests.Sub_dag_digest.equal
       (Sub_dag.digest (default_sub_dag ()))
       (Sub_dag.digest (sd1 ())));
  Alcotest.(check bool) "as the oracle's own two rows do" false
    (String.equal CBV.cb_genesis_sub_dag_digest SDV.sd1_digest)

(* {1 ChaCha12 leader-swap rows} *)

let draw label rng ~bound =
  Std_rng.random_range_inclusive rng ~bound
  |> Result.fold ~ok:fst ~error:(fun e ->
         Alcotest.failf "%s: %s" label (Std_rng.error_to_string e))

(* One [choose] over L good nodes is [random_range_inclusive ~bound:(L - 1)],
   so the row asserts exactly the draw the leader swap makes. Each row is drawn
   twice: once from the round through {!Std_rng.of_leader_round}, and once from
   the oracle's own seed bytes. If the seed write were wrong the first fails
   while the second passes, which separates a seeding bug from a sampler bug. *)
let test_chacha_swap_rows () =
  List.iter
    (fun (r : CHV.row) ->
      Alcotest.(check int)
        (r.label ^ ": the round seeds the chosen index")
        r.chosen
        (draw r.label (Std_rng.of_leader_round r.round)
           ~bound:(r.good_nodes - 1));
      Alcotest.(check int)
        (r.label ^ ": the oracle's seed bytes give the same index")
        r.chosen
        (draw r.label
           (Std_rng.of_randomness (OH.hash32_of (r.label ^ " seed") r.seed))
           ~bound:(r.good_nodes - 1)))
    CHV.rows

(* The rows must not all agree, or the set would pass for a constant sampler.
   CH1 is the degenerate bound and is excluded: index zero is forced there. *)
let test_chacha_rows_vary () =
  let indices =
    List.filter_map
      (fun (r : CHV.row) ->
        if r.good_nodes > 1 then Some r.chosen else None)
      CHV.rows
  in
  Alcotest.(check bool) "at least two distinct indices across the rows" true
    (List.length (List.sort_uniq Int.compare indices) > 1)

(* CH-NEG. The house SplitMix64 {!Tn_std.Prng} is what this port drew from
   before the fix; if it happened to return the same index the whole ChaCha12
   row set would prove nothing about which RNG is wired in. *)
let test_chacha_neg_house_prng_differs () =
  let ch5 =
    OH.force "CH5"
      (List.find_opt
         (fun (r : CHV.row) -> String.equal r.label "CH5")
         CHV.rows)
  in
  Alcotest.(check int) "the oracle's CH-NEG reference is CH5's index"
    CHV.ch_neg_reference_index ch5.chosen;
  let index, _ =
    Prng.int_in (Prng.of_seed ch5.round) ~lo:0 ~hi:(ch5.good_nodes - 1)
  in
  Alcotest.(check bool) "the house Prng draws a DIFFERENT index" false
    (Int.equal index CHV.ch_neg_reference_index)

let () =
  Alcotest.run "chunk41 byte compat"
    [
      ( "sub-DAG oracle rows",
        [
          Alcotest.test_case "SD-CODEC1/2 = oracle bytes" `Quick
            test_sub_dag_codec_rows;
          Alcotest.test_case "every codec row round-trips" `Quick
            test_sub_dag_codec_rows_round_trip;
          Alcotest.test_case "randomness: bare in the pre-image, prefixed on the wire"
            `Quick
            test_sub_dag_randomness_is_bare_in_the_preimage_and_prefixed_on_the_wire;
          Alcotest.test_case "a bare randomness leg is refused" `Quick
            test_sub_dag_neg_bare_randomness_is_refused;
          Alcotest.test_case "SD-RAND1 keccak256 of the aggregate" `Quick
            test_sub_dag_randomness_is_keccak_of_the_aggregate;
          Alcotest.test_case "SD-RAND2 default-signature fallback" `Quick
            test_sub_dag_default_randomness;
          Alcotest.test_case "the pre-image shape matches the oracle" `Quick
            test_sub_dag_preimage_shape;
          Alcotest.test_case "SD-NEG no domain tag" `Quick
            test_sub_dag_neg_domain_tag;
        ] );
      ( "consensus-block oracle rows",
        [
          Alcotest.test_case "CB1-CB3 = oracle bytes" `Quick
            test_consensus_block_wire_rows;
          Alcotest.test_case "every wire row round-trips" `Quick
            test_consensus_block_rows_round_trip;
          Alcotest.test_case "extra is on the wire and off the digest" `Quick
            test_extra_is_on_the_wire_and_off_the_digest;
          Alcotest.test_case "CB-NEG three-field pre-image" `Quick
            test_consensus_block_neg_three_field_preimage;
          Alcotest.test_case "the genesis anchor is computed" `Quick
            test_genesis_anchor_is_computed_from_the_default_header;
        ] );
      ( "ChaCha12 leader swap",
        [
          Alcotest.test_case "CH1-CH8 draw the oracle's index" `Quick
            test_chacha_swap_rows;
          Alcotest.test_case "the rows vary" `Quick test_chacha_rows_vary;
          Alcotest.test_case "CH-NEG the house Prng disagrees" `Quick
            test_chacha_neg_house_prng_differs;
        ] );
    ]
