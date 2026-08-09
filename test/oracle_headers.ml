(* The chunk-41 oracle's H1-H6 headers, built from the oracle's FIELD values
   rather than from its bytes, so the encoding is always what is under test.

   Shared the way batch_vectors.ml is: not listed in test/dune's (names ...),
   so dune links it into every test binary. It lives here rather than inside
   test_vertex.ml because the sub-DAG and consensus-block rows are built OVER
   these same headers (SD1 is [H1], SD2 is [H2; H4; H5]), and two hand-typed
   copies of a header set are two things that can drift apart while both stay
   green.

   The field values themselves are documented row by row in header_vectors.ml.
   Unlike that module this one is not pure stdlib: it names {!Tn_vertex} and
   {!Tn_types}, so copying it into an isolated test directory means giving
   that directory the same libraries. *)

open Tn_types
open Tn_vertex

(* Fold, then one tail call: [Option.fold]'s [~none] is eager, so the failure
   has to sit behind a thunk or it would fire on every call. *)
let force label o =
  Option.fold
    ~none:(fun () -> Alcotest.failf "chunk-41 vector %s is malformed" label)
    ~some:(fun v () -> v)
    o ()

let of_hex label h = force label (Hex_bytes.decode h)

let crypto_digest label h =
  force label (Tn_crypto.Digest.of_bytes (of_hex label h))

let batch_digest label h = Digests.Batch_digest.of_digest (crypto_digest label h)

let header_digest label h =
  Digests.Header_digest.of_digest (crypto_digest label h)

let author_of label h = force label (Authority_id.of_bytes (of_hex label h))
let round_of label n = force label (Round.of_int n)
let epoch_of label n = force label (Units.Epoch.of_int n)
let created_of label n = force label (Units.Timestamp.of_sec n)
let worker_of label n = force label (Units.Worker_id.of_int n)
let hash32_of label h = force label (Tn_hash32.Hash32.of_bytes (of_hex label h))

let anchor label ~number ~hash =
  Block_num_hash.make ~number ~hash:(hash32_of label hash)

let zeros32 = String.concat "" (List.init 32 (fun _ -> "00"))
let repeat32 byte = String.concat "" (List.init 32 (fun _ -> byte))

let h1 () =
  Header.make
    ~author:(author_of "H1 author" zeros32)
    ~round:(round_of "H1 round" 0)
    ~epoch:(epoch_of "H1 epoch" 0)
    ~created_at:(created_of "H1 created_at" 0L)
    ~payload:[] ~parents:[]
    ~latest_execution_block:(anchor "H1 anchor" ~number:0L ~hash:zeros32)

let h2 () =
  Header.make
    ~author:(author_of "H2 author" (repeat32 "01"))
    ~round:(round_of "H2 round" 1)
    ~epoch:(epoch_of "H2 epoch" 0)
    ~created_at:(created_of "H2 created_at" 0L)
    ~payload:[] ~parents:[]
    ~latest_execution_block:(anchor "H2 anchor" ~number:0L ~hash:zeros32)

let h3 () =
  Header.make
    ~author:(author_of "H3 author" (repeat32 "01"))
    ~round:(round_of "H3 round" 1)
    ~epoch:(epoch_of "H3 epoch" 7)
    ~created_at:(created_of "H3 created_at" 1_700_000_000L)
    ~payload:
      [ (batch_digest "H3 payload key" (repeat32 "aa"), worker_of "H3 worker" 0) ]
    ~parents:[]
    ~latest_execution_block:(anchor "H3 anchor" ~number:0L ~hash:zeros32)

(* H4's payload keeps INSERTION order (Rust's IndexMap with serde_seq), and its
   two worker ids differ so a dropped id cannot hide. *)
let h4_payload () =
  [
    (batch_digest "H4 payload key 0" (repeat32 "aa"), worker_of "H4 worker 0" 0);
    (batch_digest "H4 payload key 1" (repeat32 "bb"), worker_of "H4 worker 1" 3);
  ]

let h4_parents () =
  [
    header_digest "H4 parent 0" (repeat32 "11");
    header_digest "H4 parent 1" (repeat32 "22");
  ]

let h4 () =
  Header.make
    ~author:(author_of "H4 author" (repeat32 "01"))
    ~round:(round_of "H4 round" 1)
    ~epoch:(epoch_of "H4 epoch" 7)
    ~created_at:(created_of "H4 created_at" 1_700_000_000L)
    ~payload:(h4_payload ()) ~parents:(h4_parents ())
    ~latest_execution_block:(anchor "H4 anchor" ~number:0L ~hash:zeros32)

(* H5 varies BOTH sub-fields of field 7, so neither a dead number nor a dead
   hash can hide behind a zero. *)
let h5 () =
  Header.make
    ~author:(author_of "H5 author" (repeat32 "01"))
    ~round:(round_of "H5 round" 1)
    ~epoch:(epoch_of "H5 epoch" 7)
    ~created_at:(created_of "H5 created_at" 1_700_000_000L)
    ~payload:(h4_payload ()) ~parents:(h4_parents ())
    ~latest_execution_block:
      (anchor "H5 anchor" ~number:0x0102030405060708L ~hash:(repeat32 "cc"))

(* H6 is H4 with the parents PRESENTED descending; canonicalisation must bring
   it back to H4's bytes, which is what pins the BTreeSet ordering. *)
let h6 () =
  Header.make
    ~author:(author_of "H6 author" (repeat32 "01"))
    ~round:(round_of "H6 round" 1)
    ~epoch:(epoch_of "H6 epoch" 7)
    ~created_at:(created_of "H6 created_at" 1_700_000_000L)
    ~payload:(h4_payload ())
    ~parents:(List.rev (h4_parents ()))
    ~latest_execution_block:(anchor "H6 anchor" ~number:0L ~hash:zeros32)
