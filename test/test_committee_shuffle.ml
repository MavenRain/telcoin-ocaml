(* Tests for Tn_evm.Committee_shuffle, the port of shuffle_new_committee
   (block.rs:428-482).

   Every expectation below is DERIVED from the stage-1 golden vectors for
   seed 0x...01 (telcoin-ocaml-chunk32-rand-vectors.json, embedded in
   test_rand.ml), never from running the port on itself. The derivations use
   these pinned facts:

     keystream words 0-7 of seed 0x...01 (test_rand.ml u32_head):
       w0 = 2607801029   w1 = 646719537   w2 = 2099327372   w3 = 2208813800
       w4 = 2086979566   w5 = 2196016427  w6 = 1520627846   w7 = 1264178733

     fisher_yates sections (draw sequence for i = len-1 .. 1, and the
     resulting permutation of 0..len-1):
       len 4: draws [2; 0; 0]    -> shuffled [1; 3; 0; 2]
       len 5: draws [3; 0; 1; 1] -> shuffled [4; 2; 1; 0; 3]

     choose_multiple section: pool 7, amount 3 -> chosen indices [4; 1; 5],
     consuming exactly pool - amount = 4 words (w0-w3).

     the u32 range sampler at inclusive bound b draws
     j = floor(w * (b + 1) / 2^32) from one keystream word w; none of the
     words used here fires Canon's rare second (bias-correction) draw, whose
     per-draw chance is about (b + 1) / 2^32 (test_rand.ml pins the firing
     branch separately). This model is itself pinned by the range_inclusive
     vectors: e.g. at bound 2 the first draw is 1 = floor(w0 * 3 / 2^32), at
     bound 3 it is 2 = floor(w0 * 4 / 2^32).

   Addresses are assigned so that pool ARRIVAL order, address byte order and
   status blocks all disagree: a pool pre-sort, an output sort, a partition
   flip, an ascending Fisher-Yates, an exclusive draw bound, or an RNG-order
   swap each visibly change some expected list below. *)

open Tn_types
module Committee_shuffle = Tn_evm.Committee_shuffle
module Registry_abi = Tn_evm.Registry_abi
module Hash32 = Tn_evm.Hash32

(* ---------- helpers ---------- *)

let hex s =
  let digit c =
    match c with
    | '0' .. '9' -> Char.code c - Char.code '0'
    | 'a' .. 'f' -> Char.code c - Char.code 'a' + 10
    | 'A' .. 'F' -> Char.code c - Char.code 'A' + 10
    | _ -> 0
  in
  String.init
    (String.length s / 2)
    (fun i ->
      Char.chr ((digit (String.get s (2 * i)) lsl 4) lor digit (String.get s ((2 * i) + 1))))

let seed_one =
  match Hash32.of_bytes (hex "0000000000000000000000000000000000000000000000000000000000000001") with
  | Some h -> h
  | None -> Alcotest.fail "seed fixture is not 32 bytes"

(* A 20-byte address of one repeated byte: outputs read as byte labels. *)
let addr b =
  match Units.Address.of_bytes (String.make 20 (Char.chr b)) with
  | Some a -> a
  | None -> Alcotest.fail "20-byte address fixture refused"

let addr_hex a =
  String.concat ""
    (List.map
       (fun c -> Printf.sprintf "%02x" (Char.code c))
       (List.of_seq (String.to_seq (Units.Address.to_bytes a))))

let validator b status =
  match
    Registry_abi.Validator_info.make ~validator_address:(addr b) ~activation_epoch:0
      ~exit_epoch:0 ~current_status:status ~is_retired:false ~stake_version:0 ~region:0
  with
  | Some v -> v
  | None -> Alcotest.fail "validator fixture refused"

let active b = validator b Registry_abi.Validator_status.Active
let pending_activation b = validator b Registry_abi.Validator_status.Pending_activation
let pending_exit b = validator b Registry_abi.Validator_status.Pending_exit

let shuffle_hex ~pool ~committee_size =
  List.map addr_hex
    (Committee_shuffle.shuffle ~pool ~committee_size ~randomness:seed_one)

let expect bytes = List.map (fun b -> addr_hex (addr b)) bytes

(* ---------- A: active side full, vector Fisher-Yates, pending-exit dropped ---------- *)

(* Pool arrival order (statuses interleaved, addresses scrambled vs arrival):
     pos 0: v0 Active           0xa3
     pos 1: p5 PendingExit      0x90
     pos 2: v1 Active           0xa0
     pos 3: v2 PendingActivation 0xa4   <- rides the ACTIVE side
     pos 4: p6 PendingExit      0xff
     pos 5: v3 Active           0xa1
     pos 6: v4 Active           0xa2
   Partition on PendingExit keeps arrival order: active = [v0;v1;v2;v3;v4],
   pending_exit = [p5;p6]. active count 5 >= size 5, so the pending-exit side
   is dropped whole and NO top-up draw is consumed: the Fisher-Yates runs on
   a fresh RNG, which is exactly the len-5 vector section.
   Derivation of shuffled [4;2;1;0;3] from draws [3;0;1;1] over [0;1;2;3;4]:
     i=4 j=3: [0;1;2;4;3]   i=3 j=0: [4;1;2;0;3]
     i=2 j=1: [4;2;1;0;3]   i=1 j=1: unchanged.
   Result [v4;v2;v1;v0;v3] = addresses [0xa2;0xa4;0xa0;0xa3;0xa1]. *)
let test_active_side_full () =
  let pool =
    [ active 0xa3; pending_exit 0x90; active 0xa0; pending_activation 0xa4;
      pending_exit 0xff; active 0xa1; active 0xa2 ]
  in
  Alcotest.(check (list string))
    "vector permutation [4;2;1;0;3] of the active side, pending-exit dropped"
    (expect [ 0xa2; 0xa4; 0xa0; 0xa3; 0xa1 ])
    (shuffle_hex ~pool ~committee_size:5)

(* ---------- B: top-up consumes the RNG BEFORE the shuffle ---------- *)

(* Pool arrival order: a0 (Active, 0x21) at pos 0, a1 (PendingActivation,
   0x0c) at pos 4, and seven PendingExit p0..p6 at 0xd0 0x35 0x77 0x02 0xe1
   0x4a 0x9b. active = [a0;a1] (2 of size 5), so choose_multiple draws
   amount = 3 from the 7 pending-exit FIRST, consuming w0-w3 (the pinned
   pool-7/amount-3 vector): chosen indices [4;1;5] = [p4;p1;p5]. Then
   for_shuffle = [a0;a1;p4;p1;p5] and the Fisher-Yates draws come from the
   ADVANCED stream, words w4-w7:
     i=4: j = floor(w4 * 5 / 2^32) = floor(10434897830 / 2^32) = 2
     i=3: j = floor(w5 * 4 / 2^32) = floor(8784065708 / 2^32)  = 2
     i=2: j = floor(w6 * 3 / 2^32) = floor(4561883538 / 2^32)  = 1
     i=1: j = floor(w7 * 2 / 2^32) = floor(2528357466 / 2^32)  = 0
   Applied to [a0;a1;p4;p1;p5]:
     i=4 j=2: [a0;a1;p5;p1;p4]   i=3 j=2: [a0;a1;p1;p5;p4]
     i=2 j=1: [a0;p1;a1;p5;p4]   i=1 j=0: [p1;a0;a1;p5;p4]
   Addresses [0x35;0x21;0x0c;0x4a;0xe1]. A port that runs the shuffle before
   the top-up (or hands either consumer the other's stream segment) diverges
   here on both membership and order. *)
let test_top_up_before_shuffle () =
  let pool =
    [ active 0x21; pending_exit 0xd0; pending_exit 0x35; pending_exit 0x77;
      pending_activation 0x0c; pending_exit 0x02; pending_exit 0xe1;
      pending_exit 0x4a; pending_exit 0x9b ]
  in
  Alcotest.(check (list string))
    "choose_multiple [4;1;5] on w0-w3, then Fisher-Yates [2;2;1;0] on w4-w7"
    (expect [ 0x35; 0x21; 0x0c; 0x4a; 0xe1 ])
    (shuffle_hex ~pool ~committee_size:5)

(* ---------- C: truncate AFTER the shuffle, and never a sort ---------- *)

(* Four Active validators (addresses scrambled vs arrival: 0xa1 0xa3 0xa0
   0xa2), size 3: the whole active side shuffles (len-4 vector: draws
   [2;0;0] -> shuffled [1;3;0;2]), THEN truncates to 3.
   Derivation over [0;1;2;3]:
     i=3 j=2: [0;1;3;2]   i=2 j=0: [3;1;0;2]   i=1 j=0: [1;3;0;2]
   Result [v1;v3;v0;v2] truncated to [v1;v3;v0] = [0xa3;0xa2;0xa1]: a
   descending-byte list, so ANY sort (before or after the truncate, of the
   pool or of the output) visibly breaks it. *)
let test_truncate_after_shuffle () =
  let pool = [ active 0xa1; active 0xa3; active 0xa0; active 0xa2 ] in
  Alcotest.(check (list string))
    "vector permutation [1;3;0;2] truncated to 3, unsorted"
    (expect [ 0xa3; 0xa2; 0xa1 ])
    (shuffle_hex ~pool ~committee_size:3)

(* ---------- D: an undersized pool is returned whole, no local error ---------- *)

(* Three Active validators at size 5 (block.rs:453-463 has no local size
   check; rejection is the on-chain concludeEpoch call's business). The
   top-up branch runs but choose_multiple over the EMPTY pending-exit side
   selects nothing and consumes NOTHING (stage-1 pinned degenerate), so the
   Fisher-Yates still starts at w0:
     i=2: j = floor(w0 * 3 / 2^32) = floor(7823403087 / 2^32) = 1
     i=1: j = floor(w1 * 2 / 2^32) = floor(1293439074 / 2^32) = 0
   Over [0;1;2]: i=2 j=1: [0;2;1]; i=1 j=0: [2;0;1].
   Result [v2;v0;v1] = [0xa2;0xa0;0xa1]: all three members, shuffled, and
   truncate to 5 is a no-op. *)
let test_undersized_pool_is_whole () =
  let pool = [ active 0xa0; active 0xa1; active 0xa2 ] in
  Alcotest.(check (list string))
    "all three validators come back, shuffled from w0"
    (expect [ 0xa2; 0xa0; 0xa1 ])
    (shuffle_hex ~pool ~committee_size:5)

(* ---------- E: totality at the edges ---------- *)

let test_edges () =
  Alcotest.(check (list string))
    "empty pool shuffles to the empty committee" []
    (shuffle_hex ~pool:[] ~committee_size:5);
  Alcotest.(check (list string))
    "size 0 truncates to empty" []
    (shuffle_hex ~pool:[ active 0xa0; active 0xa1 ] ~committee_size:0);
  Alcotest.(check (list string))
    "a negative size (no Rust image) truncates to empty" []
    (shuffle_hex ~pool:[ active 0xa0; active 0xa1 ] ~committee_size:(-1));
  Alcotest.(check (list string))
    "a singleton pool shuffles to itself"
    (expect [ 0xa0 ])
    (shuffle_hex ~pool:[ active 0xa0 ] ~committee_size:1)

let () =
  Alcotest.run "committee_shuffle"
    [
      ( "shuffle",
        [
          Alcotest.test_case "active side full: vector FY, pending-exit dropped" `Quick
            test_active_side_full;
          Alcotest.test_case "top-up consumes the RNG before the shuffle" `Quick
            test_top_up_before_shuffle;
          Alcotest.test_case "truncate after the shuffle, never a sort" `Quick
            test_truncate_after_shuffle;
          Alcotest.test_case "undersized pool returned whole" `Quick
            test_undersized_pool_is_whole;
          Alcotest.test_case "edges: empty pool, zero and negative size" `Quick test_edges;
        ] );
    ]
