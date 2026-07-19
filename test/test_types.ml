(* Foundation tests: crypto stub, scalar invariants, and the committee
   threshold table. The threshold cases are the load-bearing ones — they pin
   the 2f+1 / f+1 formula against the values the Rust node uses. *)

open Tn_types

let unwrap_committee = function
  | Ok c -> c
  | Error e -> Alcotest.failf "committee build failed: %s" (Committee.error_to_string e)

(* Build a committee of [n] distinct authorities from seeds 0..n-1. *)
let committee_of n =
  let auth i =
    let sk = Tn_crypto.Secret_key.derive (Int64.of_int i) in
    Authority.make
      ~protocol_key:(Tn_crypto.Secret_key.public_key sk)
      ~execution_address:Units.Address.zero
  in
  Committee.create ~epoch:Units.Epoch.zero
    (List.init n auth)

(* ---- crypto stub ---- *)

let test_sign_verify () =
  let sk = Tn_crypto.Secret_key.derive 42L in
  let pk = Tn_crypto.Secret_key.public_key sk in
  let sg = Tn_crypto.sign sk "hello" in
  Alcotest.(check bool) "verifies own message" true (Tn_crypto.verify pk "hello" sg);
  Alcotest.(check bool) "rejects other message" false (Tn_crypto.verify pk "world" sg);
  let other = Tn_crypto.Secret_key.public_key (Tn_crypto.Secret_key.derive 43L) in
  Alcotest.(check bool) "rejects other signer" false (Tn_crypto.verify other "hello" sg)

let test_aggregate () =
  let msg = "quorum-message" in
  let sks = List.init 4 (fun i -> Tn_crypto.Secret_key.derive (Int64.of_int i)) in
  let pks = List.map Tn_crypto.Secret_key.public_key sks in
  let agg = Tn_crypto.aggregate (List.map (fun sk -> Tn_crypto.sign sk msg) sks) in
  Alcotest.(check bool) "aggregate verifies for all signers" true
    (Tn_crypto.verify_aggregate pks msg agg);
  Alcotest.(check bool) "aggregate fails on wrong message" false
    (Tn_crypto.verify_aggregate pks "other" agg);
  (* Order independence: reversing the key list must not change the verdict. *)
  Alcotest.(check bool) "order independent" true
    (Tn_crypto.verify_aggregate (List.rev pks) msg agg);
  (* A missing signer must fail. *)
  let short = match pks with _ :: rest -> rest | [] -> [] in
  Alcotest.(check bool) "subset of keys fails (count mismatch)" false
    (Tn_crypto.verify_aggregate short msg agg)

let test_digest_determinism () =
  let a = Tn_crypto.Digest.hash "x" and b = Tn_crypto.Digest.hash "x" in
  Alcotest.(check bool) "hash is deterministic" true (Tn_crypto.Digest.equal a b);
  Alcotest.(check int) "digest is 32 bytes" 32
    (String.length (Tn_crypto.Digest.to_bytes a));
  Alcotest.(check bool) "distinct inputs differ" false
    (Tn_crypto.Digest.equal a (Tn_crypto.Digest.hash "y"))

(* ---- scalars ---- *)

let test_round () =
  Alcotest.(check (option int)) "genesis has no predecessor" None
    (Option.map Round.to_int (Round.pred Round.genesis));
  let r5 = Option.get (Round.of_int 5) in
  Alcotest.(check int) "succ" 6 (Round.to_int (Round.succ r5));
  Alcotest.(check int) "sub saturates at genesis" 0
    (Round.to_int (Round.sub_saturating r5 10));
  Alcotest.(check bool) "u32 range rejects negatives" true
    (Option.is_none (Round.of_int (-1)))

let test_leader_round () =
  let leader r = Option.map Leader_round.schedule_index (Leader_round.of_round (Option.get (Round.of_int r))) in
  Alcotest.(check (option int)) "round 2 -> index 0" (Some 0) (leader 2);
  Alcotest.(check (option int)) "round 4 -> index 1" (Some 1) (leader 4);
  Alcotest.(check (option int)) "odd round has no leader" None (leader 3);
  Alcotest.(check (option int)) "round 0 has no leader" None (leader 0)

let test_sequence_number () =
  let e = Option.get (Units.Epoch.of_int 3) and r = Option.get (Round.of_int 7) in
  let sn = Units.Sequence_number.of_epoch_round e r in
  Alcotest.(check int) "epoch recovered" 3 (Units.Epoch.to_int (Units.Sequence_number.epoch sn));
  Alcotest.(check int) "round recovered" 7 (Round.to_int (Units.Sequence_number.round sn))

(* ---- committee thresholds: the pinned table ---- *)

let threshold_case (n, quorum, validity) () =
  let c = unwrap_committee (committee_of n) in
  Alcotest.(check int) (Printf.sprintf "size %d" n) n (Committee.size c);
  Alcotest.(check int) (Printf.sprintf "quorum %d" n) quorum
    (Units.Stake.to_int (Committee.quorum_threshold c));
  Alcotest.(check int) (Printf.sprintf "validity %d" n) validity
    (Units.Stake.to_int (Committee.validity_threshold c))

let test_committee_rejects () =
  Alcotest.(check bool) "rejects size 1" true (Result.is_error (committee_of 1));
  Alcotest.(check bool) "rejects size 0" true (Result.is_error (committee_of 0));
  (* Duplicate protocol key: same seed twice. *)
  let sk = Tn_crypto.Secret_key.derive 9L in
  let a =
    Authority.make ~protocol_key:(Tn_crypto.Secret_key.public_key sk)
      ~execution_address:Units.Address.zero
  in
  Alcotest.(check bool) "rejects duplicate key" true
    (Result.is_error (Committee.create ~epoch:Units.Epoch.zero [ a; a ]))

let test_committee_ordering () =
  let c = unwrap_committee (committee_of 5) in
  let ids = List.map Authority.id (Committee.authorities c) in
  let sorted = List.sort Authority_id.compare ids in
  Alcotest.(check bool) "authorities are id-sorted" true (ids = sorted);
  (* index_of / nth are inverse over the sorted list. *)
  let ok =
    List.for_all
      (fun i ->
        match Committee.nth c i with
        | Some a -> Committee.index_of c (Authority.id a) = Some i
        | None -> false)
      (List.init 5 Fun.id)
  in
  Alcotest.(check bool) "index_of inverts nth" true ok

let () =
  Alcotest.run "tn_types"
    [
      ( "crypto",
        [
          Alcotest.test_case "sign/verify" `Quick test_sign_verify;
          Alcotest.test_case "aggregate" `Quick test_aggregate;
          Alcotest.test_case "digest determinism" `Quick test_digest_determinism;
        ] );
      ( "scalars",
        [
          Alcotest.test_case "round" `Quick test_round;
          Alcotest.test_case "leader_round" `Quick test_leader_round;
          Alcotest.test_case "sequence_number" `Quick test_sequence_number;
        ] );
      ( "committee",
        [
          Alcotest.test_case "thresholds n=4" `Quick (threshold_case (4, 3, 2));
          Alcotest.test_case "thresholds n=7" `Quick (threshold_case (7, 5, 3));
          Alcotest.test_case "thresholds n=10" `Quick (threshold_case (10, 7, 4));
          Alcotest.test_case "thresholds n=3" `Quick (threshold_case (3, 3, 1));
          Alcotest.test_case "rejects invalid" `Quick test_committee_rejects;
          Alcotest.test_case "ordering" `Quick test_committee_ordering;
        ] );
    ]
