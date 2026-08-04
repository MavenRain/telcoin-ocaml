(* Chunk-38 stage 2: [Tn_execution.Replay], the recovery gap as a value.

   The gap between a resumed node's executed watermark and its durable store's
   tip is collected exactly once, by [Replay.collect], which walks the range
   itself and verifies the hash chain as it goes. These cases pin the four
   things that makes true - the range is HALF-OPEN at the floor, the empty gap
   is an ordinary run rather than a special case, a mid-range miss is fatal
   rather than silently truncating, and a run that is a set of blocks rather
   than a chain is refused at whichever height first breaks the link, floor
   included.

   The fixture is a hand-built four-block chain rather than a simulation: the
   walk reads only numbers, parent digests and bodies, so the cheapest chain
   that is a real one (minted by the same [Consensus_chain] fold the driver
   uses) is the honest fixture. Later stages add their groups to this file. *)

open Tn_types
open Tn_vertex
open Tn_consensus
module Cb = Tn_execution.Consensus_block
module Chain = Tn_execution.Consensus_chain
module Replay = Tn_execution.Replay
module Nonempty = Tn_std.Nonempty

(* Totalise an option under a named expectation; Result.fold keeps both arms
   lazy, where Option.fold's ~none is eager. *)
let get what o =
  Result.fold ~ok:Fun.id ~error:(fun msg -> Alcotest.fail msg)
    (Option.to_result ~none:what o)

let nth what l n = get what (List.nth_opt l n)

(* Substring search as a total fold - no [String.sub], no index. A local copy;
   the shared test prelude that absorbs it arrives with the resume harness. *)
let mentions needle haystack =
  let n = String.length needle in
  List.exists
    (fun start ->
      String.equal needle
        (String.of_seq (Seq.take n (Seq.drop start (String.to_seq haystack)))))
    (List.init (Stdlib.max 0 (String.length haystack - n + 1)) Fun.id)

(* Four validators; nothing here reads an execution address. *)
let committee, sk_of =
  let sks =
    List.init 4 (fun i -> Tn_crypto.Secret_key.derive (Int64.of_int i))
  in
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

(* A one-certificate sub-DAG at [r], as in test_consensus_chain.ml. Stage 3 adds
   the two optional arguments - a sub-DAG that DECLARES payload digests, and one
   whose leader sits in a later epoch - both defaulting to the stage-2 shape, so
   the fixture chain below is exactly what it was. *)
let synthetic_sub_dag ?(epoch = Units.Epoch.zero) ?(payload = []) ~author ~r () =
  let certify header =
    let votes = List.map (fun id -> Vote.sign (sk_of id) ~voter:id header) ids in
    Result.fold ~ok:Fun.id
      ~error:(fun e ->
        Alcotest.failf "certify: %s" (Certificate.error_to_string e))
      (Certificate.assemble committee header votes)
  in
  let header =
    Header.make ~author
      ~round:(get "round" (Round.of_int r))
      ~epoch
      ~created_at:(get "timestamp" (Units.Timestamp.of_sec 55L))
      ~payload
      ~parents:(List.map Certificate.digest (Certificate.genesis committee))
  in
  Sub_dag.create
    ~sequence:(Nonempty.singleton (certify header))
    ~scores:(Reputation_scores.fresh committee)
    ~previous:None

(* The fixture chain: four blocks at heights 1..4, minted by the driver's own
   fold, so the links are real rather than asserted into existence. *)
let blocks =
  let sds =
    List.mapi
      (fun i r -> synthetic_sub_dag ~author:(nth "author" ids (i mod 4)) ~r ())
      [ 1; 2; 3; 4 ]
  in
  let _, rev =
    List.fold_left
      (fun (c, acc) sd ->
        let c', b = Chain.append c sd in
        (c', b :: acc))
      (Chain.genesis, []) sds
  in
  List.rev rev

let b1 = nth "b1" blocks 0
let b2 = nth "b2" blocks 1
let b3 = nth "b3" blocks 2
let b4 = nth "b4" blocks 3

let batch tag =
  Batch.make ~transactions:[ tag ] ~epoch:Units.Epoch.zero
    ~beneficiary:Units.Address.zero
    ~base_fee_per_gas:(Units.Base_fee.of_int64 7L)
    ~worker_id:Units.Worker_id.zero

let ba = batch "\x0a"
let bb = batch "\x0b"
let bc = batch "\x0c"

(* What the store appears to hold. [b3] carries no bodies (an output that
   committed no payload still consumes a height), and [ba] appears under two
   records - a digest under two certificates is one body resolved twice, and the
   run preserves both. *)
let records = [ (b1, [ ba ]); (b2, [ ba; bb ]); (b3, []); (b4, [ ba; bc ]) ]

(* A [fetch] over an explicit record list: total, and the ONLY way a case varies
   what the store appears to hold. *)
let fetch_of recs number =
  List.find_map
    (fun (b, bs) ->
      if Cb.Number.equal (Cb.number b) number then Some (b, bs) else None)
    recs

let full_fetch = fetch_of records
let dhex b = Digests.Output_digest.to_hex (Cb.digest b)
let bhex body = Digests.Batch_digest.to_hex (Batch.digest body)
let heights t =
  List.map (fun b -> Cb.Number.to_int (Cb.number b)) (Replay.blocks t)

(* The same records with the height of [b3] absent. *)
let punctured =
  List.filter
    (fun (b, _) -> not (Cb.Number.equal (Cb.number b) (Cb.number b3)))
    records

let run_of what r =
  Result.fold ~ok:Fun.id
    ~error:(fun b -> Alcotest.failf "%s: %s" what (Replay.break_to_string b))
    r

let break_of what r =
  Result.fold
    ~ok:(fun t ->
      Alcotest.failf "%s: expected a break, got a run of %d records" what
        (Replay.length t))
    ~error:Fun.id r

let hole_number what b =
  match b with
  | Replay.Hole { number } -> number
  | Replay.Broken_link _ ->
      Alcotest.failf "%s: expected a hole, got %s" what
        (Replay.break_to_string b)

let link_parts what b =
  match b with
  | Replay.Broken_link { number; expected; found } -> (number, expected, found)
  | Replay.Hole _ ->
      Alcotest.failf "%s: expected a broken link, got %s" what
        (Replay.break_to_string b)

(* S2.1: a complete chain collected above the executed tip is the half-open
   range (after, upto] - three records, ascending, with the bodies flattened in
   record order and duplicates kept. *)
let test_complete_run () =
  let t =
    run_of "collect over a complete chain"
      (Replay.collect ~after:(Cb.number b1) ~parent:(Cb.digest b1)
         ~upto:(Cb.number b4) ~fetch:full_fetch)
  in
  Alcotest.(check int) "three records, the floor block excluded" 3
    (Replay.length t);
  Alcotest.(check bool) "a three-record run is not empty" false
    (Replay.is_empty t);
  Alcotest.(check int) "after is the executed watermark it was collected above"
    (Cb.Number.to_int (Cb.number b1))
    (Cb.Number.to_int (Replay.after t));
  Alcotest.(check int) "upto is the ceiling it was collected against"
    (Cb.Number.to_int (Cb.number b4))
    (Cb.Number.to_int (Replay.upto t));
  Alcotest.(check (list int)) "heights are dense and ascending, starting at 2"
    [ 2; 3; 4 ] (heights t);
  Alcotest.(check (list string)) "the blocks are b2, b3, b4 in that order"
    [ dhex b2; dhex b3; dhex b4 ]
    (List.map dhex (Replay.blocks t));
  Alcotest.(check (list string)) "the sub-DAGs are those blocks', in order"
    (List.map
       (fun b -> Digests.Sub_dag_digest.to_hex (Sub_dag.digest (Cb.sub_dag b)))
       [ b2; b3; b4 ])
    (List.map
       (fun sd -> Digests.Sub_dag_digest.to_hex (Sub_dag.digest sd))
       (Replay.sub_dags t));
  Alcotest.(check (list string))
    "bodies are the concatenation in record order, duplicates kept"
    [ bhex ba; bhex bb; bhex ba; bhex bc ]
    (List.map bhex (Replay.bodies t));
  Alcotest.(check (list string)) "last is the final block"
    [ dhex b4 ]
    (Option.to_list (Option.map dhex (Replay.last t)))

(* S2.2: a caught-up node collects the empty run, and a stale ceiling below the
   floor collects it too - both report the watermark the node stays at. *)
let test_empty_run () =
  let at_tip =
    run_of "collect with upto = after"
      (Replay.collect ~after:(Cb.number b4) ~parent:(Cb.digest b4)
         ~upto:(Cb.number b4) ~fetch:full_fetch)
  in
  Alcotest.(check bool) "nothing outstanding is an empty run, not an error" true
    (Replay.is_empty at_tip);
  Alcotest.(check int) "the empty run holds no records" 0 (Replay.length at_tip);
  Alcotest.(check (list int)) "the empty run has no blocks" [] (heights at_tip);
  Alcotest.(check (list string)) "the empty run has no bodies" []
    (List.map bhex (Replay.bodies at_tip));
  Alcotest.(check (list string)) "the empty run has no last block" []
    (Option.to_list (Option.map dhex (Replay.last at_tip)));
  Alcotest.(check int) "upto equals after on the empty run"
    (Cb.Number.to_int (Replay.after at_tip))
    (Cb.Number.to_int (Replay.upto at_tip));
  let below =
    run_of "collect with upto below after"
      (Replay.collect ~after:(Cb.number b4) ~parent:(Cb.digest b4)
         ~upto:(Cb.number b2) ~fetch:full_fetch)
  in
  Alcotest.(check bool) "a ceiling below the floor is empty too" true
    (Replay.is_empty below);
  Alcotest.(check int) "the stale ceiling is normalised away, not carried"
    (Cb.Number.to_int (Cb.number b4))
    (Cb.Number.to_int (Replay.upto below));
  Alcotest.(check int) "after is unchanged by the normalisation"
    (Cb.Number.to_int (Cb.number b4))
    (Cb.Number.to_int (Replay.after below))

(* S2.3: a height missing from the middle of the range is a Hole naming exactly
   that height - never a shortened success. *)
let test_mid_range_hole () =
  let br =
    break_of "collect over a punctured range"
      (Replay.collect ~after:(Cb.number b1) ~parent:(Cb.digest b1)
         ~upto:(Cb.number b4) ~fetch:(fetch_of punctured))
  in
  Alcotest.(check int) "the hole names the missing height"
    (Cb.Number.to_int (Cb.number b3))
    (Cb.Number.to_int (hole_number "punctured range" br))

(* S2.4: a block that links to some other block rather than to its predecessor
   breaks the run at its own height, naming the digest it should have carried. *)
let test_broken_link_mid_range () =
  let forged =
    Cb.create ~parent_hash:(Cb.digest b2) ~sub_dag:(Cb.sub_dag b4)
      ~number:(Cb.number b4)
  in
  let br =
    break_of "collect over a mislinked chain"
      (Replay.collect ~after:(Cb.number b1) ~parent:(Cb.digest b1)
         ~upto:(Cb.number b4)
         ~fetch:
           (fetch_of [ (b1, [ ba ]); (b2, [ ba; bb ]); (b3, []); (forged, []) ]))
  in
  let number, expected, found = link_parts "mislinked chain" br in
  Alcotest.(check int) "the break names the mislinked height"
    (Cb.Number.to_int (Cb.number b4))
    (Cb.Number.to_int number);
  Alcotest.(check string) "expected is the predecessor's digest" (dhex b3)
    (Digests.Output_digest.to_hex expected);
  Alcotest.(check string) "found is the digest it actually links to" (dhex b2)
    (Digests.Output_digest.to_hex found)

(* S2.5: the floor link is checked against the caller's stated parent, so a
   checkpoint and a store from two different runs cannot be spliced. *)
let test_broken_link_at_floor () =
  let br =
    break_of "collect against a foreign parent"
      (Replay.collect ~after:(Cb.number b1) ~parent:(Cb.digest b4)
         ~upto:(Cb.number b4) ~fetch:full_fetch)
  in
  let number, expected, found = link_parts "foreign parent" br in
  Alcotest.(check int) "the break is at the first collected height"
    (Cb.Number.to_int (Cb.number b2))
    (Cb.Number.to_int number);
  Alcotest.(check string) "expected is the parent the caller stated" (dhex b4)
    (Digests.Output_digest.to_hex expected);
  Alcotest.(check string) "found is the real predecessor's digest" (dhex b1)
    (Digests.Output_digest.to_hex found)

(* S2.6: both arms render the offending height. The needle carries the word
   before the number so a hex digit inside a rendered digest cannot satisfy it
   vacuously. *)
let test_break_rendering () =
  let hole =
    Replay.break_to_string
      (break_of "hole"
         (Replay.collect ~after:(Cb.number b1) ~parent:(Cb.digest b1)
            ~upto:(Cb.number b4) ~fetch:(fetch_of punctured)))
  in
  let link =
    Replay.break_to_string
      (break_of "broken link"
         (Replay.collect ~after:(Cb.number b1) ~parent:(Cb.digest b4)
            ~upto:(Cb.number b4) ~fetch:full_fetch))
  in
  Alcotest.(check bool) "the hole rendering names its height" true
    (mentions ("block " ^ Cb.Number.to_string (Cb.number b3)) hole);
  Alcotest.(check bool) "the broken-link rendering names its height" true
    (mentions ("block " ^ Cb.Number.to_string (Cb.number b2)) link);
  Alcotest.(check bool) "the two arms render differently" false
    (String.equal hole link);
  Alcotest.(check bool) "the broken-link rendering carries both digests" true
    (mentions (dhex b4) link && mentions (dhex b1) link)

(* ------------------------------------------------------------------------ *)
(* Chunk-38 stage 3: [Tn_execution.Consensus_store], the durable seam and its
   in-memory reference.

   Two groups. The first pins the reference itself: a record's bodies are
   DERIVED from its own header, the write side is gapless and hash-linked and
   idempotent-but-not-blind, an epoch roll retains the read space, a missing
   height is diagnosed rather than collapsed, and the recovery read derives both
   of its ends. The second is the seam's own evidence: the same records fed
   through a second, independently written implementation (assoc_store.ml) must
   answer every one of those questions identically. *)

module Store = Tn_execution.Consensus_store

(* A height as a value, built the only way [Number] allows - from the genesis
   anchor by [succ]. Total: no [of_int], no index, no arithmetic. *)
let number_of i =
  List.fold_left
    (fun n _ -> Cb.Number.succ n)
    Cb.Number.genesis
    (List.init (Stdlib.max 0 i) Fun.id)

let payload_of bodies =
  List.map (fun b -> (Batch.digest b, Units.Worker_id.zero)) bodies

(* A body lookup over an explicit list: the ONLY thing a case varies about what
   the worker tier can still answer. *)
let lookup_of bodies digest =
  List.find_opt
    (fun b -> Digests.Batch_digest.equal (Batch.digest b) digest)
    bodies

let record_of what ~lookup block =
  Result.fold ~ok:Fun.id
    ~error:(fun e ->
      Alcotest.failf "%s: %s" what (Store.Record.error_to_string e))
    (Store.Record.create ~consensus:block ~lookup)

let rhex r = Digests.Output_digest.to_hex (Store.Record.digest r)

let store_ok what r =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "%s: %s" what (Store.error_to_string e))
    r

let store_error what r =
  Result.fold
    ~ok:(fun t ->
      Alcotest.failf "%s: expected a refusal, got a store of %d" what
        (Store.cardinal t))
    ~error:Fun.id r

let miss_of what r =
  Result.fold
    ~ok:(fun _ -> Alcotest.failf "%s: expected a miss, got an answer" what)
    ~error:Fun.id r

let run_ok what r =
  Result.fold ~ok:Fun.id
    ~error:(fun m -> Alcotest.failf "%s: %s" what (Store.miss_to_string m))
    r

(* One projector per arm, each exhaustive over the five write refusals, so a new
   arm breaks every case that cares rather than silently widening a wildcard. *)
let not_next_parts what e =
  match e with
  | Store.Not_next { expected; got } -> (expected, got)
  | Store.Broken_chain _ | Store.Conflicting_record _ | Store.Wrong_epoch _
  | Store.Epoch_not_advanced _ ->
      Alcotest.failf "%s: expected Not_next, got %s" what
        (Store.error_to_string e)

let broken_chain_parts what e =
  match e with
  | Store.Broken_chain { expected; got } -> (expected, got)
  | Store.Not_next _ | Store.Conflicting_record _ | Store.Wrong_epoch _
  | Store.Epoch_not_advanced _ ->
      Alcotest.failf "%s: expected Broken_chain, got %s" what
        (Store.error_to_string e)

let conflict_parts what e =
  match e with
  | Store.Conflicting_record { number; stored; offered } ->
      (number, stored, offered)
  | Store.Not_next _ | Store.Broken_chain _ | Store.Wrong_epoch _
  | Store.Epoch_not_advanced _ ->
      Alcotest.failf "%s: expected Conflicting_record, got %s" what
        (Store.error_to_string e)

let wrong_epoch_parts what e =
  match e with
  | Store.Wrong_epoch { open_epoch; offered } -> (open_epoch, offered)
  | Store.Not_next _ | Store.Broken_chain _ | Store.Conflicting_record _
  | Store.Epoch_not_advanced _ ->
      Alcotest.failf "%s: expected Wrong_epoch, got %s" what
        (Store.error_to_string e)

let not_advanced_parts what e =
  match e with
  | Store.Epoch_not_advanced { open_epoch; proposed } -> (open_epoch, proposed)
  | Store.Not_next _ | Store.Broken_chain _ | Store.Conflicting_record _
  | Store.Wrong_epoch _ ->
      Alcotest.failf "%s: expected Epoch_not_advanced, got %s" what
        (Store.error_to_string e)

let below_parts what m =
  match m with
  | Store.Below_retained { earliest; asked } -> (earliest, asked)
  | Store.Above_tip _ | Store.Forked _ | Store.Broken _ ->
      Alcotest.failf "%s: expected Below_retained, got %s" what
        (Store.miss_to_string m)

let above_parts what m =
  match m with
  | Store.Above_tip { expected_next; asked } -> (expected_next, asked)
  | Store.Below_retained _ | Store.Forked _ | Store.Broken _ ->
      Alcotest.failf "%s: expected Above_tip, got %s" what
        (Store.miss_to_string m)

let forked_parts what m =
  match m with
  | Store.Forked { number; stored; offered } -> (number, stored, offered)
  | Store.Below_retained _ | Store.Above_tip _ | Store.Broken _ ->
      Alcotest.failf "%s: expected Forked, got %s" what (Store.miss_to_string m)

(* Three bodies DECLARED in an order that is deliberately not their sorted
   order: a derivation that follows the header and one that re-sorts by digest
   disagree on this fixture and agree on every weaker one. *)
let sorted_three =
  List.sort
    (fun x y -> Digests.Batch_digest.compare (Batch.digest x) (Batch.digest y))
    [ ba; bb; bc ]

let declared_three = List.rev sorted_three

let three_sub_dag =
  synthetic_sub_dag
    ~epoch:(Units.Epoch.succ Units.Epoch.zero)
    ~payload:(payload_of declared_three)
    ~author:(nth "author" ids 0) ~r:9 ()

let three_block =
  Cb.create ~parent_hash:Cb.genesis_parent ~sub_dag:three_sub_dag
    ~number:(number_of 1)

(* S3.1: the record derives its bodies from the block's own sub-DAG, in the
   header's declared commit order, and its epoch from the same sub-DAG. *)
let test_record_derives_bodies () =
  Alcotest.(check bool)
    "the fixture's declared order is not its sorted order, so the case can tell \
     them apart"
    false
    (List.equal
       (fun x y -> String.equal (bhex x) (bhex y))
       declared_three sorted_three);
  let r =
    record_of "three bodies" ~lookup:(lookup_of declared_three) three_block
  in
  Alcotest.(check (list string)) "bodies follow the header's declared order"
    (List.map bhex declared_three)
    (List.map bhex (Store.Record.bodies r));
  Alcotest.(check (list string))
    "which is exactly the sub-DAG's own payload sequence"
    (List.map Digests.Batch_digest.to_hex
       (Sub_dag.payload_digests three_sub_dag))
    (List.map bhex (Store.Record.bodies r));
  Alcotest.(check string) "the epoch is the sub-DAG's leader epoch"
    (Units.Epoch.to_string (Sub_dag.leader_epoch three_sub_dag))
    (Units.Epoch.to_string (Store.Record.epoch r));
  Alcotest.(check bool) "and it is not the zero an unread field would answer"
    false
    (Units.Epoch.equal (Store.Record.epoch r) Units.Epoch.zero);
  Alcotest.(check string) "the record's digest is the block's" (dhex three_block)
    (rhex r);
  Alcotest.(check int) "and its number is the block's height"
    (Cb.Number.to_int (Cb.number three_block))
    (Cb.Number.to_int (Store.Record.number r))

(* S3.2: a lookup that cannot supply one declared digest yields the refusal
   naming it, and no partial record at all. *)
let test_record_refuses_partial () =
  let missing = nth "the second declared body" declared_three 1 in
  let supplied =
    List.filter (fun b -> not (String.equal (bhex b) (bhex missing)))
      declared_three
  in
  let e =
    Result.fold
      ~ok:(fun r ->
        Alcotest.failf "expected a refusal, got a record of %d bodies"
          (List.length (Store.Record.bodies r)))
      ~error:Fun.id
      (Store.Record.create ~consensus:three_block
         ~lookup:(lookup_of supplied))
  in
  let named = match e with Store.Record.Missing_body d -> d in
  Alcotest.(check string) "the refusal names the digest the lookup could not \
                           supply"
    (bhex missing)
    (Digests.Batch_digest.to_hex named);
  Alcotest.(check bool) "and its rendering carries that digest" true
    (mentions (bhex missing) (Store.Record.error_to_string e));
  Alcotest.(check bool) "and names neither of the two it could" false
    (mentions (bhex (nth "first" declared_three 0))
       (Store.Record.error_to_string e)
    || mentions
         (bhex (nth "third" declared_three 2))
         (Store.Record.error_to_string e))

(* Stage 3's own chain: four blocks whose sub-DAGs DECLARE their payloads, so a
   record's bodies come from its header rather than from an empty list. Minted
   by the same [Consensus_chain] fold the driver uses, from the cold-start
   accumulator, so block 1 links to [genesis_parent] as a real chain's does. *)
let store_payloads = [ [ ba ]; [ ba; bb ]; []; [ bc ] ]

let store_sub_dags =
  List.mapi
    (fun i bodies ->
      synthetic_sub_dag
        ~payload:(payload_of bodies)
        ~author:(nth "author" ids (i mod 4))
        ~r:(21 + i) ())
    store_payloads

let store_blocks =
  let _, rev =
    List.fold_left
      (fun (c, acc) sd ->
        let c', b = Chain.append c sd in
        (c', b :: acc))
      (Chain.genesis, []) store_sub_dags
  in
  List.rev rev

let sb1 = nth "sb1" store_blocks 0
let sb2 = nth "sb2" store_blocks 1
let sb3 = nth "sb3" store_blocks 2
let sb4 = nth "sb4" store_blocks 3
let all_bodies = [ ba; bb; bc ]
let record_at_block what b = record_of what ~lookup:(lookup_of all_bodies) b
let r1 = record_at_block "r1" sb1
let r2 = record_at_block "r2" sb2
let r3 = record_at_block "r3" sb3
let r4 = record_at_block "r4" sb4

let genesis_store =
  Store.create ~epoch:Units.Epoch.zero ~anchor:Cb.Number.genesis
    ~parent:Cb.genesis_parent

let filled records =
  store_ok "filling the store"
    (List.fold_left
       (fun acc record -> Result.bind acc (fun s -> Store.receive s record))
       (Ok genesis_store) records)

(* S3.3: the write side is strictly gapless - the next slot or nothing. *)
let test_receive_is_gapless () =
  Alcotest.(check int) "an empty store expects the start it was opened at"
    (Cb.Number.to_int (Cb.number sb1))
    (Cb.Number.to_int (Store.expected_next genesis_store));
  let one = store_ok "receive at the expected slot" (Store.receive genesis_store r1) in
  Alcotest.(check int) "the accepted record is retained" 1 (Store.cardinal one);
  Alcotest.(check int) "and the store now expects one past it"
    (Cb.Number.to_int (Cb.Number.succ (Cb.number sb1)))
    (Cb.Number.to_int (Store.expected_next one));
  let e =
    store_error "receive one slot too high" (Store.receive genesis_store r2)
  in
  let expected, got = not_next_parts "one slot too high" e in
  Alcotest.(check int) "the refusal names the slot the store expects"
    (Cb.Number.to_int (Cb.number sb1))
    (Cb.Number.to_int expected);
  Alcotest.(check int) "and the slot it was offered"
    (Cb.Number.to_int (Cb.number sb2))
    (Cb.Number.to_int got);
  Alcotest.(check int) "the refused write left the store alone" 0
    (Store.cardinal genesis_store)

(* S3.4: and hash-linked - a record that links anywhere but the tip is refused,
   which is the premise [Replay.collect]'s induction rests on. *)
let test_receive_checks_the_link () =
  let adrift =
    Cb.create ~parent_hash:(Cb.digest sb4) ~sub_dag:(Cb.sub_dag sb1)
      ~number:(Cb.number sb1)
  in
  let e =
    store_error "receive a record linking past the anchor"
      (Store.receive genesis_store (record_at_block "adrift" adrift))
  in
  let expected, got = broken_chain_parts "past the anchor" e in
  Alcotest.(check string) "an empty store's link is the epoch anchor"
    (Digests.Output_digest.to_hex Cb.genesis_parent)
    (Digests.Output_digest.to_hex expected);
  Alcotest.(check string) "and the refusal names what the record carried"
    (dhex sb4)
    (Digests.Output_digest.to_hex got);
  let one = filled [ r1 ] in
  let skips =
    Cb.create ~parent_hash:Cb.genesis_parent ~sub_dag:(Cb.sub_dag sb2)
      ~number:(Cb.number sb2)
  in
  let e2 =
    store_error "receive a record linking past the tip"
      (Store.receive one (record_at_block "skips" skips))
  in
  let expected2, got2 = broken_chain_parts "past the tip" e2 in
  Alcotest.(check string) "a filled store's link is its tip's digest" (dhex sb1)
    (Digests.Output_digest.to_hex expected2);
  Alcotest.(check string) "and the refusal names what that record carried"
    (Digests.Output_digest.to_hex Cb.genesis_parent)
    (Digests.Output_digest.to_hex got2)

(* S3.5: a shell's post-crash retry of the identical record is a plain success
   that changes nothing. *)
let test_resubmission_is_idempotent () =
  let one = filled [ r1 ] in
  let again = store_ok "re-receive the identical record" (Store.receive one r1) in
  Alcotest.(check int) "cardinal is unchanged by the retry" (Store.cardinal one)
    (Store.cardinal again);
  Alcotest.(check int) "and the retry is not a second entry" 1
    (Store.cardinal again);
  Alcotest.(check (list string)) "latest_received is the same record"
    (List.map rhex (Option.to_list (Store.latest_received one)))
    (List.map rhex (Option.to_list (Store.latest_received again)));
  Alcotest.(check int) "and the store expects the same next slot"
    (Cb.Number.to_int (Store.expected_next one))
    (Cb.Number.to_int (Store.expected_next again))

(* S3.6: but a DIFFERENT block at an occupied number is a fork, not a no-op -
   the deliberate strengthening of upstream's blind skip. *)
let test_conflicting_record () =
  let one = filled [ r1 ] in
  let rival =
    Cb.create ~parent_hash:Cb.genesis_parent
      ~sub_dag:(synthetic_sub_dag ~author:(nth "author" ids 1) ~r:31 ())
      ~number:(Cb.number sb1)
  in
  Alcotest.(check bool) "the rival really is a different block" false
    (String.equal (dhex rival) (dhex sb1));
  let e =
    store_error "receive a rival at an occupied slot"
      (Store.receive one (record_at_block "rival" rival))
  in
  let number, stored, offered = conflict_parts "rival" e in
  Alcotest.(check int) "the refusal names the contested height"
    (Cb.Number.to_int (Cb.number sb1))
    (Cb.Number.to_int number);
  Alcotest.(check string) "stored is what the store already holds" (dhex sb1)
    (Digests.Output_digest.to_hex stored);
  Alcotest.(check string) "offered is what the writer brought" (dhex rival)
    (Digests.Output_digest.to_hex offered)

(* S3.7: the epoch guard on the write side, the strict-advance guard on the
   roll, and the roll's retention of the whole read space. *)
let test_epoch_roll () =
  let four = filled [ r1; r2; r3; r4 ] in
  let one_epoch = Units.Epoch.succ Units.Epoch.zero in
  let next_block =
    Cb.create ~parent_hash:(Cb.digest sb4)
      ~sub_dag:
        (synthetic_sub_dag ~epoch:one_epoch ~author:(nth "author" ids 0) ~r:41 ())
      ~number:(Cb.Number.succ (Cb.number sb4))
  in
  let next_record = record_at_block "the first record of epoch 1" next_block in
  let e =
    store_error "receive an epoch-1 record into an epoch-0 store"
      (Store.receive four next_record)
  in
  let open_epoch, offered = wrong_epoch_parts "the epoch guard" e in
  Alcotest.(check string) "the refusal names the open epoch"
    (Units.Epoch.to_string Units.Epoch.zero)
    (Units.Epoch.to_string open_epoch);
  Alcotest.(check string) "and the one it was offered"
    (Units.Epoch.to_string one_epoch)
    (Units.Epoch.to_string offered);
  let stale =
    store_error "reopen at the epoch already open"
      (Store.open_epoch four ~epoch:Units.Epoch.zero)
  in
  let held, proposed = not_advanced_parts "a stale roll" stale in
  Alcotest.(check string) "the roll refusal names the open epoch"
    (Units.Epoch.to_string Units.Epoch.zero)
    (Units.Epoch.to_string held);
  Alcotest.(check string) "and the epoch that failed to advance"
    (Units.Epoch.to_string Units.Epoch.zero)
    (Units.Epoch.to_string proposed);
  let rolled =
    store_ok "roll to epoch 1" (Store.open_epoch four ~epoch:one_epoch)
  in
  Alcotest.(check int) "every prior record is RETAINED across the roll"
    (Store.cardinal four) (Store.cardinal rolled);
  Alcotest.(check int) "all four of them" 4 (Store.cardinal rolled);
  Alcotest.(check string) "epoch_parent is the old tip's digest" (dhex sb4)
    (Digests.Output_digest.to_hex (Store.epoch_parent rolled));
  Alcotest.(check int) "epoch_start is one past the old tip"
    (Cb.Number.to_int (Cb.Number.succ (Cb.number sb4)))
    (Cb.Number.to_int (Store.epoch_start rolled));
  Alcotest.(check string) "and the open epoch is the one asked for"
    (Units.Epoch.to_string one_epoch)
    (Units.Epoch.to_string (Store.epoch rolled));
  let five =
    store_ok "receive the epoch-1 record after the roll"
      (Store.receive rolled next_record)
  in
  Alcotest.(check (list bool))
    "and the read space still spans the boundary, 1 through 5"
    [ true; true; true; true; true ]
    (List.map
       (fun i -> Result.is_ok (Store.record_at five (number_of i)))
       [ 1; 2; 3; 4; 5 ])

(* A store opened ABOVE genesis, so there is a retained floor to be below.
   [Chain.resume] is the accumulator a restarted node derives from its store. *)
let high_anchor = Cb.digest sb4

let high_blocks =
  let _, rev =
    List.fold_left
      (fun (c, acc) sd ->
        let c', b = Chain.append c sd in
        (c', b :: acc))
      (Chain.resume ~parent:high_anchor ~number:(number_of 2), [])
      (List.map
         (fun r -> synthetic_sub_dag ~author:(nth "author" ids 0) ~r ())
         [ 51; 52 ])
  in
  List.rev rev

let hb1 = nth "hb1" high_blocks 0
let hb2 = nth "hb2" high_blocks 1
let high_records = List.map (record_at_block "a high record") high_blocks

let high_store =
  store_ok "the store opened above genesis"
    (List.fold_left
       (fun acc record -> Result.bind acc (fun s -> Store.receive s record))
       (Ok
          (Store.create ~epoch:Units.Epoch.zero ~anchor:(number_of 2)
             ~parent:high_anchor))
       high_records)

(* S3.8: the four diagnoses are kept apart. A lost log and a stale checkpoint
   reach opposite conclusions from the same shaped symptom. *)
let test_record_at_diagnoses () =
  List.iter
    (fun i ->
      let m =
        miss_of "an empty store" (Store.record_at genesis_store (number_of i))
      in
      let bound, asked = above_parts "an empty store" m in
      Alcotest.(check int) "an empty store answers with its own bound"
        (Cb.Number.to_int (Store.expected_next genesis_store))
        (Cb.Number.to_int bound);
      Alcotest.(check int) "and echoes the ask" i (Cb.Number.to_int asked))
    [ 0; 1; 2; 9 ];
  Alcotest.(check int) "the high store retains exactly two records" 2
    (Store.cardinal high_store);
  Alcotest.(check (list int)) "at heights three and four" [ 3; 4 ]
    (List.map
       (fun b -> Cb.Number.to_int (Cb.number b))
       high_blocks);
  let below =
    below_parts "below the floor"
      (miss_of "below the floor" (Store.record_at high_store (number_of 2)))
  in
  Alcotest.(check int) "earliest is the lowest height retained" 3
    (Cb.Number.to_int (fst below));
  Alcotest.(check int) "and the ask is echoed" 2 (Cb.Number.to_int (snd below));
  let at_bound =
    above_parts "at the bound"
      (miss_of "at the bound" (Store.record_at high_store (number_of 5)))
  in
  Alcotest.(check int) "expected_next is one past the tip" 5
    (Cb.Number.to_int (fst at_bound));
  Alcotest.(check int) "and the ask is echoed" 5
    (Cb.Number.to_int (snd at_bound));
  let far =
    above_parts "far above the bound"
      (miss_of "far above the bound" (Store.record_at high_store (number_of 9)))
  in
  Alcotest.(check int) "the bound is the store's, never the ask" 5
    (Cb.Number.to_int (fst far));
  Alcotest.(check int) "and the ask is echoed" 9 (Cb.Number.to_int (snd far))

(* S3.9: the recovery read derives BOTH ends - the floor from the caller's
   executed block, the ceiling from the store's own tip. *)
let test_gap_is_the_recovery_read () =
  let three = filled [ r1; r2; r3 ] in
  let from_nothing = run_ok "gap from nothing" (Store.gap three ~after:None) in
  Alcotest.(check int) "a node that executed nothing replays the whole store" 3
    (Replay.length from_nothing);
  Alcotest.(check (list string)) "the run is the store's blocks, ascending"
    [ dhex sb1; dhex sb2; dhex sb3 ]
    (List.map dhex (Replay.blocks from_nothing));
  Alcotest.(check (list string))
    "carrying their bodies in record order, duplicates kept"
    (List.map bhex (List.concat (List.filteri (fun i _ -> i < 3) store_payloads)))
    (List.map bhex (Replay.bodies from_nothing));
  Alcotest.(check int) "the ceiling is the store's tip, not one past it"
    (Cb.Number.to_int (Cb.number sb3))
    (Cb.Number.to_int (Replay.upto from_nothing));
  let above_two = run_ok "gap above block 2" (Store.gap three ~after:(Some sb2)) in
  Alcotest.(check int) "a node executed through 2 replays only what is above it"
    1 (Replay.length above_two);
  Alcotest.(check (list string)) "which is block 3 alone" [ dhex sb3 ]
    (List.map dhex (Replay.blocks above_two));
  Alcotest.(check int) "the floor is the executed block's own height"
    (Cb.Number.to_int (Cb.number sb2))
    (Cb.Number.to_int (Replay.after above_two));
  let caught_up = run_ok "gap at the tip" (Store.gap three ~after:(Some sb3)) in
  Alcotest.(check bool) "a caught-up node replays nothing" true
    (Replay.is_empty caught_up);
  Alcotest.(check int) "and stays where it is"
    (Cb.Number.to_int (Cb.number sb3))
    (Cb.Number.to_int (Replay.upto caught_up))

(* S3.9b, the finding-3 pin: a store opened above genesis anchors its
   from-nothing recovery read at its OWN floor. When [create] hard-coded the
   genesis anchor, this exact call walked from height 1 into [Broken (Hole _)] -
   corruption vocabulary for a well-formed store. *)
let test_gap_from_nothing_above_genesis () =
  let run =
    run_ok "gap from nothing on the high store"
      (Store.gap high_store ~after:None)
  in
  Alcotest.(check int)
    "a node that executed nothing replays every record the high store retains"
    2 (Replay.length run);
  Alcotest.(check (list int)) "which are the retained heights, ascending"
    [ 3; 4 ] (heights run);
  Alcotest.(check int) "the floor is the store's own anchor, not genesis" 2
    (Cb.Number.to_int (Replay.after run));
  Alcotest.(check int) "and the ceiling is its tip" 4
    (Cb.Number.to_int (Replay.upto run))

(* S3.10: the floor is checked by DIGEST, which is the one place a checkpoint
   and a store from two different runs are caught. *)
let test_gap_catches_a_fork () =
  let three = filled [ r1; r2; r3 ] in
  let rival =
    Cb.create ~parent_hash:(Cb.digest sb1)
      ~sub_dag:(synthetic_sub_dag ~author:(nth "author" ids 2) ~r:61 ())
      ~number:(Cb.number sb2)
  in
  Alcotest.(check bool) "the rival really is a different block at that height"
    false
    (String.equal (dhex rival) (dhex sb2));
  let number, stored, offered =
    forked_parts "a foreign floor"
      (miss_of "a foreign floor" (Store.gap three ~after:(Some rival)))
  in
  Alcotest.(check int) "the fork names the height both claim"
    (Cb.Number.to_int (Cb.number sb2))
    (Cb.Number.to_int number);
  Alcotest.(check string) "stored is the store's own record there" (dhex sb2)
    (Digests.Output_digest.to_hex stored);
  Alcotest.(check string) "offered is the checkpoint's block" (dhex rival)
    (Digests.Output_digest.to_hex offered)

(* S3.11: the seam as evidence. Everything the signature promises, rendered to
   strings so two implementations with two unrelated [t] types can be compared
   at all, at every prefix of the same record list. *)
module Profile (St : Store.S) = struct
  let render_record r =
    Printf.sprintf "record %s at %s" (rhex r)
      (Cb.Number.to_string (Store.Record.number r))

  let render_run run =
    String.concat "|"
      [
        String.concat "," (List.map dhex (Replay.blocks run));
        String.concat "," (List.map bhex (Replay.bodies run));
        Cb.Number.to_string (Replay.upto run);
      ]

  let profile t ~asks ~afters =
    [
      Printf.sprintf "cardinal %d" (St.cardinal t);
      Printf.sprintf "expected_next %s"
        (Cb.Number.to_string (St.expected_next t));
      Printf.sprintf "earliest %s"
        (Option.fold ~none:"none" ~some:Cb.Number.to_string (St.earliest t));
      Printf.sprintf "latest %s"
        (Option.fold ~none:"none" ~some:render_record (St.latest_received t));
    ]
    @ List.map
        (fun n ->
          Result.fold ~ok:render_record ~error:Store.miss_to_string
            (St.record_at t n))
        asks
    @ List.map
        (fun after ->
          Result.fold ~ok:render_run ~error:Store.miss_to_string
            (St.gap t ~after))
        afters

  let prefix ~anchor ~parent records k =
    List.fold_left
      (fun acc record ->
        Result.bind acc (fun s ->
            Result.map_error St.error_to_string (St.receive s record)))
      (Ok (St.create ~epoch:Units.Epoch.zero ~anchor ~parent))
      (List.filteri (fun i _ -> i < k) records)

  (* [prefix], rolled to [epoch] and continued with [more]: the shape the
     rolled-store conformance rows profile. *)
  let rolled ~anchor ~parent ~epoch ~more records k =
    List.fold_left
      (fun acc record ->
        Result.bind acc (fun s ->
            Result.map_error St.error_to_string (St.receive s record)))
      (Result.bind (prefix ~anchor ~parent records k) (fun s ->
           Result.map_error St.error_to_string (St.open_epoch s ~epoch)))
      more
end

module Reference_profile = Profile (Store)
module Assoc_profile = Profile (Assoc_store.Assoc)

let test_seam_conformance () =
  let asks = List.map number_of [ 0; 1; 2; 3; 4; 5; 6 ] in
  let afters = None :: List.map Option.some [ sb1; sb2; sb3; sb4 ] in
  let records = [ r1; r2; r3; r4 ] in
  let both =
    List.map
      (fun k ->
        ( k,
          Result.fold
            ~ok:(fun s -> Reference_profile.profile s ~asks ~afters)
            ~error:(fun m -> Alcotest.failf "reference prefix %d: %s" k m)
            (Reference_profile.prefix ~anchor:Cb.Number.genesis
               ~parent:Cb.genesis_parent records k),
          Result.fold
            ~ok:(fun s -> Assoc_profile.profile s ~asks ~afters)
            ~error:(fun m -> Alcotest.failf "assoc prefix %d: %s" k m)
            (Assoc_profile.prefix ~anchor:Cb.Number.genesis
               ~parent:Cb.genesis_parent records k) ))
      [ 0; 1; 2; 3; 4 ]
  in
  List.iter
    (fun (k, reference, assoc) ->
      Alcotest.(check (list string))
        (Printf.sprintf "the two implementations agree at prefix %d" k)
        reference assoc)
    both;
  (* A differential whose observation never moves is vacuously true, so the
     profile must distinguish all five prefixes before its agreement means
     anything. *)
  Alcotest.(check int) "the profile tells the five prefixes apart" 5
    (List.length
       (List.sort_uniq (List.compare String.compare)
          (List.map (fun (_, reference, _) -> reference) both)))

(* The finding-3 pin, differentially: the from-nothing recovery read on a store
   opened ABOVE genesis goes through BOTH implementations, so neither can drift
   back to a genesis-seeded anchor without disagreeing with the other. *)
let test_seam_conformance_above_genesis () =
  let asks = List.map number_of [ 1; 2; 3; 4; 5 ] in
  let afters = None :: List.map Option.some [ hb1; hb2 ] in
  let both =
    List.map
      (fun k ->
        ( k,
          Result.fold
            ~ok:(fun s -> Reference_profile.profile s ~asks ~afters)
            ~error:(fun m -> Alcotest.failf "reference high prefix %d: %s" k m)
            (Reference_profile.prefix ~anchor:(number_of 2)
               ~parent:high_anchor high_records k),
          Result.fold
            ~ok:(fun s -> Assoc_profile.profile s ~asks ~afters)
            ~error:(fun m -> Alcotest.failf "assoc high prefix %d: %s" k m)
            (Assoc_profile.prefix ~anchor:(number_of 2) ~parent:high_anchor
               high_records k) ))
      [ 0; 1; 2 ]
  in
  List.iter
    (fun (k, reference, assoc) ->
      Alcotest.(check (list string))
        (Printf.sprintf
           "the two implementations agree above genesis at prefix %d" k)
        reference assoc)
    both;
  Alcotest.(check int) "the high profile tells the three prefixes apart" 3
    (List.length
       (List.sort_uniq (List.compare String.compare)
          (List.map (fun (_, reference, _) -> reference) both)))

(* The finding-5 anchor pin, differentially: the roll's anchor recurrence is
   exactly the logic the two implementations now derive differently (the
   reference maintains three fields, Assoc re-derives two from its ceiling),
   and no unit test reads [gap ~after:None] AFTER a roll - so without these
   rows the reference could drop its anchor recurrence entirely and every
   suite stay green. One extra row crosses the epoch boundary, so the rolled
   write path (link and slot both re-derived) is compared too. *)
let test_seam_conformance_after_roll () =
  let one_epoch = Units.Epoch.succ Units.Epoch.zero in
  let next_block =
    Cb.create ~parent_hash:(Cb.digest sb4)
      ~sub_dag:
        (synthetic_sub_dag ~epoch:one_epoch ~author:(nth "author" ids 0) ~r:43
           ())
      ~number:(Cb.Number.succ (Cb.number sb4))
  in
  let next_record =
    record_at_block "the epoch-1 conformance record" next_block
  in
  let asks = List.map number_of [ 0; 1; 2; 3; 4; 5; 6 ] in
  let afters = None :: List.map Option.some [ sb1; sb2; sb3; sb4; next_block ] in
  let records = [ r1; r2; r3; r4 ] in
  let pair ~more k =
    ( Result.fold
        ~ok:(fun s -> Reference_profile.profile s ~asks ~afters)
        ~error:(fun m -> Alcotest.failf "reference rolled prefix %d: %s" k m)
        (Reference_profile.rolled ~anchor:Cb.Number.genesis
           ~parent:Cb.genesis_parent ~epoch:one_epoch ~more records k),
      Result.fold
        ~ok:(fun s -> Assoc_profile.profile s ~asks ~afters)
        ~error:(fun m -> Alcotest.failf "assoc rolled prefix %d: %s" k m)
        (Assoc_profile.rolled ~anchor:Cb.Number.genesis
           ~parent:Cb.genesis_parent ~epoch:one_epoch ~more records k) )
  in
  let rolled_only = List.map (fun k -> (k, pair ~more:[] k)) [ 0; 1; 2; 3; 4 ] in
  List.iter
    (fun (k, (reference, assoc)) ->
      Alcotest.(check (list string))
        (Printf.sprintf
           "the two implementations agree on the rolled store at prefix %d" k)
        reference assoc)
    rolled_only;
  let crossed_ref, crossed_assoc = pair ~more:[ next_record ] 4 in
  Alcotest.(check (list string))
    "and agree across the epoch boundary" crossed_ref crossed_assoc;
  Alcotest.(check int) "the rolled profile tells the six shapes apart" 6
    (List.length
       (List.sort_uniq
          (List.compare String.compare)
          (crossed_ref
          :: List.map (fun (_, (reference, _)) -> reference) rolled_only)))

let () =
  Alcotest.run "consensus_store"
    [
      ( "the replay run",
        [
          Alcotest.test_case "a complete chain collects half-open" `Quick
            test_complete_run;
          Alcotest.test_case "nothing outstanding is the empty run" `Quick
            test_empty_run;
          Alcotest.test_case "a mid-range miss is a hole, not a prefix" `Quick
            test_mid_range_hole;
          Alcotest.test_case "a mislinked block breaks the run" `Quick
            test_broken_link_mid_range;
          Alcotest.test_case "the floor link is checked against the caller"
            `Quick test_broken_link_at_floor;
          Alcotest.test_case "both break arms name their height" `Quick
            test_break_rendering;
        ] );
      ( "the durable seam",
        [
          Alcotest.test_case "a record derives its bodies from its own header"
            `Quick test_record_derives_bodies;
          Alcotest.test_case "an unresolvable digest files no partial record"
            `Quick test_record_refuses_partial;
          Alcotest.test_case "the write side is strictly gapless" `Quick
            test_receive_is_gapless;
          Alcotest.test_case "and hash-linked to its own tip" `Quick
            test_receive_checks_the_link;
          Alcotest.test_case "an identical resubmission is a no-op success"
            `Quick test_resubmission_is_idempotent;
          Alcotest.test_case "a different block at an occupied slot is a fork"
            `Quick test_conflicting_record;
          Alcotest.test_case "an epoch roll retains the whole read space" `Quick
            test_epoch_roll;
          Alcotest.test_case "a missed height is diagnosed, not collapsed"
            `Quick test_record_at_diagnoses;
          Alcotest.test_case "the recovery read derives both of its ends" `Quick
            test_gap_is_the_recovery_read;
          Alcotest.test_case "a store above genesis anchors at its own floor"
            `Quick test_gap_from_nothing_above_genesis;
          Alcotest.test_case "and catches a floor from another run" `Quick
            test_gap_catches_a_fork;
        ] );
      ( "the seam, differentially",
        [
          Alcotest.test_case "a second implementation answers identically"
            `Quick test_seam_conformance;
          Alcotest.test_case "and identically on a store above genesis" `Quick
            test_seam_conformance_above_genesis;
          Alcotest.test_case "and identically across an epoch roll" `Quick
            test_seam_conformance_after_roll;
        ] );
    ]
