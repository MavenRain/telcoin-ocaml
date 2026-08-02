(* Chunk-37 stage 3: the subscriber's receive arm.

   [Tn_driver.Subscriber.receive] is mint-first-then-attach: the consensus
   block's (parent, number) is decided from the accumulator at receipt,
   before any body is looked up (subscriber.rs:367-371), and attachment goes
   through the frozen [Output.attach] with [Batch_store.find] as its lookup.
   Fixtures are hand-built sub-DAGs in test_engine.ml's chain-builder style
   (a real committee with DISTINCT execution addresses, real certificates,
   leader last); nothing here hardcodes a consensus parent, because minting
   the parent is exactly what is under test. *)

open Tn_types
open Tn_vertex
open Tn_consensus
module Cb = Tn_execution.Consensus_block
module Chain = Tn_execution.Consensus_chain
module Nonempty = Tn_std.Nonempty
module Output = Tn_batch.Output
module Subscriber = Tn_driver.Subscriber
module Batch_store = Tn_driver.Batch_store
module Address_book = Tn_driver.Address_book

(* Totalise an option under a named expectation; Result.fold keeps both arms
   lazy, where Option.fold's ~none is eager. *)
let get what o =
  Result.fold ~ok:Fun.id
    ~error:(fun msg -> Alcotest.fail msg)
    (Option.to_result ~none:what o)

let nth what l n = get what (List.nth_opt l n)
let mk_addr c = get "address" (Units.Address.of_bytes (String.make 20 c))

(* Four validators, each with its own execution address, so an id resolved to
   the WRONG seat's address cannot pass (no constant-valued fixture). *)
let member_addresses =
  [ mk_addr '\xa0'; mk_addr '\xa1'; mk_addr '\xa2'; mk_addr '\xa3' ]

let committee, sk_of =
  let sks =
    List.init 4 (fun i -> Tn_crypto.Secret_key.derive (Int64.of_int i))
  in
  let authorities =
    List.mapi
      (fun i sk ->
        Authority.make
          ~protocol_key:(Tn_crypto.Secret_key.public_key sk)
          ~execution_address:(nth "member address" member_addresses i))
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

(* The address table as the tested Address_book value (design patch P10). *)
let book = Address_book.of_committee committee

(* The same book with ONE id unresolvable: the T3.4 divergence probe. *)
let address_of_missing missing id =
  if Authority_id.equal id missing then None else Address_book.find book id

let ts n = get "timestamp" (Units.Timestamp.of_sec n)
let round n = get "round" (Round.of_int n)
let genesis_parents = List.map Certificate.digest (Certificate.genesis committee)

let certify header =
  let votes = List.map (fun id -> Vote.sign (sk_of id) ~voter:id header) ids in
  Result.fold ~ok:Fun.id
    ~error:(fun e ->
      Alcotest.failf "certify: %s" (Certificate.error_to_string e))
    (Certificate.assemble committee header votes)

(* One committed sub-DAG. [entries] is (author, payload) in header order with
   the LEADER LAST, which is the shape [Sub_dag] commits and the reason [at]
   (the leader's creation time) is the output's commit timestamp. *)
let sub_dag_on ~r ~at entries =
  let n = List.length entries in
  let headers_rev, _ =
    List.fold_left
      (fun (acc, parents) (i, (author, payload)) ->
        let created_at =
          if i = n - 1 then ts at else ts (Int64.of_int (10 + i))
        in
        let header =
          Header.make ~author ~round:(round (r + i)) ~epoch:Units.Epoch.zero
            ~created_at ~payload ~parents
        in
        (header :: acc, [ Header.digest header ]))
      ([], genesis_parents)
      (List.mapi (fun i entry -> (i, entry)) entries)
  in
  let sequence =
    get "certificates" (Nonempty.of_list (List.rev_map certify headers_rev))
  in
  Sub_dag.create ~sequence
    ~scores:(Reputation_scores.fresh committee)
    ~previous:None

let w0 = Units.Worker_id.zero
let fee n = Units.Base_fee.of_int64 (Int64.of_int n)

(* Distinct transaction lists, so the two digests differ. The bytes are
   placeholders (the engine records them as skipped, risk R4): what the
   subscriber underwrites is threading, not execution. *)
let body_a =
  Batch.make ~transactions:[ "\x01" ] ~epoch:Units.Epoch.zero
    ~beneficiary:(mk_addr '\xb1') ~base_fee_per_gas:(fee 7) ~worker_id:w0

let body_b =
  Batch.make
    ~transactions:[ "\x02"; "\x03" ]
    ~epoch:Units.Epoch.zero ~beneficiary:(mk_addr '\xb2')
    ~base_fee_per_gas:(fee 7) ~worker_id:w0

let receive_ok what s sd ~bodies =
  Result.fold ~ok:Fun.id
    ~error:(fun e ->
      Alcotest.failf "%s: %s" what (Subscriber.error_to_string e))
    (Subscriber.receive s sd ~bodies ~address_of:(Address_book.find book))

(* Fold a sub-DAG list through the subscriber, returning the final subscriber
   and the minted blocks in chain order. *)
let fold_receive s sds ~bodies =
  let final, rev_blocks =
    List.fold_left
      (fun (s, acc) sd ->
        let s', block, _ = receive_ok "fold" s sd ~bodies in
        (s', block :: acc))
      (s, []) sds
  in
  (final, List.rev rev_blocks)

(* T3.1: a store missing one payload digest makes receive return
   Error (Attach (Missing_batch d)) naming that EXACT digest. Structurally, no
   subscriber state comes back at all: the Error arm carries the error and
   nothing else, so a caller cannot resume past the violation. *)
let test_missing_batch () =
  let sd =
    sub_dag_on ~r:1 ~at:55L
      [ (id0, [ (Batch.digest body_a, w0); (Batch.digest body_b, w0) ]) ]
  in
  let bodies = Batch_store.of_bodies [ body_a ] in
  Result.fold
    ~ok:(fun (_, block, _) ->
      Alcotest.failf "receive succeeded at number %s despite the missing body"
        (Cb.Number.to_string (Cb.number block)))
    ~error:(fun (Subscriber.Attach e) ->
      match e with
      | Output.Missing_batch d ->
          Alcotest.(check string) "the error names the exact missing digest"
            (Digests.Batch_digest.to_hex (Batch.digest body_b))
            (Digests.Batch_digest.to_hex d)
      | Output.Unknown_authority a ->
          Alcotest.failf "expected Missing_batch, got Unknown_authority %s"
            (Authority_id.to_hex a))
    (Subscriber.receive
       (Subscriber.create Chain.genesis)
       sd ~bodies
       ~address_of:(Address_book.find book))

(* T3.2: ONE digest under TWO headers resolves TWICE (H17/H18): the flat
   digest list keeps both references and both certified entries carry that
   same body, mirroring the subscriber's duplicate-clone rather than a
   BTreeSet's dedup. *)
let test_duplicate_resolves_twice () =
  let payload = [ (Batch.digest body_a, w0) ] in
  let sd = sub_dag_on ~r:1 ~at:56L [ (id0, payload); (id1, payload) ] in
  let bodies = Batch_store.of_bodies [ body_a ] in
  let _, _, output =
    receive_ok "duplicate" (Subscriber.create Chain.genesis) sd ~bodies
  in
  Alcotest.(check int) "the flat digest list keeps both references" 2
    (List.length (Output.batch_digests output));
  Alcotest.(check bool) "both flat entries are that one digest" true
    (List.for_all
       (Digests.Batch_digest.equal (Batch.digest body_a))
       (Output.batch_digests output));
  let entries = Output.certified output in
  Alcotest.(check int) "two certified entries, one per header" 2
    (List.length entries);
  Alcotest.(check bool) "each certified entry carries that same body once" true
    (List.for_all
       (fun (_, bs) ->
         List.length bs = 1 && List.for_all (Batch.equal body_a) bs)
       entries)

(* T3.3: over a mixed list of empty and non-empty outputs the minted numbers
   are dense 1..n (H1: an empty output consumes a number exactly like a full
   one) and every block links to its predecessor's digest (the P5 chain-link
   assertion, with an executable kill). *)
let test_dense_numbers_and_links () =
  let bodies = Batch_store.of_bodies [ body_a; body_b ] in
  let sds =
    [
      sub_dag_on ~r:1 ~at:55L [ (id0, []) ];
      sub_dag_on ~r:2 ~at:56L [ (id1, [ (Batch.digest body_a, w0) ]) ];
      sub_dag_on ~r:3 ~at:57L [ (id0, []) ];
      sub_dag_on ~r:4 ~at:58L [ (id1, [ (Batch.digest body_b, w0) ]) ];
    ]
  in
  let final, blocks = fold_receive (Subscriber.create Chain.genesis) sds ~bodies in
  Alcotest.(check (list int))
    "numbers are dense 1,2,3,4 across the empty/non-empty mix" [ 1; 2; 3; 4 ]
    (List.map (fun b -> Cb.Number.to_int (Cb.number b)) blocks);
  let (_ : Digests.Output_digest.t) =
    List.fold_left
      (fun expected b ->
        Alcotest.(check bool) "block links to its predecessor's digest" true
          (Digests.Output_digest.equal (Cb.parent_hash b) expected);
        Cb.digest b)
      Cb.genesis_parent blocks
  in
  Alcotest.(check int) "the subscriber's number is the last minted" 4
    (Cb.Number.to_int (Subscriber.number final))

(* T3.4: an address_of returning None for one header author gives
   Error (Attach (Unknown_authority a)) EVEN on an all-empty output, pinning
   the port's known stricter divergence (divergence 3): telcoin resolves no
   address at all on an all-empty output (subscriber.rs:439-442), the port
   resolves every author unconditionally. The unknown author is a NON-leader
   header so the pin is about header resolution, not the leader lookup. *)
let test_unknown_authority_on_empty () =
  let sd = sub_dag_on ~r:1 ~at:59L [ (id0, []); (id1, []) ] in
  Result.fold
    ~ok:(fun (_, _, _) ->
      Alcotest.fail
        "the port must resolve every header author, even on an all-empty \
         output (a future relaxation has to turn this red deliberately)")
    ~error:(fun (Subscriber.Attach e) ->
      match e with
      | Output.Unknown_authority a ->
          Alcotest.(check string) "the error names the unresolved author"
            (Authority_id.to_hex id0) (Authority_id.to_hex a)
      | Output.Missing_batch d ->
          Alcotest.failf "expected Unknown_authority, got Missing_batch 0x%s"
            (Digests.Batch_digest.to_hex d))
    (Subscriber.receive
       (Subscriber.create Chain.genesis)
       sd ~bodies:Batch_store.empty
       ~address_of:(address_of_missing id0))

(* T3.5: the minted consensus digests for a given sub-DAG list are IDENTICAL
   under two batch stores that differ in extra bodies (L2-F15). Honest
   scope: today this differential CANNOT fail - [Consensus_chain.append]'s
   type has no body parameter, so body-independence of the mint is a fact of
   the type, not of any runtime path this test could catch misbehaving. It
   is kept as a tripwire: the day a body-parameterised mint appears, this is
   the case that must be turned red deliberately. *)
let test_body_independent_mint () =
  let sds =
    [
      sub_dag_on ~r:1 ~at:60L [ (id0, [ (Batch.digest body_a, w0) ]) ];
      sub_dag_on ~r:2 ~at:61L [ (id1, []) ];
    ]
  in
  let mint bodies =
    let _, blocks = fold_receive (Subscriber.create Chain.genesis) sds ~bodies in
    List.map (fun b -> Digests.Output_digest.to_hex (Cb.digest b)) blocks
  in
  let exact = Batch_store.of_bodies [ body_a ] in
  let extra = Batch_store.of_bodies [ body_a; body_b ] in
  Alcotest.(check bool) "the two stores genuinely differ" true
    (Batch_store.cardinal extra > Batch_store.cardinal exact);
  Alcotest.(check (list string))
    "minted consensus digests are identical under the two stores" (mint exact)
    (mint extra)

let () =
  Alcotest.run "driver_subscriber"
    [
      ( "receive",
        [
          Alcotest.test_case "a missing body fails naming its digest" `Quick
            test_missing_batch;
          Alcotest.test_case "one digest under two headers resolves twice"
            `Quick test_duplicate_resolves_twice;
          Alcotest.test_case "empty outputs consume numbers and links hold"
            `Quick test_dense_numbers_and_links;
          Alcotest.test_case "an unknown author halts even on an empty output"
            `Quick test_unknown_authority_on_empty;
          Alcotest.test_case "the mint never reads the body store" `Quick
            test_body_independent_mint;
        ] );
    ]
