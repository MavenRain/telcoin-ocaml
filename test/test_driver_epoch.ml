(* Chunk-37 stage 5: the epoch handoff - seal, refuse, boundary rule, and
   the registry close proven by FIXTURE (D9), whatever the sim later does.

   The driver folds committed outputs over the REAL ConsensusRegistry world
   ([Registry_genesis], the 28,381-byte testnet bytecode plus its storage
   dump) and committees over the five testnet validator execution addresses
   (chain-configs/testnet/committee.yaml), so the closing block's registry
   system calls run against the state they were deployed for. The spec runs
   a 100 s epoch from genesis second 1, and the closing output deliberately
   OVERSHOOTS the first boundary (commit 108 vs boundary 101), so the two
   candidate boundary rules - closed_at + duration (H9) and
   previous_boundary + duration - differ by 7 s and T5.2 can tell them
   apart behaviourally (G4). T4.7's P7 honesty carries over: the one
   transaction here is a placeholder the decode layer drops, so nothing in
   this file leans on a fee credit. *)

open Tn_types
open Tn_vertex
open Tn_consensus
module Bf = Block_fixtures
module Cb = Tn_execution.Consensus_block
module Nonempty = Tn_std.Nonempty
module Output = Tn_batch.Output
module Driver = Tn_driver.Driver
module Outcome = Tn_driver.Outcome
module Batch_store = Tn_driver.Batch_store
module Chain_spec = Tn_driver.Chain_spec
module Epoch_duration = Tn_driver.Chain_spec.Epoch_duration
module Address_book = Tn_driver.Address_book
module Engine = Tn_engine.Engine
module Block_number = Tn_engine.Block_number
module Executed_block = Tn_engine.Executed_block
module Block_header = Tn_evm.Block_header
module Withdrawal = Tn_evm.Withdrawal
module Rewards_counter = Tn_evm.Rewards_counter
module System_contracts = Tn_evm.System_contracts
module Account = Tn_state.Account
module Storage = Tn_state.Storage
module U256 = Tn_state.U256
module World = Tn_state.World_state

(* Totalise an option under a named expectation; Result.fold keeps both arms
   lazy, where Option.fold's ~none is eager. *)
let get what o =
  Result.fold ~ok:Fun.id
    ~error:(fun msg -> Alcotest.fail msg)
    (Option.to_result ~none:what o)

let nth what l n = get what (List.nth_opt l n)
let last what l = nth what l (List.length l - 1)
let mk_addr c = get "address" (Units.Address.of_bytes (String.make 20 c))
let ts n = get "timestamp" (Units.Timestamp.of_sec n)
let round n = get "round" (Round.of_int n)
let w0 = Units.Worker_id.zero
let fee n = Units.Base_fee.of_int64 (Int64.of_int n)

(* The five testnet validator execution addresses, verbatim from
   chain-configs/testnet/committee.yaml (as in test_engine_epoch.ml): the
   fixture registry knows exactly these, so whichever of them leads an
   output, the closing block's withdrawal names a registered validator. *)
let validator_addresses =
  List.map
    (fun h -> get "validator address" (Units.Address.of_bytes (Bf.hex h)))
    [
      "0033a370616805b1fd275b7ffab83fc41d665ccb";
      "89dab9f6fdc569c1bcdbd6493f25b7040b55dc79";
      "3518b301b86ceb53b5a3dff62e55cd43ef59d024";
      "efaacf04b92298a88200aa50aa6bb7bfce587b17";
      "7489025dfbaad94f2366d88a62989147d9c8b5d3";
    ]

(* One committee's worth of machinery. Two chains over the SAME validator
   addresses and DIFFERENT protocol keys model successive committees the
   registry pays at the same seats. *)
type chain = {
  cmt : Committee.t;
  certify : Header.t -> Certificate.t;
  parents : Digests.Header_digest.t list;
}

let build_chain ~seed ~epoch =
  let sks =
    List.mapi
      (fun i _ -> Tn_crypto.Secret_key.derive (Int64.of_int (seed + i)))
      validator_addresses
  in
  let authorities =
    List.mapi
      (fun i sk ->
        Authority.make
          ~protocol_key:(Tn_crypto.Secret_key.public_key sk)
          ~execution_address:(nth "validator address" validator_addresses i))
      sks
  in
  let cmt =
    Result.fold ~ok:Fun.id
      ~error:(fun e ->
        Alcotest.failf "committee: %s" (Committee.error_to_string e))
      (Committee.create ~epoch authorities)
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
  let ids = List.map Authority.id (Committee.authorities cmt) in
  let certify header =
    let votes =
      List.map (fun id -> Vote.sign (sk_of id) ~voter:id header) ids
    in
    Result.fold ~ok:Fun.id
      ~error:(fun e ->
        Alcotest.failf "certify: %s" (Certificate.error_to_string e))
      (Certificate.assemble cmt header votes)
  in
  {
    cmt;
    certify;
    parents = List.map Certificate.digest (Certificate.genesis cmt);
  }

let epoch0 = Units.Epoch.zero
let epoch1 = Units.Epoch.succ Units.Epoch.zero
let chain_now = build_chain ~seed:500 ~epoch:epoch0
let chain_next = build_chain ~seed:600 ~epoch:epoch1

(* Both epochs' authors resolve through ONE monotone book (P10): the two
   committees share their execution addresses but not their ids. *)
let address_of =
  Address_book.find
    (Address_book.union
       (Address_book.of_committee chain_now.cmt)
       (Address_book.of_committee chain_next.cmt))

let seat ch i = nth "seat" (Committee.authorities ch.cmt) i
let leader ch i = Authority.id (seat ch i)
let leader_address ch i = Authority.execution_address (seat ch i)

(* One committed sub-DAG on [ch]. [entries] is (author, payload) in header
   order with the LEADER LAST, which is the shape [Sub_dag] commits and the
   reason [at] (the leader's creation time) is the output's commit
   timestamp. *)
let sub_dag_on ch ~epoch ~r ~at entries =
  let n = List.length entries in
  let headers_rev, _ =
    List.fold_left
      (fun (acc, parents) (i, (author, payload)) ->
        let created_at =
          if i = n - 1 then ts at else ts (Int64.of_int (10 + i))
        in
        let header =
          Header.make ~latest_execution_block:Tn_types.Block_num_hash.zero ~author ~round:(round (r + i)) ~epoch ~created_at
            ~payload ~parents
        in
        (header :: acc, [ Header.digest header ]))
      ([], ch.parents)
      (List.mapi (fun i entry -> (i, entry)) entries)
  in
  let sequence =
    get "certificates" (Nonempty.of_list (List.rev_map ch.certify headers_rev))
  in
  Sub_dag.create ~sequence
    ~scores:(Reputation_scores.fresh ch.cmt)
    ~previous:None

(* The one batch here is a placeholder the decode layer drops before the
   block (P7 as tightened by test_engine_txskip T-35): what stage 5
   underwrites is the handoff, never transaction validity. *)
let body_e =
  Batch.make ~transactions:[ "\x06" ] ~epoch:epoch0
    ~beneficiary:(mk_addr '\xb5') ~base_fee_per_gas:(fee 7) ~worker_id:w0

let bodies = Batch_store.of_bodies [ body_e ]

(* ---------- the spec: real registry world, 100 s epochs ---------- *)

let u256_int n = get "u256" (U256.of_int n)
let u256_hex s = get "word" (U256.of_hex s)

let registry_entry =
  Tn_state.Genesis_account.make ~nonce:Tn_state.Nonce.zero
    ~balance:
      (get "balance"
         (U256.of_hex
            (String.make (64 - String.length Registry_genesis.balance_hex) '0'
           ^ Registry_genesis.balance_hex)))
    ~code:(Some (Bf.hex Registry_genesis.code_hex))
    ~storage:
      (List.map
         (fun (s, v) -> (u256_hex s, u256_hex v))
         Registry_genesis.storage_hex)

let genesis_hash = Tn_keccak.digest "chunk-37 epoch handoff genesis sentinel"
let basefee_address = mk_addr '\xbe'
let duration_100 = get "epoch duration" (Epoch_duration.of_secs 100)

(* Genesis at second 1 with a 100 s epoch puts the FIRST boundary at 101;
   the closing output commits at 108, a 7 s overshoot, so the two candidate
   next boundaries - closed_at + 100 = 208 (H9) and first_boundary + 100 =
   201 - genuinely differ (G4). *)
let spec =
  Result.fold ~ok:Fun.id
    ~error:(fun e ->
      Alcotest.failf "chain spec: %s" (Chain_spec.error_to_string e))
    (Chain_spec.create ~chain_id:(u256_int 2017) ~basefee_address
       ~genesis_hash ~genesis_base_fee:(u256_int 7)
       ~genesis_gas_limit:30_000_000 ~genesis_timestamp:(ts 1L)
       ~epoch_duration:duration_100 ~registry:registry_entry ~extra_alloc:[]
       ())

let driver0 () = Driver.create spec ~committee:chain_now.cmt

(* The epoch-0 stream: two empty mid-epoch outputs crediting seats 0 and 1,
   then an empty output at 108 that crosses the 101 boundary and closes the
   epoch. Counts at the close: seat 0 led twice (o1 and the closing
   output), seat 1 once, nobody else at all. *)
let o1 () =
  sub_dag_on chain_now ~epoch:epoch0 ~r:1 ~at:55L [ (leader chain_now 0, []) ]

let o2 () =
  sub_dag_on chain_now ~epoch:epoch0 ~r:3 ~at:60L [ (leader chain_now 1, []) ]

let o3 () =
  sub_dag_on chain_now ~epoch:epoch0 ~r:5 ~at:108L [ (leader chain_now 0, []) ]

(* Epoch-1 outputs: one batch committed at 207 - one second SHORT of the
   H9 boundary 208, but past the wrong rule's 201 - then an empty one at
   208, exactly ON the boundary ([>=], not [>]). *)
let o4 () =
  sub_dag_on chain_next ~epoch:epoch1 ~r:7 ~at:207L
    [ (leader chain_next 2, [ (Batch.digest body_e, w0) ]) ]

let o5 () =
  sub_dag_on chain_next ~epoch:epoch1 ~r:9 ~at:208L
    [ (leader chain_next 3, []) ]

let step_ok what d sd =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "%s: %s" what (Outcome.error_to_string e))
    (Driver.step d sd ~bodies ~address_of)

let fold_ok what d sds =
  match Driver.fold d sds ~bodies ~address_of with
  | Outcome.Advance { driver; advances } -> (driver, advances)
  | Outcome.Sealed { driver = _; advances = _; rest } ->
      Alcotest.failf "%s: sealed with %d outputs unconsumed" what
        (List.length rest)
  | Outcome.Halted { advances = _; error } ->
      Alcotest.failf "%s: %s" what (Outcome.error_to_string error)

(* A fold expected to end SEALED: the sealed driver, the executed prefix
   and the unconsumed suffix. *)
let fold_sealed what d sds =
  match Driver.fold d sds ~bodies ~address_of with
  | Outcome.Sealed { driver; advances; rest } -> (driver, advances, rest)
  | Outcome.Advance { driver = _; advances } ->
      Alcotest.failf "%s: still running after %d advances" what
        (List.length advances)
  | Outcome.Halted { advances = _; error } ->
      Alcotest.failf "%s: %s" what (Outcome.error_to_string error)

let sealed_driver () =
  let d, advances, rest =
    fold_sealed "epoch-0 fold" (driver0 ()) [ o1 (); o2 (); o3 () ]
  in
  Alcotest.(check int) "the epoch-0 stream is consumed to the end" 0
    (List.length rest);
  (d, advances)

let begin_ok what d cmt =
  Result.fold ~ok:Fun.id
    ~error:(fun e ->
      Alcotest.failf "%s: %s" what (Driver.handoff_error_to_string e))
    (Driver.begin_epoch d ~committee:cmt)

(* The rendered refusal, or ["ok"] when there was none: a string comparison
   rather than a three-arm match, and it names what the refusal is about. *)
let handoff_outcome r =
  Result.fold ~ok:(fun _ -> "ok") ~error:Driver.handoff_error_to_string r

let withdrawals block = Block_header.withdrawals (Executed_block.header block)

let amount_at block address =
  List.fold_left
    (fun acc w ->
      if Units.Address.equal (Withdrawal.address w) address then
        acc + Withdrawal.amount w
      else acc)
    0 (withdrawals block)

let closing_block advances =
  let a = last "closing advance" advances in
  last "closing block" a.Outcome.blocks

(* T5.1: the boundary-crossing output closes the epoch and seals the driver;
   a FURTHER step is refused by the DRIVER's own guard - the rendering is
   Sealed_needs_handoff's, not the engine's Epoch_sealed (obligation 9:
   test is_sealed, do not discover the seal through a failed execute). *)
let t51 () =
  let d, advances = sealed_driver () in
  Alcotest.(check (list bool))
    "exactly the boundary-crossing output closes the epoch"
    [ false; false; true ]
    (List.map (fun a -> a.Outcome.closes_epoch) advances);
  Alcotest.(check bool) "and the driver is sealed behind it" true
    (Driver.is_sealed d);
  Alcotest.(check string)
    "a further step is refused by the DRIVER, never by a failed execute"
    "the driver's epoch is sealed: the epoch handoff (begin_epoch) is owed \
     before the next output"
    (Result.fold
       ~ok:(fun _ -> "ok")
       ~error:Outcome.error_to_string
       (Driver.step d (o4 ()) ~bodies ~address_of))

(* T5.2 (G4's discriminating fixture): closed_at is the closing COMMIT
   timestamp, the boundary is closed_at + duration WITH the overshoot kept,
   and behaviourally an epoch-1 commit at 207 stays open while 208 closes -
   under previous_boundary + duration = 201 the 207 output would have
   closed. *)
let t52 () =
  Alcotest.(check (option int64)) "mid-epoch there is no boundary owed" None
    (Option.map Units.Timestamp.to_sec (Driver.next_boundary (driver0 ())));
  let d, _ = sealed_driver () in
  Alcotest.(check (option int64))
    "closed_at is the closing output's commit timestamp" (Some 108L)
    (Option.map Units.Timestamp.to_sec (Driver.closed_at d));
  Alcotest.(check (option int64))
    "next_boundary = closed_at + duration, overshoot kept (H9)" (Some 208L)
    (Option.map Units.Timestamp.to_sec (Driver.next_boundary d));
  let d1 = begin_ok "handoff" d chain_next.cmt in
  let d2, a4 = step_ok "epoch-1 output at 207" d1 (o4 ()) in
  Alcotest.(check bool) "207 < 208: the first epoch-1 output stays open"
    false a4.Outcome.closes_epoch;
  let _, a5 = step_ok "epoch-1 output at 208" d2 (o5 ()) in
  Alcotest.(check bool) "208 >= 208: the second closes epoch 1" true
    a5.Outcome.closes_epoch

(* T5.3: begin_epoch on a RUNNING driver refuses with Not_sealed - the
   guard the engine deliberately does not have (H12) - and the leader count
   the running epoch accrued is untouched. *)
let t53 () =
  let d1, _ = step_ok "first output" (driver0 ()) (o1 ()) in
  Alcotest.(check string) "a running driver refuses the handoff"
    "epoch handoff refused: the epoch is still running, so no closing \
     block has rooted the leader counts begin_epoch would clear"
    (handoff_outcome (Driver.begin_epoch d1 ~committee:chain_next.cmt));
  Alcotest.(check (list (pair string int)))
    "and the accrued leader count is untouched"
    [ (Units.Address.to_bytes (leader_address chain_now 0), 1) ]
    (List.map
       (fun (a, c) -> (Units.Address.to_bytes a, c))
       (Rewards_counter.address_counts (Engine.rewards (Driver.engine d1))))

(* T5.4 (G3: the credits are observed through the CLOSING BLOCK's
   withdrawals, behaviour not accessor): the closing block pays exactly the
   leaders counted during the epoch - seat 0 twice (o1 + the closing
   output itself, H14), seat 1 once, nobody else. G5: a fold split before
   the close pays identically. *)
let t54 () =
  let _, advances = sealed_driver () in
  let closing = closing_block advances in
  Alcotest.(check int) "the closing block carries exactly two records" 2
    (List.length (withdrawals closing));
  Alcotest.(check int) "seat 0 is paid its two led outputs" 2
    (amount_at closing (leader_address chain_now 0));
  Alcotest.(check int) "seat 1 its one" 1
    (amount_at closing (leader_address chain_now 1));
  Alcotest.(check int) "and seat 2, which led nothing, is absent" 0
    (amount_at closing (leader_address chain_now 2));
  let d2, _ = fold_ok "prefix" (driver0 ()) [ o1 (); o2 () ] in
  let _, tail, _ = fold_sealed "continuation" d2 [ o3 () ] in
  let pay block =
    List.map
      (fun w ->
        (Units.Address.to_bytes (Withdrawal.address w), Withdrawal.amount w))
      (withdrawals block)
  in
  Alcotest.(check (list (pair string int)))
    "a fold split before the close pays identically (G5)" (pay closing)
    (pay (closing_block tail))

(* T5.5 (D9's fixture proof): the fold returns Ok, ONLY the closing block
   carries a close disposition, and the registry system calls demonstrably
   RAN against Chain_spec.world - the close writes registry storage
   (test_epoch_close's own non-no-op pin), which a trivially succeeding
   call against a world that never seated the registry cannot fake. *)
let t55 () =
  let _, advances = sealed_driver () in
  Alcotest.(check (list (list bool)))
    "only the closing block carries a close disposition"
    [ []; []; [ true ] ]
    (List.map
       (fun a ->
         List.map
           (fun b -> Option.is_some (Executed_block.close_disposition b))
           a.Outcome.blocks)
       advances);
  let closing = closing_block advances in
  Alcotest.(check bool)
    "the close is not a silent no-op: registry storage changed" false
    (Storage.equal
       (Account.storage
          (World.account (Chain_spec.world spec)
             System_contracts.consensus_registry_address))
       (Account.storage
          (World.account
             (Executed_block.world closing)
             System_contracts.consensus_registry_address)))

(* T5.6 (H13): after a successful handoff the NEXT output's first execution
   block builds on the CLOSING block's hash at number closing + 1 - anchor,
   world, hash window and tip all survived the transition; and the
   consensus chain kept counting (H8: global numbering, no per-epoch
   reset). *)
let t56 () =
  let d, advances = sealed_driver () in
  let closing = closing_block advances in
  let d1 = begin_ok "handoff" d chain_next.cmt in
  Alcotest.(check bool) "the handoff reopens the driver" false
    (Driver.is_sealed d1);
  let _, a4 = step_ok "first epoch-1 output" d1 (o4 ()) in
  let b4 = nth "first epoch-1 block" a4.Outcome.blocks 0 in
  Alcotest.(check string)
    "the first post-handoff block builds on the closing block's hash"
    (Tn_keccak.to_hex (Executed_block.hash closing))
    (Tn_keccak.to_hex (Block_header.parent_hash (Executed_block.header b4)));
  Alcotest.(check int) "and its number is closing + 1"
    (Block_number.to_int (Executed_block.number closing) + 1)
    (Block_number.to_int (Executed_block.number b4));
  Alcotest.(check int) "while the consensus chain kept counting" 4
    (Cb.Number.to_int (Cb.number a4.Outcome.consensus))

(* T5.7 (H8's InvalidPackEpoch analogue): a committee whose epoch does not
   strictly exceed the installed one is refused with both epochs named, and
   the sealed driver still owes the same handoff. *)
let t57 () =
  let d, _ = sealed_driver () in
  Alcotest.(check string) "a committee at the SAME epoch does not install"
    "epoch handoff refused: proposed committee epoch 0 does not advance \
     past the installed epoch 0"
    (handoff_outcome (Driver.begin_epoch d ~committee:chain_now.cmt));
  Alcotest.(check bool) "the driver stays sealed" true (Driver.is_sealed d);
  Alcotest.(check (option int64)) "with its boundary still owed" (Some 208L)
    (Option.map Units.Timestamp.to_sec (Driver.next_boundary d))

(* T5.8 (the fold's sealed arm): a stream that keeps going PAST the close
   neither halts nor loses the driver - the fold stops at the seal and
   returns the executed prefix, the SEALED driver and the unconsumed
   suffix, upstream's routine boundary crossing ([subscriber.rs:362],
   [run_epoch.rs:142]). The suffix must be EXACTLY the unconsumed outputs
   in order (the caller re-folds these after the handoff, so a dropped or
   reordered one is a lost output), and folding it after begin_epoch
   resumes the same chain to epoch 1's own close. *)
let t58 () =
  let sd_hex sd = Digests.Sub_dag_digest.to_hex (Sub_dag.digest sd) in
  let s4 = o4 () and s5 = o5 () in
  let d, advances, rest =
    fold_sealed "fold past the close" (driver0 ())
      [ o1 (); o2 (); o3 (); s4; s5 ]
  in
  Alcotest.(check (list bool)) "the prefix ends at the closing output"
    [ false; false; true ]
    (List.map (fun a -> a.Outcome.closes_epoch) advances);
  Alcotest.(check (list string))
    "the suffix is exactly the unconsumed outputs, in order"
    [ sd_hex s4; sd_hex s5 ] (List.map sd_hex rest);
  let d1 = begin_ok "handoff" d chain_next.cmt in
  let _, advances1, rest1 = fold_sealed "the resumed suffix" d1 rest in
  Alcotest.(check int) "the suffix is consumed to the end" 0
    (List.length rest1);
  Alcotest.(check (list int)) "the consensus chain kept counting (H8)"
    [ 4; 5 ]
    (List.map
       (fun a -> Cb.Number.to_int (Cb.number a.Outcome.consensus))
       advances1);
  Alcotest.(check (list bool)) "and the suffix's close is epoch 1's own"
    [ false; true ]
    (List.map (fun a -> a.Outcome.closes_epoch) advances1)

(* T5.9 (H8's InvalidPackEpoch, the per-output side): an output committed
   under the WRONG epoch's committee is refused before minting, in both
   directions - the premature epoch-1 output on the epoch-0 driver, and
   the stale epoch-0 output replayed after the handoff. The refusal names
   both epochs, and because it precedes the mint, the next matching output
   takes the next consensus number as if the refusals never happened. *)
let t59 () =
  let refusal d sd =
    Result.fold
      ~ok:(fun _ -> "ok")
      ~error:Outcome.error_to_string
      (Driver.step d sd ~bodies ~address_of)
  in
  Alcotest.(check string) "a premature epoch-1 output is refused at epoch 0"
    "output refused: leader epoch 1 does not match the installed committee \
     epoch 0"
    (refusal (driver0 ()) (o4 ()));
  let d, _ = sealed_driver () in
  let d1 = begin_ok "handoff" d chain_next.cmt in
  Alcotest.(check string) "a stale epoch-0 output is refused at epoch 1"
    "output refused: leader epoch 0 does not match the installed committee \
     epoch 1"
    (refusal d1 (o1 ()));
  let _, a4 = step_ok "the matching output still executes" d1 (o4 ()) in
  Alcotest.(check int) "and the refusals consumed no consensus number" 4
    (Cb.Number.to_int (Cb.number a4.Outcome.consensus))

let () =
  Alcotest.run "driver epoch"
    [
      ( "handoff",
        [
          Alcotest.test_case "the seal refuses further steps at the driver"
            `Quick t51;
          Alcotest.test_case
            "the next boundary is the closing commit + duration" `Quick t52;
          Alcotest.test_case "begin_epoch refuses a running driver" `Quick
            t53;
          Alcotest.test_case "the closing block pays the counted leaders"
            `Quick t54;
          Alcotest.test_case "the registry close ran against the spec's world"
            `Quick t55;
          Alcotest.test_case "the chain survives the handoff" `Quick t56;
          Alcotest.test_case "a non-advancing committee epoch is refused"
            `Quick t57;
          Alcotest.test_case "the fold survives its own seal" `Quick t58;
          Alcotest.test_case "a wrong-epoch output is refused per output"
            `Quick t59;
        ] );
    ]
