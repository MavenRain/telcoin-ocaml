(* Chunk-37 stage 2: the driver's leaf modules.

   [Batch_store] is the batch-body seam (key derived, non-consuming, deduped);
   [Chain_spec] is the one-constructor genesis configuration whose world
   cannot lack the registry or the EIP-4788/2935 predeploys, exercised here on
   the CITED testnet scalars; [Address_book] is the [address_of] contract as a
   value. The Continuity classifier was dropped from the library (design patch
   P1) - a driver that mints its own numbers always classifies Next, so its
   other arms would be dead public surface - and T2.4 is void with it. T2.5 is
   reshaped by patch P9: the illegal duration is unrepresentable
   ([Epoch_duration.of_secs] answers [None]), not refused at [create]. *)

open Tn_types
module Bf = Block_fixtures
module Batch_store = Tn_driver.Batch_store
module Chain_spec = Tn_driver.Chain_spec
module Epoch_duration = Tn_driver.Chain_spec.Epoch_duration
module Address_book = Tn_driver.Address_book
module Anchor = Tn_engine.Anchor
module Block_number = Tn_engine.Block_number
module System_contracts = Tn_evm.System_contracts
module U256 = Tn_state.U256
module World = Tn_state.World_state

(* Totalise an option under a named expectation; Result.fold keeps both arms
   lazy, where Option.fold's ~none is eager. *)
let get what o =
  Result.fold ~ok:Fun.id
    ~error:(fun msg -> Alcotest.fail msg)
    (Option.to_result ~none:what o)

let addr c = get "address" (Units.Address.of_bytes (String.make 20 c))
let ts n = get "timestamp" (Units.Timestamp.of_sec n)
let u256_int n = get "u256" (U256.of_int n)
let fee n = Units.Base_fee.of_int64 (Int64.of_int n)
let w0 = Units.Worker_id.zero

let u256_short s =
  get "word" (U256.of_hex (String.make (64 - String.length s) '0' ^ s))

let u256_hex s = get "word" (U256.of_hex s)

let batch_t =
  Alcotest.testable
    (fun fmt b ->
      Format.pp_print_string fmt (Digests.Batch_digest.to_hex (Batch.digest b)))
    Batch.equal

let address_t =
  Alcotest.testable
    (fun fmt a ->
      Format.pp_print_string fmt (String.escaped (Units.Address.to_bytes a)))
    Units.Address.equal

(* Two bodies with distinct transaction lists, so their digests differ. The
   transaction bytes are placeholders (the engine records them as skipped);
   what the store underwrites is threading, not execution (risk R4). *)
let body_a =
  Batch.make ~transactions:[ "\x01" ] ~epoch:Units.Epoch.zero
    ~beneficiary:(addr 'a') ~base_fee_per_gas:(fee 7) ~worker_id:w0

let body_b =
  Batch.make
    ~transactions:[ "\x02"; "\x03" ]
    ~epoch:Units.Epoch.zero ~beneficiary:(addr 'b') ~base_fee_per_gas:(fee 7)
    ~worker_id:w0

(* ---------- T2.1-T2.3: the batch store ---------- *)

let test_store_roundtrip () =
  let store = Batch_store.of_bodies [ body_a ] in
  Alcotest.(check (option batch_t))
    "the added body answers by its own derived digest" (Some body_a)
    (Batch_store.find store (Batch.digest body_a));
  Alcotest.(check (option batch_t)) "an unrelated digest answers None" None
    (Batch_store.find store (Batch.digest body_b))

let test_store_rereads () =
  let store = Batch_store.of_bodies [ body_a ] in
  let digest = Batch.digest body_a in
  Alcotest.(check (option batch_t)) "first find answers the body" (Some body_a)
    (Batch_store.find store digest);
  Alcotest.(check (option batch_t))
    "second find of the same digest still answers (non-consuming)"
    (Some body_a)
    (Batch_store.find store digest)

let test_store_dedups () =
  let copy =
    Batch.make ~transactions:[ "\x01" ] ~epoch:Units.Epoch.zero
      ~beneficiary:(addr 'a') ~base_fee_per_gas:(fee 7) ~worker_id:w0
  in
  let store = Batch_store.add (Batch_store.add Batch_store.empty body_a) copy in
  Alcotest.(check int) "two adds of an equal body leave cardinal 1" 1
    (Batch_store.cardinal store);
  Alcotest.(check (option batch_t)) "and the body still answers" (Some body_a)
    (Batch_store.find store (Batch.digest body_a))

(* ---------- the cited testnet spec ---------- *)

let registry_entry =
  Tn_state.Genesis_account.make ~nonce:Tn_state.Nonce.zero
    ~balance:(u256_short Registry_genesis.balance_hex)
    ~code:(Some (Bf.hex Registry_genesis.code_hex))
    ~storage:
      (List.map
         (fun (s, v) -> (u256_hex s, u256_hex v))
         Registry_genesis.storage_hex)

let duration_28800 = get "epoch duration" (Epoch_duration.of_secs 28800)

(* chain id 2017 (chain-configs/testnet/genesis.yaml:3), base fee 0x7 (:264),
   gas limit 0x1c9c380 = 30,000,000 (:23), genesis timestamp 0x69fceea7 (:21),
   epoch duration 28800 s (tn-reth/src/test_utils.rs:836). The genesis hash is
   the caller's unverifiable claim, so any keccak stands in. *)
let testnet_spec () =
  get "chain spec"
    (Result.to_option
       (Chain_spec.create ~chain_id:(u256_int 2017)
          ~basefee_address:System_contracts.governance_safe_address
          ~genesis_hash:(Tn_keccak.digest "chunk-37 stand-in genesis hash")
          ~genesis_base_fee:(u256_int 7) ~genesis_gas_limit:30_000_000
          ~genesis_timestamp:(ts 0x69fceea7L) ~epoch_duration:duration_28800
          ~registry:registry_entry ~extra_alloc:[] ()))

(* ---------- T2.5 (as reshaped by P9): the duration guard ---------- *)

let test_duration_guard () =
  Alcotest.(check bool) "of_secs 0 is None" true
    (Option.is_none (Epoch_duration.of_secs 0));
  Alcotest.(check bool) "of_secs (-1) is None" true
    (Option.is_none (Epoch_duration.of_secs (-1)));
  Alcotest.(check (option int)) "of_secs 28800 holds 28800" (Some 28800)
    (Option.map Epoch_duration.to_secs (Epoch_duration.of_secs 28800));
  Alcotest.(check bool) "create with a positive duration is Ok" true
    (Result.is_ok
       (Chain_spec.create ~chain_id:(u256_int 2017)
          ~basefee_address:System_contracts.governance_safe_address
          ~genesis_hash:(Tn_keccak.digest "chunk-37 stand-in genesis hash")
          ~genesis_base_fee:(u256_int 7) ~genesis_gas_limit:30_000_000
          ~genesis_timestamp:(ts 0x69fceea7L) ~epoch_duration:duration_28800
          ~registry:registry_entry ~extra_alloc:[] ()))

(* ---------- T2.6: the world cannot lack the predeploys ---------- *)

let test_world_predeployed () =
  let world = Chain_spec.world (testnet_spec ()) in
  List.iter
    (fun (name, address) ->
      Alcotest.(check bool) (name ^ " holds code") true
        (System_contracts.is_deployed world address))
    [
      ("consensus registry", System_contracts.consensus_registry_address);
      ("EIP-4788 beacon roots", System_contracts.beacon_roots_address);
      ("EIP-2935 history storage", System_contracts.history_storage_address);
    ];
  List.iter
    (fun deployer ->
      Alcotest.(check int) "deployer EOA at nonce 1" 1
        (Tn_state.Nonce.to_int (World.nonce world deployer)))
    System_contracts.deployer_accounts

(* ---------- T2.7: the genesis anchor ---------- *)

let test_anchor () =
  let anchor = Chain_spec.anchor (testnet_spec ()) in
  Alcotest.(check bool) "height is Block_number.genesis" true
    (Block_number.equal (Anchor.number anchor) Block_number.genesis);
  Alcotest.(check bool) "base fee is the cited 0x7" true
    (U256.equal (Anchor.base_fee anchor) (u256_int 7));
  Alcotest.(check int) "gas limit is the cited 0x1c9c380" 30_000_000
    (Anchor.gas_limit anchor);
  Alcotest.(check bool) "a genesis anchor has no header" true
    (Option.is_none (Anchor.header anchor))

(* ---------- T2.8: epoch 0's boundary pins genesis ---------- *)

let test_first_boundary () =
  Alcotest.(check int64) "first boundary = genesis timestamp + epoch duration"
    (Int64.add 0x69fceea7L 28800L)
    (Units.Timestamp.to_sec (Chain_spec.first_boundary (testnet_spec ())))

(* ---------- P10: the address book contract ---------- *)

let authority seed address =
  Authority.make
    ~protocol_key:
      (Tn_crypto.Secret_key.public_key (Tn_crypto.Secret_key.derive seed))
    ~execution_address:address

let id_of seed =
  Authority_id.of_public_key
    (Tn_crypto.Secret_key.public_key (Tn_crypto.Secret_key.derive seed))

let committee_of entries =
  get "committee"
    (Result.to_option
       (Committee.create ~epoch:Units.Epoch.zero
          (List.map (fun (seed, a) -> authority seed a) entries)))

(* Distinct execution addresses per seat, so a book pairing an id with the
   WRONG seat's address cannot pass (no constant-valued fixture). *)
let test_book_members () =
  let cmt =
    committee_of [ (101L, addr 'a'); (102L, addr 'b'); (103L, addr 'c') ]
  in
  let book = Address_book.of_committee cmt in
  List.iter
    (fun a ->
      Alcotest.(check (option address_t)) "a member resolves to its own address"
        (Some (Authority.execution_address a))
        (Address_book.find book (Authority.id a)))
    (Committee.authorities cmt);
  Alcotest.(check (option address_t)) "a non-member resolves to None" None
    (Address_book.find book Authority_id.zero)

let test_book_union () =
  let older =
    Address_book.of_committee
      (committee_of [ (201L, addr 'x'); (202L, addr 'y') ])
  in
  let newer =
    Address_book.of_committee
      (committee_of [ (201L, addr 'X'); (203L, addr 'z') ])
  in
  let merged = Address_book.union newer older in
  Alcotest.(check (option address_t))
    "a conflicting id keeps the newer (left) address" (Some (addr 'X'))
    (Address_book.find merged (id_of 201L));
  Alcotest.(check (option address_t)) "a newer-only member survives the union"
    (Some (addr 'z'))
    (Address_book.find merged (id_of 203L));
  Alcotest.(check (option address_t)) "an older-only member survives the union"
    (Some (addr 'y'))
    (Address_book.find merged (id_of 202L))

let () =
  Alcotest.run "driver_spec"
    [
      ( "batch store",
        [
          Alcotest.test_case "find answers by derived digest only" `Quick
            test_store_roundtrip;
          Alcotest.test_case "the store is non-consuming" `Quick
            test_store_rereads;
          Alcotest.test_case "equal bodies dedup to one entry" `Quick
            test_store_dedups;
        ] );
      ( "chain spec",
        [
          Alcotest.test_case "an illegal epoch duration is unrepresentable"
            `Quick test_duration_guard;
          Alcotest.test_case "the world cannot lack the predeploys" `Quick
            test_world_predeployed;
          Alcotest.test_case "the genesis anchor carries the cited scalars"
            `Quick test_anchor;
          Alcotest.test_case "epoch 0's boundary pins genesis" `Quick
            test_first_boundary;
        ] );
      ( "address book",
        [
          Alcotest.test_case "members resolve, non-members are None" `Quick
            test_book_members;
          Alcotest.test_case "union is monotone and newer-biased" `Quick
            test_book_union;
        ] );
    ]
