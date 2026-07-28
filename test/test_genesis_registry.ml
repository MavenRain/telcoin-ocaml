(* Tests for the genesis-alloc widening: [Tn_state.Genesis_account],
   [World_state.of_genesis_alloc] and the ConsensusRegistry address constant,
   exercised against the real registry alloc entry of telcoin's committed
   testnet genesis ([chain-configs/testnet/genesis.yaml], materialized as
   [Registry_genesis] by scratchpad/chunk32-stage3-extract.py).

   FIXTURE MODE: LEGACY (pre-fork). The seeded bytecode is the PRE-fork
   registry runtime - its Keccak-256 is the exact
   [CONSENSUS_REGISTRY_PRE_FORK_CODE_HASH] pin of
   [crates/types/src/forks.rs:23-24], re-derived below through the port's own
   keccak - and its dispatcher answers the legacy [getValidators(uint8)]
   selector [8cc05eda], NOT the post-fork [getValidatorsInfo(uint8)]
   [2870259d]. The selector-surface test pins that fact in the suite so the
   later close-path stages cannot silently run post-fork calls against this
   fixture (the chunk-30-class trap the design judge flagged). A post-fork
   (code, storage) alloc could not be generated cheaply: the committed
   tn-contracts artifact at ac22e265 carries the post-fork deployedBytecode,
   but the constructor-derived storage map needs
   [RethEnv::create_consensus_registry_genesis_accounts]
   ([tn-reth/src/lib.rs:1446]) and the telcoin-network workspace has no build
   cache, so running it would be a forbidden cold reth build. *)

open Tn_types
module U256 = Tn_state.U256
module Nonce = Tn_state.Nonce
module Account = Tn_state.Account
module Storage = Tn_state.Storage
module Genesis_account = Tn_state.Genesis_account
module World_state = Tn_state.World_state
module System_contracts = Tn_evm.System_contracts

let get = function Some x -> x | None -> Alcotest.fail "expected Some"

let get_ok = function
  | Ok x -> x
  | Error _ -> Alcotest.fail "expected Ok"

(* Hex codecs, mirrored from [block_fixtures.ml:53-69]. *)
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

let to_hex s =
  let buf = Buffer.create (2 * String.length s) in
  String.iter (fun c -> Buffer.add_string buf (Printf.sprintf "%02x" (Char.code c))) s;
  Buffer.contents buf

(* A short big-endian hex quantity, left-padded to the exact 64 digits
   [U256.of_hex] requires. *)
let u256_short s = get (U256.of_hex (String.make (64 - String.length s) '0' ^ s))
let u256_hex s = get (U256.of_hex s)

(* Whether [needle] occurs as a byte substring of [haystack] - the selector
   probe. Positions walked as a [Seq]; no loop keywords. *)
let contains ~needle haystack =
  let n = String.length needle and h = String.length haystack in
  n <= h
  && Seq.exists
       (fun i -> String.equal (String.sub haystack i n) needle)
       (Seq.take (h - n + 1) (Seq.ints 0))

(* ---------- the fixture, decoded once ---------- *)

let registry_address = get (Units.Address.of_bytes (hex Registry_genesis.address_hex))
let registry_balance = u256_short Registry_genesis.balance_hex
let registry_code = hex Registry_genesis.code_hex

let registry_storage =
  List.map (fun (slot, value) -> (u256_hex slot, u256_hex value)) Registry_genesis.storage_hex

let registry_entry =
  Genesis_account.make ~nonce:Nonce.zero ~balance:registry_balance ~code:(Some registry_code)
    ~storage:registry_storage

(* The pre-fork code-hash pin, [crates/types/src/forks.rs:23-24]. *)
let pre_fork_code_hash = "5318ebc5cd8123cfb0808fac0f3c0b95ed6f45f67c0853fea0766b52035fea53"

(* ---------- the registry address constant ---------- *)

(* Same honesty rule as [test_system_contracts_are_pinned]: the literal's hex
   and width live in the suite because [Address.of_bytes]'s partiality means a
   typo collapses to the zero address, not to a compile error. *)
let test_registry_address_pinned () =
  Alcotest.(check string)
    "CONSENSUS_REGISTRY_ADDRESS" "07e17e17e17e17e17e17e17e17e17e17e17e17e1"
    (to_hex (Units.Address.to_bytes System_contracts.consensus_registry_address));
  Alcotest.(check bool)
    "not the zero address" false
    (Units.Address.equal System_contracts.consensus_registry_address Units.Address.zero);
  Alcotest.(check bool)
    "equals the fixture's address" true
    (Units.Address.equal System_contracts.consensus_registry_address registry_address)

(* ---------- the alloc round trip ---------- *)

(* The testnet registry entry through [of_genesis_alloc]: code and storage
   both land, byte- and word-identical. The code pin is the derived keccak, so
   this is simultaneously the fixture-integrity check and the port-keccak
   re-derivation of [CONSENSUS_REGISTRY_PRE_FORK_CODE_HASH]. *)
let test_registry_round_trip () =
  let world = get_ok (World_state.of_genesis_alloc [ (registry_address, registry_entry) ]) in
  let acct = World_state.account world registry_address in
  Alcotest.(check string)
    "keccak(code) is the pre-fork pin" pre_fork_code_hash
    (Tn_keccak.to_hex (Account.code_hash acct));
  Alcotest.(check int) "code length" 28381 (Account.code_length acct);
  Alcotest.(check string)
    "balance 0x422ca8b0a00a425000000" (U256.to_hex registry_balance)
    (U256.to_hex (World_state.balance world registry_address));
  Alcotest.(check int) "nonce zero" 0 (Nonce.to_int (World_state.nonce world registry_address));
  (* Slot 0: the short-string "ConsensusNFT" (12 bytes, length byte 0x18). *)
  Alcotest.(check string)
    "slot 0" "436f6e73656e7375734e46540000000000000000000000000000000000000018"
    (U256.to_hex (World_state.storage world registry_address U256.zero));
  (* A keccak-derived mapping slot, deep in the constructor-written region. *)
  Alcotest.(check string)
    "hashed slot 13da..e3" "00000000000000000000000000000000000000000000d3c21bcecceda1000000"
    (U256.to_hex
       (World_state.storage world registry_address
          (u256_hex "13da86008ba1c6922daee3e07db95305ef49ebced9f5467a0b8613fcc6b343e3")));
  (* Every listed slot landed: the yaml carries no zero values, so the stored
     bindings must be exactly the fixture's 115 pairs. *)
  Alcotest.(check int)
    "all 115 slots stored"
    (List.length Registry_genesis.storage_hex)
    (List.length (Storage.bindings (Account.storage acct)))

(* The seeded code answers the LEGACY selector surface and not the post-fork
   one. This is the fixture-mode pin: a close-path test that encodes
   [getValidatorsInfo] (0x2870259d) against this world is calling a function
   the deployed dispatcher does not have, exactly the vacuous-test trap the
   design review rejected in design B. *)
let test_legacy_selector_surface () =
  List.iter
    (fun (name, selector) ->
      Alcotest.(check bool) (name ^ " present") true (contains ~needle:(hex selector) registry_code))
    [
      ("getValidators (legacy) 8cc05eda", "8cc05eda");
      ("getNextCommitteeSize eb8535c2", "eb8535c2");
      ("concludeEpoch 7b55a300", "7b55a300");
      ("applyIncentives 0a36cdef", "0a36cdef");
    ];
  List.iter
    (fun (name, selector) ->
      Alcotest.(check bool) (name ^ " absent") false (contains ~needle:(hex selector) registry_code))
    [
      ("getValidatorsInfo (post-fork) 2870259d", "2870259d");
      ("post-fork aaffd270", "aaffd270");
    ]

(* ---------- the refusal ---------- *)

(* Storage on a codeless entry is the one alloc shape [of_genesis_alloc]
   refuses: it is exactly the class on which [World_state]'s pruning rule
   diverges from revm's EIP-161 touch-clearing ([world_state.ml:9-25]), so
   admitting it would seed a state revm could disagree with. [Some ""] is
   refused too, because zero bytes of code is no code. *)
let test_storage_without_code_refused () =
  let slot = (U256.one, u256_short "2a") in
  let refused code =
    Genesis_account.make ~nonce:Nonce.zero ~balance:U256.zero ~code ~storage:[ slot ]
  in
  List.iter
    (fun (name, code) ->
      match World_state.of_genesis_alloc [ (registry_address, refused code) ] with
      | Ok _ -> Alcotest.fail (name ^ ": expected Storage_without_code")
      | Error (World_state.Storage_without_code addr) ->
          Alcotest.(check bool)
            (name ^ ": error names the address")
            true
            (Units.Address.equal addr registry_address))
    [ ("no code", None); ("empty code", Some "") ];
  (* The refusal is precise: one byte of code admits the same storage, and a
     codeless entry without storage is plain balance seeding. *)
  let coded =
    Genesis_account.make ~nonce:Nonce.zero ~balance:U256.zero ~code:(Some "\xfe")
      ~storage:[ slot ]
  in
  let codeless_bare =
    Genesis_account.make ~nonce:Nonce.zero ~balance:U256.one ~code:None ~storage:[]
  in
  Alcotest.(check bool)
    "code admits storage" true
    (Result.is_ok (World_state.of_genesis_alloc [ (registry_address, coded) ]));
  Alcotest.(check bool)
    "codeless entry without storage is fine" true
    (Result.is_ok (World_state.of_genesis_alloc [ (registry_address, codeless_bare) ]));
  Alcotest.(check string)
    "error rendering names the address"
    "genesis alloc entry 0x07e17e17e17e17e17e17e17e17e17e17e17e17e1 pre-populates storage \
     but installs no code"
    (World_state.error_to_string (World_state.Storage_without_code registry_address))

(* ---------- of_alloc delegation ---------- *)

(* [of_alloc] is now the [balance_only] special case of [of_genesis_alloc]:
   same entries, same world, and the zero-allocation still stores nothing. *)
let test_of_alloc_delegates () =
  let a = registry_address in
  let b = get (Units.Address.of_bytes (hex "00000000000000000000000000000000000000b2")) in
  let direct = World_state.of_alloc [ (a, u256_short "0de0b6b3a7640000"); (b, U256.zero) ] in
  let via_genesis =
    get_ok
      (World_state.of_genesis_alloc
         [
           (a, Genesis_account.balance_only (u256_short "0de0b6b3a7640000"));
           (b, Genesis_account.balance_only U256.zero);
         ])
  in
  Alcotest.(check bool) "same world" true (World_state.equal direct via_genesis);
  Alcotest.(check int) "zero allocation stores no entry" 1
    (List.length (World_state.accounts direct))

(* ---------- Genesis_account canonicity ---------- *)

let test_genesis_account_canonical () =
  let s = U256.one in
  let dup =
    Genesis_account.make ~nonce:Nonce.zero ~balance:U256.zero ~code:(Some "\xfe")
      ~storage:[ (s, u256_short "01"); (s, u256_short "02") ]
  in
  Alcotest.(check string)
    "repeated slot takes the last value" (U256.to_hex (u256_short "02"))
    (U256.to_hex (Storage.get (Genesis_account.storage dup) s));
  let zeroed =
    Genesis_account.make ~nonce:Nonce.zero ~balance:U256.zero ~code:None
      ~storage:[ (s, U256.zero) ]
  in
  Alcotest.(check bool)
    "zero-valued slot stores nothing" true
    (Storage.is_empty (Genesis_account.storage zeroed));
  let empty_code =
    Genesis_account.make ~nonce:Nonce.zero ~balance:U256.zero ~code:(Some "") ~storage:[]
  in
  let no_code = Genesis_account.make ~nonce:Nonce.zero ~balance:U256.zero ~code:None ~storage:[] in
  Alcotest.(check bool) "Some \"\" normalizes to None" true
    (Option.is_none (Genesis_account.code empty_code));
  Alcotest.(check bool) "empty code is no code" false (Genesis_account.has_code empty_code);
  Alcotest.(check bool)
    "normalization makes the two equal" true
    (Genesis_account.equal empty_code no_code);
  let funded = Genesis_account.balance_only (u256_short "2a") in
  Alcotest.(check string)
    "balance_only keeps the balance" (U256.to_hex (u256_short "2a"))
    (U256.to_hex (Genesis_account.balance funded));
  Alcotest.(check int) "balance_only nonce zero" 0 (Nonce.to_int (Genesis_account.nonce funded));
  Alcotest.(check bool) "balance_only has no code" false (Genesis_account.has_code funded);
  Alcotest.(check bool)
    "balance_only has no storage" true
    (Storage.is_empty (Genesis_account.storage funded))

let () =
  Alcotest.run "genesis registry"
    [
      ( "genesis-registry",
        [
          Alcotest.test_case "the registry address is pinned" `Quick test_registry_address_pinned;
          Alcotest.test_case "the testnet registry entry round-trips" `Quick
            test_registry_round_trip;
          Alcotest.test_case "the fixture is legacy-mode by selector surface" `Quick
            test_legacy_selector_surface;
          Alcotest.test_case "storage without code is refused" `Quick
            test_storage_without_code_refused;
          Alcotest.test_case "of_alloc delegates to of_genesis_alloc" `Quick
            test_of_alloc_delegates;
          Alcotest.test_case "Genesis_account construction is canonical" `Quick
            test_genesis_account_canonical;
        ] );
    ]
