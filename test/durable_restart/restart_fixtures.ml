(* Chunk-40 stage S7: the ONE copy of the restart suite's fixtures.

   The restart suite is two programs - a child that dies inside a named crash
   window and a parent that reads what it left behind - and both of them have
   to agree, byte for byte, on what the run WAS: the same committee, the same
   chain spec, the same sub-DAGs in the same order at the same timestamps.
   Two copies of that agreement would let a row go green for a reason that is
   not the row (a drifted timestamp moves the epoch boundary, a drifted
   committee moves the leader), so it lives here, once, and both programs open
   this module. That is test/driver_prelude.ml's argument, applied across a
   process boundary instead of across two files.

   No .mli, by the same rule driver_prelude.ml states: this is test
   scaffolding, and an interface over it would only restate it.

   The one thing this module may NOT borrow from driver_prelude is Alcotest.
   The child does not link it, so a fixture that cannot be built reports
   itself on standard error and leaves through {!fail}, which is
   [Unix._exit] and therefore raises nothing. Every fixture below is a
   function of constants, so reaching {!fail} means the port changed under
   the suite, not that a case failed. *)

open Tn_types
open Tn_vertex
open Tn_consensus
module Cb = Tn_execution.Consensus_block
module Chain = Tn_execution.Consensus_chain
module Store = Tn_execution.Consensus_store
module Nonempty = Tn_std.Nonempty
module Driver = Tn_driver.Driver
module Checkpoint = Tn_driver.Checkpoint
module Chain_spec = Tn_driver.Chain_spec
module Epoch_duration = Tn_driver.Chain_spec.Epoch_duration
module Address_book = Tn_driver.Address_book
module Batch_store = Tn_driver.Batch_store
module Outcome = Tn_driver.Outcome
module Engine = Tn_engine.Engine
module Anchor = Tn_engine.Anchor
module Recent_hashes = Tn_engine.Recent_hashes
module Block_number = Tn_engine.Block_number
module Block_header = Tn_evm.Block_header
module Rewards_counter = Tn_evm.Rewards_counter
module World = Tn_state.World_state
module Account = Tn_state.Account
module Storage = Tn_state.Storage
module Nonce = Tn_state.Nonce
module U256 = Tn_state.U256

(* {1 Totalising a constant} *)

let fail : string -> 'a =
 fun what ->
  let () = Printf.eprintf "restart fixture: %s\n%!" what in
  Unix._exit 91

(* [Result.fold] keeps both arms lazy, where [Option.fold]'s [~none] is
   eager: the same idiom every suite in this tree uses. *)
let get what o = Result.fold ~ok:Fun.id ~error:fail (Option.to_result ~none:what o)
let ok what render r = Result.fold ~ok:Fun.id ~error:(fun e -> fail (what ^ ": " ^ render e)) r
let nth what l n = get what (List.nth_opt l n)

(* Hex to bytes, built by folding over the characters and emitting through
   [Buffer.add_uint8], so neither a partial accessor nor [Char.chr] appears.
   An odd-length input drops its last nibble and a non-hex character reads as
   zero; every input here is a committed constant. *)
let hex s =
  let digit c =
    match c with
    | '0' .. '9' -> Char.code c - Char.code '0'
    | 'a' .. 'f' -> Char.code c - Char.code 'a' + 10
    | 'A' .. 'F' -> Char.code c - Char.code 'A' + 10
    | _ -> 0
  in
  let buf = Buffer.create (String.length s / 2) in
  let dangling =
    String.fold_left
      (fun pending c ->
        Option.fold
          ~none:(Some (digit c))
          ~some:(fun high ->
            let () = Buffer.add_uint8 buf ((high lsl 4) lor digit c) in
            None)
          pending)
      None s
  in
  let () = Option.fold ~none:() ~some:(fun (_ : int) -> ()) dangling in
  Buffer.contents buf

let to_hex s =
  let buf = Buffer.create (2 * String.length s) in
  let () = String.iter (fun c -> Buffer.add_string buf (Printf.sprintf "%02x" (Char.code c))) s in
  Buffer.contents buf

(* {1 The committee} *)

(* Four of the five testnet validator execution addresses, verbatim from
   chain-configs/testnet/committee.yaml and identical to the list
   test/driver_prelude.ml carries. They have to be THESE addresses: the
   epoch family closes a real epoch against the real ConsensusRegistry world,
   and the registry pays only seats it knows. *)
let validator_addresses =
  List.map
    (fun h -> get "validator address" (Units.Address.of_bytes (hex h)))
    [
      "0033a370616805b1fd275b7ffab83fc41d665ccb";
      "89dab9f6fdc569c1bcdbd6493f25b7040b55dc79";
      "3518b301b86ceb53b5a3dff62e55cd43ef59d024";
      "efaacf04b92298a88200aa50aa6bb7bfce587b17";
    ]

let build_committee ~seed ~epoch =
  let sks =
    List.mapi
      (fun i (_ : Units.Address.t) -> Tn_crypto.Secret_key.derive (Int64.of_int (seed + i)))
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
  (ok "committee" Committee.error_to_string (Committee.create ~epoch authorities), sks)

let epoch0 = Units.Epoch.zero
let epoch1 = Units.Epoch.succ epoch0
let committee, sks = build_committee ~seed:0 ~epoch:epoch0
let committee_next, sks_next = build_committee ~seed:600 ~epoch:epoch1

let key_in pool what id =
  get what
    (List.find_opt
       (fun sk ->
         Authority_id.equal (Authority_id.of_public_key (Tn_crypto.Secret_key.public_key sk)) id)
       pool)

let sk_of = key_in sks "epoch-0 secret key"
let sk_next_of = key_in sks_next "epoch-1 secret key"
let ids = List.map Authority.id (Committee.authorities committee)

(* Both epochs' authors resolve through ONE monotone book, so a resumed
   driver and a live one look leaders up the same way. *)
let address_of =
  Address_book.find
    (Address_book.union (Address_book.of_committee committee)
       (Address_book.of_committee committee_next))

(* {1 The bodies} *)

let worker n = get "worker id" (Units.Worker_id.of_int n)

let batch tag =
  Batch.make ~transactions:[ tag ] ~epoch:epoch0
    ~beneficiary:(nth "beneficiary" validator_addresses 0)
    ~base_fee_per_gas:Units.Base_fee.min_protocol ~worker_id:Units.Worker_id.zero

(* Two pairwise distinct bodies. The transactions are deliberately not
   decodable envelopes: the engine skips what it cannot decode, which keeps
   the executed blocks cheap while still making every record carry real
   payload bytes through the codec and the frame. *)
let body_a = batch "\x0a\x0a"
let body_b = batch "\x0b\x0b"
let bodies_pool = [ body_a; body_b ]
let bodies = Batch_store.of_bodies bodies_pool
let lookup = Batch_store.find bodies
let da = Batch.digest body_a
let db = Batch.digest body_b

(* {1 The sub-DAGs} *)

(* One single-certificate sub-DAG, hand-minted. Hand-minted rather than
   simulated because the restart suite needs to place a commit timestamp on
   either side of an epoch boundary to the second, which a simulation does
   not let it choose. *)
let sub_dag_of ~cmt ~sk_for ~author ~epoch ~r ~at ~payload =
  let seats = List.map Authority.id (Committee.authorities cmt) in
  let header =
    Header.make ~author
      ~round:(get "round" (Round.of_int r))
      ~epoch
      ~created_at:(get "timestamp" (Units.Timestamp.of_sec at))
      ~payload
      ~parents:(List.map Certificate.digest (Certificate.genesis cmt))
  in
  let votes = List.map (fun id -> Vote.sign (sk_for id) ~voter:id header) seats in
  Sub_dag.create
    ~sequence:
      (Nonempty.singleton
         (ok "certificate" Certificate.error_to_string (Certificate.assemble cmt header votes)))
    ~scores:(Reputation_scores.fresh cmt) ~previous:None

let epoch0_sub_dag ~author ~r ~at ~payload =
  sub_dag_of ~cmt:committee ~sk_for:sk_of ~author ~epoch:epoch0 ~r ~at ~payload

(* The RECORD family's stream: four outputs at 2, 4, 6 and 8 seconds, well
   inside the wide epoch, so nothing here ever seals. The payloads differ per
   height, so no two records are byte-equal and a mis-numbered replay cannot
   pass by collision. *)
let record_sub_dags =
  List.map
    (fun (i, payload) ->
      epoch0_sub_dag
        ~author:(nth "author" ids (i mod 4))
        ~r:((2 * i) - 1)
        ~at:(Int64.of_int (2 * i))
        ~payload)
    [
      (1, [ (da, worker 0) ]);
      (2, [ (da, worker 0); (db, worker 1) ]);
      (3, []);
      (4, [ (db, worker 1) ]);
    ]

(* The first three turns are the child's phase A; the fourth is the turn every
   record-family window dies inside. *)
let record_sub_dags_a = List.filteri (fun i (_ : Sub_dag.t) -> i < 3) record_sub_dags
let record_sub_dag_b = nth "the fourth output" record_sub_dags 3

(* The EPOCH family's stream: two outputs inside the ten-second epoch and one
   at twelve seconds, which crosses the boundary and closes the epoch. The
   closing output is empty, which is the shape test_driver_epoch.ml's own
   closing fixture uses. *)
let epoch_sub_dags =
  List.map
    (fun (i, at, payload) ->
      epoch0_sub_dag ~author:(nth "author" ids (i mod 4)) ~r:((2 * i) - 1) ~at ~payload)
    [ (1, 2L, [ (da, worker 0) ]); (2, 4L, [ (db, worker 1) ]); (3, 12L, []) ]

(* {1 The chain specs} *)

let u256_int n = get "u256" (U256.of_int n)
let u256_hex s = get "word" (U256.of_hex s)

let registry_entry =
  Tn_state.Genesis_account.make ~nonce:Nonce.zero
    ~balance:
      (get "balance"
         (U256.of_hex
            (String.make (64 - String.length Registry_genesis.balance_hex) '0'
            ^ Registry_genesis.balance_hex)))
    ~code:(Some (hex Registry_genesis.code_hex))
    ~storage:(List.map (fun (s, v) -> (u256_hex s, u256_hex v)) Registry_genesis.storage_hex)

let genesis_hash = Tn_keccak.digest "chunk-40 restart genesis sentinel"
let basefee_address = get "basefee address" (Units.Address.of_bytes (String.make 20 '\xbe'))

(* Genesis at second zero, so a sub-DAG's own commit second IS the chain's
   clock and the epoch boundary is exactly the duration. *)
let spec_of duration_s =
  ok "chain spec" Chain_spec.error_to_string
    (Chain_spec.create ~chain_id:(u256_int 2017) ~basefee_address ~genesis_hash
       ~genesis_base_fee:(u256_int 7) ~genesis_gas_limit:30_000_000
       ~genesis_timestamp:Units.Timestamp.zero
       ~epoch_duration:(get "epoch duration" (Epoch_duration.of_secs duration_s))
       ~registry:registry_entry ~extra_alloc:[] ())

(* Forced once per process: seating the real registry runtime is the most
   expensive thing either program does. *)
let wide_spec = lazy (spec_of 28800)
let short_spec = lazy (spec_of 10)

(* {1 Root layout} *)

let checkpoint_temp_name = "checkpoint.tmp"
let child_log_name = "child.log"

(* {1 Renderings} *)

let render_committee c =
  String.concat ","
    (Units.Epoch.to_string (Committee.epoch c)
    :: List.map
         (fun a ->
           Authority_id.to_hex (Authority.id a)
           ^ "@"
           ^ to_hex (Units.Address.to_bytes (Authority.execution_address a)))
         (Committee.authorities c))

let render_phase p =
  match p with
  | Engine.Running { boundary; committee = c } ->
      "running " ^ Units.Timestamp.to_string boundary ^ " " ^ render_committee c
  | Engine.Sealed { closed_at; committee = c } ->
      "sealed " ^ Units.Timestamp.to_string closed_at ^ " " ^ render_committee c

let render_account (addr, a) =
  String.concat "/"
    ([
       to_hex (Units.Address.to_bytes addr);
       Nonce.to_string (Account.nonce a);
       U256.to_hex (Account.balance a);
       to_hex (Account.code a);
       Option.fold ~none:"no delegation"
         ~some:(fun d -> to_hex (Units.Address.to_bytes d))
         (Account.delegation a);
     ]
    @ List.map
        (fun (slot, word) -> U256.to_hex slot ^ "=" ^ U256.to_hex word)
        (Storage.bindings (Account.storage a)))

(* Every field of the engine half, the whole world included: what a resumed
   driver IS, not a summary of it. *)
let render_engine (p : Engine.persisted) =
  String.concat "|"
    ([
       Tn_keccak.to_hex (Anchor.hash p.Engine.anchor);
       string_of_int (Block_number.to_int (Anchor.number p.Engine.anchor));
       U256.to_hex (Anchor.base_fee p.Engine.anchor);
       string_of_int (Anchor.gas_limit p.Engine.anchor);
       Option.fold ~none:"no header"
         ~some:(fun h -> Tn_keccak.to_hex (Block_header.hash h))
         (Anchor.header p.Engine.anchor);
       string_of_int (Recent_hashes.depth p.Engine.hashes);
       render_phase p.Engine.phase;
     ]
    @ List.map Tn_keccak.to_hex (Recent_hashes.to_list p.Engine.hashes)
    @ List.map
        (fun (a, n) -> to_hex (Units.Address.to_bytes a) ^ "x" ^ string_of_int n)
        (Rewards_counter.address_counts p.Engine.rewards)
    @ List.map render_account (World.accounts p.Engine.world))

let render_checkpoint cp =
  let acc = Checkpoint.accumulator cp in
  String.concat "|"
    [
      Cb.Number.to_string (Checkpoint.watermark cp);
      Option.fold ~none:"none"
        ~some:(fun b -> Digests.Output_digest.to_hex (Cb.digest b))
        (Checkpoint.last_executed cp);
      Units.Epoch.to_string (Checkpoint.epoch cp);
      string_of_bool (Checkpoint.is_sealed cp);
      Option.fold ~none:"none"
        ~some:(fun t -> Int64.to_string (Units.Timestamp.to_sec t))
        (Checkpoint.closed_at cp);
      render_committee (Checkpoint.committee cp);
      Digests.Output_digest.to_hex (Chain.parent acc);
      Cb.Number.to_string (Chain.number acc);
      Option.fold ~none:"no tip"
        ~some:(fun b -> Digests.Output_digest.to_hex (Cb.digest b))
        (Chain.tip acc);
      render_engine (Checkpoint.engine cp);
    ]

(* Every height the store retains, in order, by the digest the record itself
   carries. *)
let render_records mirror =
  let ceiling = Cb.Number.to_int (Store.expected_next mirror) in
  let heights =
    List.filter_map
      (fun i -> Cb.Number.of_int i)
      (List.init (Stdlib.max 0 (Stdlib.pred ceiling)) (fun i -> Stdlib.succ i))
  in
  List.map
    (fun h ->
      Result.fold
        ~ok:(fun r -> Digests.Output_digest.to_hex (Store.Record.digest r))
        ~error:Store.miss_to_string (Store.record_at mirror h))
    heights

(* THE convergence value. A resumed run and a run that never crashed are the
   same run when this string is the same string: every retained record, the
   height the driver has forwarded to, and the whole resumable state the
   driver would snapshot next - world, anchor, window, counters and phase -
   folded into one digest so a mismatch prints as one line rather than as
   thirty kilobytes of registry storage. The three readable fields in front
   of the digest are there so a mismatch says WHERE before it says that. *)
let render_chain ~mirror ~driver =
  let cp = Driver.snapshot driver in
  let full = String.concat "|" (render_records mirror @ [ render_checkpoint cp ]) in
  Printf.sprintf "tip=%s forwarded=%s watermark=%s state=%s"
    (Cb.Number.to_string (Store.expected_next mirror))
    (Cb.Number.to_string (Driver.last_forwarded driver))
    (Cb.Number.to_string (Checkpoint.watermark cp))
    (Tn_keccak.to_hex (Tn_keccak.digest full))

let render_outcome o =
  match o with
  | Outcome.Advance { driver = _; advances } ->
      Printf.sprintf "advance replaying %d" (List.length advances)
  | Outcome.Sealed { driver = _; advances; rest } ->
      Printf.sprintf "sealed replaying %d with %d unconsumed" (List.length advances)
        (List.length rest)
  | Outcome.Halted { advances; error } ->
      Printf.sprintf "halted after %d: %s" (List.length advances) (Outcome.error_to_string error)
