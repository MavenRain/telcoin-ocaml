(* Chunk-40 stage S6: the durable checkpoint, on a real filesystem.

   The store's log is an append-only stream whose recovery is a replay; the
   checkpoint is the opposite shape - one small artefact, rewritten whole, made
   durable by a rename. So the questions here are different ones. Does every
   field of a resumable execution state survive a byte round trip, INCLUDING
   the ones [Engine.resume] would silently renormalise afterwards? Does the
   publish refuse the two cross-artefact states that no later check could
   repair, and refuse them before it spends a byte? And does a reader meeting a
   damaged file say so, rather than quietly answering "fresh node" and rewinding
   a populated chain to genesis?

   The fixtures are [test_driver_resume]'s, through [Driver_prelude]: the same
   seed-42 four-authority run, so a checkpoint here is one a real driver
   produced rather than one hand-built to be easy to encode. The world it
   carries holds the genesis registry contract, which is what makes the
   [World_state.equal] round trip a real test of the code field.

   The container's magic and format number are restated in this file rather
   than exported from [Checkpoint_file]. That is deliberate: they are the
   on-disk format, and a test that reproduces them byte for byte is what pins
   them; a test that imported them could not notice them changing. *)

open Tn_types
open Driver_prelude
module Bcs = Tn_codec.Bcs
module Atomic_file = Tn_durable.Atomic_file
module Io = Tn_durable.Io
module Io_ops = Tn_durable.Io_ops
module Disk = Tn_durable_store.Consensus_store_disk
module Ckpt = Tn_durable_checkpoint.Checkpoint_file
module Ckpt_codec = Tn_durable_checkpoint.Checkpoint_codec
module Chain = Tn_execution.Consensus_chain
module Anchor = Tn_engine.Anchor
module Recent_hashes = Tn_engine.Recent_hashes
module World = Tn_state.World_state
module Account = Tn_state.Account
module Storage = Tn_state.Storage
module Nonce = Tn_state.Nonce
module Rewards_counter = Tn_evm.Rewards_counter

(* ---------- roots ---------- *)

let io_ok what r =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "%s: %s" what (Io.error_to_string e))
    r

let run_root =
  Filename.concat (Filename.get_temp_dir_name ())
    (Printf.sprintf "tn-checkpoint-%d" (Unix.getpid ()))

(* The FILESYSTEM is the register of roots already minted, exactly the idiom
   [test_consensus_store.ml] settled on: a name is free when nothing is at it,
   and the directory is created before the name is handed out, so nothing
   mutable has to survive between calls. *)
let rec free_root_name base n =
  let path = Printf.sprintf "%s-%d" base n in
  match io_ok "look for a free checkpoint root" (Io.exists ~ops:Io_ops.real ~path) with
  | true -> free_root_name base (Stdlib.succ n)
  | false -> path

let fresh_root label =
  let path = free_root_name (Filename.concat run_root label) 0 in
  let () = io_ok "create a checkpoint root" (Io.mkdir_p ~ops:Io_ops.real ~path) in
  (* Alcotest shows a case's own output only when the case FAILS, so this is
     the kept-evidence path announcing itself exactly when it is wanted. *)
  let () = Printf.printf "  checkpoint root: %s\n" path in
  path

let sweep root =
  List.iter
    (fun name ->
      io_ok "sweep a checkpoint root"
        (Io.unlink_if_present ~ops:Io_ops.real ~path:(Filename.concat root name)))
    [ "consensus.log"; "LOCK"; "checkpoint"; "checkpoint.tmp" ]

(* ---------- the shell protocol, once ---------- *)

let mint_ok what d sd =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "%s: %s" what (Outcome.error_to_string e))
    (Driver.mint d sd)

let record_ok what block ~bodies =
  Result.fold ~ok:Fun.id
    ~error:(fun e ->
      Alcotest.failf "%s: %s" what (Consensus_store.Record.error_to_string e))
    (Consensus_store.Record.create ~consensus:block
       ~lookup:(Batch_store.find bodies))

let receive_ok what store record =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "%s: %s" what (Disk.write_error_to_string e))
    (Disk.receive store record)

let open_store dir =
  Result.fold ~ok:fst
    ~error:(fun f -> Alcotest.failf "open store: %s" (Disk.fault_to_string f))
    (Disk.open_ ~ops:Io_ops.real ~dir ~epoch:Units.Epoch.zero
       ~anchor:Cb.Number.genesis ~parent:Cb.genesis_parent ())

let close_store store =
  Result.fold ~ok:Fun.id
    ~error:(fun f -> Alcotest.failf "close store: %s" (Disk.fault_to_string f))
    (Disk.close store)

let fill store records = List.fold_left (receive_ok "receive") store records

(* [k] turns of [mint -> Record.create -> step], with the records handed back
   rather than filed: a case decides for itself how much of the log the store
   is allowed to hold, which is what makes the AHEAD state buildable. *)
let turns k =
  let bodies = store () in
  let sds = take k (committed_self ()) in
  let d, records_rev =
    List.fold_left
      (fun (d, acc) sd ->
        let block = mint_ok "mint" d sd in
        let record = record_ok "record" block ~bodies in
        let d, (_ : Outcome.advance) = step_ok "step" d sd ~bodies in
        (d, record :: acc))
      (Driver.create (Lazy.force wide_spec) ~committee, [])
      sds
  in
  (Driver.snapshot d, List.rev records_rev)

let fixture = lazy (turns 3)

(* ---------- renderings ---------- *)

let hex_of = Bf.to_hex

let render_committee c =
  String.concat ","
    (Units.Epoch.to_string (Committee.epoch c)
    :: List.map
         (fun a ->
           Authority_id.to_hex (Authority.id a)
           ^ "@"
           ^ hex_of (Units.Address.to_bytes (Authority.execution_address a)))
         (Committee.authorities c))

let render_phase = function
  | Engine.Running { boundary; committee } ->
      "running " ^ Units.Timestamp.to_string boundary ^ " "
      ^ render_committee committee
  | Engine.Sealed { closed_at; committee } ->
      "sealed " ^ Units.Timestamp.to_string closed_at ^ " "
      ^ render_committee committee

let render_account (addr, a) =
  String.concat "/"
    ([
       hex_of (Units.Address.to_bytes addr);
       Nonce.to_string (Account.nonce a);
       U256.to_hex (Account.balance a);
       hex_of (Account.code a);
       Option.fold ~none:"no delegation"
         ~some:(fun d -> hex_of (Units.Address.to_bytes d))
         (Account.delegation a);
     ]
    @ List.map
        (fun (slot, word) -> U256.to_hex slot ^ "=" ^ U256.to_hex word)
        (Storage.bindings (Account.storage a)))

(* Every field of the engine half, the two the .mli calls out most loudly
   first: the anchor's own header (an anchor that came back as a genesis one
   would tell the engine its parent has no header) and the whole BLOCKHASH
   window, newest entry included. *)
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
        (fun (a, n) ->
          hex_of (Units.Address.to_bytes a) ^ "x" ^ string_of_int n)
        (Rewards_counter.address_counts p.Engine.rewards)
    @ List.map render_account (World.accounts p.Engine.world))

(* Every projection [Checkpoint] publishes, the accumulator included. *)
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

let render_file = function
  | Atomic_file.Io e -> "io: " ^ Io.error_to_string e
  | Atomic_file.Bad_magic _ -> "bad magic"
  | Atomic_file.Bad_format _ -> "bad format"
  | Atomic_file.Bad_body_tag _ -> "bad body tag"
  | Atomic_file.Short _ -> "short"
  | Atomic_file.Bad_generation _ -> "bad generation"

let render_error = function
  | Ckpt.Io e -> "io: " ^ Io.error_to_string e
  | Ckpt.File e -> "file: " ^ render_file e
  | Ckpt.Decode e -> "decode: " ^ Bcs.error_to_string e
  | Ckpt.Trailing { left } -> Printf.sprintf "trailing %d" left
  | Ckpt.Ahead { watermark; durable_tip } ->
      Printf.sprintf "ahead %d over %d" watermark durable_tip
  | Ckpt.Unknown_block { number } -> Printf.sprintf "unknown block at %d" number
  | Ckpt.Generation_regressed { stored; offered } ->
      Printf.sprintf "generation %d does not advance %d" offered stored

let render_load = function
  | Ckpt.Absent -> "absent"
  | Ckpt.Loaded { checkpoint; generation } ->
      Printf.sprintf "gen %d: %s" generation (render_checkpoint checkpoint)

let generation_of = function
  | Ckpt.Absent -> 0
  | Ckpt.Loaded { generation; checkpoint = _ } -> generation

let payload_of = function
  | Ckpt.Absent -> "absent"
  | Ckpt.Loaded { checkpoint; generation = _ } -> render_checkpoint checkpoint

let save_ok what ~dir ~store cp =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "%s: %s" what (Ckpt.error_to_string e))
    (Ckpt.save ~dir ~store cp)

let load_ok what ~dir =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "%s: %s" what (Ckpt.error_to_string e))
    (Ckpt.load ~dir ())

let refusal what r =
  Result.fold
    ~ok:(fun g -> Alcotest.failf "%s: published at generation %d" what g)
    ~error:render_error r

(* ---------- the codec, on its own ---------- *)

let codec_round_trip what cp =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "%s: %s" what (Bcs.error_to_string e))
    (Bcs.decode Ckpt_codec.checkpoint (Bcs.encode Ckpt_codec.checkpoint cp))

(* S6.1 - the whole value survives the wire, read through every projection the
   type publishes. The rendering names each field, so a dropped one is a diff
   at that field rather than a structural mismatch. *)
let s61 () =
  let cp, (_ : Consensus_store.Record.t list) = Lazy.force fixture in
  Alcotest.(check string) "every projection round-trips" (render_checkpoint cp)
    (render_checkpoint (codec_round_trip "round trip" cp))

(* S6.2 - the world, through [World_state.equal] rather than through a
   rendering, and over a fixture carrying a SENTINEL row: an account with a
   nonzero nonce, a balance, code and storage, which is the shape
   [set_account]'s pruning rule would eat if [accounts] could ever list an
   absent entry (open risk 2). The registry contract is already in there, so
   the code field is under test twice. *)
let sentinel_address = mk_addr '\x5e'

let sentinel_account =
  Account.with_storage
    (Account.with_code
       (Account.make
          ~nonce:(get "sentinel nonce" (Nonce.of_int 7))
          ~balance:(u256_int 123_456))
       "\x60\x01\x60\x02\x01")
    (Storage.set Storage.empty (u256_int 3) (u256_int 9))

let with_sentinel (p : Engine.persisted) =
  {
    p with
    Engine.world =
      World.set_account p.Engine.world sentinel_address sentinel_account;
  }

let s62 () =
  let cp, (_ : Consensus_store.Record.t list) = Lazy.force fixture in
  let seeded =
    Checkpoint.of_execution
      (with_sentinel (Checkpoint.engine cp))
      ~last_executed:(Checkpoint.last_executed cp)
  in
  let before = (Checkpoint.engine seeded).Engine.world in
  (* The positive control: the fixture world really does carry a contract, so
     a codec that dropped [code] has something to drop. *)
  let () =
    Alcotest.(check bool)
      "the fixture holds at least one account with code" true
      (List.exists
         (fun (_, a) -> String.length (Account.code a) > 0)
         (World.accounts before))
  in
  let after =
    (Checkpoint.engine (codec_round_trip "world round trip" seeded)).Engine.world
  in
  let () =
    Alcotest.(check bool) "World_state.equal on the round-tripped world" true
      (World.equal before after)
  in
  let () =
    Alcotest.(check string) "the sentinel row survives"
      (render_account (sentinel_address, sentinel_account))
      (render_account (sentinel_address, World.account after sentinel_address))
  in
  Alcotest.(check int) "no account was pruned by the fold"
    (List.length (World.accounts before))
    (List.length (World.accounts after))

(* S6.3 - the BLOCKHASH window is round-tripped, NOT renormalised. The fixture
   is skewed on purpose: its newest entry is not the anchor's hash, which is
   the one cross-field fact [Engine.resume] re-derives. A decoder that rebuilt
   the pair its own way - or that ran the value through resume-and-snapshot on
   the way in - would hand back the normalised window and this case would go
   red, while the resumed engines below would still agree. *)
let skew_hash = Tn_keccak.digest "chunk-40 skewed window sentinel"

let with_skewed_window (p : Engine.persisted) =
  {
    p with
    Engine.hashes =
      Recent_hashes.of_genesis skew_hash
        ~ancestors:(Recent_hashes.ancestors p.Engine.hashes);
  }

let s63 () =
  let cp, (_ : Consensus_store.Record.t list) = Lazy.force fixture in
  let honest = Checkpoint.engine cp in
  let skewed =
    Checkpoint.of_execution
      (with_skewed_window honest)
      ~last_executed:(Checkpoint.last_executed cp)
  in
  let window (p : Engine.persisted) =
    List.map Tn_keccak.to_hex (Recent_hashes.to_list p.Engine.hashes)
  in
  (* The fixture is genuinely skewed, so the case cannot pass vacuously. *)
  let () =
    Alcotest.(check bool) "the skewed window differs from the honest one" true
      (not
         (List.equal String.equal (window honest)
            (window (Checkpoint.engine skewed))))
  in
  let decoded = Checkpoint.engine (codec_round_trip "skewed round trip" skewed) in
  let () =
    Alcotest.(check (list string)) "the skew survives the wire verbatim"
      (window (Checkpoint.engine skewed))
      (window decoded)
  in
  (* And the normalised form the two share is only reachable through resume,
     which is why the wire must not produce it. *)
  let resumed p =
    List.map Tn_keccak.to_hex
      (Recent_hashes.to_list
         (Engine.recent_hashes
            (Engine.resume ~chain_id:(u256_int 2017) ~basefee_address p)))
  in
  Alcotest.(check (list string)) "resume renormalises both sides alike"
    (resumed (Checkpoint.engine skewed))
    (resumed decoded)

(* ---------- the file ---------- *)

(* S6.4 - save then load, over a store that really holds the checkpoint's
   last-executed block. *)
let s64 () =
  let cp, records = Lazy.force fixture in
  let dir = fresh_root "round-trip" in
  let store = fill (open_store dir) records in
  let generation = save_ok "save" ~dir ~store cp in
  let loaded = load_ok "load" ~dir in
  let () = close_store store in
  let () =
    Alcotest.(check int) "the first publish is generation one" 1 generation
  in
  let () =
    Alcotest.(check string) "the file round-trips through every projection"
      (Printf.sprintf "gen 1: %s" (render_checkpoint cp))
      (render_load loaded)
  in
  sweep dir

(* S6.5 - AHEAD, and no byte spent. The store holds two records and the
   checkpoint has executed three: the exact state a crash between the two
   durable writes CANNOT produce, because the record is filed first. *)
let s65 () =
  let cp, records = Lazy.force fixture in
  let dir = fresh_root "ahead" in
  let store = fill (open_store dir) (take 2 records) in
  let before = Io.bytes_written () in
  let verdict = refusal "ahead" (Ckpt.save ~dir ~store cp) in
  let spent = Io.bytes_written () - before in
  let after = load_ok "load after the refusal" ~dir in
  let () = close_store store in
  let () =
    Alcotest.(check string) "the publish is refused" "ahead 3 over 2" verdict
  in
  let () = Alcotest.(check int) "no byte was written" 0 spent in
  let () =
    Alcotest.(check string) "nothing was published" "absent" (render_load after)
  in
  sweep dir

(* S6.6 - UNKNOWN_BLOCK, and no byte spent. Same height, different digest: two
   durable artefacts from two different runs. *)
let foreign_fixture =
  lazy
    (let bodies = store () in
     let sds = committed_self () in
     let sd0 = nth "sd0" sds 0 in
     let sd1 = nth "sd1" sds 1 in
     let d0 = Driver.create (Lazy.force wide_spec) ~committee in
     let honest = mint_ok "mint sd0" d0 sd0 in
     let d1, (_ : Outcome.advance) = step_ok "step sd0" d0 sd0 ~bodies in
     let foreign = mint_ok "mint sd1" d0 sd1 in
     ( Driver.snapshot d1,
       record_ok "foreign record" foreign ~bodies,
       Cb.digest honest,
       Cb.digest foreign ))

let s66 () =
  let cp, foreign, honest_digest, foreign_digest = Lazy.force foreign_fixture in
  (* The positive control: the two blocks really are different, so the store
     below really does hold something else at that height. *)
  let () =
    Alcotest.(check bool) "the foreign block is a different block" false
      (Digests.Output_digest.equal honest_digest foreign_digest)
  in
  let dir = fresh_root "unknown-block" in
  let store = fill (open_store dir) [ foreign ] in
  let before = Io.bytes_written () in
  let verdict = refusal "unknown block" (Ckpt.save ~dir ~store cp) in
  let spent = Io.bytes_written () - before in
  let after = load_ok "load after the refusal" ~dir in
  let () = close_store store in
  let () =
    Alcotest.(check string) "the publish is refused" "unknown block at 1" verdict
  in
  let () = Alcotest.(check int) "no byte was written" 0 spent in
  let () =
    Alcotest.(check string) "nothing was published" "absent" (render_load after)
  in
  sweep dir

(* S6.7 - a fresh root is ABSENT, and a damaged canonical file is never that.
   Answering absent on damage would send the caller to [Checkpoint.genesis] and
   rewind a populated node to epoch zero at block zero. *)
let poke ~path ~at ~byte =
  io_ok "poke a byte"
    (Io.with_file ~ops:Io_ops.real ~path ~mode:Io.Read_write_create (fun fd ->
         Result.bind (Io.seek_to fd ~at) (fun () ->
             Io.write_all fd (String.make 1 byte))))

let s67 () =
  let cp, records = Lazy.force fixture in
  let fresh = fresh_root "fresh" in
  let () =
    Alcotest.(check string) "a fresh root is absent" "absent"
      (render_load (load_ok "fresh load" ~dir:fresh))
  in
  let () = sweep fresh in
  let dir = fresh_root "corrupt" in
  let store = fill (open_store dir) records in
  let (_ : int) = save_ok "save" ~dir ~store cp in
  let () = close_store store in
  let path = Filename.concat dir "checkpoint" in
  (* 0x20 is the first payload byte: the tag at 0x18 still commits to the old
     one, so this is a body-tag failure and not a decode failure. *)
  let () = poke ~path ~at:0x20 ~byte:'\xff' in
  let verdict =
    Result.fold
      ~ok:(fun l -> "loaded: " ^ render_load l)
      ~error:render_error (Ckpt.load ~dir ())
  in
  let () =
    Alcotest.(check string) "a damaged canonical file is named, never absent"
      "file: bad body tag" verdict
  in
  sweep dir

(* S6.8 - the generation is strictly increasing, and its one refusal is
   reachable: at the container's u64be ceiling there is no greater generation
   to publish, so the publish stops rather than wrapping. *)
let generation_ceiling = (1 lsl 62) - 1

let plant ~dir ~generation cp =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "plant: %s" (Atomic_file.error_to_string e))
    (Atomic_file.save ~ops:Io_ops.real ~dir ~name:"checkpoint"
       ~magic:"TNCKPT\x00\x00" ~format:1 ~generation
       ~payload:(Bcs.encode Ckpt_codec.checkpoint cp))

let s68 () =
  let cp, records = Lazy.force fixture in
  let dir = fresh_root "generation" in
  let store = fill (open_store dir) records in
  let g1 = save_ok "first publish" ~dir ~store cp in
  let g2 = save_ok "second publish" ~dir ~store cp in
  let g3 = save_ok "third publish" ~dir ~store cp in
  let () =
    Alcotest.(check (list int)) "strictly increasing" [ 1; 2; 3 ] [ g1; g2; g3 ]
  in
  let () =
    Alcotest.(check int) "the reader sees the newest generation" 3
      (generation_of (load_ok "load after three publishes" ~dir))
  in
  let () = plant ~dir ~generation:generation_ceiling cp in
  let before = Io.bytes_written () in
  let verdict = refusal "at the ceiling" (Ckpt.save ~dir ~store cp) in
  let spent = Io.bytes_written () - before in
  let () = close_store store in
  let () =
    Alcotest.(check string) "the ceiling refuses rather than wraps"
      (Printf.sprintf "generation %d does not advance %d" generation_ceiling
         generation_ceiling)
      verdict
  in
  let () = Alcotest.(check int) "and spends no byte" 0 spent in
  sweep dir

(* S6.9 - the flush count is an equality, not a claim: one for the temp file
   and one for the directory, and nothing else on the publish path flushes. *)
let s69 () =
  let cp, records = Lazy.force fixture in
  let dir = fresh_root "flushes" in
  let store = fill (open_store dir) records in
  let before = Io.fsyncs () in
  let (_ : int) = save_ok "save" ~dir ~store cp in
  let spent = Io.fsyncs () - before in
  let after = Io.fsyncs () in
  let (_ : Ckpt.load) = load_ok "load" ~dir in
  let read_flushes = Io.fsyncs () - after in
  let () = close_store store in
  let () = Alcotest.(check int) "a publish costs exactly two flushes" 2 spent in
  let () = Alcotest.(check int) "a read costs none" 0 read_flushes in
  sweep dir

(* S6.10 - W8 at the byte level. A publish that dies part-way through writing
   the temp leaves a PARTIAL [checkpoint.tmp]; the canonical name still binds
   the previous publish, the reader sweeps the temp before it reads anything,
   and the previous checkpoint comes back whole. *)
let s610 () =
  let cp, records = Lazy.force fixture in
  let dir = fresh_root "w8-partial-temp" in
  let store = fill (open_store dir) records in
  let g1 = save_ok "the publish that completes" ~dir ~store cp in
  let temp = Filename.concat dir "checkpoint.tmp" in
  let killed =
    refusal "the publish that dies mid-write"
      (Ckpt.save
         ~ops:(Durable_faults.short_write_at ~nth:1 ~bytes:16)
         ~dir ~store cp)
  in
  let temp_before =
    io_ok "look for the temp" (Io.exists ~ops:Io_ops.real ~path:temp)
  in
  let loaded = load_ok "load after the partial write" ~dir in
  let temp_after =
    io_ok "look for the temp" (Io.exists ~ops:Io_ops.real ~path:temp)
  in
  let () = close_store store in
  let () =
    Alcotest.(check bool) "the partial publish reports a short write" true
      (String.starts_with ~prefix:"file: io: " killed)
  in
  let () =
    Alcotest.(check bool) "a partial temp really was left behind" true temp_before
  in
  let () =
    Alcotest.(check string) "the previous checkpoint loads, whole"
      (Printf.sprintf "gen %d: %s" g1 (render_checkpoint cp))
      (render_load loaded)
  in
  let () =
    Alcotest.(check bool) "and the temp is swept by the read" false temp_after
  in
  sweep dir

(* S6.11 - W9 at the byte level. The publish is four ordered calls; a kill
   BEFORE the rename and a kill BETWEEN the rename and the directory flush are
   the two windows that straddle the moment of publication. Either way the
   reader finds exactly ONE complete checkpoint - the old one on the near side,
   the new one on the far side - and never a half of either. *)
let s611 () =
  let cp, records = Lazy.force fixture in
  let dir = fresh_root "w9-rename" in
  let store = fill (open_store dir) records in
  let g1 = save_ok "the first publish" ~dir ~store cp in
  (* Near side: the rename never happens. *)
  let (_ : string) =
    refusal "killed before the rename"
      (Ckpt.save
         ~ops:
           (Durable_faults.fail_at ~nth:1 ~op:Io.Rename
              ~code:Durable_faults.Absent)
         ~dir ~store cp)
  in
  let near = load_ok "load on the near side" ~dir in
  (* Far side: the rename happens and the directory flush does not. *)
  let (_ : string) =
    refusal "killed after the rename"
      (Ckpt.save
         ~ops:
           (Durable_faults.fail_at ~nth:2 ~op:Io.Fsync
              ~code:Durable_faults.Absent)
         ~dir ~store cp)
  in
  let far = load_ok "load on the far side" ~dir in
  let () = close_store store in
  let () =
    Alcotest.(check int) "the near side is the previous publish" g1
      (generation_of near)
  in
  let () =
    Alcotest.(check int) "the far side is the new publish" (Stdlib.succ g1)
      (generation_of far)
  in
  Alcotest.(check (list string)) "both sides are one COMPLETE checkpoint"
    [ render_checkpoint cp; render_checkpoint cp ]
    [ payload_of near; payload_of far ]

let () =
  Alcotest.run "checkpoint file"
    [
      ( "the checkpoint codec",
        [
          Alcotest.test_case "every projection round-trips" `Quick s61;
          Alcotest.test_case "the world round-trips through equal" `Quick s62;
          Alcotest.test_case "the window round-trips unnormalised" `Quick s63;
        ] );
      ( "the checkpoint file",
        [
          Alcotest.test_case "save then load" `Quick s64;
          Alcotest.test_case "ahead of the durable tip is refused" `Quick s65;
          Alcotest.test_case "a block the store does not hold is refused" `Quick
            s66;
          Alcotest.test_case "absent, and never absent on damage" `Quick s67;
          Alcotest.test_case "the generation only ever advances" `Quick s68;
          Alcotest.test_case "a publish costs exactly two flushes" `Quick s69;
        ] );
      ( "crash windows, at the byte level",
        [
          Alcotest.test_case "W8: a partial temp is swept" `Quick s610;
          Alcotest.test_case "W9: rename and directory flush" `Quick s611;
        ] );
    ]
