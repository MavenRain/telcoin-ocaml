(* Chunk-38 stage 5: the WRITE side - [Driver.mint], [Consensus_store.receive]
   and [Driver.snapshot], i.e. the two durable writes and the gap between them.

   The shell protocol under test is one sub-DAG at a time:

     mint -> Record.create -> receive -> step -> snapshot

   and the whole point of it is that the first write happens strictly BEFORE
   execution and the second strictly after, so a crash between them leaves a
   store ahead of a checkpoint. Chunk 37's [Driver.fold] is left untouched on
   the other side of every differential here, which is what makes S5.1 a
   regression control rather than a tautology: a refactor that shifted both
   sides together would have to shift a function this stage never edits.

   Fixtures are test_driver_sim.ml's, deliberately: the seed-42 four-authority
   run is the golden run the central property is stated over. Stage 7 migrated
   both files onto the one [Driver_prelude], so the two sides of every
   differential here consume the SAME helper values and cannot drift through
   an edit to only one file.

   P7 carries over: every injected transaction is a placeholder the decode
   layer drops before the block, so nothing here reads a fee credit. *)

open Tn_types
open Tn_vertex
open Tn_consensus
open Tn_sim
open Driver_prelude

(* ---------- the chunk-38 write protocol ---------- *)

let mint_ok what d sd =
  Result.fold ~ok:Fun.id
    ~error:(fun e -> Alcotest.failf "%s: %s" what (Outcome.error_to_string e))
    (Driver.mint d sd)

let record_ok what block ~bodies =
  Result.fold ~ok:Fun.id
    ~error:(fun e ->
      Alcotest.failf "%s: %s" what
        (Consensus_store.Record.error_to_string e))
    (Consensus_store.Record.create ~consensus:block
       ~lookup:(Batch_store.find bodies))

let receive_ok what store record =
  Result.fold ~ok:Fun.id
    ~error:(fun e ->
      Alcotest.failf "%s: %s" what (Consensus_store.error_to_string e))
    (Consensus_store.receive store record)

(* The empty log a cold-started shell opens beside a cold-started driver:
   epoch 0, first record at one, linking to the chain's own genesis parent. *)
let fresh_store () =
  Consensus_store.create ~epoch:Units.Epoch.zero ~anchor:Cb.Number.genesis
    ~parent:Cb.genesis_parent

(* ONE turn of the shell protocol, in the documented order. The checkpoint is
   taken after the step, so the pair carried out of here is always the
   post-step one; every crash state is built by stopping part-way instead. *)
let write_turn (d, store) sd ~bodies =
  let block = mint_ok "mint" d sd in
  let store = receive_ok "receive" store (record_ok "record" block ~bodies) in
  let d, advance = step_ok "step" d sd ~bodies in
  ((d, store), advance)

let write_run d sds ~bodies =
  let (d, store), advances_rev =
    List.fold_left
      (fun (state, acc) sd ->
        let state, advance = write_turn state sd ~bodies in
        (state, advance :: acc))
      ((d, fresh_store ()), [])
      sds
  in
  (d, store, List.rev advances_rev)

(* The observable shape of one advance: the two digests a shell persists, the
   epoch flag, and the execution blocks in order. Rendered as one string so a
   disagreement prints as a diff rather than as a structural mismatch. *)
let shape a =
  String.concat "|"
    (Digests.Output_digest.to_hex (Cb.digest a.Outcome.consensus)
     :: Digests.Output_digest.to_hex (Output.output_digest a.Outcome.output)
     :: string_of_bool a.Outcome.closes_epoch
     :: List.map
          (fun b -> Tn_keccak.to_hex (Executed_block.hash b))
          a.Outcome.blocks)

let payload_count sd = List.length (Sub_dag.payload_digests sd)

(* The shortest prefix of the committed log whose LAST output references at
   least one batch. S5.7 needs it: a step over an EMPTY output attaches
   nothing, so an empty body store could not make it fail and the crash site
   would be vacuous. *)
let prefix_to_first_payload () =
  let rec go acc = function
    | [] -> Alcotest.fail "no committed output references a batch"
    | sd :: rest ->
        if payload_count sd > 0 then List.rev (sd :: acc) else go (sd :: acc) rest
  in
  go [] (committed_self ())

(* ---------- S5.1 ---------- *)

(* The regression control. The whole golden run, driven twice: once through
   the chunk-38 write protocol (mint -> Record.create -> receive -> step ->
   snapshot) and once through chunk 37's UNTOUCHED [Driver.fold]. The two
   advance lists must agree element for element on the consensus digest, the
   output digest, the ordered execution block hashes and [closes_epoch].
   Length is asserted first and separately, so "the write run is shorter" and
   "element 4 differs" stay two distinct red assertions. *)
let s51 () =
  let bodies = store () in
  let sds = committed_self () in
  let spec = Lazy.force wide_spec in
  let _, _, written = write_run (Driver.create spec ~committee) sds ~bodies in
  let _, folded = fold_ok "fold" (Driver.create spec ~committee) sds ~bodies in
  Alcotest.(check bool) "the golden run is non-empty (anti-vacuity)" true
    (List.length folded > 0);
  Alcotest.(check int)
    "the write protocol produced one advance per folded output"
    (List.length folded) (List.length written);
  Alcotest.(check (list string))
    "every advance agrees on consensus digest, output digest, block hashes \
     and closes_epoch"
    (List.map shape folded) (List.map shape written)

(* ---------- S5.2 ---------- *)

(* [mint] advances nothing. Minting twice from the same driver answers the
   same block BOTH times, that block's number is exactly one above the
   driver's watermark - never two, which is what a mint that consumed a
   number would give - and the watermark itself is unmoved. Asserted at a
   cold start AND after three real steps, so "one above" is a live property
   rather than an artefact of starting at genesis. *)
let s52 () =
  let bodies = store () in
  let sds = committed_self () in
  let spec = Lazy.force wide_spec in
  let probe what d =
    let sd = nth "probe output" sds 5 in
    let b1 = mint_ok "first mint" d sd in
    let b2 = mint_ok "second mint" d sd in
    Alcotest.(check string)
      (what ^ ": minting twice answers the same block")
      (Digests.Output_digest.to_hex (Cb.digest b1))
      (Digests.Output_digest.to_hex (Cb.digest b2));
    Alcotest.(check int)
      (what ^ ": the minted number is exactly one above the watermark")
      (Cb.Number.to_int (Driver.last_forwarded d) + 1)
      (Cb.Number.to_int (Cb.number b1));
    Cb.Number.to_int (Driver.last_forwarded d)
  in
  let d0 = Driver.create spec ~committee in
  Alcotest.(check int) "a cold driver forwards nothing before minting" 0
    (probe "cold" d0);
  let d3, _ = fold_ok "fold" d0 (take 3 sds) ~bodies in
  Alcotest.(check int) "and three steps in, the watermark is three" 3
    (probe "after three steps" d3)

(* ---------- S5.3 ---------- *)

(* [mint] applies [step]'s two pre-mint refusals, in [step]'s order. The third
   assertion is the ORDER itself: a sealed driver handed an epoch-mismatched
   output reports the SEAL, because the handoff is owed before anything about
   the output matters. *)
let s53 () =
  let bodies = store () in
  let sds = committed_self () in
  let mismatched = epoch1_sub_dag ~r:1 ~at:5L [] in
  let running = Driver.create (Lazy.force wide_spec) ~committee in
  let refusal d sd =
    Result.fold
      ~ok:(fun b ->
        Alcotest.failf "mint returned block %s instead of refusing"
          (Digests.Output_digest.to_hex (Cb.digest b)))
      ~error:Outcome.error_to_string (Driver.mint d sd)
  in
  Alcotest.(check bool)
    "a running driver refuses an epoch-mismatched output at mint" true
    (mentions "does not match the installed committee epoch"
       (refusal running mismatched));
  (* The 10 s epoch closes inside the horizon, so stepping the golden run
     under the short spec reaches a genuinely sealed driver. *)
  let rec to_seal d = function
    | [] -> Alcotest.fail "no output closed the 10 s epoch inside the horizon"
    | sd :: rest ->
        let d, a = step_ok "pre-close step" d sd ~bodies in
        if a.Outcome.closes_epoch then (d, rest) else to_seal d rest
  in
  let sealed, rest = to_seal (Driver.create (Lazy.force short_spec) ~committee) sds in
  let next = nth "post-seal output" rest 0 in
  Alcotest.(check string) "a sealed driver refuses a well-formed output at mint"
    (Outcome.error_to_string Outcome.Sealed_needs_handoff)
    (refusal sealed next);
  Alcotest.(check string)
    "and a sealed driver handed an epoch-mismatched output reports the SEAL, \
     not the mismatch: the guards fire in step's order"
    (Outcome.error_to_string Outcome.Sealed_needs_handoff)
    (refusal sealed mismatched)

(* ---------- S5.4 ---------- *)

(* [snapshot] after k steps files the k-th advance and nothing else: the
   watermark IS the k-th consensus number, the last-executed block IS the
   k-th advance's own consensus block (by digest), the epoch and committee
   are the installed ones, and the two phase projections agree with the
   driver's. *)
let s54 () =
  let bodies = store () in
  let k = 4 in
  let d, advances =
    fold_ok "fold"
      (Driver.create (Lazy.force wide_spec) ~committee)
      (take k (committed_self ()))
      ~bodies
  in
  Alcotest.(check int) "the fixture really folded k outputs" k
    (List.length advances);
  let last = nth "k-th advance" advances (k - 1) in
  let cp = Driver.snapshot d in
  Alcotest.(check int) "the watermark is the k-th consensus number"
    (Cb.Number.to_int (Cb.number last.Outcome.consensus))
    (Cb.Number.to_int (Checkpoint.watermark cp));
  Alcotest.(check (option string))
    "last_executed is the k-th advance's own consensus block"
    (Some (Digests.Output_digest.to_hex (Cb.digest last.Outcome.consensus)))
    (Option.map
       (fun b -> Digests.Output_digest.to_hex (Cb.digest b))
       (Checkpoint.last_executed cp));
  Alcotest.(check string) "the checkpoint's epoch is the installed one"
    (Units.Epoch.to_string (Committee.epoch committee))
    (Units.Epoch.to_string (Checkpoint.epoch cp));
  Alcotest.(check (list string)) "and so is its committee, seat for seat"
    (List.map
       (fun a -> Authority_id.to_hex (Authority.id a))
       (Committee.authorities committee))
    (List.map
       (fun a -> Authority_id.to_hex (Authority.id a))
       (Committee.authorities (Checkpoint.committee cp)));
  Alcotest.(check bool) "is_sealed agrees with the driver's" (Driver.is_sealed d)
    (Checkpoint.is_sealed cp);
  Alcotest.(check (option int64)) "closed_at agrees with the driver's"
    (Option.map Units.Timestamp.to_sec (Driver.closed_at d))
    (Option.map Units.Timestamp.to_sec (Checkpoint.closed_at cp))

(* ---------- S5.5 ---------- *)

(* The seed IS the executed tip. A checkpoint at k, handed through
   [Checkpoint.accumulator] to [Subscriber.create], reports number k - not
   k+1 - so the first block a resumed chain mints lands at k+1 and not k+2.
   The cold checkpoint is asserted alongside, because "genesis" and "resumed
   at zero" must be the same seed for a shell's startup path to be uniform. *)
let s55 () =
  let bodies = store () in
  let k = 4 in
  let spec = Lazy.force wide_spec in
  let seed_number cp =
    Cb.Number.to_int (Subscriber.number (Subscriber.create (Checkpoint.accumulator cp)))
  in
  Alcotest.(check int) "a genesis checkpoint seeds the accumulator at zero" 0
    (seed_number (Checkpoint.genesis spec ~committee));
  let d, _ =
    fold_ok "fold" (Driver.create spec ~committee)
      (take k (committed_self ()))
      ~bodies
  in
  Alcotest.(check int)
    "a checkpoint at k seeds the accumulator at k, with no adjustment" k
    (seed_number (Driver.snapshot d));
  Alcotest.(check int) "which is the driver's own watermark" k
    (Cb.Number.to_int (Driver.last_forwarded d))

(* ---------- S5.6 ---------- *)

(* The driver's deleted phase field, derived. After the sealing step
   [Driver.is_sealed] and [Driver.closed_at] are exactly the engine's phase -
   [closed_at] being the closing output's COMMIT timestamp, which is the value
   chunk 37's field held - and a further step is refused. *)
let s56 () =
  let bodies = store () in
  let rec to_seal d = function
    | [] -> Alcotest.fail "no output closed the 10 s epoch inside the horizon"
    | sd :: rest ->
        let d, a = step_ok "pre-close step" d sd ~bodies in
        if a.Outcome.closes_epoch then (d, a, rest) else to_seal d rest
  in
  let d, closing, rest =
    to_seal (Driver.create (Lazy.force short_spec) ~committee) (committed_self ())
  in
  let engine_closed_at =
    match Engine.phase (Driver.engine d) with
    | Engine.Running { boundary = _; committee = _ } ->
        Alcotest.fail "the engine is Running after the output that sealed it"
    | Engine.Sealed { closed_at; committee = _ } -> closed_at
  in
  Alcotest.(check bool) "is_sealed reads the engine's phase" true
    (Driver.is_sealed d);
  Alcotest.(check (option int64)) "closed_at reads the engine's phase"
    (Some (Units.Timestamp.to_sec engine_closed_at))
    (Option.map Units.Timestamp.to_sec (Driver.closed_at d));
  Alcotest.(check int64)
    "and that timestamp is the closing output's commit time, the value the \
     deleted field held"
    (Units.Timestamp.to_sec (Output.committed_at closing.Outcome.output))
    (Units.Timestamp.to_sec engine_closed_at);
  Alcotest.(check string) "a further step is refused, handoff first"
    (Outcome.error_to_string Outcome.Sealed_needs_handoff)
    (Result.fold
       ~ok:(fun _ -> "ok")
       ~error:Outcome.error_to_string
       (Driver.step d (nth "post-seal output" rest 0) ~bodies ~address_of))

(* ---------- S5.7 ---------- *)

(* THE FAILING-STEP STATE. Drive the protocol to output k, file record k, then
   step it with an EMPTY body store so the step genuinely fails at attach.
   What survives is crash site C2: the store holds k, the checkpoint holds
   k-1, and no driver came back at all - the caller still holds the pre-step
   one, which is the only driver the error arm can leave, since
   [Outcome.error] carries no driver field. *)
let s57 () =
  let bodies = store () in
  let prefix = prefix_to_first_payload () in
  let k = List.length prefix in
  let last_sd = nth "the k-th output" prefix (k - 1) in
  let d, store_before, _ =
    write_run
      (Driver.create (Lazy.force wide_spec) ~committee)
      (take (k - 1) prefix) ~bodies
  in
  Alcotest.(check bool) "the k-th output really references a batch (anti-vacuity)"
    true
    (payload_count last_sd > 0);
  let block = mint_ok "mint k" d last_sd in
  let store =
    receive_ok "receive k" store_before (record_ok "record k" block ~bodies)
  in
  let error =
    Result.fold
      ~ok:(fun (_, a) ->
        Alcotest.failf "the step succeeded on an empty body store at number %d"
          (Cb.Number.to_int (Cb.number a.Outcome.consensus)))
      ~error:Fun.id
      (Driver.step d last_sd ~bodies:Batch_store.empty ~address_of)
  in
  Alcotest.(check bool)
    "the step failed at attach on a missing body, not somewhere else" true
    (mentions "attach: missing fetched batch" (Outcome.error_to_string error));
  Alcotest.(check bool) "and it names the k-th output's own first digest" true
    (mentions
       (Digests.Batch_digest.to_hex
          (nth "first payload digest" (Sub_dag.payload_digests last_sd) 0))
       (Outcome.error_to_string error));
  Alcotest.(check (option int)) "C2: the store holds k" (Some k)
    (Option.map
       (fun r -> Cb.Number.to_int (Consensus_store.Record.number r))
       (Consensus_store.latest_received store));
  Alcotest.(check int) "C2: the checkpoint holds k-1" (k - 1)
    (Cb.Number.to_int (Checkpoint.watermark (Driver.snapshot d)));
  Alcotest.(check int)
    "and the pre-step driver the caller still holds is unmoved" (k - 1)
    (Cb.Number.to_int (Driver.last_forwarded d))

(* ==================== stage 6: the resumed run ==================== *)

let drop k l = List.filteri (fun i _ -> i >= k) l

(* Resume, totalised on the shape each case expects. Any [resume_error] is a
   test failure rendered through the function under test's own printer. *)
let resume_ok what spec ~checkpoint ~store:cstore =
  Result.fold ~ok:Fun.id
    ~error:(fun e ->
      Alcotest.failf "%s: %s" what (Driver.resume_error_to_string e))
    (Driver.resume spec ~committee ~checkpoint ~store:cstore ~address_of)

let resume_advance what spec ~checkpoint ~store:cstore =
  match resume_ok what spec ~checkpoint ~store:cstore with
  | Outcome.Advance { driver; advances } -> (driver, advances)
  | Outcome.Sealed { driver = _; advances = _; rest } ->
      Alcotest.failf "%s: sealed with %d outputs unconsumed" what
        (List.length rest)
  | Outcome.Halted { advances = _; error } ->
      Alcotest.failf "%s: %s" what (Outcome.error_to_string error)

let resume_err what spec ~committee:cmt ~checkpoint ~store:cstore =
  Result.fold
    ~ok:(fun _ ->
      Alcotest.failf "%s: resume succeeded instead of refusing" what)
    ~error:Fun.id
    (Driver.resume spec ~committee:cmt ~checkpoint ~store:cstore ~address_of)

(* Drive the write protocol to k, then file record k+1 WITHOUT stepping it:
   the canonical one-record gap, store at k+1 and checkpoint at k, plus the
   sub-DAG that fell in the gap. [sds] is any committed prefix source. *)
let one_record_gap spec sds ~k ~bodies =
  let gap_sd = nth "the gap output" sds k in
  let d, store_k, _ =
    write_run (Driver.create spec ~committee) (take k sds) ~bodies
  in
  let block = mint_ok "mint the gap output" d gap_sd in
  let store_k1 =
    receive_ok "receive the gap record" store_k
      (record_ok "record the gap output" block ~bodies)
  in
  (Driver.snapshot d, store_k1, gap_sd)

(* ---------- S6.1 ---------- *)

(* THE one-record gap. The store is one record ahead of the checkpoint; resume
   re-mints exactly that record and lands, advance for advance, on the golden
   run's own k+1 - which is what refutes the naive-wrong seed: an accumulator
   seeded at the store tip would mint the replayed block at k+2 under a
   different parent and every digest here would disagree. *)
let s61 () =
  let bodies = store () in
  let sds = committed_self () in
  let spec = Lazy.force wide_spec in
  let k = 4 in
  let cp, store_k1, _ = one_record_gap spec sds ~k ~bodies in
  Alcotest.(check int) "the fixture really is a one-record gap: store at k+1"
    (k + 1)
    (get "store tip"
       (Option.map
          (fun r -> Cb.Number.to_int (Consensus_store.Record.number r))
          (Consensus_store.latest_received store_k1)));
  Alcotest.(check int) "and the checkpoint at k" k
    (Cb.Number.to_int (Checkpoint.watermark cp));
  let resumed, advances =
    resume_advance "resume" spec ~checkpoint:cp ~store:store_k1
  in
  let _, golden =
    fold_ok "golden"
      (Driver.create spec ~committee)
      (take (k + 1) sds)
      ~bodies
  in
  Alcotest.(check int) "the resume carries exactly one advance" 1
    (List.length advances);
  Alcotest.(check (list string))
    "and it equals the golden's k+1 on consensus digest, output digest and \
     block hashes"
    (List.map shape (drop k golden))
    (List.map shape advances);
  Alcotest.(check int)
    "last_forwarded equals the collected gap's upto, the store's tip" (k + 1)
    (Cb.Number.to_int (Driver.last_forwarded resumed))

(* ---------- S6.2 ---------- *)

(* The empty gap: a caught-up node's restart is a no-op that returns a LIVE
   driver, and the rest of the chain folds through it exactly as the golden
   run folds. *)
let s62 () =
  let bodies = store () in
  let sds = committed_self () in
  let spec = Lazy.force wide_spec in
  let k = 4 in
  let d, store_k, _ =
    write_run (Driver.create spec ~committee) (take k sds) ~bodies
  in
  let resumed, advances =
    resume_advance "resume" spec ~checkpoint:(Driver.snapshot d) ~store:store_k
  in
  Alcotest.(check int) "an empty gap replays nothing" 0 (List.length advances);
  Alcotest.(check int) "and the resumed watermark is k" k
    (Cb.Number.to_int (Driver.last_forwarded resumed));
  let _, golden = fold_ok "golden" (Driver.create spec ~committee) sds ~bodies in
  let _, tail = fold_ok "tail" resumed (drop k sds) ~bodies in
  Alcotest.(check (list string))
    "folding the tail through the resumed driver matches the golden"
    (List.map shape (drop k golden))
    (List.map shape tail)

(* ---------- S6.3 ---------- *)

(* The committee cross-check: an epoch-1 committee against an epoch-0
   checkpoint is refused BEFORE anything replays, and the rendering names
   both epochs. *)
let s63 () =
  let bodies = store () in
  let sds = committed_self () in
  let spec = Lazy.force wide_spec in
  let d, store_k, _ =
    write_run (Driver.create spec ~committee) (take 3 sds) ~bodies
  in
  let err =
    resume_err "committee cross-check" spec ~committee:committee_next
      ~checkpoint:(Driver.snapshot d) ~store:store_k
  in
  (match err with
  | Driver.Committee_epoch { supplied; checkpoint } ->
      Alcotest.(check string) "the supplied epoch is the committee's"
        (Units.Epoch.to_string epoch1)
        (Units.Epoch.to_string supplied);
      Alcotest.(check string) "the checkpoint epoch is the executed one"
        (Units.Epoch.to_string Units.Epoch.zero)
        (Units.Epoch.to_string checkpoint)
  | Driver.Committee_mismatch _ | Driver.Store_epoch _ | Driver.Gap _ ->
      Alcotest.failf "wrong refusal: %s" (Driver.resume_error_to_string err));
  let rendered = Driver.resume_error_to_string err in
  Alcotest.(check bool) "the rendering names the supplied epoch" true
    (mentions ("epoch " ^ Units.Epoch.to_string epoch1) rendered);
  Alcotest.(check bool) "and the checkpoint's" true
    (mentions ("epoch " ^ Units.Epoch.to_string Units.Epoch.zero) rendered)

(* ---------- S6.4 ---------- *)

(* The store cross-check: a store rolled to epoch 1 against an epoch-0
   checkpoint is refused - two durable values from different epochs are not a
   pair, even though each is well-formed alone. *)
let s64 () =
  let bodies = store () in
  let sds = committed_self () in
  let spec = Lazy.force wide_spec in
  let d, store_k, _ =
    write_run (Driver.create spec ~committee) (take 3 sds) ~bodies
  in
  let rolled =
    Result.fold ~ok:Fun.id
      ~error:(fun e ->
        Alcotest.failf "open_epoch: %s" (Consensus_store.error_to_string e))
      (Consensus_store.open_epoch store_k ~epoch:epoch1)
  in
  let err =
    resume_err "store cross-check" spec ~committee
      ~checkpoint:(Driver.snapshot d) ~store:rolled
  in
  match err with
  | Driver.Store_epoch { checkpoint; store } ->
      Alcotest.(check string) "the checkpoint's epoch"
        (Units.Epoch.to_string Units.Epoch.zero)
        (Units.Epoch.to_string checkpoint);
      Alcotest.(check string) "the store's open epoch"
        (Units.Epoch.to_string epoch1)
        (Units.Epoch.to_string store)
  | Driver.Committee_epoch _ | Driver.Committee_mismatch _ | Driver.Gap _ ->
      Alcotest.failf "wrong refusal: %s" (Driver.resume_error_to_string err)

(* ---------- S6.4b ---------- *)

(* The whole-value committee cross-check: a committee of the RIGHT epoch but
   the wrong roster is refused BEFORE anything replays - epoch equality alone
   cannot tell two rosters of one epoch apart, and resuming under the
   imposter would resolve leaders against the wrong seats. The first three
   assertions pin [Committee.equal] itself: different keys at the same epoch
   differ, and - the trap an id-only comparison falls into - the SAME keys
   routed to shifted execution addresses differ too. *)
let s69 () =
  let bodies = store () in
  let sds = committed_self () in
  let spec = Lazy.force wide_spec in
  let alt, _ = build_committee ~seed:900 ~epoch:Units.Epoch.zero in
  Alcotest.(check string) "the two committees share an epoch (anti-vacuity)"
    (Units.Epoch.to_string (Committee.epoch committee))
    (Units.Epoch.to_string (Committee.epoch alt));
  Alcotest.(check bool) "Committee.equal is reflexive on the installed one"
    true
    (Committee.equal committee committee);
  Alcotest.(check bool)
    "the same-epoch different-keys committee is genuinely different" false
    (Committee.equal committee alt);
  let rotated =
    let auths = Committee.authorities committee in
    let addrs = List.map Authority.execution_address auths in
    let shifted = drop 1 addrs @ take 1 addrs in
    Result.fold ~ok:Fun.id
      ~error:(fun e ->
        Alcotest.failf "rotated committee: %s" (Committee.error_to_string e))
      (Committee.create ~epoch:Units.Epoch.zero
         (List.map
            (fun (a, addr) ->
              Authority.make
                ~protocol_key:(Authority.protocol_key a)
                ~execution_address:addr)
            (get "rotated pairing" (zip auths shifted))))
  in
  Alcotest.(check bool)
    "same keys, shifted execution addresses: still a different committee"
    false
    (Committee.equal committee rotated);
  let d, store_k, _ =
    write_run (Driver.create spec ~committee) (take 3 sds) ~bodies
  in
  let err =
    resume_err "whole-value committee cross-check" spec ~committee:alt
      ~checkpoint:(Driver.snapshot d) ~store:store_k
  in
  (match err with
  | Driver.Committee_mismatch { epoch } ->
      Alcotest.(check string) "the mismatch names the shared epoch"
        (Units.Epoch.to_string Units.Epoch.zero)
        (Units.Epoch.to_string epoch)
  | Driver.Committee_epoch _ | Driver.Store_epoch _ | Driver.Gap _ ->
      Alcotest.failf "wrong refusal: %s" (Driver.resume_error_to_string err));
  Alcotest.(check bool) "the rendering names the shared epoch" true
    (mentions
       ("epoch " ^ Units.Epoch.to_string Units.Epoch.zero)
       (Driver.resume_error_to_string err))

(* ---------- S6.5 ---------- *)

(* Fork detection end to end. Run B is the golden log SHIFTED by one output -
   same committee, same epoch, but every height holds a different block - so
   run A's checkpoint at k and run B's store at k are individually well-formed
   halves of two different chains. The gap's floor digest comparison is the
   only place that mispairing can be caught, and it must answer [Forked] at
   exactly k with both digests. *)
let s65 () =
  let bodies = store () in
  let sds = committed_self () in
  let spec = Lazy.force wide_spec in
  let k = 3 in
  let dA, _, _ =
    write_run (Driver.create spec ~committee) (take k sds) ~bodies
  in
  let cp = Driver.snapshot dA in
  let offered_digest =
    Digests.Output_digest.to_hex
      (Cb.digest (get "checkpoint tip" (Checkpoint.last_executed cp)))
  in
  let _, store_b, _ =
    write_run (Driver.create spec ~committee) (take k (drop 1 sds)) ~bodies
  in
  let stored_digest =
    Result.fold
      ~ok:(fun r ->
        Digests.Output_digest.to_hex (Consensus_store.Record.digest r))
      ~error:(fun m ->
        Alcotest.failf "store B has no record at k: %s"
          (Consensus_store.miss_to_string m))
      (Consensus_store.record_at store_b
         (Cb.number (get "checkpoint tip" (Checkpoint.last_executed cp))))
  in
  Alcotest.(check bool)
    "the two runs really disagree at k (anti-vacuity)" false
    (String.equal offered_digest stored_digest);
  let err = resume_err "forked resume" spec ~committee ~checkpoint:cp ~store:store_b in
  match err with
  | Driver.Gap (Consensus_store.Forked { number; stored; offered }) ->
      Alcotest.(check int) "forked at exactly the floor" k
        (Cb.Number.to_int number);
      Alcotest.(check string) "naming the store's own digest" stored_digest
        (Digests.Output_digest.to_hex stored);
      Alcotest.(check string) "and the checkpoint's" offered_digest
        (Digests.Output_digest.to_hex offered)
  | Driver.Gap
      ( Consensus_store.Below_retained _ | Consensus_store.Above_tip _
      | Consensus_store.Broken _ )
  | Driver.Committee_epoch _ | Driver.Committee_mismatch _
  | Driver.Store_epoch _ ->
      Alcotest.failf "wrong refusal: %s" (Driver.resume_error_to_string err)

(* ---------- S6.6 ---------- *)

(* Bodies come from the store, and only from the store. The replayed advance's
   attached bodies are compared against the INJECTION-side bytes - the batches
   the sim's plan created, before any store existed - never through a store
   lookup on the assertion side, so a self-consistent store that filed the
   wrong bytes cannot vacuously agree with itself (T140). *)
let s66 () =
  let bodies = store () in
  let spec = Lazy.force wide_spec in
  let prefix = prefix_to_first_payload () in
  let m = List.length prefix in
  let cp, store_m, gap_sd = one_record_gap spec prefix ~k:(m - 1) ~bodies in
  let _, advances = resume_advance "resume" spec ~checkpoint:cp ~store:store_m in
  let a = nth "the replayed advance" advances 0 in
  let attached = List.concat_map snd (Output.certified a.Outcome.output) in
  Alcotest.(check bool)
    "the replayed output really attached a body (anti-vacuity)" true
    (List.length attached > 0);
  Alcotest.(check (list string))
    "the attached digests are the header's own payload, in commit order"
    (List.map Digests.Batch_digest.to_hex (Sub_dag.payload_digests gap_sd))
    (List.map
       (fun b -> Digests.Batch_digest.to_hex (Batch.digest b))
       attached);
  let injected = Sim.batch_bodies (Lazy.force sim) in
  List.iter
    (fun b ->
      let d = Batch.digest b in
      let source =
        get
          ("no injected batch has digest " ^ Digests.Batch_digest.to_hex d)
          (List.find_opt
             (fun c -> Digests.Batch_digest.equal (Batch.digest c) d)
             injected)
      in
      Alcotest.(check bool)
        ("attached body " ^ Digests.Batch_digest.to_hex d
       ^ " equals the injection-side bytes")
        true (Batch.equal source b))
    attached

(* ---------- S6.7 ---------- *)

(* Replay-and-close: the gap's last record is the epoch-closing output, so the
   resume itself crosses the seal and must return chunk 37's own [Sealed]
   terminal - driver, one advance, nothing unconsumed - with [begin_epoch]
   accepted on the driver it carries, and the closing block's
   [withdrawals_root] (the root the replayed leader counts fund) equal to the
   golden's. *)
let s67 () =
  let bodies = store () in
  let sds = committed_self () in
  let spec = Lazy.force short_spec in
  let golden_advances =
    match Driver.fold (Driver.create spec ~committee) sds ~bodies ~address_of with
    | Outcome.Sealed { driver = _; advances; rest = _ } -> advances
    | Outcome.Advance { driver = _; advances = _ } ->
        Alcotest.fail "the 10 s epoch never sealed inside the horizon (fixture)"
    | Outcome.Halted { advances = _; error } ->
        Alcotest.failf "golden run halted: %s" (Outcome.error_to_string error)
  in
  let c = List.length golden_advances in
  let golden_closing = nth "the golden closing advance" golden_advances (c - 1) in
  Alcotest.(check bool)
    "the golden's last advance really closes the epoch (anti-vacuity)" true
    golden_closing.Outcome.closes_epoch;
  let cp, store_c, _ = one_record_gap spec sds ~k:(c - 1) ~bodies in
  let resumed, advances =
    match resume_ok "resume" spec ~checkpoint:cp ~store:store_c with
    | Outcome.Sealed { driver; advances; rest = [] } -> (driver, advances)
    | Outcome.Sealed { driver = _; advances = _; rest } ->
        Alcotest.failf "sealed with %d outputs unconsumed instead of none"
          (List.length rest)
    | Outcome.Advance { driver = _; advances = _ } ->
        Alcotest.fail "resume returned Advance across the seal"
    | Outcome.Halted { advances = _; error } ->
        Alcotest.failf "resume halted: %s" (Outcome.error_to_string error)
  in
  Alcotest.(check int) "replay-and-close carries exactly the closing advance" 1
    (List.length advances);
  let closing = nth "the replayed closing advance" advances 0 in
  Alcotest.(check bool) "and it closes the epoch" true
    closing.Outcome.closes_epoch;
  let root a =
    let blocks = a.Outcome.blocks in
    Tn_evm.Hash32.to_hex
      (Tn_evm.Block_header.withdrawals_root
         (Executed_block.header
            (nth "closing block" blocks (List.length blocks - 1))))
  in
  Alcotest.(check string)
    "the replayed closing block's withdrawals_root equals the golden's"
    (root golden_closing) (root closing);
  Result.fold
    ~ok:(fun (_ : Driver.t) -> ())
    ~error:(fun e ->
      Alcotest.failf "begin_epoch on the resumed sealed driver refused: %s"
        (Driver.handoff_error_to_string e))
    (Driver.begin_epoch resumed ~committee:committee_next)

(* ---------- S6.8 ---------- *)

(* The INDEPENDENT ORACLE, off the production path: derive the watermark the
   way upstream does - resolve the final anchor header's
   [parent_beacon_block_root] back through the store - and require it at or
   BELOW the post-resume checkpoint's watermark. At or below, never equal: an
   output that carries no batches and does not close the epoch produces zero
   blocks and leaves the anchor naming an earlier output
   ([outcome.mli:35-36]). No production code takes this route, which is what
   lets it catch a checkpoint and a store that are wrong TOGETHER. *)
let s68 () =
  let bodies = store () in
  let spec = Lazy.force wide_spec in
  let prefix = prefix_to_first_payload () in
  let m = List.length prefix in
  let cp, store_m, _ = one_record_gap spec prefix ~k:(m - 1) ~bodies in
  let resumed, _ = resume_advance "resume" spec ~checkpoint:cp ~store:store_m in
  let cp' = Driver.snapshot resumed in
  let header =
    get "the resumed anchor has a real header (anti-vacuity)"
      (Tn_engine.Anchor.header (Engine.anchor (Driver.engine resumed)))
  in
  let record =
    get "the anchor's parent_beacon_block_root resolves in the store"
      (Consensus_store.record_by_digest store_m
         (Tn_evm.Block_header.parent_beacon_block_root header))
  in
  Alcotest.(check bool)
    "upstream's own watermark derivation lands at or below the checkpoint's"
    true
    (Cb.Number.to_int (Consensus_store.Record.number record)
    <= Cb.Number.to_int (Checkpoint.watermark cp'))

(* ==================== stage 7: the sweep ==================== *)

module Chain = Tn_execution.Consensus_chain
module Replay = Tn_execution.Replay
module Rewards_counter = Tn_evm.Rewards_counter
module World = Tn_state.World_state
module Anchor = Tn_engine.Anchor
module Recent_hashes = Tn_engine.Recent_hashes

let all_blocks advances = List.concat_map (fun a -> a.Outcome.blocks) advances

(* ONE pass of the write protocol over the whole committed log, keeping every
   intermediate durable state: entry k of the first component is the
   (driver, store) pair after k turns - entry 0 the cold pair - and the second
   component is the n records the protocol filed, in order. Every sweep cell's
   crash state is cut from this single pass rather than re-driven per cell. *)
let sweep_pass =
  lazy
    (let bodies = store () in
     let cold =
       (Driver.create (Lazy.force wide_spec) ~committee, fresh_store ())
     in
     let (_ : Driver.t * Consensus_store.t), states_rev, records_rev =
       List.fold_left
         (fun ((d, st), states, records) sd ->
           let block = mint_ok "sweep mint" d sd in
           let record = record_ok "sweep record" block ~bodies in
           let st = receive_ok "sweep receive" st record in
           let d, _ = step_ok "sweep step" d sd ~bodies in
           ((d, st), (d, st) :: states, record :: records))
         (cold, [ cold ], [])
         (committed_self ())
     in
     (List.rev states_rev, List.rev records_rev))

(* The comparison side of every cell: chunk 37's UNTOUCHED fold, so a
   regression in the write side cannot shift both sides together (S5.1 pins
   the two paths equal before any cell runs). *)
let sweep_golden =
  lazy
    (fold_ok "sweep golden"
       (Driver.create (Lazy.force wide_spec) ~committee)
       (committed_self ()) ~bodies:(store ()))

(* File the records of a gap: blocks minted through the SAME accumulator seam
   a resumed subscriber uses, one record per output, without ever stepping a
   driver - the durable trace of a shell that received [sds] and crashed
   before executing any of them. [lookup_of] narrows what each record may
   resolve. *)
let file_gap ~lookup_of cp cstore sds =
  let _, cstore =
    List.fold_left
      (fun (acc, cstore) sd ->
        let acc, block = Chain.append acc sd in
        let record =
          Result.fold ~ok:Fun.id
            ~error:(fun e ->
              Alcotest.failf "gap record: %s"
                (Consensus_store.Record.error_to_string e))
            (Consensus_store.Record.create ~consensus:block
               ~lookup:(lookup_of sd))
        in
        (acc, receive_ok "gap receive" cstore record))
      (Checkpoint.accumulator cp, cstore)
      sds
  in
  cstore

(* Each record resolves ONLY its own output's digests - the per-output body
   discipline S7.1 files under, so a record reaching for another output's
   body fails at create instead of succeeding by ambient lookup. *)
let own_lookup bodies sd =
  let owned = Sub_dag.payload_digests sd in
  fun digest ->
    if List.exists (Digests.Batch_digest.equal digest) owned then
      Batch_store.find bodies digest
    else None

(* S7.3's harness edit: every record may resolve against the whole injected
   body set, as one monolithic durable blob. *)
let monolithic_lookup bodies (_ : Sub_dag.t) digest =
  Batch_store.find bodies digest

(* The (k, g) grid: every crash index against gap lengths 1..3, clamped at
   the log's end and deduplicated after clamping. *)
let cells n =
  List.sort_uniq compare
    (List.concat_map
       (fun k ->
         List.filter_map
           (fun g ->
             let g = Stdlib.min g (n - k) in
             if g >= 1 then Some (k, g) else None)
           [ 1; 2; 3 ])
       (List.init n Fun.id))

(* One cell: cut the durable pair at k, file the g-record gap, drop every
   driver, resume, fold the tail. Any refusal, halt or mid-epoch seal is a
   red cell - the central property says no cell errors. *)
let run_cell ~label ~lookup_of k g =
  let bodies = store () in
  let sds = committed_self () in
  let states, _ = Lazy.force sweep_pass in
  let d_k, store_k = nth (label ^ ": prefix state") states k in
  let cp = Driver.snapshot d_k in
  let store_kg = file_gap ~lookup_of cp store_k (take g (drop k sds)) in
  let outcome =
    Result.fold ~ok:Fun.id
      ~error:(fun e ->
        Alcotest.failf "%s: resume refused: %s" label
          (Driver.resume_error_to_string e))
      (Driver.resume (Lazy.force wide_spec) ~committee ~checkpoint:cp
         ~store:store_kg ~address_of)
  in
  match outcome with
  | Outcome.Sealed { driver = _; advances = _; rest } ->
      Alcotest.failf "%s: sealed mid-epoch with %d unconsumed" label
        (List.length rest)
  | Outcome.Halted { advances = _; error } ->
      Alcotest.failf "%s: halted: %s" label (Outcome.error_to_string error)
  | Outcome.Advance { driver; advances } ->
      let driver, tail =
        fold_ok (label ^ ": tail") driver (drop (k + g) sds) ~bodies
      in
      (driver, advances, tail)

let word n = u256_int n
let word_hex v = Bf.to_hex (U256.to_be_bytes v)

(* Every answer BLOCKHASH can get out of an engine's window, read through
   [Block_hashes.lookup] - the interpreter's own resolution function - from
   one past the far edge up to the block being built (the S4.3 probe, applied
   at the driver layer; the floor is clamped at zero because the golden chain
   is shorter than the window). *)
let window_answers e =
  let w = Recent_hashes.window (Engine.recent_hashes e) in
  let current = 1 + Block_number.to_int (Anchor.number (Engine.anchor e)) in
  let floor = Stdlib.max 0 (current - Tn_evm.Block_hashes.depth_limit - 1) in
  List.map
    (fun requested ->
      word_hex
        (Tn_evm.Block_hashes.lookup w ~current:(word current)
           ~requested:(word requested)))
    (List.init (current - floor + 1) (fun i -> floor + i))

let rendered_counts e =
  List.map
    (fun (a, n) ->
      Printf.sprintf "%s:%d" (Bf.to_hex (Units.Address.to_bytes a)) n)
    (Rewards_counter.address_counts (Engine.rewards e))

let keccak_hexes blocks =
  List.map (fun b -> Tn_keccak.to_hex (Executed_block.hash b)) blocks

let root_hexes blocks =
  List.map
    (fun b ->
      Tn_evm.Hash32.to_hex
        (Tn_evm.Block_header.state_root (Executed_block.header b)))
    blocks

(* The six projections of the central property, asserted for one cell against
   the golden suffix at k and the golden run's FINAL driver. *)
let assert_cell ~label ~golden_driver ~golden_suffix (driver, advances, tail) =
  let combined = advances @ tail in
  Alcotest.(check int)
    (label ^ ": the combined run has the golden suffix's length")
    (List.length golden_suffix) (List.length combined);
  List.iteri
    (fun i (g, c) ->
      Alcotest.(check string)
        (Printf.sprintf "%s: advance %d minted the golden consensus digest"
           label i)
        (Digests.Output_digest.to_hex (Cb.digest g.Outcome.consensus))
        (Digests.Output_digest.to_hex (Cb.digest c.Outcome.consensus)))
    (get (label ^ ": zip after equal lengths") (zip golden_suffix combined));
  Alcotest.(check (list string))
    (label ^ ": the flattened execution block hashes agree")
    (keccak_hexes (all_blocks golden_suffix))
    (keccak_hexes (all_blocks combined));
  Alcotest.(check (list string))
    (label ^ ": every state root agrees")
    (root_hexes (all_blocks golden_suffix))
    (root_hexes (all_blocks combined));
  Alcotest.(check bool) (label ^ ": the final worlds are equal states") true
    (World.equal
       (Engine.world (Driver.engine golden_driver))
       (Engine.world (Driver.engine driver)));
  Alcotest.(check (list string)) (label ^ ": the final leader counts agree")
    (rendered_counts (Driver.engine golden_driver))
    (rendered_counts (Driver.engine driver));
  Alcotest.(check (list string)) (label ^ ": the hash window carries whole")
    (List.map Tn_keccak.to_hex
       (Recent_hashes.to_list
          (Engine.recent_hashes (Driver.engine golden_driver))))
    (List.map Tn_keccak.to_hex
       (Recent_hashes.to_list (Engine.recent_hashes (Driver.engine driver))));
  Alcotest.(check (list string))
    (label ^ ": every BLOCKHASH answer agrees")
    (window_answers (Driver.engine golden_driver))
    (window_answers (Driver.engine driver));
  Alcotest.(check int) (label ^ ": last_forwarded agrees")
    (Cb.Number.to_int (Driver.last_forwarded golden_driver))
    (Cb.Number.to_int (Driver.last_forwarded driver));
  Alcotest.(check bool) (label ^ ": is_sealed agrees")
    (Driver.is_sealed golden_driver)
    (Driver.is_sealed driver);
  Alcotest.(check (option int64)) (label ^ ": closed_at agrees")
    (Option.map Units.Timestamp.to_sec (Driver.closed_at golden_driver))
    (Option.map Units.Timestamp.to_sec (Driver.closed_at driver))

(* Every cell's result under the per-output body discipline, computed once
   and shared by S7.1 (against the golden) and S7.3 (against the monolithic
   rebuild). *)
let restricted_cells =
  lazy
    (let bodies = store () in
     let n = List.length (committed_self ()) in
     List.map
       (fun (k, g) ->
         ( (k, g),
           run_cell
             ~label:(Printf.sprintf "cell k=%d g=%d" k g)
             ~lookup_of:(own_lookup bodies) k g ))
       (cells n))

(* ---------- S7.1 ---------- *)

(* THE SWEEP. Two dimensions, crossed: crash index k over every committed
   output, gap length g in {1, 2, 3} clamped at the log's end. Each cell cuts
   the durable pair at k, files the gap records, drops the driver, resumes,
   folds the tail, and must agree with the golden run on all six projections
   of the central property. The length dimension is what makes a
   stop-after-one-record collect (M43) a red sweep rather than a green one. *)
let s71 () =
  let n = List.length (committed_self ()) in
  Alcotest.(check bool) "the log is long enough to sweep (anti-vacuity)" true
    (n >= 5);
  let golden_driver, golden_advances = Lazy.force sweep_golden in
  List.iter
    (fun ((k, g), result) ->
      assert_cell
        ~label:(Printf.sprintf "cell k=%d g=%d" k g)
        ~golden_driver
        ~golden_suffix:(drop k golden_advances)
        result)
    (Lazy.force restricted_cells)

(* ---------- S7.2: the six crash sites, by name ---------- *)

(* The mid-epoch sites C1..C4 crash around the first payload-carrying output
   (index m-1), so attachment and execution are both live at the site. *)
let payload_k () =
  let m = List.length (prefix_to_first_payload ()) in
  let sd = nth "the crash-site output" (committed_self ()) (m - 1) in
  Alcotest.(check bool)
    "the crash-site output references a batch (anti-vacuity)" true
    (payload_count sd > 0);
  (m - 1, sd)

(* C1 - minted, nothing filed: the mint left NOTHING durable, so the gap is
   empty, resume returns the pre-output driver, and re-feeding the sub-DAG
   mints the identical block. *)
let s72_c1 () =
  let spec = Lazy.force wide_spec in
  let k, sd = payload_k () in
  let states, _ = Lazy.force sweep_pass in
  let d_k, store_k = nth "C1 state" states k in
  let minted = mint_ok "C1 mint" d_k sd in
  let resumed, advances =
    resume_advance "C1 resume" spec ~checkpoint:(Driver.snapshot d_k)
      ~store:store_k
  in
  Alcotest.(check int) "C1: the gap is empty" 0 (List.length advances);
  Alcotest.(check int) "C1: the resumed watermark is k" k
    (Cb.Number.to_int (Driver.last_forwarded resumed));
  Alcotest.(check string) "C1: re-feeding the sub-DAG mints it identically"
    (Digests.Output_digest.to_hex (Cb.digest minted))
    (Digests.Output_digest.to_hex (Cb.digest (mint_ok "C1 re-mint" resumed sd)))

(* C2 - filed, not stepped: the gap is exactly [k+1]. *)
let s72_c2 () =
  let spec = Lazy.force wide_spec in
  let bodies = store () in
  let k, sd = payload_k () in
  let states, _ = Lazy.force sweep_pass in
  let d_k, store_k = nth "C2 state" states k in
  let cp = Driver.snapshot d_k in
  let store_k1 = file_gap ~lookup_of:(own_lookup bodies) cp store_k [ sd ] in
  let _, advances = resume_advance "C2 resume" spec ~checkpoint:cp ~store:store_k1 in
  Alcotest.(check (list int)) "C2: the gap is exactly [k+1]" [ k + 1 ]
    (List.map
       (fun a -> Cb.Number.to_int (Cb.number a.Outcome.consensus))
       advances)

(* The durable pair, rendered - what a disk would hold. *)
let render_store st =
  String.concat "|"
    [
      string_of_int (Consensus_store.cardinal st);
      Units.Epoch.to_string (Consensus_store.epoch st);
      Cb.Number.to_string (Consensus_store.expected_next st);
      Digests.Output_digest.to_hex (Consensus_store.epoch_parent st);
      Option.fold ~none:"none"
        ~some:(fun r ->
          Cb.Number.to_string (Consensus_store.Record.number r)
          ^ "@"
          ^ Digests.Output_digest.to_hex (Consensus_store.Record.digest r)
          ^ "/"
          ^ String.concat ","
              (List.map
                 (fun b -> Digests.Batch_digest.to_hex (Batch.digest b))
                 (Consensus_store.Record.bodies r)))
        (Consensus_store.latest_received st);
    ]

let render_checkpoint cp =
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
    ]

(* C3 - attached, not executed: the attach leaves no durable trace, so the
   pair is asserted EQUAL to C2's. The C3 store is built through a different
   path on purpose - [Subscriber.receive] really resolves and attaches the
   bodies before the crash - so the equality compares two constructions, not
   one expression with itself. *)
let s72_c3 () =
  let spec = Lazy.force wide_spec in
  let bodies = store () in
  let k, sd = payload_k () in
  let states, _ = Lazy.force sweep_pass in
  let d_k, store_k = nth "C3 state" states k in
  let cp = Driver.snapshot d_k in
  let store_c2 = file_gap ~lookup_of:(own_lookup bodies) cp store_k [ sd ] in
  let _, block, (_ : Output.t) =
    Result.fold ~ok:Fun.id
      ~error:(fun e ->
        Alcotest.failf "C3 attach: %s" (Subscriber.error_to_string e))
      (Subscriber.receive
         (Subscriber.create (Checkpoint.accumulator cp))
         sd ~bodies ~address_of)
  in
  let store_c3 =
    receive_ok "C3 receive" store_k (record_ok "C3 record" block ~bodies)
  in
  Alcotest.(check string) "C3: the store half equals C2's"
    (render_store store_c2) (render_store store_c3);
  Alcotest.(check string) "C3: the checkpoint half equals C2's"
    (render_checkpoint cp)
    (render_checkpoint (Driver.snapshot d_k));
  let _, adv_c2 = resume_advance "C3: C2's resume" spec ~checkpoint:cp ~store:store_c2 in
  let _, adv_c3 = resume_advance "C3: C3's resume" spec ~checkpoint:cp ~store:store_c3 in
  Alcotest.(check (list string)) "C3: the two resumes are indistinguishable"
    (List.map shape adv_c2) (List.map shape adv_c3)

(* C4 - executed, not snapshotted: the durable pair is C2's, so resume
   RE-EXECUTES from the checkpoint's world; the replayed advance equals both
   the lost in-memory one and the golden's k+1, and the resumed world equals
   the world the crash destroyed - the checkpoint, not the engine's
   in-memory success, is the execution durability boundary. *)
let s72_c4 () =
  let spec = Lazy.force wide_spec in
  let bodies = store () in
  let k, sd = payload_k () in
  let states, _ = Lazy.force sweep_pass in
  let d_k, store_k = nth "C4 state" states k in
  let cp = Driver.snapshot d_k in
  let store_k1 = file_gap ~lookup_of:(own_lookup bodies) cp store_k [ sd ] in
  let d_exec, lost = step_ok "C4: the lost execution" d_k sd ~bodies in
  let resumed, advances =
    resume_advance "C4 resume" spec ~checkpoint:cp ~store:store_k1
  in
  Alcotest.(check int) "C4: exactly one advance" 1 (List.length advances);
  let a = nth "C4: the replayed advance" advances 0 in
  Alcotest.(check string) "C4: the re-execution equals the lost advance"
    (shape lost) (shape a);
  Alcotest.(check string) "C4: and the golden's k+1"
    (shape (nth "golden k+1" (snd (Lazy.force sweep_golden)) k))
    (shape a);
  Alcotest.(check bool)
    "C4: the resumed world equals the world the crash destroyed" true
    (World.equal
       (Engine.world (Driver.engine d_exec))
       (Engine.world (Driver.engine resumed)))

(* The short-spec write run, driven to its seal: the pre-close and post-close
   durable states plus the closing advance. *)
let short_states =
  lazy
    (let bodies = store () in
     let rec go (d, st) = function
       | [] -> Alcotest.fail "no output closed the 10 s epoch inside the horizon"
       | sd :: rest ->
           let block = mint_ok "short mint" d sd in
           let st' =
             receive_ok "short receive" st (record_ok "short record" block ~bodies)
           in
           let d', a = step_ok "short step" d sd ~bodies in
           if a.Outcome.closes_epoch then ((d, st), (d', st'), a)
           else go (d', st') rest
     in
     go
       (Driver.create (Lazy.force short_spec) ~committee, fresh_store ())
       (committed_self ()))

let sealed_of what outcome =
  match outcome with
  | Outcome.Sealed { driver; advances; rest = [] } -> (driver, advances)
  | Outcome.Sealed { driver = _; advances = _; rest } ->
      Alcotest.failf "%s: sealed with %d outputs unconsumed" what
        (List.length rest)
  | Outcome.Advance { driver = _; advances = _ } ->
      Alcotest.failf "%s: returned Advance across the seal" what
  | Outcome.Halted { advances = _; error } ->
      Alcotest.failf "%s: halted: %s" what (Outcome.error_to_string error)

(* C5 - closing output filed and executed, not snapshotted: the checkpoint is
   pre-close, the store holds the closing record, and resume returns Sealed
   carrying exactly the closing advance. The post-resume snapshot must say
   sealed too - the durable witness M44 falsifies. *)
let s72_c5 () =
  let (d_prev, _), (_, store_close), _ = Lazy.force short_states in
  let cp = Driver.snapshot d_prev in
  let driver, advances =
    sealed_of "C5 resume"
      (resume_ok "C5 resume" (Lazy.force short_spec) ~checkpoint:cp
         ~store:store_close)
  in
  Alcotest.(check int) "C5: exactly the closing advance" 1
    (List.length advances);
  Alcotest.(check bool) "C5: and it closes the epoch" true
    (nth "C5 closing advance" advances 0).Outcome.closes_epoch;
  Alcotest.(check bool) "C5: the resumed driver is sealed" true
    (Driver.is_sealed driver);
  Alcotest.(check bool) "C5: and its own snapshot says sealed" true
    (Checkpoint.is_sealed (Driver.snapshot driver))

(* C6 - closing output snapshotted, handoff not done: gap empty, resume
   returns a SEALED driver with no advances, and re-performing [begin_epoch]
   is idempotent - the same committee, the same boundary, counts already
   cleared. *)
let s72_c6 () =
  let _, (d_close, store_close), closing = Lazy.force short_states in
  let cp = Driver.snapshot d_close in
  Alcotest.(check bool) "C6: the checkpoint is sealed (fixture)" true
    (Checkpoint.is_sealed cp);
  let driver, advances =
    sealed_of "C6 resume"
      (resume_ok "C6 resume" (Lazy.force short_spec) ~checkpoint:cp
         ~store:store_close)
  in
  Alcotest.(check int) "C6: the gap is empty" 0 (List.length advances);
  Alcotest.(check bool) "C6: the resumed driver is sealed" true
    (Driver.is_sealed driver);
  Alcotest.(check (option int64))
    "C6: closed_at is the closing output's commit time"
    (Some (Units.Timestamp.to_sec (Output.committed_at closing.Outcome.output)))
    (Option.map Units.Timestamp.to_sec (Driver.closed_at driver));
  let handoff what d =
    Result.fold ~ok:Fun.id
      ~error:(fun e ->
        Alcotest.failf "%s: %s" what (Driver.handoff_error_to_string e))
      (Driver.begin_epoch d ~committee:committee_next)
  in
  let ra = handoff "C6: handoff on the resumed driver" driver in
  let rb = handoff "C6: handoff on the pre-crash driver" d_close in
  Alcotest.(check string) "C6: the same committee epoch"
    (Units.Epoch.to_string (Committee.epoch (Engine.committee (Driver.engine rb))))
    (Units.Epoch.to_string (Committee.epoch (Engine.committee (Driver.engine ra))));
  Alcotest.(check (option int64)) "C6: the same boundary"
    (Option.map Units.Timestamp.to_sec (Driver.next_boundary rb))
    (Option.map Units.Timestamp.to_sec (Driver.next_boundary ra));
  Alcotest.(check (list string)) "C6: counts already cleared, identically"
    (rendered_counts (Driver.engine rb))
    (rendered_counts (Driver.engine ra))

let begin_epoch_ok what d ~committee:cmt =
  Result.fold ~ok:Fun.id
    ~error:(fun e ->
      Alcotest.failf "%s: %s" what (Driver.handoff_error_to_string e))
    (Driver.begin_epoch d ~committee:cmt)

let open_epoch_ok what st ~epoch =
  Result.fold ~ok:Fun.id
    ~error:(fun e ->
      Alcotest.failf "%s: %s" what (Consensus_store.error_to_string e))
    (Consensus_store.open_epoch st ~epoch)

(* C7 - handoff performed, store rolled, snapshot NOT taken: the crash in the
   epoch handoff's own two-durable-write window, the one site C1..C6 cannot
   cover because it lies between steps. The surviving pair is Sealed-at-0
   beside a store open at 1 with nothing filed above the checkpoint - the
   exact skew the handoff-window divergence accepts - and resume returns the
   sealed driver with nothing to replay, so the shell redoes [begin_epoch]
   (idempotent per C6), skips the already-done roll, snapshots, and the
   healed pair resumes LIVE under the next committee. *)
let s72_c7 () =
  let spec = Lazy.force short_spec in
  let _, (d_close, store_close), closing = Lazy.force short_states in
  let cp = Driver.snapshot d_close in
  let store1 = open_epoch_ok "C7 roll" store_close ~epoch:epoch1 in
  Alcotest.(check bool) "C7: the pair really is the handoff skew (fixture)"
    true
    (Checkpoint.is_sealed cp
    && Units.Epoch.equal
         (Consensus_store.epoch store1)
         (Units.Epoch.succ (Checkpoint.epoch cp)));
  let driver, advances =
    sealed_of "C7 resume"
      (resume_ok "C7 resume" spec ~checkpoint:cp ~store:store1)
  in
  Alcotest.(check int) "C7: the redo-able gap is empty" 0
    (List.length advances);
  Alcotest.(check bool) "C7: the resumed driver is sealed" true
    (Driver.is_sealed driver);
  Alcotest.(check (option int64))
    "C7: closed_at is the closing output's commit time"
    (Some (Units.Timestamp.to_sec (Output.committed_at closing.Outcome.output)))
    (Option.map Units.Timestamp.to_sec (Driver.closed_at driver));
  let healed =
    begin_epoch_ok "C7 redo handoff" driver ~committee:committee_next
  in
  let cp1 = Driver.snapshot healed in
  Alcotest.(check string) "C7: the healed pair is matched at the next epoch"
    (Units.Epoch.to_string (Consensus_store.epoch store1))
    (Units.Epoch.to_string (Checkpoint.epoch cp1));
  let relived =
    Result.fold ~ok:Fun.id
      ~error:(fun e ->
        Alcotest.failf "C7: the healed resume refused: %s"
          (Driver.resume_error_to_string e))
      (Driver.resume spec ~committee:committee_next ~checkpoint:cp1
         ~store:store1 ~address_of)
  in
  match relived with
  | Outcome.Advance { driver = live; advances = replayed } ->
      Alcotest.(check int) "C7: the healed resume replays nothing" 0
        (List.length replayed);
      Alcotest.(check string) "C7: and runs live under the next committee"
        (Units.Epoch.to_string epoch1)
        (Units.Epoch.to_string
           (Committee.epoch (Engine.committee (Driver.engine live))))
  | Outcome.Sealed { driver = _; advances = _; rest } ->
      Alcotest.failf "C7: the healed resume sealed with %d unconsumed"
        (List.length rest)
  | Outcome.Halted { advances = _; error } ->
      Alcotest.failf "C7: the healed resume halted: %s"
        (Outcome.error_to_string error)

(* C7's refusal edge, depth: ONE redo-able skew only. A store rolled twice
   past a sealed checkpoint is not one crashed handoff but two, and the
   second [begin_epoch] could never be redone from this checkpoint, so the
   strict [Store_epoch] refusal stands. *)
let s72_c7_deep () =
  let spec = Lazy.force short_spec in
  let _, (d_close, store_close), _ = Lazy.force short_states in
  let cp = Driver.snapshot d_close in
  let store2 =
    open_epoch_ok "C7 deep: second roll"
      (open_epoch_ok "C7 deep: first roll" store_close ~epoch:epoch1)
      ~epoch:(Units.Epoch.succ epoch1)
  in
  let err =
    resume_err "C7 deep" spec ~committee ~checkpoint:cp ~store:store2
  in
  match err with
  | Driver.Store_epoch { checkpoint; store } ->
      Alcotest.(check string) "C7 deep: the checkpoint's epoch"
        (Units.Epoch.to_string Units.Epoch.zero)
        (Units.Epoch.to_string checkpoint);
      Alcotest.(check string) "C7 deep: the store's open epoch"
        (Units.Epoch.to_string (Units.Epoch.succ epoch1))
        (Units.Epoch.to_string store)
  | Driver.Committee_epoch _ | Driver.Committee_mismatch _ | Driver.Gap _ ->
      Alcotest.failf "wrong refusal: %s" (Driver.resume_error_to_string err)

(* C7's refusal edge, contents: the skew is accepted EMPTY only. A record
   filed above the sealed checkpoint after the roll means the next epoch
   already ran; resuming to Sealed would silently orphan it (this checkpoint
   cannot replay a record of an epoch it never entered), so the pair stays
   [Store_epoch]. *)
let s72_c7_filed () =
  let spec = Lazy.force short_spec in
  let _, (d_close, store_close), closing = Lazy.force short_states in
  let cp = Driver.snapshot d_close in
  let store1 = open_epoch_ok "C7 filed: roll" store_close ~epoch:epoch1 in
  let closed =
    Units.Timestamp.to_sec (Output.committed_at closing.Outcome.output)
  in
  let store1f =
    file_gap
      ~lookup_of:(fun (_ : Sub_dag.t) (_ : Digests.Batch_digest.t) -> None)
      cp store1
      [ epoch1_sub_dag ~r:1 ~at:(Int64.add closed 1L) [] ]
  in
  Alcotest.(check int)
    "C7 filed: the store really holds a record above (anti-vacuity)"
    (Cb.Number.to_int (Checkpoint.watermark cp) + 1)
    (get "C7 filed: store tip"
       (Option.map
          (fun r -> Cb.Number.to_int (Consensus_store.Record.number r))
          (Consensus_store.latest_received store1f)));
  let err =
    resume_err "C7 filed" spec ~committee ~checkpoint:cp ~store:store1f
  in
  match err with
  | Driver.Store_epoch { checkpoint; store } ->
      Alcotest.(check string) "C7 filed: the checkpoint's epoch"
        (Units.Epoch.to_string Units.Epoch.zero)
        (Units.Epoch.to_string checkpoint);
      Alcotest.(check string) "C7 filed: the store's open epoch"
        (Units.Epoch.to_string epoch1)
        (Units.Epoch.to_string store)
  | Driver.Committee_epoch _ | Driver.Committee_mismatch _ | Driver.Gap _ ->
      Alcotest.failf "wrong refusal: %s" (Driver.resume_error_to_string err)

(* ---------- S7.3 ---------- *)

let render_final driver =
  String.concat "|"
    [
      Cb.Number.to_string (Driver.last_forwarded driver);
      string_of_bool (Driver.is_sealed driver);
      Option.fold ~none:"none"
        ~some:(fun t -> Int64.to_string (Units.Timestamp.to_sec t))
        (Driver.closed_at driver);
      Tn_keccak.to_hex (Anchor.hash (Engine.anchor (Driver.engine driver)));
      String.concat ","
        (List.map Tn_keccak.to_hex
           (Recent_hashes.to_list (Engine.recent_hashes (Driver.engine driver))));
      String.concat "," (rendered_counts (Driver.engine driver));
      String.concat "," (window_answers (Driver.engine driver));
    ]

let render_cell (driver, advances, tail) =
  String.concat "#" (render_final driver :: List.map shape (advances @ tail))

(* THE HARNESS META-MUTANT, a test of the test: rebuild every crash store
   with the monolithic body set instead of per-output records and require
   EVERY cell to pass identically. If this fails, the harness has smuggled a
   dependency on the body discipline and would not have noticed a design in
   which no gap can exist. It is the only assertion in the plan whose subject
   is the harness; it has no implementation mutation because its mutation IS
   the harness edit it performs. *)
let s73 () =
  let bodies = store () in
  List.iter
    (fun ((k, g), restricted) ->
      let label = Printf.sprintf "meta cell k=%d g=%d" k g in
      let monolithic =
        run_cell
          ~label:(label ^ " (monolithic)")
          ~lookup_of:(monolithic_lookup bodies) k g
      in
      Alcotest.(check string)
        (label ^ ": the two body disciplines are indistinguishable")
        (render_cell restricted) (render_cell monolithic);
      let dr, _, _ = restricted in
      let dm, _, _ = monolithic in
      Alcotest.(check bool) (label ^ ": and the final worlds are equal") true
        (World.equal
           (Engine.world (Driver.engine dr))
           (Engine.world (Driver.engine dm))))
    (Lazy.force restricted_cells)

(* ---------- S7.4 ---------- *)

(* The S3.11 seam conformance, re-run over the sweep's OWN record log rather
   than hand-built chains: at every prefix the two implementations must
   answer identically on every read, on the recovery gap, and on a
   wrong-parent offer - the negative row that makes an Assoc which accepts a
   broken link (M45) visibly diverge here while the reference's own tests
   stay green. *)
module Conformance (St : Consensus_store.S) = struct
  let render_record r =
    Cb.Number.to_string (Consensus_store.Record.number r)
    ^ "@"
    ^ Digests.Output_digest.to_hex (Consensus_store.Record.digest r)
    ^ "/"
    ^ String.concat ","
        (List.map
           (fun b -> Digests.Batch_digest.to_hex (Batch.digest b))
           (Consensus_store.Record.bodies r))

  let render_run run =
    String.concat ";"
      [
        String.concat ","
          (List.map
             (fun b -> Digests.Output_digest.to_hex (Cb.digest b))
             (Replay.blocks run));
        String.concat ","
          (List.map
             (fun b -> Digests.Batch_digest.to_hex (Batch.digest b))
             (Replay.bodies run));
        Cb.Number.to_string (Replay.upto run);
      ]

  let prefix records k =
    List.fold_left
      (fun st record ->
        Result.fold ~ok:Fun.id
          ~error:(fun e ->
            Alcotest.failf "conformance prefix: %s" (St.error_to_string e))
          (St.receive st record))
      (St.create ~epoch:Units.Epoch.zero ~anchor:Cb.Number.genesis
         ~parent:Cb.genesis_parent)
      (take k records)

  (* The refusal rendered STRUCTURALLY, constructor and payload only: the two
     implementations legitimately word their prose differently, and the
     conformance question is which decision they took, not how they spell
     it. [module type S] declares the variant concretely, so this match is
     exhaustive across every implementation. *)
  let render_refusal (e : St.error) =
    match e with
    | St.Not_next { expected; got } ->
        Printf.sprintf "not_next %s %s"
          (Cb.Number.to_string expected)
          (Cb.Number.to_string got)
    | St.Broken_chain { expected; got } ->
        Printf.sprintf "broken_chain %s %s"
          (Digests.Output_digest.to_hex expected)
          (Digests.Output_digest.to_hex got)
    | St.Conflicting_record { number; stored; offered } ->
        Printf.sprintf "conflicting_record %s %s %s"
          (Cb.Number.to_string number)
          (Digests.Output_digest.to_hex stored)
          (Digests.Output_digest.to_hex offered)
    | St.Wrong_epoch { open_epoch; offered } ->
        Printf.sprintf "wrong_epoch %s %s"
          (Units.Epoch.to_string open_epoch)
          (Units.Epoch.to_string offered)
    | St.Epoch_not_advanced { open_epoch; proposed } ->
        Printf.sprintf "epoch_not_advanced %s %s"
          (Units.Epoch.to_string open_epoch)
          (Units.Epoch.to_string proposed)

  let profile st ~asks ~afters ~offers =
    [
      Printf.sprintf "cardinal %d" (St.cardinal st);
      "expected_next " ^ Cb.Number.to_string (St.expected_next st);
      "earliest "
      ^ Option.fold ~none:"none" ~some:Cb.Number.to_string (St.earliest st);
      "latest "
      ^ Option.fold ~none:"none" ~some:render_record (St.latest_received st);
    ]
    @ List.map
        (fun n ->
          Result.fold ~ok:render_record ~error:Consensus_store.miss_to_string
            (St.record_at st n))
        asks
    @ List.map
        (fun after ->
          Result.fold ~ok:render_run ~error:Consensus_store.miss_to_string
            (St.gap st ~after))
        afters
    @ List.map
        (fun r ->
          Result.fold
            ~ok:(fun st' ->
              Printf.sprintf "accepted, cardinal %d" (St.cardinal st'))
            ~error:render_refusal (St.receive st r))
        offers
end

module Ref_conf = Conformance (Consensus_store)
module Assoc_conf = Conformance (Assoc_store.Assoc)

let s74 () =
  let bodies = store () in
  let sds = committed_self () in
  let _, records = Lazy.force sweep_pass in
  let n = List.length records in
  let blocks = List.map Consensus_store.Record.consensus records in
  let number_of i =
    List.fold_left
      (fun m _ -> Cb.Number.succ m)
      Cb.Number.genesis (List.init i Fun.id)
  in
  let asks = List.map number_of (List.init (n + 3) Fun.id) in
  let last_block = last "final sweep block" blocks in
  let afters =
    None
    :: List.filter_map
         (fun i -> Option.map Option.some (List.nth_opt blocks i))
         [ 0; n / 2; n - 1 ]
  in
  (* The wrong-parent offer at prefix k: the RIGHT number, a wrong link -
     minted off the final block's digest, which no prefix below n has as its
     tip. *)
  let wrong_offer k =
    if k >= n then []
    else
      let tip_number =
        if k = 0 then Cb.Number.genesis
        else Cb.number (nth "tip block" blocks (k - 1))
      in
      let _, block =
        Chain.append
          (Chain.resume ~parent:(Cb.digest last_block) ~number:tip_number)
          (nth "offer output" sds k)
      in
      [
        Result.fold ~ok:Fun.id
          ~error:(fun e ->
            Alcotest.failf "wrong-parent record: %s"
              (Consensus_store.Record.error_to_string e))
          (Consensus_store.Record.create ~consensus:block
             ~lookup:(Batch_store.find bodies));
      ]
  in
  let profiles =
    List.map
      (fun k ->
        let offers = wrong_offer k in
        ( k,
          Ref_conf.profile (Ref_conf.prefix records k) ~asks ~afters ~offers,
          Assoc_conf.profile (Assoc_conf.prefix records k) ~asks ~afters
            ~offers ))
      (List.init (n + 1) Fun.id)
  in
  List.iter
    (fun (k, reference, assoc) ->
      Alcotest.(check (list string))
        (Printf.sprintf
           "the two implementations agree on the sweep's log at prefix %d" k)
        reference assoc)
    profiles;
  (* A differential whose observation never moves is vacuously true. *)
  Alcotest.(check int) "the profile tells every prefix apart" (n + 1)
    (List.length
       (List.sort_uniq
          (List.compare String.compare)
          (List.map (fun (_, reference, _) -> reference) profiles)))

(* ---------- S7.5 ---------- *)

let committee2, _ =
  build_committee ~seed:1200 ~epoch:(Units.Epoch.succ epoch1)

(* TWO BOUNDARIES. The sim's own outputs are all epoch-0, so the second
   epoch's log is hand-minted by the epoch-1 committee (exactly as t75's
   continuation is): one mid-epoch output and one past the next 10 s
   boundary, which closes epoch 1. The golden composite crosses two
   boundaries - the tripwire asserts that, so an under-reaching fixture is a
   red constant rather than silent under-coverage - and the induction
   crash-resumes across both: each epoch is filed whole as a gap, resumed
   into Sealed, handed off, and the store rolled, twice; the concatenation
   must equal the golden. *)
let s75 () =
  let spec = Lazy.force short_spec in
  let sim_bodies = Sim.batch_bodies (Lazy.force sim) in
  let body_e1 tag =
    Batch.make
      ~transactions:[ "epoch-1/" ^ tag ]
      ~epoch:epoch1
      ~beneficiary:(nth "seat 0" validator_addresses 0)
      ~base_fee_per_gas:Units.Base_fee.min_protocol
      ~worker_id:Units.Worker_id.zero
  in
  let body_a = body_e1 "a" in
  let body_b = body_e1 "b" in
  let bodies_all = Batch_store.of_bodies (body_a :: body_b :: sim_bodies) in
  let sds0 = committed_self () in
  (* The golden composite, driven by chunk 37's untouched fold. *)
  let dA, advA =
    match Driver.fold (Driver.create spec ~committee) sds0 ~bodies:bodies_all ~address_of with
    | Outcome.Sealed { driver; advances; rest = _ } -> (driver, advances)
    | Outcome.Advance { driver = _; advances = _ } ->
        Alcotest.fail "the 10 s epoch never sealed inside the horizon (fixture)"
    | Outcome.Halted { advances = _; error } ->
        Alcotest.failf "golden epoch 0 halted: %s" (Outcome.error_to_string error)
  in
  let closing0 = last "epoch-0 closing advance" advA in
  let closed0 =
    Units.Timestamp.to_sec (Output.committed_at closing0.Outcome.output)
  in
  let sds1 =
    [
      epoch1_sub_dag ~r:1 ~at:(Int64.add closed0 1L)
        [ (Batch.digest body_a, Units.Worker_id.zero) ];
      epoch1_sub_dag ~r:2 ~at:(Int64.add closed0 11L)
        [ (Batch.digest body_b, Units.Worker_id.zero) ];
    ]
  in
  let d1g = begin_epoch_ok "golden handoff" dA ~committee:committee_next in
  let _, advB =
    sealed_of "golden epoch 1"
      (Driver.fold d1g sds1 ~bodies:bodies_all ~address_of)
  in
  let golden = advA @ advB in
  Alcotest.(check bool)
    "the tripwire: the golden crosses at least two epoch boundaries" true
    (List.length (List.filter (fun a -> a.Outcome.closes_epoch) golden) >= 2);
  (* The induction: two crash-resumes, each gap an entire epoch. *)
  let c0 = List.length advA in
  let cp0 = Checkpoint.genesis spec ~committee in
  let store0 =
    file_gap
      ~lookup_of:(fun _ -> Batch_store.find bodies_all)
      cp0 (fresh_store ()) (take c0 sds0)
  in
  let rA, advA' =
    sealed_of "first resume"
      (Result.fold ~ok:Fun.id
         ~error:(fun e ->
           Alcotest.failf "first resume refused: %s"
             (Driver.resume_error_to_string e))
         (Driver.resume spec ~committee ~checkpoint:cp0 ~store:store0
            ~address_of))
  in
  Alcotest.(check (list string)) "the first resume replays epoch 0 whole"
    (List.map shape advA) (List.map shape advA');
  let rA1 = begin_epoch_ok "resumed handoff" rA ~committee:committee_next in
  let store1 = open_epoch_ok "roll to epoch 1" store0 ~epoch:epoch1 in
  Alcotest.(check string)
    "open_epoch anchors the new epoch on the closing block (M46's witness)"
    (Digests.Output_digest.to_hex (Cb.digest closing0.Outcome.consensus))
    (Digests.Output_digest.to_hex (Consensus_store.epoch_parent store1));
  let cp1 = Driver.snapshot rA1 in
  let store2 =
    file_gap ~lookup_of:(fun _ -> Batch_store.find bodies_all) cp1 store1 sds1
  in
  let rB, advB' =
    sealed_of "second resume"
      (Result.fold ~ok:Fun.id
         ~error:(fun e ->
           Alcotest.failf "second resume refused: %s"
             (Driver.resume_error_to_string e))
         (Driver.resume spec ~committee:committee_next ~checkpoint:cp1
            ~store:store2 ~address_of))
  in
  Alcotest.(check (list string)) "the second resume replays epoch 1 whole"
    (List.map shape advB) (List.map shape advB');
  Alcotest.(check (list string)) "and the concatenation equals the golden"
    (List.map shape golden)
    (List.map shape (advA' @ advB'));
  let (_ : Driver.t) = begin_epoch_ok "handoff to epoch 2" rB ~committee:committee2 in
  let (_ : Consensus_store.t) =
    open_epoch_ok "roll to epoch 2" store2 ~epoch:(Units.Epoch.succ epoch1)
  in
  ()

let () =
  Alcotest.run "driver resume"
    [
      ( "the write side",
        [
          Alcotest.test_case
            "the write protocol and the untouched fold agree advance for \
             advance"
            `Quick s51;
          Alcotest.test_case "mint advances nothing" `Quick s52;
          Alcotest.test_case "mint applies step's guards, in step's order"
            `Quick s53;
          Alcotest.test_case "snapshot files the executed pair" `Quick s54;
          Alcotest.test_case "the accumulator is seeded at the executed tip"
            `Quick s55;
          Alcotest.test_case "the epoch phase is the engine's, derived" `Quick
            s56;
          Alcotest.test_case "a failing step leaves crash site C2" `Quick s57;
        ] );
      ( "the resumed run",
        [
          Alcotest.test_case "a one-record gap replays to the golden k+1"
            `Quick s61;
          Alcotest.test_case "an empty gap resumes as a live no-op" `Quick s62;
          Alcotest.test_case "a committee from another epoch is refused"
            `Quick s63;
          Alcotest.test_case "a store from another epoch is refused" `Quick
            s64;
          Alcotest.test_case "a checkpoint and a store from different runs \
                              are Forked at the floor"
            `Quick s65;
          Alcotest.test_case "replayed bodies are the injection-side bytes"
            `Quick s66;
          Alcotest.test_case "replay-and-close returns Sealed and hands off"
            `Quick s67;
          Alcotest.test_case "the independent watermark oracle agrees" `Quick
            s68;
          Alcotest.test_case
            "a different committee of the same epoch is refused" `Quick s69;
        ] );
      ( "the sweep",
        [
          Alcotest.test_case
            "every (crash index, gap length) cell replays to the golden"
            `Quick s71;
          Alcotest.test_case "C1: minted, nothing filed" `Quick s72_c1;
          Alcotest.test_case "C2: filed, not stepped" `Quick s72_c2;
          Alcotest.test_case "C3: attached, not executed, equals C2's pair"
            `Quick s72_c3;
          Alcotest.test_case "C4: executed, not snapshotted, re-executes"
            `Quick s72_c4;
          Alcotest.test_case "C5: closed and executed, not snapshotted" `Quick
            s72_c5;
          Alcotest.test_case "C6: closed and snapshotted, handoff not done"
            `Quick s72_c6;
          Alcotest.test_case
            "C7: store rolled, snapshot not taken - resumes Sealed and heals"
            `Quick s72_c7;
          Alcotest.test_case "C7: a two-epoch skew stays refused" `Quick
            s72_c7_deep;
          Alcotest.test_case
            "C7: a skewed store with records above stays refused" `Quick
            s72_c7_filed;
          Alcotest.test_case
            "the harness meta-mutant: monolithic bodies change nothing" `Quick
            s73;
          Alcotest.test_case "the seam conformance runs over the sweep's log"
            `Quick s74;
          Alcotest.test_case
            "two boundaries: the crash-resume induction spans epochs" `Quick
            s75;
        ] );
    ]
