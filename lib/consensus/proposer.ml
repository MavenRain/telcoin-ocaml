open Tn_types
open Tn_vertex

type config = {
  min_header_delay : Units.Duration.t;
  max_header_delay : Units.Duration.t;
  header_batch_threshold : int;
  max_batches_per_header : int;
}

let config ~min_header_delay ~max_header_delay ~header_batch_threshold
    ~max_batches_per_header =
  {
    min_header_delay;
    max_header_delay;
    header_batch_threshold;
    max_batches_per_header;
  }

(* [of_ms] is total for these fixed, in-range constants; the [Option.value]
   fallback of zero is never taken and only keeps the definition partial-free. *)
let ms n = Option.value (Units.Duration.of_ms n) ~default:Units.Duration.zero

let default_config =
  {
    min_header_delay = ms 500;
    max_header_delay = ms 1000;
    header_batch_threshold = 32;
    max_batches_per_header = 1000;
  }

type timer_kind = Min_delay | Max_delay

type input =
  | Our_digest of {
      batch : Digests.Batch_digest.t;
      worker_id : Units.Worker_id.t;
    }
  | Parents of { certs : Certificate.t list; round : Round.t }
  | Timer_fired of { kind : timer_kind; gen : int }
  | Committed_headers of { committed : Round.t list }

type action =
  | Ack_digest
  | Broadcast_header of Header.t
  | Arm_timer of { kind : timer_kind; gen : int; after : Units.Duration.t }

type t = {
  config : config;
  committee : Committee.t;
  authority : Authority_id.t;
  (* The leader schedule, read for the fast-path delays and the readiness gate.
     Rust shares one [Arc<RwLock<LeaderSchedule>>] between consensus and the
     proposer, so the proposer always observes the table consensus last
     installed; here the node re-publishes it with {!update_schedule} after
     every commit, which is the same observation in a pure setting. *)
  schedule : Leader_schedule.t;
  (* The round of the most recently proposed header; the next header is built
     for [round + 1]. Advances only on a proposal or a forward parent jump. *)
  round : Round.t;
  (* Monotone timer generation. Every re-arm bumps it; a [Timer_fired] carrying
     a stale generation is discarded, the pure stand-in for [Interval::reset]. *)
  gen : int;
  (* Parents for the next header. Seeded with the genesis certificates, drained
     to empty on every proposal, and refilled by released parent quorums. A
     non-empty value is exactly a released 2f+1 quorum for the current round. *)
  last_parents : Certificate.t list;
  (* Batch digests awaiting inclusion, oldest at the front (FIFO). *)
  digests : (Digests.Batch_digest.t * Units.Worker_id.t) list;
  (* Proposed headers not yet known committed, by round. *)
  proposed_headers : Header.t Round.Map.t;
  (* The most recent proposal — the in-memory stand-in for [ProposerStore], the
     equivocation guard read on a restart-driven re-proposal. *)
  last_proposed : Header.t option;
  (* The certificate of the current round's leader, when the held parents carry
     it — Rust's [last_leader], refreshed by [update_leader] on even rounds and
     read by [enough_votes] on the odd round that follows. *)
  last_leader : Certificate.t option;
  (* Rust's [advance_round]: the readiness gate. Recomputed from [ready] every
     time parents are processed and cleared on every proposal, it withholds an
     early (pre-max-timeout) proposal until the round's leader is actually
     visible in the DAG. The max-delay deadline overrides it. *)
  advance_round : bool;
  (* Sticky timer-expiry flags, cleared only when a proposal actually fires. *)
  min_timed_out : bool;
  max_timed_out : bool;
}

let round t = t.round
let pending_digests t = t.digests
let last_proposed t = t.last_proposed

let proposed_rounds t =
  Round.Map.fold (fun r _ acc -> r :: acc) t.proposed_headers [] |> List.rev

let update_schedule t schedule = { t with schedule }

(* ---- the leader fast path ---- *)

(* Does this node lead [round]? [None] from {!Leader_round.of_round} means the
   round carries no leader at all (odd, or below 2), which is exactly the guard
   Rust spells [next_round.is_multiple_of(2)] beside its own [leader] call. *)
let leads t round =
  Option.map (Leader_schedule.leader t.schedule) (Leader_round.of_round round)
  |> Option.fold ~none:false ~some:(fun a ->
         Authority_id.equal (Authority.id a) t.authority)

(* Rust's [calc_max_delay] / [calc_min_delay]. Both look one round past the round
   just proposed — the round these re-armed timers will gate — and shorten the
   wait when this node is that round's anticipated leader: a leader that proposes
   sooner is likelier to land in the DAG and be committed. Leaders sit only on
   even rounds, so an odd next round always takes the full delay. The min delay
   collapses to zero for the leader (not merely halved), the max to half. *)
let max_delay_after t ~proposed_round =
  if leads t (Round.succ proposed_round) then
    Units.Duration.half t.config.max_header_delay
  else t.config.max_header_delay

let min_delay_after t ~proposed_round =
  if leads t (Round.succ proposed_round) then Units.Duration.zero
  else t.config.min_header_delay

(* ---- the readiness gate ([advance_round]) ---- *)

(* Rust's [update_leader]: cache the current round's leader certificate if the
   held parents carry it, and report whether they do. A round with no leader
   witness (only reachable at genesis, which never receives parents) has nothing
   to wait for and reports ready — where Rust, unable to represent such a round,
   would assert. *)
let update_leader t =
  Option.fold
    (Option.map (Leader_schedule.leader t.schedule)
       (Leader_round.of_round t.round))
    ~none:({ t with last_leader = None }, true)
    ~some:(fun leader ->
      let last_leader =
        List.find_opt
          (fun c ->
            Authority_id.equal (Certificate.origin c) (Authority.id leader))
          t.last_parents
      in
      ({ t with last_leader }, Option.is_some last_leader))

(* Rust's [enough_votes], run on odd rounds: the previous even round's leader
   certificate has been found, and this round's parents are the votes on it. The
   round may advance as soon as the leader is committable either way — f+1 stake
   parented on it (available to every honest node), or a 2f+1 quorum that did not
   (it can no longer commit at this round). Leading the next round short-circuits
   to true; a round whose leader was never found has nothing to count. *)
let enough_votes t =
  if leads t (Round.succ t.round) then true
  else
    Option.fold t.last_leader ~none:true ~some:(fun leader ->
        let leader_digest = Certificate.digest leader in
        let stake_of c =
          Committee.stake_of t.committee
            (Authority_id.Set.singleton (Certificate.origin c))
        in
        let for_leader, against =
          List.fold_left
            (fun (yes, no) c ->
              if
                List.exists
                  (Digests.Header_digest.equal leader_digest)
                  (Header.parents (Certificate.header c))
              then (Units.Stake.add yes (stake_of c), no)
              else (yes, Units.Stake.add no (stake_of c)))
            (Units.Stake.zero, Units.Stake.zero)
            t.last_parents
        in
        Committee.reaches_validity t.committee for_leader
        || Committee.reaches_quorum t.committee against)

(* Rust's [ready]: on an even round the round's own leader certificate must be
   held; on an odd round the votes on the previous even round's leader must have
   settled. Returns the (possibly leader-cache-updated) state and the gate. *)
let ready t =
  match Round.parity t.round with
  | Round.Even -> update_leader t
  | Round.Odd -> (t, enough_votes t)

(* Split the queue at the per-header cap: the first [n] drained into the header,
   the remainder kept for later. *)
let take_digests n digests =
  let taken = List.filteri (fun i _ -> i < n) digests in
  let rest = List.filteri (fun i _ -> i >= n) digests in
  (taken, rest)

(* A header's [created_at] must not fall below any parent's, so the committed
   sub-DAG timestamp stays monotone; clamp to the max of now and the parents. *)
let created_at_of ~now parents =
  List.fold_left
    (fun acc c -> Units.Timestamp.max acc (Header.created_at (Certificate.header c)))
    now parents

(* Emit the round-[round+1] proposal, or re-emit a stored header on a
   restart-driven repeat of an already-proposed round. Both paths advance the
   round, clear the parents, reset the sticky flags, clear the readiness gate
   (Rust's [handle_proposal_result], where [advance_round <- false] and the two
   intervals re-arm), and re-arm both timers under a fresh generation. The
   re-armed delays are the leader fast-path delays for the round just proposed:
   Rust re-arms with [calc_min_delay]/[calc_max_delay] read after advancing the
   round, both looking one round ahead. *)
let propose t ~now =
  let next = Round.succ t.round in
  let gen = t.gen + 1 in
  let arm =
    [
      Arm_timer
        { kind = Min_delay; gen; after = min_delay_after t ~proposed_round:next };
      Arm_timer
        { kind = Max_delay; gen; after = max_delay_after t ~proposed_round:next };
    ]
  in
  let build_fresh () =
    let taken, rest = take_digests t.config.max_batches_per_header t.digests in
    let parents = List.map Certificate.digest t.last_parents in
    let header =
      Header.make ~author:t.authority ~round:next
        ~epoch:(Committee.epoch t.committee)
        ~created_at:(created_at_of ~now t.last_parents)
        ~payload:taken ~parents
    in
    let t =
      {
        t with
        round = next;
        gen;
        last_parents = [];
        digests = rest;
        proposed_headers = Round.Map.add next header t.proposed_headers;
        last_proposed = Some header;
        advance_round = false;
        min_timed_out = false;
        max_timed_out = false;
      }
    in
    (t, Broadcast_header header :: arm)
  in
  let stored_for_next =
    Option.bind t.last_proposed (fun h ->
        if Round.equal (Header.round h) next then Some h else None)
  in
  (* Recovery/idempotence: on a restart-driven repeat of a stored round,
     re-broadcast the persisted header verbatim, so a round can never carry two
     distinct headers. Unreachable while the round only advances (the common
     path builds a fresh header); kept for the storage chunk. *)
  Option.fold stored_for_next
    ~none:(build_fresh ())
    ~some:(fun h ->
      let t =
        {
          t with
          round = next;
          last_parents = [];
          gen;
          advance_round = false;
          min_timed_out = false;
          max_timed_out = false;
        }
      in
      (t, Broadcast_header h :: arm))

(* Rust's [should_create_header] predicate (proposer.rs:755-757). A parent quorum
   must be held, and then either the max deadline has elapsed — the unconditional
   override that ignores the readiness gate — or the round is ready to advance
   {e and} a header-filling trigger fired (a full batch, or the min spacing).
   The [advance_round] conjunct is the leader-election gate: without it a node
   would propose the next round the moment it had a quorum plus the min timer,
   before the round's leader is even visible, which is Rust's own early-proposal
   pitfall the gate exists to prevent. *)
let try_propose t ~now =
  let enough_parents = not (List.is_empty t.last_parents) in
  let enough_digests =
    List.length t.digests >= t.config.header_batch_threshold
  in
  if
    enough_parents
    && (t.max_timed_out
       || (t.advance_round && (enough_digests || t.min_timed_out)))
  then propose t ~now
  else (t, [])

(* A released parent set for [round]: a forward round jumps the machine and lets
   the min spacing lapse immediately (catch-up); the current round extends the
   held set with the delta; an older round is ignored. In every case the
   readiness gate is then recomputed from the post-merge state — Rust runs
   [advance_round <- ready()] unconditionally at the end of [process_parents]
   (its transient [advance_round = false] on the forward jump is immediately
   superseded by that line). The current-round extension additionally re-arms the
   min spacing when a schedule change has made this node the next leader (Rust's
   [calc_min_delay().is_zero()] re-check), which in the pure model is exactly
   marking the min timer already elapsed.

   The forward jump is the only branch that emits an action. Rust resets {e both}
   intervals there: [min_delay_interval.reset_immediately()] and
   [max_delay_interval.reset_after(calc_max_delay())]. The min reset is the
   [min_timed_out] flag; the max reset is a genuine re-arm, so the jump bumps the
   generation (discarding the timers armed for the round just left — the pure
   analogue of the interval reset dropping their pending ticks) and arms a fresh
   max deadline for the new round. Without this the stale max timer from the last
   proposal would still match the unchanged generation and fire at the old,
   earlier deadline; with the readiness gate now withholding the min-lapse
   proposal on a jump into a round whose leader is not yet held, that stale timer
   would force a proposal up to a full [max_header_delay] before Rust does. *)
let apply_parents t certs round =
  let cmp = Round.compare round t.round in
  let t, arm =
    if cmp > 0 then
      let gen = t.gen + 1 in
      let t = { t with round; last_parents = certs; gen; min_timed_out = true } in
      ( t,
        [ Arm_timer { kind = Max_delay; gen; after = max_delay_after t ~proposed_round:round } ] )
    else if cmp = 0 then
      let t = { t with last_parents = t.last_parents @ certs } in
      let t =
        if Units.Duration.compare (min_delay_after t ~proposed_round:t.round)
             Units.Duration.zero
           = 0
        then { t with min_timed_out = true }
        else t
      in
      (t, [])
    else (t, [])
  in
  let t, adv = ready t in
  ({ t with advance_round = adv }, arm)

let set_timed_out t = function
  | Min_delay -> { t with min_timed_out = true }
  | Max_delay -> { t with max_timed_out = true }

(* Prune committed rounds and re-queue skipped headers' digests. The skip horizon
   is the highest committed round; a still-proposed header at or below it that was
   not itself committed is skipped, its payload re-queued oldest-round-first to
   the front of the FIFO so no batch is ever silently dropped. *)
let apply_committed t committed =
  let horizon =
    List.fold_left
      (fun acc r -> if Round.compare r acc > 0 then r else acc)
      Round.genesis committed
  in
  let committed_set = Round.Set.of_list committed in
  let requeued, remaining =
    Round.Map.fold
      (fun r header (req, rem) ->
        if Round.Set.mem r committed_set then (req, rem)
        else if Round.compare r horizon <= 0 then
          (req @ Header.payload header, rem)
        else (req, Round.Map.add r header rem))
      t.proposed_headers ([], Round.Map.empty)
  in
  { t with digests = requeued @ t.digests; proposed_headers = remaining }

let step t ~now = function
  | Our_digest { batch; worker_id } ->
      let t = { t with digests = t.digests @ [ (batch, worker_id) ] } in
      let t, actions = try_propose t ~now in
      (t, Ack_digest :: actions)
  | Parents { certs; round } ->
      (* the jump re-arm (if any) precedes the proposal's own actions; when a
         proposal follows it re-arms again under a fresher generation, so the
         jump's max timer is simply discarded on fire, exactly as Rust's second
         interval reset in [handle_proposal_result] supersedes the first *)
      let t, arm = apply_parents t certs round in
      let t, actions = try_propose t ~now in
      (t, arm @ actions)
  | Timer_fired { kind; gen } ->
      if gen <> t.gen then (t, [])
      else try_propose (set_timed_out t kind) ~now
  | Committed_headers { committed } ->
      (* a re-queue can push the digest count over the batch threshold, so
         re-evaluate the propose condition, exactly as the Rust run loop does *)
      try_propose (apply_committed t committed) ~now

let create ~config ~committee ~authority ~schedule ~genesis ~now =
  let t =
    {
      config;
      committee;
      authority;
      schedule;
      round = Round.genesis;
      gen = 0;
      last_parents = genesis;
      digests = [];
      proposed_headers = Round.Map.empty;
      last_proposed = None;
      last_leader = None;
      (* Rust's [Proposer::new] sets [advance_round = true]; the startup round-1
         proposal fires through the max-timeout override regardless. *)
      advance_round = true;
      (* tokio's first interval tick is immediate, so the round-1 proposal fires
         at startup the moment a parent set is present. *)
      min_timed_out = true;
      max_timed_out = true;
    }
  in
  try_propose t ~now

(* Restart the proposer from persistence. A node that never committed and never
   proposed ([recovered_round] genesis, no stored header) is a cold start, so it
   is exactly {!create}. Otherwise the machine resumes at the recovered round with
   the persisted header loaded: parent aggregators are volatile and start empty,
   so no proposal fires until a fresh parent quorum for [recovered_round + 1]
   arrives — at which point {!step} re-emits the stored header verbatim when it is
   the header for that round (Rust's re-propose equivocation guard) or builds a
   fresh one otherwise. Proposed-header tracking and the digest queue are volatile
   and start empty, matching Rust's cold [Proposer::new] plus the recovered round
   watch. *)
let recover ~config ~committee ~authority ~schedule ~genesis ~now ~recovered_round
    ~last_proposed =
  if Round.equal recovered_round Round.genesis && Option.is_none last_proposed then
    create ~config ~committee ~authority ~schedule ~genesis ~now
  else
    let t =
      {
        config;
        committee;
        authority;
        schedule;
        round = recovered_round;
        gen = 0;
        last_parents = [];
        digests = [];
        proposed_headers = Round.Map.empty;
        last_proposed;
        last_leader = None;
        (* Rust's cold [Proposer::new] default; the gate is recomputed from
           [ready] the moment a recovered parent quorum is re-fed. *)
        advance_round = true;
        min_timed_out = true;
        max_timed_out = true;
      }
    in
    (t, [])
