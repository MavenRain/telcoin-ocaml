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
  (* Sticky timer-expiry flags, cleared only when a proposal actually fires. *)
  min_timed_out : bool;
  max_timed_out : bool;
}

let round t = t.round
let pending_digests t = t.digests

let proposed_rounds t =
  Round.Map.fold (fun r _ acc -> r :: acc) t.proposed_headers [] |> List.rev

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
   round, clear the parents, reset the sticky flags, and re-arm both timers under
   a fresh generation. *)
let propose t ~now =
  let next = Round.succ t.round in
  let gen = t.gen + 1 in
  let arm =
    [
      Arm_timer { kind = Min_delay; gen; after = t.config.min_header_delay };
      Arm_timer { kind = Max_delay; gen; after = t.config.max_header_delay };
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
          min_timed_out = false;
          max_timed_out = false;
        }
      in
      (t, Broadcast_header h :: arm))

(* Propose iff a parent quorum is available and either the max deadline elapsed,
   enough batches are queued to fill a header, or the min spacing elapsed. *)
let try_propose t ~now =
  let enough_parents = not (List.is_empty t.last_parents) in
  let enough_digests =
    List.length t.digests >= t.config.header_batch_threshold
  in
  if enough_parents && (t.max_timed_out || enough_digests || t.min_timed_out)
  then propose t ~now
  else (t, [])

(* A released parent set for [round]: a forward round jumps the machine and lets
   the min spacing lapse immediately (catch-up); the current round extends the
   held set with the delta; an older round is ignored. *)
let apply_parents t certs round =
  let cmp = Round.compare round t.round in
  if cmp > 0 then { t with round; last_parents = certs; min_timed_out = true }
  else if cmp = 0 then { t with last_parents = t.last_parents @ certs }
  else t

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
  | Parents { certs; round } -> try_propose (apply_parents t certs round) ~now
  | Timer_fired { kind; gen } ->
      if gen <> t.gen then (t, [])
      else try_propose (set_timed_out t kind) ~now
  | Committed_headers { committed } ->
      (* a re-queue can push the digest count over the batch threshold, so
         re-evaluate the propose condition, exactly as the Rust run loop does *)
      try_propose (apply_committed t committed) ~now

let create ~config ~committee ~authority ~genesis ~now =
  let t =
    {
      config;
      committee;
      authority;
      round = Round.genesis;
      gen = 0;
      last_parents = genesis;
      digests = [];
      proposed_headers = Round.Map.empty;
      last_proposed = None;
      (* tokio's first interval tick is immediate, so the round-1 proposal fires
         at startup the moment a parent set is present. *)
      min_timed_out = true;
      max_timed_out = true;
    }
  in
  try_propose t ~now
