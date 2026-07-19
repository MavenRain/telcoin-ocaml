open Tn_std
open Tn_types
open Tn_vertex
open Tn_consensus

(* Certificates the network has revealed so far, keyed by the header digest a
   header names its parents by (also a certificate's own digest). Used to offer a
   voter the parents it needs and to answer a missing-parent request. *)
module Cert_map = Map.Make (Digests.Header_digest)

(* The event queue is ordered by (delivery time in ms, scheduling counter). The
   counter is globally unique and monotone, so the key is a total, deterministic
   order: simultaneous events deliver in the order they were scheduled. *)
module Timed = Map.Make (struct
  type t = int * int

  let compare (at1, seq1) (at2, seq2) =
    let c = Int.compare at1 at2 in
    if c = 0 then Int.compare seq1 seq2 else c
end)

type config = {
  lo : int;
  hi : int;
  horizon : int;
  max_steps : int;
  seed : int64;
  crashed : Authority_id.Set.t;
  drop_permille : int;
}

let config ~min_latency ~max_latency ~horizon ~max_steps ~seed ?(crashed = [])
    ?(drop_permille = 0) () =
  {
    lo = Units.Duration.to_ms min_latency;
    hi = Units.Duration.to_ms max_latency;
    horizon = Units.Duration.to_ms horizon;
    max_steps;
    seed;
    crashed = Authority_id.Set.of_list crashed;
    drop_permille = Int.max 0 (Int.min 1000 drop_permille);
  }

type scheduled = { target : Authority_id.t; event : Node.event }

type t = {
  committee : Committee.t;
  nodes : Node.t Authority_id.Map.t;
  certs : Certificate.t Cert_map.t;
  queue : scheduled Timed.t;
  clock : int;
  seq : int;
  prng : Prng.t;
  drop_prng : Prng.t;
  lo : int;
  hi : int;
  horizon : int;
  max_steps : int;
  crashed : Authority_id.Set.t;
  drop_permille : int;
  output : Sub_dag.t list Authority_id.Map.t;
  steps : int;
  err : (Authority_id.t * Node.error) option;
}

type agreement =
  | Agree of int
  | Diverge of { left : Authority_id.t; right : Authority_id.t; index : int }

(* ---- scheduling ---- *)

let ids committee = List.map Authority.id (Committee.authorities committee)

let peers committee src =
  List.filter (fun id -> not (Authority_id.equal id src)) (ids committee)

(* The pure core works in whole seconds (the digest domain); the shell works in
   milliseconds. A delivery time is coarsened to the second it falls in. *)
let ts_of_ms ms =
  Option.value ~default:Units.Timestamp.zero
    (Units.Timestamp.of_sec (Int64.of_int (ms / 1000)))

let schedule t ~delay ~target ~event =
  let at = t.clock + delay in
  {
    t with
    queue = Timed.add (at, t.seq) { target; event } t.queue;
    seq = t.seq + 1;
  }

(* A network message crossing to [target]. With a lossy network the message is
   dropped with probability [drop_permille / 1000], drawn from a private stream
   ([drop_prng]) that is distinct from the latency stream and untouched when
   [drop_permille = 0] — so an honest, reliable run (the default) draws latencies
   in exactly the same order and replays byte-for-byte. Timers are local, not
   network crossings, so they route through [schedule] directly and never drop. *)
let unicast t ~target ~event =
  if t.drop_permille = 0 then
    let delay, prng = Prng.int_in t.prng ~lo:t.lo ~hi:t.hi in
    schedule { t with prng } ~delay ~target ~event
  else
    let coin, drop_prng = Prng.int_in t.drop_prng ~lo:0 ~hi:999 in
    let t = { t with drop_prng } in
    if coin < t.drop_permille then t
    else
      let delay, prng = Prng.int_in t.prng ~lo:t.lo ~hi:t.hi in
      schedule { t with prng } ~delay ~target ~event

let broadcast t ~src ~event =
  List.fold_left
    (fun t target -> unicast t ~target ~event)
    t (peers t.committee src)

let resolve_parents t header =
  List.filter_map (fun d -> Cert_map.find_opt d t.certs) (Header.parents header)

(* ---- command interpretation ---- *)

(* Turn one command emitted by node [src] into scheduled events or recorded
   output. [src] is the header author for a broadcast and the same node for a
   timer. Exhaustive over every command variant. *)
let interpret t ~src (cmd : Node.command) =
  match cmd with
  | Node.Broadcast_header header ->
      let parents = resolve_parents t header in
      broadcast t ~src ~event:(Node.Vote_request { from_ = src; header; parents })
  | Node.Send_vote { to_; vote } ->
      unicast t ~target:to_ ~event:(Node.Vote_received vote)
  | Node.Send_missing_parents { to_ = _; digests } ->
      (* Answer the requester [src] from the revealed-certificate set — the peer
         being asked would hold these, modelled here by the shared set. *)
      List.fold_left
        (fun t d ->
          Option.fold ~none:t
            ~some:(fun c ->
              unicast t ~target:src ~event:(Node.Certificate_received c))
            (Cert_map.find_opt d t.certs))
        t digests
  | Node.Broadcast_certificate c ->
      let t = { t with certs = Cert_map.add (Certificate.digest c) c t.certs } in
      broadcast t ~src ~event:(Node.Certificate_received c)
  | Node.Arm_timer { kind; after; gen } ->
      schedule t
        ~delay:(Units.Duration.to_ms after)
        ~target:src
        ~event:(Node.Timer_fired { kind; gen })
  | Node.Emit_committed sd ->
      let prev = Option.value ~default:[] (Authority_id.Map.find_opt src t.output) in
      { t with output = Authority_id.Map.add src (sd :: prev) t.output }

(* ---- delivery and the event loop ---- *)

let deliver t ~target ~event =
  if Authority_id.Set.mem target t.crashed then t
  else
  Option.fold ~none:t
    ~some:(fun node ->
      Result.fold
        ~ok:(fun (node, cmds) ->
          let t = { t with nodes = Authority_id.Map.add target node t.nodes } in
          List.fold_left (fun t cmd -> interpret t ~src:target cmd) t cmds)
        ~error:(fun e -> { t with err = Some (target, e) })
        (Node.step node ~now:(ts_of_ms t.clock) event))
    (Authority_id.Map.find_opt target t.nodes)

let rec run t =
  if Option.is_some t.err || t.steps >= t.max_steps then t
  else
    Option.fold ~none:t
      ~some:(fun ((at, seq), sch) ->
        if at > t.horizon then t
        else
          let t =
            {
              t with
              queue = Timed.remove (at, seq) t.queue;
              clock = at;
              steps = t.steps + 1;
            }
          in
          run (deliver t ~target:sch.target ~event:sch.event))
      (Timed.min_binding_opt t.queue)

(* ---- construction ---- *)

let create ~committee ~secret_key ~proposer_config ~sub_dags_per_schedule ~gc_depth
    ~config =
  let certs =
    List.fold_left
      (fun m c -> Cert_map.add (Certificate.digest c) c m)
      Cert_map.empty
      (Certificate.genesis committee)
  in
  let now0 = ts_of_ms 0 in
  let nodes, startups =
    List.fold_left
      (fun (nodes, startups) authority ->
        let id = Authority.id authority in
        let node, cmds =
          Node.create ~committee ~secret_key:(secret_key id) ~self_id:id
            ~proposer_config ~sub_dags_per_schedule ~gc_depth ~now:now0
        in
        (Authority_id.Map.add id node nodes, startups @ [ (id, cmds) ]))
      (Authority_id.Map.empty, [])
      (Committee.authorities committee)
  in
  let t0 =
    {
      committee;
      nodes;
      certs;
      queue = Timed.empty;
      clock = 0;
      seq = 0;
      prng = Prng.of_seed config.seed;
      (* A second stream for the drop coin, so it never perturbs the latency
         schedule (and is only consumed when the network is lossy). Its seed is
         the config seed pushed once through the SplitMix64 output mix (after a
         non-gamma xor), which scatters it clear of the latency stream's state
         orbit — a plain [seed xor gamma] would, for seeds disjoint from gamma,
         land exactly one step along that orbit and alias the latency draws. *)
      drop_prng =
        Prng.of_seed
          (fst (Prng.next_int64 (Prng.of_seed (Int64.logxor config.seed 0xD1B54A32D192ED03L))));
      lo = config.lo;
      hi = config.hi;
      horizon = config.horizon;
      max_steps = config.max_steps;
      crashed = config.crashed;
      drop_permille = config.drop_permille;
      output = Authority_id.Map.empty;
      steps = 0;
      err = None;
    }
  in
  (* A crash-stopped authority never runs: its startup proposal and timers are
     dropped here, and {!deliver} makes it silent to every later event. *)
  List.fold_left
    (fun t (id, cmds) ->
      if Authority_id.Set.mem id t.crashed then t
      else List.fold_left (fun t cmd -> interpret t ~src:id cmd) t cmds)
    t0 startups

(* ---- observability ---- *)

let committed t authority =
  List.rev (Option.value ~default:[] (Authority_id.Map.find_opt authority t.output))

let commit_count t authority = List.length (committed t authority)

(* Fold the Noop execution engine over an authority's committed output to form
   its consensus chain. The engine cannot fail ([error] is uninhabited), so
   [Nothing.absurd] discharges the impossible error branch of each step. This is
   a pure function of the committed prefix, computed on demand here rather than
   run in the event loop, so the honest run stays byte-for-byte deterministic. *)
let executed t authority =
  let _engine, blocks =
    List.fold_left
      (fun (engine, blocks) sd ->
        Result.fold
          ~ok:(fun (engine, block) -> (engine, block :: blocks))
          ~error:Tn_execution.Nothing.absurd
          (Tn_execution.Engine.Noop.execute engine sd))
      (Tn_execution.Engine.Noop.genesis, [])
      (committed t authority)
  in
  List.rev blocks

(* The head of the chain is, by construction, the last block of {!executed} —
   derived from it rather than re-folded, so the two cannot drift apart. *)
let execution_tip t authority = List.nth_opt (List.rev (executed t authority)) 0

let error t = t.err
let elapsed t = Option.value ~default:Units.Duration.zero (Units.Duration.of_ms t.clock)
let steps t = t.steps

(* All unordered pairs of a list, each once. *)
let rec pairs = function
  | [] -> []
  | x :: rest -> List.map (fun y -> (x, y)) rest @ pairs rest

(* The first commit index at which two logs disagree within their common prefix,
   if any. *)
let first_divergence l1 l2 =
  let n = min (List.length l1) (List.length l2) in
  let take k l = List.filteri (fun i _ -> i < k) l in
  List.combine (take n l1) (take n l2)
  |> List.mapi (fun i (a, b) ->
         (i, Digests.Sub_dag_digest.equal (Sub_dag.digest a) (Sub_dag.digest b)))
  |> List.find_map (fun (i, eq) -> if eq then None else Some i)

(* The pure oracle: over already-extracted committed logs, [Diverge] if any pair
   disagrees within its common prefix, else [Agree] on the shortest log (the
   prefix every node shares). Factored out of {!agreement} so its
   divergence-detection path — which an honest simulation never triggers — is
   unit-testable through {!For_testing}. *)
let agree_of_logs logs =
  let diverged =
    pairs logs
    |> List.find_map (fun ((ia, la), (ib, lb)) ->
           Option.map (fun index -> (ia, ib, index)) (first_divergence la lb))
  in
  let common =
    List.fold_left (fun m (_, l) -> min m (List.length l)) max_int logs
  in
  Option.fold
    ~none:(Agree (if common = max_int then 0 else common))
    ~some:(fun (left, right, index) -> Diverge { left; right; index })
    diverged

let agreement t =
  agree_of_logs
    (List.map
       (fun a -> (Authority.id a, committed t (Authority.id a)))
       (Committee.authorities t.committee))

module For_testing = struct
  let agree_of_logs = agree_of_logs
end
