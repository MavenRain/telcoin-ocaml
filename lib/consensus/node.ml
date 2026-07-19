open Tn_std
open Tn_types
open Tn_vertex

type event =
  | Our_digest of {
      batch : Digests.Batch_digest.t;
      worker_id : Units.Worker_id.t;
    }
  | Vote_request of {
      from_ : Authority_id.t;
      header : Header.t;
      parents : Certificate.t list;
    }
  | Vote_received of Vote.t
  | Certificate_received of Certificate.t
  | Timer_fired of { kind : Proposer.timer_kind; gen : int }

type command =
  | Broadcast_header of Header.t
  | Send_vote of { to_ : Authority_id.t; vote : Vote.t }
  | Send_missing_parents of {
      to_ : Authority_id.t;
      digests : Digests.Header_digest.t list;
    }
  | Broadcast_certificate of Certificate.t
  | Arm_timer of { kind : Proposer.timer_kind; after : Units.Duration.t; gen : int }
  | Emit_committed of Sub_dag.t

type error =
  | Certificate_equivocation of Round.t * Authority_id.t
  | Missing_parent of Digests.Header_digest.t
  | Missing_parent_round of Round.t

type t = {
  self_id : Authority_id.t;
  secret_key : Tn_crypto.Secret_key.t;
  committee : Committee.t;
  proposer : Proposer.t;
  voter : Voter.t;
  bullshark : Bullshark.t;
  (* The in-flight vote collection on our own current header, if any. Replaced
     wholesale on a new proposal, which cancels the previous collection. *)
  votes : (Header.t * Vote_aggregator.t) option;
  (* Per-round parent accumulators — the CertificatesAggregatorManager. Each
     releases a 2f+1 delta to the proposer; garbage-collected below gc_round. *)
  parents : Parent_aggregator.t Round.Map.t;
}

let ( let* ) = Result.bind
let dag t = Bullshark.dag t.bullshark
let last_committed t = Bullshark.last_sub_dag t.bullshark

let map_dag_error = function
  | Dag.Equivocation (r, a) -> Certificate_equivocation (r, a)
  | Dag.Missing_parent d -> Missing_parent d
  | Dag.Missing_parent_round r -> Missing_parent_round r

(* Translate the proposer's actions into node commands. A broadcast header opens
   a fresh vote collection primed with our own implicit self-vote. *)
let apply_proposer_actions t actions =
  List.fold_left
    (fun (t, cmds) action ->
      match action with
      | Proposer.Ack_digest -> (t, cmds)
      | Proposer.Arm_timer { kind; gen; after } ->
          (t, cmds @ [ Arm_timer { kind; after; gen } ])
      | Proposer.Broadcast_header header ->
          let self_vote = Vote.sign t.secret_key ~voter:t.self_id header in
          let agg, _ =
            Vote_aggregator.add Vote_aggregator.empty t.committee header self_vote
          in
          ({ t with votes = Some (header, agg) }, cmds @ [ Broadcast_header header ]))
    (t, []) actions

(* The rounds at which our own headers were committed, across these sub-DAGs. *)
let committed_own_rounds sub_dags self_id =
  List.concat_map
    (fun sd ->
      Sub_dag.headers sd |> Nonempty.to_list
      |> List.filter (fun h -> Authority_id.equal (Header.author h) self_id)
      |> List.map Header.round)
    sub_dags

(* Emit committed sub-DAGs in order, tell the proposer which of our headers
   committed (so it prunes and re-queues), and GC the parent aggregators the
   advanced GC round has left behind. *)
let handle_outcome t ~now outcome =
  match outcome with
  | Bullshark.No_commit _ -> (t, [])
  | Bullshark.Committed sub_dags ->
      let sds = Nonempty.to_list sub_dags in
      let emit = List.map (fun sd -> Emit_committed sd) sds in
      let committed = committed_own_rounds sds t.self_id in
      (* the commit prunes and may re-queue the proposer's digests, which can
         cross the batch threshold and trigger an immediate proposal *)
      let proposer, actions =
        Proposer.step t.proposer ~now (Proposer.Committed_headers { committed })
      in
      let gc = Dag.gc_round (Bullshark.dag t.bullshark) in
      let parents =
        Round.Map.filter (fun r _ -> Round.compare r gc > 0) t.parents
      in
      let t, propose_cmds = apply_proposer_actions { t with proposer; parents } actions in
      (t, emit @ propose_cmds)

(* Feed one accepted certificate to its round's parent aggregator; a released
   quorum delta becomes the proposer's parents for the next round, which may
   trigger the next proposal. Certificates at or below the GC round are ignored. *)
let feed_parents t ~now cert =
  let gc = Dag.gc_round (Bullshark.dag t.bullshark) in
  let r = Certificate.round cert in
  if Round.compare r gc <= 0 then (t, [])
  else
    let agg =
      Option.value (Round.Map.find_opt r t.parents) ~default:Parent_aggregator.empty
    in
    let agg, release = Parent_aggregator.add agg t.committee cert in
    let t = { t with parents = Round.Map.add r agg t.parents } in
    Option.fold release ~none:(t, []) ~some:(fun delta ->
        let certs = Nonempty.to_list delta in
        let proposer, actions =
          Proposer.step t.proposer ~now (Proposer.Parents { certs; round = r })
        in
        apply_proposer_actions { t with proposer } actions)

(* The shared insertion spine, used by gossip, self-delivery of our own formed
   certificate, and parents offered inside a vote request. Wrong-epoch and
   below-GC certificates are protocol-normal no-ops; only a DAG invariant break
   is an error. *)
let insert_certificate t ~now cert =
  if not (Units.Epoch.equal (Certificate.epoch cert) (Committee.epoch t.committee))
  then Ok (t, [])
  else
    Bullshark.process_certificate t.bullshark cert
    |> Result.map_error map_dag_error
    |> Result.map (fun (bullshark, outcome) ->
           let t = { t with bullshark } in
           let t, commit_cmds = handle_outcome t ~now outcome in
           let t, parent_cmds = feed_parents t ~now cert in
           (t, commit_cmds @ parent_cmds))

let insert_certificates t ~now certs =
  List.fold_left
    (fun acc cert ->
      let* t, cmds = acc in
      Result.map
        (fun (t, cmds') -> (t, cmds @ cmds'))
        (insert_certificate t ~now cert))
    (Ok (t, [])) certs

(* A certificate this node receives before it has synced that certificate's own
   parents is protocol-normal, not an invariant break. This happens two ways: a
   node several rounds behind is offered a round-(r-1) certificate on a vote
   request, or a gossiped certificate arrives while an ancestor's delivery was
   lost (only reachable once the shell models message loss). Inserting either
   through the plain spine would surface [Missing_parent]/[Missing_parent_round]
   as a fatal error and halt an honest node on a message a real network drops
   routinely. Rust buffers such a certificate and fetches its ancestors; the slice
   has no fetcher yet, so it drops the unplaceable certificate — the voter falls
   back to a missing-parents response, and gossip re-delivers on a later round. An
   {e equivocating} certificate stays an invariant break whatever its source. *)
let insert_certificate_tolerant t ~now cert =
  Result.fold
    (insert_certificate t ~now cert)
    ~ok:(fun r -> Ok r)
    ~error:(function
      | Missing_parent _ | Missing_parent_round _ -> Ok (t, [])
      | Certificate_equivocation _ as e -> Error e)

let insert_offered_parents t ~now certs =
  List.fold_left
    (fun acc cert ->
      let* t, cmds = acc in
      Result.map
        (fun (t, cmds') -> (t, cmds @ cmds'))
        (insert_certificate_tolerant t ~now cert))
    (Ok (t, [])) certs

(* Vote on a peer's header. Offered parents are inserted first (a
   parent-carrying request can itself commit), then the voter decides against the
   updated DAG. We never vote on our own header — the self-vote is implicit. *)
let handle_vote_request t ~now ~from_ ~header ~parents =
  if Authority_id.equal (Header.author header) t.self_id then Ok (t, [])
  else
    let* t, parent_cmds = insert_offered_parents t ~now parents in
    let voter, decision = Voter.vote t.voter ~dag:(dag t) ~now header in
    let t = { t with voter } in
    let vote_cmds =
      match decision with
      | Voter.Vote v | Voter.Recast v -> [ Send_vote { to_ = from_; vote = v } ]
      | Voter.Need_parents digests -> [ Send_missing_parents { to_ = from_; digests } ]
      | Voter.Reject _ -> []
    in
    Ok (t, parent_cmds @ vote_cmds)

(* A vote answering our own header. Only votes for the in-flight header count;
   at quorum the certificate is formed, the collection cleared, the certificate
   self-inserted (the same spine as gossip) and broadcast. *)
let handle_vote_received t ~now v =
  Option.fold t.votes ~none:(Ok (t, [])) ~some:(fun (header, agg) ->
      if
        not
          (Digests.Header_digest.equal (Vote.header_digest v)
             (Header.digest header))
      then Ok (t, [])
      else
        let agg, result = Vote_aggregator.add agg t.committee header v in
        let t = { t with votes = Some (header, agg) } in
        Result.fold result
          ~error:(fun _ -> Ok (t, []))
          ~ok:(fun cert_opt ->
            Option.fold cert_opt ~none:(Ok (t, [])) ~some:(fun cert ->
                let t = { t with votes = None } in
                Result.map
                  (fun (t, cmds) -> (t, Broadcast_certificate cert :: cmds))
                  (insert_certificate t ~now cert))))

let step t ~now = function
  | Our_digest { batch; worker_id } ->
      let proposer, actions =
        Proposer.step t.proposer ~now (Proposer.Our_digest { batch; worker_id })
      in
      Ok (apply_proposer_actions { t with proposer } actions)
  | Timer_fired { kind; gen } ->
      let proposer, actions =
        Proposer.step t.proposer ~now (Proposer.Timer_fired { kind; gen })
      in
      Ok (apply_proposer_actions { t with proposer } actions)
  | Vote_request { from_; header; parents } ->
      handle_vote_request t ~now ~from_ ~header ~parents
  | Vote_received v -> handle_vote_received t ~now v
  (* Gossip ingress tolerates an unsynced ancestor (protocol-normal under message
     loss); only our own formed certificate self-inserts through the strict spine,
     where an absent parent would mean our own routing broke. *)
  | Certificate_received c -> insert_certificate_tolerant t ~now c

let create ~committee ~secret_key ~self_id ~proposer_config ~sub_dags_per_schedule
    ~gc_depth ~now =
  let genesis = Certificate.genesis committee in
  let schedule =
    Leader_schedule.create committee ~threshold:Leader_schedule.Threshold.default
  in
  let proposer, actions =
    Proposer.create ~config:proposer_config ~committee ~authority:self_id ~genesis
      ~now
  in
  let voter = Voter.create ~committee ~secret_key ~self_id ~genesis in
  let bullshark =
    Bullshark.create ~committee ~schedule ~sub_dags_per_schedule ~gc_depth
  in
  let t =
    {
      self_id;
      secret_key;
      committee;
      proposer;
      voter;
      bullshark;
      votes = None;
      parents = Round.Map.empty;
    }
  in
  apply_proposer_actions t actions

type persisted = {
  certificates : Certificate.t list;
  last_proposed : Header.t option;
  votes : (Authority_id.t * Voter.persisted) list;
}

(* The node-owned persisted state: the DAG certificate slice (post-GC by
   construction), the proposer's last-proposed header, and the voter's per-author
   vote-once records. The committed sub-DAG log is not held here — it is the
   node's output stream, persisted by whatever consumes {!Emit_committed}. *)
let snapshot t =
  {
    certificates = Dag.all_certificates (Bullshark.dag t.bullshark);
    last_proposed = Proposer.last_proposed t.proposer;
    votes = Voter.snapshot t.voter;
  }

(* Rebuild a whole node from persistence — Rust's node recovery, composing
   [ConsensusState::new_from_store] (the DAG and commit state), [from_store] (the
   leader schedule), the [LastProposed] re-propose, and the [VoteInfo] vote-once
   restore. The leader schedule is recovered first (installed before the commit
   state, as Rust installs it before spawning consensus). Volatile machinery — the
   in-flight vote collection and the parent aggregators — starts empty. *)
let recover ~committee ~secret_key ~self_id ~proposer_config ~sub_dags_per_schedule
    ~gc_depth ~now ~persisted:snap ~committed =
  let genesis = Certificate.genesis committee in
  let schedule =
    Leader_schedule.from_store committee ~threshold:Leader_schedule.Threshold.default committed
  in
  Bullshark.of_store ~committee ~schedule ~sub_dags_per_schedule ~gc_depth
    ~certificates:snap.certificates ~committed
  |> Result.map_error map_dag_error
  |> Result.map (fun bullshark ->
         let voter =
           Voter.recover ~committee ~secret_key ~self_id ~genesis ~votes:snap.votes
         in
         let recovered_round = Committed_log.last_committed_round committed in
         let proposer, boot =
           Proposer.recover ~config:proposer_config ~committee ~authority:self_id
             ~genesis ~now ~recovered_round ~last_proposed:snap.last_proposed
         in
         let t =
           {
             self_id;
             secret_key;
             committee;
             proposer;
             voter;
             bullshark;
             votes = None;
             parents = Round.Map.empty;
           }
         in
         let t, boot_cmds = apply_proposer_actions t boot in
         (* Reconstruct the parent quorum at the recovered frontier — Rust's
            certificate-manager [recover_state]. Without it a restarted node holds
            every certificate in its rebuilt DAG but its parent aggregators are
            empty, so it never re-forms a quorum from certificates it already has
            and cannot propose until the network re-gossips them — a whole
            committee restarting together (a deployment or epoch roll) would stall.
            Re-feeding the highest recovered round that carries a 2f+1 quorum
            releases that quorum to the proposer, which advances to the frontier
            and proposes the next round, re-emitting the persisted header verbatim
            exactly when the frontier is the round below it (the in-flight header
            was not yet certified) or building fresh otherwise. A node whose
            in-flight proposal never reached a stored quorum (an empty recovered
            DAG) has no frontier to resume from; re-proposing it on a bare timeout
            (Rust's [should_repropose_header]) is deferred with the networking
            chunk, where the network re-delivers the missing certificates. *)
         let dag = Bullshark.dag bullshark in
         let has_quorum r =
           Dag.round_certificates dag r
           |> List.map Certificate.origin
           |> Authority_id.Set.of_list
           |> Committee.stake_of committee
           |> Committee.reaches_quorum committee
         in
         Dag.rounds dag |> List.rev |> List.find_opt has_quorum
         |> Option.fold ~none:(t, boot_cmds) ~some:(fun r ->
                List.fold_left
                  (fun (t, cmds) cert ->
                    let t, cmds' = feed_parents t ~now cert in
                    (t, cmds @ cmds'))
                  (t, boot_cmds)
                  (Dag.round_certificates dag r)))
