open Tn_types
open Tn_consensus

module Record = struct
  (* The block and the bodies its own sub-DAG names. [bodies] is derived by
     [create] and by nothing else, so the pairing cannot be assembled wrongly
     from outside. *)
  type t = { consensus : Consensus_block.t; bodies : Batch.t list }

  type error = Missing_body of Digests.Batch_digest.t

  let error_to_string = function
    | Missing_body digest ->
        Printf.sprintf "no batch body for payload digest %s"
          (Digests.Batch_digest.to_hex digest)

  (* Walk the sub-DAG's own declared payload digests in commit order, resolving
     each through [lookup] and stopping at the first one it cannot supply. The
     order is the header's, never the caller's, and duplicates are kept: a
     digest under two certificates resolves twice. [~none] is EAGER, so it holds
     a bare constructor and the recursion lives in [~some], which is a closure. *)
  let create ~consensus ~lookup =
    let rec walk digests resolved =
      match digests with
      | [] -> Ok { consensus; bodies = List.rev resolved }
      | digest :: rest ->
          Option.fold
            ~none:(Error (Missing_body digest))
            ~some:(fun body -> walk rest (body :: resolved))
            (lookup digest)
    in
    walk (Sub_dag.payload_digests (Consensus_block.sub_dag consensus)) []

  let consensus t = t.consensus
  let sub_dag t = Consensus_block.sub_dag t.consensus
  let number t = Consensus_block.number t.consensus
  let digest t = Consensus_block.digest t.consensus
  let parent_hash t = Consensus_block.parent_hash t.consensus
  let epoch t = Sub_dag.leader_epoch (Consensus_block.sub_dag t.consensus)
  let bodies t = t.bodies
end

type miss =
  | Below_retained of {
      earliest : Consensus_block.Number.t;
      asked : Consensus_block.Number.t;
    }
  | Above_tip of {
      expected_next : Consensus_block.Number.t;
      asked : Consensus_block.Number.t;
    }
  | Forked of {
      number : Consensus_block.Number.t;
      stored : Digests.Output_digest.t;
      offered : Digests.Output_digest.t;
    }
  | Broken of Replay.break

let miss_to_string = function
  | Below_retained { earliest; asked } ->
      Printf.sprintf
        "consensus block %s is below everything retained: the store starts at %s"
        (Consensus_block.Number.to_string asked)
        (Consensus_block.Number.to_string earliest)
  | Above_tip { expected_next; asked } ->
      Printf.sprintf
        "consensus block %s is at or above the tip: the store expects %s next"
        (Consensus_block.Number.to_string asked)
        (Consensus_block.Number.to_string expected_next)
  | Forked { number; stored; offered } ->
      Printf.sprintf
        "fork at consensus block %s: the store holds %s, the caller offers %s"
        (Consensus_block.Number.to_string number)
        (Digests.Output_digest.to_hex stored)
        (Digests.Output_digest.to_hex offered)
  | Broken break -> Replay.break_to_string break

module type S = sig
  type t

  type error =
    | Not_next of {
        expected : Consensus_block.Number.t;
        got : Consensus_block.Number.t;
      }
    | Broken_chain of {
        expected : Digests.Output_digest.t;
        got : Digests.Output_digest.t;
      }
    | Conflicting_record of {
        number : Consensus_block.Number.t;
        stored : Digests.Output_digest.t;
        offered : Digests.Output_digest.t;
      }
    | Wrong_epoch of { open_epoch : Units.Epoch.t; offered : Units.Epoch.t }
    | Epoch_not_advanced of {
        open_epoch : Units.Epoch.t;
        proposed : Units.Epoch.t;
      }

  val error_to_string : error -> string

  val create :
    epoch:Units.Epoch.t ->
    anchor:Consensus_block.Number.t ->
    parent:Digests.Output_digest.t ->
    t

  val receive : t -> Record.t -> (t, error) result
  val open_epoch : t -> epoch:Units.Epoch.t -> (t, error) result
  val epoch : t -> Units.Epoch.t
  val epoch_start : t -> Consensus_block.Number.t
  val epoch_parent : t -> Digests.Output_digest.t
  val expected_next : t -> Consensus_block.Number.t
  val earliest : t -> Consensus_block.Number.t option
  val latest_received : t -> Record.t option
  val record_at : t -> Consensus_block.Number.t -> (Record.t, miss) result
  val record_by_digest : t -> Digests.Output_digest.t -> Record.t option
  val cardinal : t -> int
  val gap : t -> after:Consensus_block.t option -> (Replay.t, miss) result
end

(* Upstream's two positional indices, [idx] and [hash]
   ([consensus_pack.rs:618-637]). Both are instantiated here because the number
   and digest modules are bare signatures with no [Map] submodule - the
   precedent [Tn_driver.Batch_store] sets. There is no batch-digest index: a
   record already carries its bodies. *)
module By_number = Map.Make (Consensus_block.Number)
module By_digest = Map.Make (Digests.Output_digest)

module Reference : S = struct
  type t = {
    epoch : Units.Epoch.t;
    epoch_start : Consensus_block.Number.t;
    epoch_parent : Digests.Output_digest.t;
    (* The NUMBER of the block [epoch_parent] names: the open epoch's chain
       anchor. Not in the signature, because no caller needs it and one more
       accessor is one more thing to get wrong; it exists because
       [Consensus_block.Number] has [succ] and no [pred], so the floor a
       from-nothing [gap] collects above cannot be computed from
       [epoch_start]. [create] stores its [anchor] argument and DERIVES
       [epoch_start] from it, so a store opened above genesis anchors its
       from-nothing [gap] at its own floor rather than reporting a hole it
       does not have; [open_epoch] re-derives it from the tip it rolls
       over. *)
    epoch_anchor : Consensus_block.Number.t;
    by_number : Record.t By_number.t;
    by_digest : Record.t By_digest.t;
  }

  type error =
    | Not_next of {
        expected : Consensus_block.Number.t;
        got : Consensus_block.Number.t;
      }
    | Broken_chain of {
        expected : Digests.Output_digest.t;
        got : Digests.Output_digest.t;
      }
    | Conflicting_record of {
        number : Consensus_block.Number.t;
        stored : Digests.Output_digest.t;
        offered : Digests.Output_digest.t;
      }
    | Wrong_epoch of { open_epoch : Units.Epoch.t; offered : Units.Epoch.t }
    | Epoch_not_advanced of {
        open_epoch : Units.Epoch.t;
        proposed : Units.Epoch.t;
      }

  let error_to_string = function
    | Not_next { expected; got } ->
        Printf.sprintf
          "consensus block %s is not the next slot: the store expects %s"
          (Consensus_block.Number.to_string got)
          (Consensus_block.Number.to_string expected)
    | Broken_chain { expected; got } ->
        Printf.sprintf
          "broken chain: the record links to %s, the store's tip is %s"
          (Digests.Output_digest.to_hex got)
          (Digests.Output_digest.to_hex expected)
    | Conflicting_record { number; stored; offered } ->
        Printf.sprintf
          "conflicting record at consensus block %s: the store holds %s, the \
           writer offers %s"
          (Consensus_block.Number.to_string number)
          (Digests.Output_digest.to_hex stored)
          (Digests.Output_digest.to_hex offered)
    | Wrong_epoch { open_epoch; offered } ->
        Printf.sprintf
          "wrong epoch: the record belongs to epoch %s, the store has epoch %s \
           open"
          (Units.Epoch.to_string offered)
          (Units.Epoch.to_string open_epoch)
    | Epoch_not_advanced { open_epoch; proposed } ->
        Printf.sprintf
          "epoch %s does not advance on the open epoch %s"
          (Units.Epoch.to_string proposed)
          (Units.Epoch.to_string open_epoch)

  let create ~epoch ~anchor ~parent =
    {
      epoch;
      epoch_start = Consensus_block.Number.succ anchor;
      epoch_parent = parent;
      epoch_anchor = anchor;
      by_number = By_number.empty;
      by_digest = By_digest.empty;
    }

  let epoch t = t.epoch
  let epoch_start t = t.epoch_start
  let epoch_parent t = t.epoch_parent
  let cardinal t = By_number.cardinal t.by_number
  let earliest t = Option.map fst (By_number.min_binding_opt t.by_number)
  let latest_received t = Option.map snd (By_number.max_binding_opt t.by_number)

  let expected_next t =
    Option.fold ~none:t.epoch_start
      ~some:(fun tip -> Consensus_block.Number.succ (Record.number tip))
      (latest_received t)

  (* The digest the next record must carry as its parent: the tip's, or the open
     epoch's stated anchor while nothing is retained. [open_epoch] re-derives
     [epoch_parent] off the tip it rolls over, so the two agree once records
     exist and the "first record of an epoch" case needs no branch of its own. *)
  let expected_parent t =
    Option.fold ~none:t.epoch_parent ~some:Record.digest (latest_received t)

  let file t record =
    {
      t with
      by_number = By_number.add (Record.number record) record t.by_number;
      by_digest = By_digest.add (Record.digest record) record t.by_digest;
    }

  (* The empty slot: strict gapless append, then the chain link. *)
  let append t record =
    let expected = expected_next t in
    let got = Record.number record in
    if not (Consensus_block.Number.equal got expected) then
      Error (Not_next { expected; got })
    else
      let expected_link = expected_parent t in
      let got_link = Record.parent_hash record in
      if not (Digests.Output_digest.equal got_link expected_link) then
        Error (Broken_chain { expected = expected_link; got = got_link })
      else Ok (file t record)

  (* The occupied slot: the same block again is the shell's post-crash retry and
     succeeds unchanged; a different one is the fork upstream detects a layer
     up. *)
  let resubmit t ~stored ~offered =
    if
      Digests.Output_digest.equal (Record.digest stored) (Record.digest offered)
    then Ok t
    else
      Error
        (Conflicting_record
           {
             number = Record.number offered;
             stored = Record.digest stored;
             offered = Record.digest offered;
           })

  (* Both branches are thunks applied at the end: [Option.fold] is EAGER, and
     filing a record would otherwise be computed and discarded on every
     idempotent retry. *)
  let receive t record =
    if Units.Epoch.equal (Record.epoch record) t.epoch then
      Option.fold
        ~none:(fun () -> append t record)
        ~some:(fun stored () -> resubmit t ~stored ~offered:record)
        (By_number.find_opt (Record.number record) t.by_number)
        ()
    else
      Error (Wrong_epoch { open_epoch = t.epoch; offered = Record.epoch record })

  let open_epoch t ~epoch =
    if Units.Epoch.compare epoch t.epoch > 0 then
      Ok
        {
          t with
          epoch;
          epoch_start = expected_next t;
          epoch_parent = expected_parent t;
          epoch_anchor =
            Option.fold ~none:t.epoch_anchor ~some:Record.number
              (latest_received t);
        }
    else Error (Epoch_not_advanced { open_epoch = t.epoch; proposed = epoch })

  (* Why a height the store does not hold is absent. An empty store has no
     retained floor to be below, so every ask against one is {!Above_tip} - the
     arm whose payload is a bound rather than a tip, for exactly that reason. *)
  let diagnose t asked =
    let bound = expected_next t in
    Option.fold
      ~none:(Above_tip { expected_next = bound; asked })
      ~some:(fun lowest ->
        if Consensus_block.Number.compare asked lowest < 0 then
          Below_retained { earliest = lowest; asked }
        else if Consensus_block.Number.compare asked bound >= 0 then
          Above_tip { expected_next = bound; asked }
        else Broken (Replay.Hole { number = asked }))
      (earliest t)

  (* [~none] is eager, so the diagnosis is computed on a hit too; it is a pair of
     map lookups and a constructor, and making it lazy would buy a thunk in
     exchange for the one accessor a resume calls once. *)
  let record_at t number =
    Option.to_result ~none:(diagnose t number)
      (By_number.find_opt number t.by_number)

  let record_by_digest t digest = By_digest.find_opt digest t.by_digest

  let fetch t number =
    Option.map
      (fun record -> (Record.consensus record, Record.bodies record))
      (By_number.find_opt number t.by_number)

  (* The ceiling is the store's OWN tip - never {!expected_next}, which is one
     past it and would walk every clean resume into a hole. *)
  let ceiling t =
    Option.fold ~none:t.epoch_anchor ~some:Record.number (latest_received t)

  let collect_above t ~after ~parent =
    Result.map_error
      (fun break -> Broken break)
      (Replay.collect ~after ~parent ~upto:(ceiling t) ~fetch:(fetch t))

  (* The floor's digest is checked against the store's own record at that height:
     the one place a checkpoint and a store from two different runs are caught. *)
  let gap_above t block =
    Result.bind (record_at t (Consensus_block.number block)) (fun stored ->
        if
          Digests.Output_digest.equal (Record.digest stored)
            (Consensus_block.digest block)
        then
          collect_above t
            ~after:(Consensus_block.number block)
            ~parent:(Consensus_block.digest block)
        else
          Error
            (Forked
               {
                 number = Consensus_block.number block;
                 stored = Record.digest stored;
                 offered = Consensus_block.digest block;
               }))

  (* Thunked for the same reason [receive] is: collecting the whole run is not
     work to do and throw away when the caller has an executed tip. *)
  let gap t ~after =
    Option.fold
      ~none:(fun () ->
        collect_above t ~after:t.epoch_anchor ~parent:t.epoch_parent)
      ~some:(fun block () -> gap_above t block)
      after ()
end

include Reference
