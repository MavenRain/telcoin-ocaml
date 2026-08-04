(* Chunk-38 stage 3: a SECOND implementation of the durable seam.

   [Tn_execution.Consensus_store] is two [Map.Make] instances; this one is a
   flat association list scanned linearly. It exists for one reason: a
   conformance differential between two copies of the same code proves nothing,
   so the seam is only evidence if something other than the reference satisfies
   it. The explicit ascription below is itself half of that evidence - if
   [module type S] ever drifts from what an implementation can supply, this file
   stops compiling.

   The other half is that the answers are DERIVED differently, not just held
   differently. The reference reads its extrema off comparison-ordered maps and
   maintains [epoch_start] as a stored field; this implementation keeps the
   record list physically ascending and reads its tip by POSITION, stores no
   [epoch_start] at all (it is re-derived as [succ epoch_anchor] on every ask),
   derives [expected_next] as one past the ceiling rather than by mirroring the
   reference's fold over the tip, and resolves [expected_parent] by a KEYED
   lookup at the ceiling instead of by extremum. Where the reference encodes
   "succ of the tip, or the opened start", this file encodes "succ of (tip or
   anchor)" - the two agree exactly when the start really is succ of the anchor
   and the ceiling really is the tip, so a wrong rule on either side surfaces
   as a conformance disagreement instead of round-tripping through two copies
   of the same text.

   Both build [gap] on [Replay.collect], deliberately: the range walk and the
   chain check have ONE definition, and what the differential compares is the
   primitives around it. *)

open Tn_types
open Tn_execution
module Number = Consensus_block.Number
module Record = Consensus_store.Record

module Assoc : Consensus_store.S = struct
  (* Oldest-first, and the order IS load-bearing: [append] admits only the
     next height, so the physical tail is the tip and the physical head the
     floor. The reference derives the same extrema by comparison over its
     maps; relying on position here is the second, independent derivation the
     differential needs. *)
  type t = {
    epoch : Units.Epoch.t;
    epoch_parent : Digests.Output_digest.t;
    epoch_anchor : Number.t;
    entries : (Number.t * Record.t) list;
  }

  type error =
    | Not_next of { expected : Number.t; got : Number.t }
    | Broken_chain of {
        expected : Digests.Output_digest.t;
        got : Digests.Output_digest.t;
      }
    | Conflicting_record of {
        number : Number.t;
        stored : Digests.Output_digest.t;
        offered : Digests.Output_digest.t;
      }
    | Wrong_epoch of { open_epoch : Units.Epoch.t; offered : Units.Epoch.t }
    | Epoch_not_advanced of { open_epoch : Units.Epoch.t; proposed : Units.Epoch.t }

  let error_to_string = function
    | Not_next { expected; got } ->
        Printf.sprintf "assoc: %s is not the expected %s" (Number.to_string got)
          (Number.to_string expected)
    | Broken_chain { expected; got } ->
        Printf.sprintf "assoc: links to %s, tip is %s"
          (Digests.Output_digest.to_hex got)
          (Digests.Output_digest.to_hex expected)
    | Conflicting_record { number; stored; offered } ->
        Printf.sprintf "assoc: %s holds %s, offered %s" (Number.to_string number)
          (Digests.Output_digest.to_hex stored)
          (Digests.Output_digest.to_hex offered)
    | Wrong_epoch { open_epoch; offered } ->
        Printf.sprintf "assoc: epoch %s offered, %s open"
          (Units.Epoch.to_string offered)
          (Units.Epoch.to_string open_epoch)
    | Epoch_not_advanced { open_epoch; proposed } ->
        Printf.sprintf "assoc: epoch %s does not advance on %s"
          (Units.Epoch.to_string proposed)
          (Units.Epoch.to_string open_epoch)

  let create ~epoch ~anchor ~parent =
    { epoch; epoch_parent = parent; epoch_anchor = anchor; entries = [] }

  let epoch t = t.epoch

  (* Not stored: the reference maintains [epoch_start] as a field across every
     roll; re-deriving it makes a start/anchor skew unrepresentable HERE, so
     if the reference's maintained copy ever drifts from succ of the anchor
     the two implementations disagree from the empty prefix on. *)
  let epoch_start t = Number.succ t.epoch_anchor
  let epoch_parent t = t.epoch_parent
  let cardinal t = List.length t.entries

  let find t number =
    List.find_map
      (fun (n, record) -> if Number.equal n number then Some record else None)
      t.entries

  (* Physical extrema: the head is the floor, the final fold state the tip. *)
  let earliest t = List.find_map (fun (n, _) -> Some n) t.entries

  let latest_received t =
    List.fold_left (fun _ (_, record) -> Some record) None t.entries

  (* The replay ceiling, read positionally: the physical last height, or the
     anchor while nothing is retained. The reference folds over its map's
     maximum; if either rule is wrong, the gap rows of the conformance
     differential walk to different ends. *)
  let ceiling t = List.fold_left (fun _ (n, _) -> n) t.epoch_anchor t.entries

  (* One past the ceiling - NOT the reference's "succ of the tip, or the
     opened start". The spellings agree only while the start is succ of the
     anchor and the ceiling is the tip; that is the invariant the
     differential watches. *)
  let expected_next t = Number.succ (ceiling t)

  (* The link the next record must carry, resolved by keyed lookup AT the
     ceiling rather than by extremum: if [ceiling] ever names a height the
     store does not hold, this falls back to [epoch_parent] and the write
     side visibly diverges from the reference. *)
  let expected_parent t =
    Option.fold ~none:t.epoch_parent ~some:Record.digest (find t (ceiling t))

  (* Appends at the TAIL, preserving the ascending physical order every
     positional reader above relies on. *)
  let append t record =
    let expected = expected_next t in
    let got = Record.number record in
    if not (Number.equal got expected) then Error (Not_next { expected; got })
    else
      let expected_link = expected_parent t in
      let got_link = Record.parent_hash record in
      if not (Digests.Output_digest.equal got_link expected_link) then
        Error (Broken_chain { expected = expected_link; got = got_link })
      else Ok { t with entries = t.entries @ [ (got, record) ] }

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

  let receive t record =
    if Units.Epoch.equal (Record.epoch record) t.epoch then
      Option.fold
        ~none:(fun () -> append t record)
        ~some:(fun stored () -> resubmit t ~stored ~offered:record)
        (find t (Record.number record))
        ()
    else
      Error (Wrong_epoch { open_epoch = t.epoch; offered = Record.epoch record })

  (* The roll re-anchors at the ceiling and re-links at the record it names;
     [epoch_start] needs no maintenance because it is never stored. The
     reference maintains three fields here - if its recurrence and this
     re-derivation ever disagree, the rolled-store conformance rows split. *)
  let open_epoch t ~epoch =
    if Units.Epoch.compare epoch t.epoch > 0 then
      Ok
        {
          t with
          epoch;
          epoch_parent = expected_parent t;
          epoch_anchor = ceiling t;
        }
    else Error (Epoch_not_advanced { open_epoch = t.epoch; proposed = epoch })

  (* The reference's three verdicts, reached in the OTHER order: the tip
     bound is checked first, so the empty store falls through to [Above_tip]
     via its missing floor rather than via a dedicated empty arm. *)
  let diagnose t asked =
    let bound = expected_next t in
    if Number.compare asked bound >= 0 then
      Consensus_store.Above_tip { expected_next = bound; asked }
    else
      Option.fold
        ~none:(Consensus_store.Above_tip { expected_next = bound; asked })
        ~some:(fun lowest ->
          if Number.compare asked lowest < 0 then
            Consensus_store.Below_retained { earliest = lowest; asked }
          else Consensus_store.Broken (Replay.Hole { number = asked }))
        (earliest t)

  let record_at t number =
    Option.to_result ~none:(diagnose t number) (find t number)

  let record_by_digest t digest =
    List.find_map
      (fun (_, record) ->
        if Digests.Output_digest.equal (Record.digest record) digest then
          Some record
        else None)
      t.entries

  let fetch t number =
    Option.map
      (fun record -> (Record.consensus record, Record.bodies record))
      (find t number)

  let collect_above t ~after ~parent =
    Result.map_error
      (fun break -> Consensus_store.Broken break)
      (Replay.collect ~after ~parent ~upto:(ceiling t) ~fetch:(fetch t))

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
            (Consensus_store.Forked
               {
                 number = Consensus_block.number block;
                 stored = Record.digest stored;
                 offered = Consensus_block.digest block;
               }))

  let gap t ~after =
    Option.fold
      ~none:(fun () ->
        collect_above t ~after:t.epoch_anchor ~parent:t.epoch_parent)
      ~some:(fun block () -> gap_above t block)
      after ()
end
