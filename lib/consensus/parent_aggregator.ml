open Tn_std
open Tn_types
open Tn_vertex

type t = {
  (* Authors counted so far, once each. The weight is their stake and never
     falls, because this set is only ever added to; that is the "do not reset the
     weight" rule. Mirrors the Rust authorities_seen. *)
  seen : Authority_id.Set.t;
  (* Certificates accumulated since the last release, newest first. Drained to
     empty on each release, exactly like the Rust drain(..). *)
  pending : Certificate.t list;
}

let empty = { seen = Authority_id.Set.empty; pending = [] }
let pending t = List.rev t.pending

let reached_quorum t committee =
  Committee.reaches_quorum committee (Committee.stake_of committee t.seen)

let add t committee certificate =
  let origin = Certificate.origin certificate in
  if Authority_id.Set.mem origin t.seen then (t, None)
  else
    let seen = Authority_id.Set.add origin t.seen in
    if Committee.reaches_quorum committee (Committee.stake_of committee seen) then
      (* Quorum, or a later straggler past it: release the buffer built up since
         the previous release and drain it. The weight (the [seen] set) is kept.
         [Nonempty.cons] is total, since this certificate is itself in the
         release. *)
      ({ seen; pending = [] }, Some (Nonempty.cons certificate t.pending))
    else ({ seen; pending = certificate :: t.pending }, None)
