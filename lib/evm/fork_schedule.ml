open Tn_types

type t = {
  shanghai : Units.Timestamp.t;
  cancun : Units.Timestamp.t option;
  prague : Units.Timestamp.t option;
}

type error = Cancun_before_shanghai | Prague_before_cancun | Prague_without_cancun

let error_to_string = function
  | Cancun_before_shanghai -> "cancun activates before shanghai"
  | Prague_before_cancun -> "prague activates before cancun"
  | Prague_without_cancun -> "prague activates on a chain that never activates cancun"

(* [Units.Timestamp] exposes [compare] directly (units.mli:55), so the ordering
   below needs no detour through [to_sec]. *)
let before a b = Units.Timestamp.compare a b < 0

(* A fork activates at its own activation time, not the second after it: the
   boundary belongs to the later fork, which is the [>=] that [Spec.is_enabled]
   also reads. *)
let activated ~at ~timestamp = Units.Timestamp.compare at timestamp <= 0

let make ~shanghai ~cancun ~prague =
  let cancun_error =
    Option.bind cancun (fun c -> if before c shanghai then Some Cancun_before_shanghai else None)
  in
  let prague_error =
    Option.bind prague (fun p ->
        Option.fold ~none:(Some Prague_without_cancun)
          ~some:(fun c -> if before p c then Some Prague_before_cancun else None)
          cancun)
  in
  List.find_map Fun.id [ cancun_error; prague_error ]
  |> Option.fold ~none:(Ok { shanghai; cancun; prague }) ~some:(fun e -> Error e)

(* [mainnet] and [testnet] are written as records rather than through [make]
   because the module owns the invariant and both are visibly monotone; the
   suite still asserts that [make] accepts the very same arguments, so the two
   spellings cannot drift apart. *)
let mainnet = { shanghai = Units.Timestamp.zero; cancun = None; prague = None }

let testnet =
  {
    shanghai = Units.Timestamp.zero;
    cancun = Some Units.Timestamp.zero;
    prague = Some Units.Timestamp.zero;
  }

(* Highest activated fork first, so the first hit wins. Shanghai is not in the
   list: it is the floor answer, including below its own activation time. *)
let active_at t ~timestamp =
  [ (t.prague, Spec.Prague); (t.cancun, Spec.Cancun) ]
  |> List.find_map (fun (at, s) ->
         Option.bind at (fun a -> if activated ~at:a ~timestamp then Some s else None))
  |> Option.value ~default:Spec.Shanghai

let equal a b =
  Units.Timestamp.equal a.shanghai b.shanghai
  && Option.equal Units.Timestamp.equal a.cancun b.cancun
  && Option.equal Units.Timestamp.equal a.prague b.prague

let to_string t =
  let at o = Option.fold ~none:"never" ~some:Units.Timestamp.to_string o in
  Printf.sprintf "shanghai=%s cancun=%s prague=%s"
    (Units.Timestamp.to_string t.shanghai)
    (at t.cancun) (at t.prague)
