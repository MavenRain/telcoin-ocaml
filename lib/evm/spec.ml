type t = Shanghai | Cancun | Prague

(* The activation rank. Every function below is a total function of it, so the
   order lives in exactly one place. A new constructor is a compile error here
   first, and at every client match site after. *)
let rank = function Shanghai -> 0 | Cancun -> 1 | Prague -> 2
let compare a b = Int.compare (rank a) (rank b)

(* [spec >= from]: the behavior introduced at [from] is active at [spec]. This
   mirrors revm's [spec_id().is_enabled_in(SpecId::$min)]. *)
let is_enabled t ~from = compare t from >= 0
let to_string = function Shanghai -> "shanghai" | Cancun -> "cancun" | Prague -> "prague"
