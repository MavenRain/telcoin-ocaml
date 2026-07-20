type t = Zero | One | Two | Three | Four

let to_int = function Zero -> 0 | One -> 1 | Two -> 2 | Three -> 3 | Four -> 4

let of_int = function
  | 0 -> Some Zero
  | 1 -> Some One
  | 2 -> Some Two
  | 3 -> Some Three
  | 4 -> Some Four
  | _ -> None

let all = [ Zero; One; Two; Three; Four ]
let equal a b = to_int a = to_int b
