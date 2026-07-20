type t = Mutable | Static

(* [Permit] is a constructor of a type the interface keeps abstract, so outside
   this module the only source of a value is [permit] applied to a mutability.
   That is what makes the guard unforgettable: the write demands the argument. *)
type permit = Permit

let permit = function Mutable -> Some Permit | Static -> None
let is_static = function Mutable -> false | Static -> true

let equal a b =
  match (a, b) with
  | Mutable, Mutable | Static, Static -> true
  | Mutable, Static | Static, Mutable -> false

let to_string = function Mutable -> "mutable" | Static -> "static"
