(* Newest first. [append] conses and [to_list] reverses, so emission order is
   paid for once at the boundary rather than on every append. *)
type t = Log.t list

let empty = []
let append t entry = entry :: t
let to_list t = List.rev t
let length = List.length
let equal a b = List.equal Log.equal a b
