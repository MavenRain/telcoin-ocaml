(* Represented as a head plus a possibly-empty tail, so non-emptiness is
   structural and no runtime check can ever observe an empty value. *)
type 'a t = { head : 'a; tail : 'a list }

let singleton x = { head = x; tail = [] }
let cons x xs = { head = x; tail = xs }
let of_list = function [] -> None | x :: xs -> Some { head = x; tail = xs }
let to_list { head; tail } = head :: tail
let head { head; _ } = head

let last { head; tail } =
  match List.rev tail with [] -> head | last :: _ -> last

let length { tail; _ } = 1 + List.length tail
let map f { head; tail } = { head = f head; tail = List.map f tail }

let iter f { head; tail } =
  f head;
  List.iter f tail

let fold_left f acc { head; tail } = List.fold_left f (f acc head) tail
let append_list { head; tail } more = { head; tail = tail @ more }

let compare cmp a b = List.compare cmp (to_list a) (to_list b)
let equal eq a b = List.equal eq (to_list a) (to_list b)
