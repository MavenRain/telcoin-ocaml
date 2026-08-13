module Bcs = Tn_codec.Bcs

type t = string

let length = 48
let of_bytes s = if String.length s = length then Some s else None
let to_bytes t = t

let codec : t Bcs.t =
  Bcs.refine
    ~inject:(fun s ->
      Option.to_result ~none:"bls_signature: not 48 bytes" (of_bytes s))
    ~project:to_bytes
    (Bcs.sized_bytes length)

let equal = String.equal
let compare = String.compare
