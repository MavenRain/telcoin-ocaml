module Bcs = Tn_codec.Bcs

type t = string

let length = 96
let of_bytes s = if String.length s = length then Some s else None
let to_bytes t = t

let codec : t Bcs.t =
  Bcs.refine
    ~inject:(fun s ->
      Option.to_result ~none:"bls_public_key: not 96 bytes" (of_bytes s))
    ~project:to_bytes
    (Bcs.sized_bytes length)

let equal = String.equal
let compare = String.compare
