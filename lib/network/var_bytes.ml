module Bcs = Tn_codec.Bcs

type t = string

let of_bytes s = s
let to_bytes t = t
let codec : t Bcs.t = Bcs.bytes
let equal = String.equal
let compare = String.compare
