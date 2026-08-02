module Batch = Tn_types.Batch
module Batch_digest = Tn_types.Digests.Batch_digest

module Digest_map = Map.Make (struct
  type t = Batch_digest.t

  let compare = Batch_digest.compare
end)

type t = Batch.t Digest_map.t

let empty = Digest_map.empty
let add store body = Digest_map.add (Batch.digest body) body store
let of_bodies bodies = List.fold_left add empty bodies
let find store digest = Digest_map.find_opt digest store
let cardinal = Digest_map.cardinal
