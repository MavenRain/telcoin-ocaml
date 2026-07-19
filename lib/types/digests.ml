module type S = sig
  type t

  val domain : string
  val of_digest : Tn_crypto.Digest.t -> t
  val to_digest : t -> Tn_crypto.Digest.t
  val to_hex : t -> string
  val equal : t -> t -> bool
  val compare : t -> t -> int
end

(* One generative application per digest kind yields four incompatible types
   from a single implementation, so the domain tag is the only thing that
   varies and the wrapping logic is written once. *)
module Make (D : sig
  val domain : string
end) : S = struct
  type t = Tn_crypto.Digest.t

  let domain = D.domain
  let of_digest d = d
  let to_digest t = t
  let to_hex = Tn_crypto.Digest.to_hex
  let equal = Tn_crypto.Digest.equal
  let compare = Tn_crypto.Digest.compare
end

module Header_digest = Make (struct
  let domain = "tn:header"
end)

module Batch_digest = Make (struct
  let domain = "tn:batch"
end)

module Sub_dag_digest = Make (struct
  let domain = "tn:subdag"
end)

module Output_digest = Make (struct
  let domain = "tn:output"
end)
