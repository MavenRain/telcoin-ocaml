module type S = sig
  type t

  val zero : t
  val of_digest : Tn_crypto.Digest.t -> t
  val to_digest : t -> Tn_crypto.Digest.t
  val to_hex : t -> string
  val equal : t -> t -> bool
  val compare : t -> t -> int
end

(* One application per digest kind yields four incompatible types from a single
   implementation, so the wrapping logic is written once. The functor is
   generative, taking [()], because nothing distinguishes the kinds but the
   identity each application mints: Rust hashes every protocol pre-image bare,
   with no tag to vary. *)
module Make () : S = struct
  type t = Tn_crypto.Digest.t

  (* Written once here, so no kind can drift to a different constant: the
     absent-value slot is the same 32 NUL bytes whatever the type says. *)
  let zero = Tn_crypto.Digest.zero
  let of_digest d = d
  let to_digest t = t
  let to_hex = Tn_crypto.Digest.to_hex
  let equal = Tn_crypto.Digest.equal
  let compare = Tn_crypto.Digest.compare
end

module Header_digest = Make ()
module Batch_digest = Make ()
module Sub_dag_digest = Make ()
module Output_digest = Make ()
