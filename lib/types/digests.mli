(** Domain-separated digest newtypes.

    Rust generates these with a [digest_newtype!] macro so that a header digest
    can never be passed where a batch digest is expected. Each module below is
    a distinct abstract type wrapping a {!Tn_crypto.Digest.t}, and each carries
    a distinct {!domain} tag that the producing module folds into the hash
    pre-image, so two structurally identical byte strings in different domains
    still hash apart. *)

module type S = sig
  type t

  val domain : string
  (** The domain-separation tag hashed ahead of this digest's pre-image. *)

  val of_digest : Tn_crypto.Digest.t -> t
  val to_digest : t -> Tn_crypto.Digest.t
  val to_hex : t -> string
  val equal : t -> t -> bool
  val compare : t -> t -> int
end

(** Digest of a {!module:Header} — also the certificate's digest. *)
module Header_digest : S

(** Digest of a worker batch. *)
module Batch_digest : S

(** Digest of a committed sub-DAG. *)
module Sub_dag_digest : S

(** Digest of a consensus output / consensus-chain header. *)
module Output_digest : S
