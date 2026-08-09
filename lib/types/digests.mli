(** Distinct digest newtypes.

    Rust generates these with a [digest_newtype!] macro so that a header digest
    can never be passed where a batch digest is expected. Each module below is
    a distinct abstract type wrapping a {!Tn_crypto.Digest.t}. The separation is
    in the type only. Rust hashes every protocol pre-image bare, so no kind
    folds a tag into its pre-image, and two kinds that wrap the same bytes are
    the same 32 bytes once unwrapped. *)

module type S = sig
  type t

  val zero : t
  (** The all-zero digest, wrapping {!Tn_crypto.Digest.zero}. This is not the
      digest of an empty thing, it is the absent-value constant Rust writes as
      [B256::ZERO], so every kind's [zero] carries the same 32 NUL bytes and
      only the type tells them apart. It exists because a header slot this chain
      leaves unused
      (the ommers hash of an epoch-closing block, which has no batch behind it)
      must hold that exact constant, and no pre-image hashes to it. *)

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
