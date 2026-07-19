(** The cryptographic seam.

    This is a dune {e virtual} library: it declares the interface the whole
    protocol codes against, and a concrete implementation is chosen at link
    time. The vertical slice links {!module:Tn_crypto_stub} — a deterministic,
    deliberately forgeable fake that exercises every code path without a native
    dependency. The full node will link a [tn_crypto_blst] implementation
    backed by real BLAKE3 and BLS12-381 min-signature aggregation. Protocol
    code never learns which is present.

    Every operation is total and allocation-explicit; nothing here raises. A
    signature that fails to verify is a [false] result, never an exception. *)

(** {1 Digests} *)

module Digest : sig
  type t
  (** A fixed 32-byte digest. Abstract so that only {!of_bytes} and {!hash} can
      manufacture one, keeping the width invariant unbreakable. *)

  val length : int
  (** 32. *)

  val hash : string -> t
  (** The protocol hash of a byte string (BLAKE3 in the real implementation;
      the stub substitutes BLAKE2b-256, which shares the 32-byte width). *)

  val of_bytes : string -> t option
  (** [Some] only for an input of exactly {!length} bytes. *)

  val to_bytes : t -> string
  val to_hex : t -> string
  val equal : t -> t -> bool
  val compare : t -> t -> int
end

(** {1 Keys and signatures} *)

module Public_key : sig
  type t

  val to_bytes : t -> string
  (** The canonical compressed encoding used as a signing-order key and as the
      pre-image of an authority identifier. *)

  val of_bytes : string -> t option
  val equal : t -> t -> bool
  val compare : t -> t -> int
end

module Secret_key : sig
  type t

  val derive : int64 -> t
  (** Deterministically derive a keypair's secret from a seed. Test- and
      genesis-only; the real implementation keeps secret material behind a
      signer service. *)

  val public_key : t -> Public_key.t
end

module Signature : sig
  type t

  val to_bytes : t -> string
  val of_bytes : string -> t option
  val equal : t -> t -> bool
end

module Aggregate : sig
  type t
  (** An aggregate signature over one message shared by many signers — the
      certificate case, where a quorum signs the same header digest. *)

  val to_bytes : t -> string
  val of_bytes : string -> t option
  val equal : t -> t -> bool
end

val sign : Secret_key.t -> string -> Signature.t
(** Sign a message (already intent-prefixed by the caller). *)

val verify : Public_key.t -> string -> Signature.t -> bool

val aggregate : Signature.t list -> Aggregate.t
(** Combine per-signer signatures over one shared message. *)

val verify_aggregate : Public_key.t list -> string -> Aggregate.t -> bool
(** Verify that every listed key signed the one shared message. Order of keys
    is irrelevant to the result. *)
