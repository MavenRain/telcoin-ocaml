(** [Certificate] exactly as Rust puts it on the wire
    (crates/types/src/primary/certificate.rs:27-38, GT:145-146).

    The port's {!Tn_vertex.Certificate} deliberately models the five-state
    [SignatureVerificationState] away: a value of that type is either genesis
    or a checked aggregate, and the three intermediate states describe a
    certificate that is not yet a value of it. That is the right core type and
    chunk 44 does not touch it. It is not, however, a wire type, so this
    module carries the Rust shape:

    [header] ++ [signature_verification_state] ++ [signed_authorities]

    with all five states present, and converts at the boundary. {!to_checked}
    is the only way out of the wire world: it rebuilds the abstract
    certificate through the claim-style ingress added to lib/vertex and then
    runs {!Tn_vertex.Certificate.check}, so a certificate that reaches the
    rest of the port has been re-verified against the committee. *)

open Tn_types

type sig_state =
  | Unsigned of Bls_signature.t  (** Rust index 0. *)
  | Unverified of Bls_signature.t  (** index 1. *)
  | Verified_directly of Bls_signature.t  (** index 2. *)
  | Verified_indirectly of Bls_signature.t  (** index 3. *)
  | Genesis  (** index 4, the unit variant: a bare tag byte. *)

type t
(** A decoded wire certificate. Abstract: it is a claim, not a proof, and
    {!to_checked} is the only door into the checked type. *)

type error =
  | Unknown_signer_index of { index : int }
      (** The bitmap names a committee position that does not exist. *)
  | Signer_not_in_committee
      (** {!of_certificate} was handed a certificate signed by an authority
          this committee does not list. *)
  | Signature_rejected
      (** The crypto seam refused the 48 wire bytes as one of its own
          aggregate encodings, or refused to render its aggregate as 48. The
          seam's width is a property of the linked implementation: the blst
          seam is 48 bytes wide and agrees with the wire, the stub seam is
          not. *)
  | Not_checked of Tn_vertex.Certificate.error
      (** The rebuilt certificate failed {!Tn_vertex.Certificate.check}. *)

val error_to_string : error -> string

val make :
  header:Tn_vertex.Header.t ->
  state:sig_state ->
  signed_authorities:Roaring.t ->
  t
(** Build a wire value, for encoding and for tests. No verification. *)

val header : t -> Tn_vertex.Header.t
val state : t -> sig_state

val signed_authorities : t -> Roaring.t
(** The committee POSITIONS that signed, which is what the bitmap holds. *)

val codec : t Tn_codec.Bcs.t
(** Header bytes ({!Tn_vertex.Header.codec}, already golden-tested by chunk
    41), then the ULEB128 state tag with its 48-byte signature where the
    variant carries one, then the roaring field. *)

val to_checked :
  Committee.t -> t -> (Tn_vertex.Certificate.t, error) result
(** Resolve the bitmap against [Committee.nth], rebuild through
    [Certificate.claim], and re-verify with [Certificate.check]. Every failure
    is named; nothing unchecked is returned. *)

val of_certificate :
  Committee.t -> Tn_vertex.Certificate.t -> (t, error) result
(** The other direction: a genesis certificate encodes as {!Genesis} with an
    empty bitmap, an aggregated one as {!Verified_directly}, which is the
    state a node that has just verified a certificate holds. Signer positions
    come from [Committee.index_of]. *)

val equal : t -> t -> bool
