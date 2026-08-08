(* Shared, implementation-agnostic conformance suite for the tn_crypto seam.

   [Make] is a functor over the seam's OBSERVABLE contract: [CRYPTO] below
   is lib/crypto/tn_crypto.mli reshaped as a first-class module type, so
   [Make (Tn_crypto)] typechecks in any executable regardless of which
   concrete implementation dune resolves for it. Every assertion here must
   hold of BOTH implementations -- the deliberately-forgeable stub default
   and the real BLS12-381 one alike -- so nothing here may pin a concrete
   hash value, a byte width beyond [Digest.length], or a fixture.
   Implementation-specific facts (BLAKE3 vs BLAKE2s output, Rust golden
   vectors, subgroup/infinity rejection) live in the per-implementation
   executables, never in this functor.

   Two shared-contract boundaries were chosen deliberately:
   - codec width negatives are off-by-one around a REAL non-empty
     encoding ([to_bytes] of a live value), never absolute byte counts,
     because the two implementations disagree on every width except the
     digest's; and never the empty string for [Aggregate.of_bytes],
     which the stub accepts as its empty aggregate;
   - the [verify_aggregate [] _ _ = false] case uses a NON-empty
     aggregate: over the empty aggregate the stub's multiset equation
     is vacuously satisfied, so only the non-empty shape is contract. *)

(** The seam's observable contract: lib/crypto/tn_crypto.mli as a module
    type, satisfied by [Tn_crypto] under either implementation. *)
module type CRYPTO = sig
  module Digest : sig
    type t

    val length : int
    val zero : t
    val hash : string -> t
    val of_bytes : string -> t option
    val to_bytes : t -> string
    val to_hex : t -> string
    val equal : t -> t -> bool
    val compare : t -> t -> int
  end

  module Public_key : sig
    type t

    val to_bytes : t -> string
    val of_bytes : string -> t option
    val equal : t -> t -> bool
    val compare : t -> t -> int
  end

  module Secret_key : sig
    type t

    val derive : int64 -> t
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

    val to_bytes : t -> string
    val of_bytes : string -> t option
    val equal : t -> t -> bool
  end

  val sign : Secret_key.t -> string -> Signature.t
  val verify : Public_key.t -> string -> Signature.t -> bool
  val aggregate : Signature.t list -> Aggregate.t
  val verify_aggregate : Public_key.t list -> string -> Aggregate.t -> bool
end

module Make (C : CRYPTO) : sig
  val tests : unit Alcotest.test_case list
  (** The impl-agnostic Alcotest cases every implementation must pass. *)
end = struct
  (* Fixed conformance inputs. The exact values are arbitrary: every
     assertion relates outputs to each other (round-trips, negations,
     order permutations), never to pinned constants. *)
  let msg = "tn_crypto conformance message v1"
  let wrong_msg = "tn_crypto conformance message v2"
  let sk0 = C.Secret_key.derive 100L
  let sk1 = C.Secret_key.derive 101L
  let sk2 = C.Secret_key.derive 102L
  let pk0 = C.Secret_key.public_key sk0
  let pk1 = C.Secret_key.public_key sk1
  let pk2 = C.Secret_key.public_key sk2
  let s0 = C.sign sk0 msg
  let s1 = C.sign sk1 msg
  let s2 = C.sign sk2 msg
  let agg = C.aggregate [ s0; s1; s2 ]

  (* Lowercase hex of raw bytes; total ([Char.code] is total on char). *)
  let hex_encode s =
    String.to_seq s
    |> Seq.map (fun c -> Printf.sprintf "%02x" (Char.code c))
    |> List.of_seq |> String.concat ""

  (* [b] without its final byte. Every call site feeds a [to_bytes]
     encoding, which is non-empty in both implementations, but the guard
     (not that claim) is what makes this total. *)
  let truncated b =
    let n = String.length b in
    if n > 0 then String.sub b 0 (n - 1) else b (* @total-accessor: 0 + (n-1) <= n, guarded on this line *)

  let digest_length_case =
    Alcotest.test_case "digest length is 32" `Quick (fun () ->
        Alcotest.(check int) ".mli:22 pins Digest.length at 32" 32
          C.Digest.length)

  let digest_hash_width_case =
    Alcotest.test_case "digest hash has length bytes" `Quick (fun () ->
        Alcotest.(check int) "String.length (to_bytes (hash msg))"
          C.Digest.length
          (String.length (C.Digest.to_bytes (C.Digest.hash msg))))

  (* .mli:24-29: [zero] is [length] NUL bytes, named by the width and
     never by hashing a pre-image. *)
  let digest_zero_bytes_case =
    Alcotest.test_case "digest zero is all-zero bytes" `Quick (fun () ->
        Alcotest.(check string) "to_bytes zero = length NUL bytes"
          (String.make (max 0 C.Digest.length) '\000')
          (C.Digest.to_bytes C.Digest.zero))

  let digest_zero_not_hash_empty_case =
    Alcotest.test_case "digest zero is not hash of empty" `Quick (fun () ->
        Alcotest.(check bool) "equal zero (hash \"\")" false
          (C.Digest.equal C.Digest.zero (C.Digest.hash "")))

  let digest_deterministic_case =
    Alcotest.test_case "digest hash is deterministic" `Quick (fun () ->
        Alcotest.(check bool) "equal (hash msg) (hash msg)" true
          (C.Digest.equal (C.Digest.hash msg) (C.Digest.hash msg)))

  let digest_distinct_case =
    Alcotest.test_case "digest distinguishes inputs" `Quick (fun () ->
        Alcotest.(check bool) "equal (hash msg) (hash wrong_msg)" false
          (C.Digest.equal (C.Digest.hash msg) (C.Digest.hash wrong_msg)))

  let digest_roundtrip_case =
    Alcotest.test_case "digest codec round-trip" `Quick (fun () ->
        let d = C.Digest.hash msg in
        Alcotest.(check (option string))
          "of_bytes (to_bytes d), mapped back to bytes"
          (Some (C.Digest.to_bytes d))
          (Option.map C.Digest.to_bytes
             (C.Digest.of_bytes (C.Digest.to_bytes d))))

  (* .mli:37: [Some] only for an input of exactly [length] bytes; probed
     at the three offsets -1/0/+1 around the pinned width. *)
  let digest_width_case n expected_some =
    Alcotest.test_case
      (Printf.sprintf "digest of_bytes at length%+d" n)
      `Quick
      (fun () ->
        let input = String.make (max 0 (C.Digest.length + n)) '\x2a' in
        Alcotest.(check bool)
          (Printf.sprintf "of_bytes on a length%+d input is %s" n
             (if expected_some then "Some" else "None"))
          expected_some
          (Option.is_some (C.Digest.of_bytes input)))

  let digest_hex_case =
    Alcotest.test_case "digest to_hex is lowercase hex of to_bytes" `Quick
      (fun () ->
        let d = C.Digest.hash msg in
        Alcotest.(check string) "to_hex d = hex (to_bytes d)"
          (hex_encode (C.Digest.to_bytes d))
          (C.Digest.to_hex d))

  let digest_compare_case =
    Alcotest.test_case "digest compare agrees with equal" `Quick (fun () ->
        let d = C.Digest.hash msg and e = C.Digest.hash wrong_msg in
        Alcotest.(check bool) "compare d d = 0" true (C.Digest.compare d d = 0);
        Alcotest.(check bool) "equal d e = (compare d e = 0)"
          (C.Digest.equal d e)
          (C.Digest.compare d e = 0))

  (* Fail-closed round-trip shape shared by the three remaining codecs:
     [Option.map (equal original)] collapses a rejected decode to [None],
     so the [Some true] expectation is red on either failure mode. *)
  let pk_roundtrip_case =
    Alcotest.test_case "public key codec round-trip" `Quick (fun () ->
        Alcotest.(check (option bool))
          "of_bytes (to_bytes pk0) is Some, equal to pk0" (Some true)
          (Option.map (C.Public_key.equal pk0)
             (C.Public_key.of_bytes (C.Public_key.to_bytes pk0))))

  let pk_width_case =
    Alcotest.test_case "public key of_bytes width rejection" `Quick (fun () ->
        let b = C.Public_key.to_bytes pk0 in
        Alcotest.(check bool) "of_bytes \"\" is None" true
          (Option.is_none (C.Public_key.of_bytes ""));
        Alcotest.(check bool) "of_bytes on one byte short is None" true
          (Option.is_none (C.Public_key.of_bytes (truncated b)));
        Alcotest.(check bool) "of_bytes on one byte long is None" true
          (Option.is_none (C.Public_key.of_bytes (b ^ "\x00"))))

  let pk_distinct_case =
    Alcotest.test_case "distinct seeds give distinct public keys" `Quick
      (fun () ->
        Alcotest.(check bool) "equal pk0 pk1" false
          (C.Public_key.equal pk0 pk1);
        Alcotest.(check bool) "compare pk0 pk0 = 0" true
          (C.Public_key.compare pk0 pk0 = 0))

  let derive_deterministic_case =
    Alcotest.test_case "derive is deterministic" `Quick (fun () ->
        Alcotest.(check bool)
          "public_key (derive 100L) twice gives equal keys" true
          (C.Public_key.equal pk0
             (C.Secret_key.public_key (C.Secret_key.derive 100L))))

  let sig_roundtrip_case =
    Alcotest.test_case "signature codec round-trip" `Quick (fun () ->
        Alcotest.(check (option bool))
          "of_bytes (to_bytes s0) is Some, equal to s0" (Some true)
          (Option.map (C.Signature.equal s0)
             (C.Signature.of_bytes (C.Signature.to_bytes s0))))

  let sig_width_case =
    Alcotest.test_case "signature of_bytes width rejection" `Quick (fun () ->
        let b = C.Signature.to_bytes s0 in
        Alcotest.(check bool) "of_bytes \"\" is None" true
          (Option.is_none (C.Signature.of_bytes ""));
        Alcotest.(check bool) "of_bytes on one byte short is None" true
          (Option.is_none (C.Signature.of_bytes (truncated b)));
        Alcotest.(check bool) "of_bytes on one byte long is None" true
          (Option.is_none (C.Signature.of_bytes (b ^ "\x00"))))

  let sign_verify_case =
    Alcotest.test_case "sign/verify self-consistency" `Quick (fun () ->
        Alcotest.(check bool) "verify pk0 msg (sign sk0 msg)" true
          (C.verify pk0 msg s0))

  let verify_wrong_msg_case =
    Alcotest.test_case "verify rejects a wrong message" `Quick (fun () ->
        Alcotest.(check bool) "verify pk0 wrong_msg s0" false
          (C.verify pk0 wrong_msg s0))

  let verify_wrong_key_case =
    Alcotest.test_case "verify rejects a wrong key" `Quick (fun () ->
        Alcotest.(check bool) "verify pk1 msg s0" false
          (C.verify pk1 msg s0))

  let aggregate_order_case =
    Alcotest.test_case "aggregate order-irrelevance" `Quick (fun () ->
        let rev = C.aggregate [ s2; s1; s0 ] in
        Alcotest.(check bool) "Aggregate.equal on both collection orders" true
          (C.Aggregate.equal agg rev);
        Alcotest.(check string) "to_bytes agrees on both collection orders"
          (C.Aggregate.to_bytes agg) (C.Aggregate.to_bytes rev))

  let aggregate_roundtrip_case =
    Alcotest.test_case "aggregate codec round-trip" `Quick (fun () ->
        Alcotest.(check (option bool))
          "of_bytes (to_bytes agg) is Some, equal to agg" (Some true)
          (Option.map (C.Aggregate.equal agg)
             (C.Aggregate.of_bytes (C.Aggregate.to_bytes agg))))

  (* Deliberately NOT [of_bytes ""] here: a zero-length input is the
     stub's own empty aggregate and decodes [Some], so the shared
     negative is off-by-one around a real non-empty encoding. *)
  let aggregate_width_case =
    Alcotest.test_case "aggregate of_bytes width rejection" `Quick (fun () ->
        let b = C.Aggregate.to_bytes agg in
        Alcotest.(check bool) "of_bytes on one byte short is None" true
          (Option.is_none (C.Aggregate.of_bytes (truncated b)));
        Alcotest.(check bool) "of_bytes on one byte long is None" true
          (Option.is_none (C.Aggregate.of_bytes (b ^ "\x00"))))

  let verify_aggregate_case =
    Alcotest.test_case "verify_aggregate accepts the signer set" `Quick
      (fun () ->
        Alcotest.(check bool) "verify_aggregate [pk0;pk1;pk2] msg agg" true
          (C.verify_aggregate [ pk0; pk1; pk2 ] msg agg))

  (* .mli:97-98: order of keys is irrelevant to the result. *)
  let verify_aggregate_order_case =
    Alcotest.test_case "verify_aggregate key order-irrelevance" `Quick
      (fun () ->
        Alcotest.(check bool) "verify_aggregate [pk2;pk0;pk1] msg agg" true
          (C.verify_aggregate [ pk2; pk0; pk1 ] msg agg))

  (* The aggregate here is the live NON-empty [agg]: over an empty
     aggregate the stub's multiset equation is vacuously true, so only
     this shape is shared contract (functor header note). *)
  let verify_aggregate_empty_case =
    Alcotest.test_case "verify_aggregate on no keys is false" `Quick
      (fun () ->
        Alcotest.(check bool) "verify_aggregate [] msg agg" false
          (C.verify_aggregate [] msg agg))

  let verify_aggregate_wrong_msg_case =
    Alcotest.test_case "verify_aggregate rejects a wrong message" `Quick
      (fun () ->
        Alcotest.(check bool) "verify_aggregate [pk0;pk1;pk2] wrong_msg agg"
          false
          (C.verify_aggregate [ pk0; pk1; pk2 ] wrong_msg agg))

  let verify_aggregate_subset_case =
    Alcotest.test_case "verify_aggregate rejects a key subset" `Quick
      (fun () ->
        Alcotest.(check bool) "verify_aggregate [pk0;pk1] msg agg" false
          (C.verify_aggregate [ pk0; pk1 ] msg agg))

  let tests =
    [ digest_length_case; digest_hash_width_case; digest_zero_bytes_case;
      digest_zero_not_hash_empty_case; digest_deterministic_case;
      digest_distinct_case; digest_roundtrip_case;
      digest_width_case (-1) false;
      digest_width_case 0 true;
      digest_width_case 1 false;
      digest_hex_case; digest_compare_case; pk_roundtrip_case; pk_width_case;
      pk_distinct_case; derive_deterministic_case; sig_roundtrip_case;
      sig_width_case; sign_verify_case; verify_wrong_msg_case;
      verify_wrong_key_case; aggregate_order_case; aggregate_roundtrip_case;
      aggregate_width_case; verify_aggregate_case;
      verify_aggregate_order_case; verify_aggregate_empty_case;
      verify_aggregate_wrong_msg_case; verify_aggregate_subset_case ]
end
