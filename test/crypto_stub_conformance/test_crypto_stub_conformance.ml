(* Conformance executable for the DEFAULT implementation of the virtual
   [tn_crypto] library.

   The dune stanza names NO concrete implementation, so dune resolves
   [Tn_crypto] through [default_implementation] to the stub
   ([telcoin_ocaml.crypto_stub]) -- exercising the fallback mechanism that
   every pre-existing executable in the repo relies on, now that the real
   implementation coexists. The [conformance] group is the SAME shared
   functor test/crypto_blst instantiates against the real implementation:
   green in both executables is the behavioral-parity claim for the seam's
   observable contract.

   The [stub_identity] group pins the one fact that distinguishes the two
   implementations at this seam: the stub's [Digest.hash] is BLAKE2s-256
   (lib/crypto_stub/tn_crypto.ml:12,22), not BLAKE3. Red here would mean
   this executable silently linked the wrong implementation, so the
   conformance group's green would be attributed to the wrong module. *)

module Conformance = Crypto_conformance.Make (Tn_crypto)

(* BLAKE2s-256 of the empty string (RFC 7693 parameters, the digestif
   backend the stub uses); independently pinned via python3
   hashlib.blake2s(b"").hexdigest(). *)
let blake2s_empty_hex =
  "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"

let stub_digest_case =
  Alcotest.test_case "digest is BLAKE2s-256 (stub linked)" `Quick (fun () ->
      Alcotest.(check string)
        "Digest.to_hex (Digest.hash \"\") is the BLAKE2s-256 empty digest"
        blake2s_empty_hex
        (Tn_crypto.Digest.to_hex (Tn_crypto.Digest.hash "")))

let () =
  Alcotest.run "tn_crypto_stub_conformance"
    [ ("conformance", Conformance.tests);
      ("stub_identity", [ stub_digest_case ]) ]
