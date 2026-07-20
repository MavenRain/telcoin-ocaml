(* Tests for Ethereum's Keccak-256.

   This module wraps a library function rather than implementing a permutation,
   so what is under test is not the arithmetic: it is the claim that the wrapper
   selected the right functor. [Digestif.KECCAK_256] and [Digestif.SHA3_256]
   have the same module type and the same digest width and differ only in the
   domain-separation byte their padding appends, so substituting one for the
   other compiles, runs, and silently forks the chain. Every vector below is a
   value published outside this project — the specifications' [KECCAK_EMPTY],
   the ERC-20 [Transfer] event topic, and two ABI function selectors that appear
   in the calldata of most transactions ever sent — so agreement with them is
   evidence about the world and not about this repository. The suite then
   asserts the negative directly: the empty digest is not SHA3-256's. *)

module Keccak = Tn_keccak

(* ---------- published vectors ---------- *)

(* [KECCAK_EMPTY]: the word [KECCAK256] pushes for a zero-length input, and the
   code hash every codeless account carries. *)
let test_keccak_empty () =
  Alcotest.(check string) "keccak256 of the empty string"
    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    (Keccak.to_hex Keccak.empty);
  Alcotest.(check bool) "the constant agrees with the function" true
    (Keccak.equal Keccak.empty (Keccak.digest ""))

(* The vector every Keccak implementation is checked against first. *)
let test_keccak_short_strings () =
  Alcotest.(check string) "keccak256 \"abc\""
    "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    (Keccak.to_hex (Keccak.digest "abc"));
  Alcotest.(check string) "keccak256 \"testing\""
    "5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02"
    (Keccak.to_hex (Keccak.digest "testing"))

(* Values a reader can check against a block explorer rather than against this
   file. The event topic is the full digest; a selector is a digest's first four
   bytes, so pinning the whole word pins the selector and more. *)
let test_keccak_ethereum_vectors () =
  Alcotest.(check string) "the ERC-20 Transfer event topic"
    "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    (Keccak.to_hex (Keccak.digest "Transfer(address,address,uint256)"));
  Alcotest.(check string) "transfer(address,uint256) selects a9059cbb" "a9059cbb"
    (String.sub (Keccak.to_hex (Keccak.digest "transfer(address,uint256)")) 0 8);
  Alcotest.(check string) "approve(address,uint256) selects 095ea7b3" "095ea7b3"
    (String.sub (Keccak.to_hex (Keccak.digest "approve(address,uint256)")) 0 8)

(* The hazard, asserted rather than merely avoided. SHA3-256 is the neighbouring
   functor with the identical signature; if the wrapper ever names it, this is
   the case that says so, at the point of failure. *)
let test_keccak_is_not_sha3 () =
  Alcotest.(check bool) "keccak256 \"\" is not SHA3-256 \"\"" false
    (String.equal (Keccak.to_hex Keccak.empty)
       "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")

(* ---------- shape and totality ---------- *)

(* The width is the backing library's fact, and the interpreter depends on it:
   a digest is converted to a word through [U256.of_be_bytes], which accepts
   exactly 32 bytes and would otherwise reach a documented-unreachable fallback. *)
let test_keccak_width () =
  Alcotest.(check int) "the advertised length is 32" 32 Keccak.length;
  Alcotest.(check int) "empty occupies that many bytes" Keccak.length
    (String.length (Keccak.to_bytes Keccak.empty));
  Alcotest.(check int) "the hex render is twice the length" (2 * Keccak.length)
    (String.length (Keccak.to_hex Keccak.empty))

(* Every string is a pre-image: there is no length this function refuses, which
   is what lets the interpreter charge for a hash before performing one and know
   the hash cannot then fail. The sponge's rate is 136 bytes for this width, so
   the lengths either side of it are where a padding error would surface; the
   assertion is that all three produce a full-width digest and that no two of
   them collide, which no correct implementation can fail and a padding bug
   readily does. *)
let test_keccak_rate_boundary () =
  let at n = Keccak.digest (String.make n 'a') in
  let below, at_rate, above = (at 135, at 136, at 137) in
  List.iter
    (fun (label, d) ->
      Alcotest.(check int) label Keccak.length (String.length (Keccak.to_bytes d)))
    [ ("135 bytes", below); ("136 bytes", at_rate); ("137 bytes", above) ];
  Alcotest.(check bool) "the rate boundary is not a fixed point" false
    (Keccak.equal below at_rate);
  Alcotest.(check bool) "nor is the byte after it" false (Keccak.equal at_rate above)

(* A hash is a function: the same bytes give the same digest, and a one-bit
   change does not. *)
let test_keccak_determinism () =
  Alcotest.(check bool) "the same input hashes the same" true
    (Keccak.equal (Keccak.digest "telcoin") (Keccak.digest "telcoin"));
  Alcotest.(check bool) "a different input does not" false
    (Keccak.equal (Keccak.digest "telcoin") (Keccak.digest "telcoim"))

(* A digest is a byte string, not a C string: an interior NUL is data. This is
   the property that would break if the wrapper ever routed bytes through a
   representation that terminates. *)
let test_keccak_nul_bytes () =
  let with_nul = "ab\000cd" in
  Alcotest.(check bool) "an interior NUL is part of the pre-image" false
    (Keccak.equal (Keccak.digest with_nul) (Keccak.digest "ab"));
  Alcotest.(check int) "and hashing it still yields a full digest" Keccak.length
    (String.length (Keccak.to_bytes (Keccak.digest with_nul)))

let () =
  Alcotest.run "keccak"
    [
      ( "published vectors",
        [
          Alcotest.test_case "the empty digest is KECCAK_EMPTY" `Quick test_keccak_empty;
          Alcotest.test_case "the classic short vectors" `Quick test_keccak_short_strings;
          Alcotest.test_case "Ethereum topics and selectors" `Quick
            test_keccak_ethereum_vectors;
          Alcotest.test_case "it is Keccak and not SHA3-256" `Quick test_keccak_is_not_sha3;
        ] );
      ( "shape and totality",
        [
          Alcotest.test_case "a digest is 32 bytes" `Quick test_keccak_width;
          Alcotest.test_case "the sponge rate boundary is total" `Quick
            test_keccak_rate_boundary;
          Alcotest.test_case "hashing is deterministic" `Quick test_keccak_determinism;
          Alcotest.test_case "an interior NUL is data" `Quick test_keccak_nul_bytes;
        ] );
    ]
