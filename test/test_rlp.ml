(* Tests for the RLP codec (Tn_rlp.Rlp), the reth alloy-rlp 0.3.13 port.

   RLP is a consensus fact: a trie node, an account leaf and a transaction
   envelope all commit to their RLP, so a wrong byte forks the chain. The
   vectors below are the crate's own [encode.rs]/[header.rs] test fixtures, so
   agreement is evidence about the deployed rules and not about this repository.
   The suite locks three things a naive port gets wrong: the byte-string versus
   scalar distinction (the number zero is [0x80] but the one-byte string [0x00]
   is [0x00]); the canonicity errors a consensus decoder must reject; and the
   short/long length-header boundary at 56 bytes. *)

module Rlp = Tn_rlp.Rlp

(* ---------- hex helpers (values are given as hex) ---------- *)

let hex s =
  let digit c =
    match c with
    | '0' .. '9' -> Char.code c - Char.code '0'
    | 'a' .. 'f' -> Char.code c - Char.code 'a' + 10
    | 'A' .. 'F' -> Char.code c - Char.code 'A' + 10
    | _ -> 0
  in
  String.init
    (String.length s / 2)
    (fun i -> Char.chr ((digit (String.get s (2 * i)) lsl 4) lor digit (String.get s ((2 * i) + 1))))

let to_hex s =
  let buf = Buffer.create (2 * String.length s) in
  String.iter (fun c -> Buffer.add_string buf (Printf.sprintf "%02x" (Char.code c))) s;
  Buffer.contents buf

(* The error a decode produced, as its rendered tag ([error_to_string] is
   injective across the six variants, so the tag identifies the variant), or
   ["ok"] on success. *)
let err_tag = function Ok _ -> "ok" | Error e -> Rlp.error_to_string e

(* The payload of a decoded single byte-string, or a marker for any other shape,
   so a round-trip can compare against the original bytes. *)
let exact_str = function
  | Ok (Rlp.Str s) -> s
  | Ok (Rlp.List _) -> "<list>"
  | Error e -> "<error:" ^ Rlp.error_to_string e ^ ">"

let exact_list_str = function
  | Ok (Rlp.List [ Rlp.Str s ]) -> s
  | Ok (Rlp.List _) -> "<list-other>"
  | Ok (Rlp.Str _) -> "<str>"
  | Error e -> "<error:" ^ Rlp.error_to_string e ^ ">"

(* ---------- encode unit vectors (spec 8.2 / encode.rs) ---------- *)

let test_encode_bytes () =
  let case input expected =
    Alcotest.(check string)
      ("encode_bytes " ^ expected) expected (to_hex (Rlp.encode_bytes (hex input)))
  in
  case "" "80";
  case "7b" "7b";
  case "80" "8180";
  case "abba" "82abba"

let test_encode_nat () =
  let case n expected =
    Alcotest.(check string)
      (Printf.sprintf "encode_nat %d" n) expected (to_hex (Rlp.encode_nat n))
  in
  case 0 "80";
  case 1 "01";
  case 0x7f "7f";
  case 0x80 "8180";
  case 0x400 "820400"

(* G1: the byte-string path preserves leading zeros and a one-byte [0x00]; the
   scalar path trims them, so the number zero is [0x80]. Conflating the two is
   the classic RLP bug, and the trie's value slot depends on the byte path. *)
let test_bytes_vs_scalar () =
  Alcotest.(check string) "encode_bytes 00 is a bare 00" "00" (to_hex (Rlp.encode_bytes (hex "00")));
  Alcotest.(check string) "encode_scalar 00 is 80" "80" (to_hex (Rlp.encode_scalar (hex "00")));
  Alcotest.(check string)
    "encode_bytes 0007 keeps the zero" "820007" (to_hex (Rlp.encode_bytes (hex "0007")));
  Alcotest.(check string)
    "encode_scalar 0007 trims to 07" "07" (to_hex (Rlp.encode_scalar (hex "0007")))

(* G1/wide scalar (spec 8.2, encode.rs:535-543): a 28-byte U256 whose big-endian
   minimal form is [0100..0e01] encodes as [0x9c] (0x80+28) then the 28 bytes. The
   same value carried as its 32-byte big-endian U256 (four leading zero bytes)
   must trim to the identical scalar, proving [encode_scalar] strips leading
   zeros before applying the byte-string rule — the account-balance/storage-slot
   path. *)
let test_wide_scalar () =
  let v = "0100020003000400050006000700080009000a0b4b000c000d000e01" in
  let expected = "9c" ^ v in
  Alcotest.(check string)
    "28-byte scalar uses the 0x9c header (spec 8.2)" expected (to_hex (Rlp.encode_scalar (hex v)));
  Alcotest.(check string)
    "the 32-byte U256 form trims to the same 28-byte scalar" expected
    (to_hex (Rlp.encode_scalar (hex ("00000000" ^ v))))

(* ---------- decode canonicity errors (G7: each of the six variants) ---------- *)

let test_decode_errors () =
  let case name buf expected =
    Alcotest.(check string) name (Rlp.error_to_string expected) (err_tag (Rlp.decode (hex buf)))
  in
  case "81 (header runs off the end)" "81" Rlp.Input_too_short;
  case "8105 (a bare byte was required)" "8105" Rlp.Non_canonical_single_byte;
  case "b8020004 (short form was required)" "b8020004" Rlp.Non_canonical_size;
  case "b800 (leading zero in a length)" "b800" Rlp.Leading_zero;
  case "bf + eight ff (length overflows int)" "bfffffffffffffffff" Rlp.Overflow;
  Alcotest.(check string)
    "0102 (decode_exact rejects the trailing 02)"
    (Rlp.error_to_string Rlp.Trailing_bytes)
    (err_tag (Rlp.decode_exact (hex "0102")))

(* ---------- decode-then-encode round-trips (spec 8.2) ---------- *)

let test_round_trip_units () =
  let case input =
    let e = Rlp.encode_bytes (hex input) in
    Alcotest.(check string)
      ("round-trips " ^ input) input (to_hex (exact_str (Rlp.decode_exact e)));
    Alcotest.(check string)
      ("re-encodes " ^ input) (to_hex e) (to_hex (Rlp.encode (Rlp.Str (hex input))))
  in
  List.iter case [ ""; "7b"; "80"; "abba"; "00"; "0007" ]

(* ---------- G4: length-header boundaries round-trip ---------- *)

let test_boundary_round_trips () =
  let string_case n prefix =
    let s = String.make n 'a' in
    let e = Rlp.encode_bytes s in
    Alcotest.(check string)
      (Printf.sprintf "%d-byte string uses prefix %s" n prefix)
      prefix
      (String.sub (to_hex e) 0 (String.length prefix));
    Alcotest.(check string)
      (Printf.sprintf "%d-byte string round-trips" n) s (exact_str (Rlp.decode_exact e))
  in
  (* 55 is the largest short string (0xb7); 56 crosses to a one-byte length
     (0xb8 0x38); 256 needs a two-byte length (0xb9 0x0100). *)
  string_case 55 "b7";
  string_case 56 "b838";
  string_case 256 "b90100";
  (* A list whose payload exceeds 255 bytes needs a two-byte list length
     (0xf9 + length). *)
  let inner = String.make 300 'a' in
  let e = Rlp.encode_list [ Rlp.encode_bytes inner ] in
  Alcotest.(check string) "list payload > 255 uses 0xf9" "f9" (String.sub (to_hex e) 0 2);
  Alcotest.(check string) "large list round-trips" inner (exact_list_str (Rlp.decode_exact e))

let () =
  Alcotest.run "rlp"
    [
      ( "encode",
        [
          Alcotest.test_case "byte-string unit vectors" `Quick test_encode_bytes;
          Alcotest.test_case "scalar unit vectors" `Quick test_encode_nat;
          Alcotest.test_case "byte-string vs scalar (G1)" `Quick test_bytes_vs_scalar;
          Alcotest.test_case "wide 28-byte scalar (spec 8.2)" `Quick test_wide_scalar;
        ] );
      ( "decode",
        [
          Alcotest.test_case "canonicity errors (G7)" `Quick test_decode_errors;
          Alcotest.test_case "unit round-trips" `Quick test_round_trip_units;
          Alcotest.test_case "length-header boundaries (G4)" `Quick test_boundary_round_trips;
        ] );
    ]
