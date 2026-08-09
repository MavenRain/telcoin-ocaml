(* Isolated test executable for the real [tn_crypto_blst] implementation.

   Naming [telcoin_ocaml.crypto_blst] in this executable's own libraries
   selects the real implementation for [Tn_crypto] (per-executable virtual
   library resolution); every other executable in the repo keeps the stub
   default. Stage S3.0 coverage: the 35 official BLAKE3 test vectors
   (BLAKE3-team/BLAKE3), driven through [Tn_crypto.Digest.hash], whose body
   is exactly the in-repo pure-OCaml [Blake3.hash]. The multi-chunk lengths
   1025..102400 exercise the chaining-value tree separately from the
   single-chunk path. Stage S3 coverage: [Digest] against the Rust golden
   fixture produced by the S2 harness (design notes section 9 S3 and
   section 8), plus the zero/of_bytes width gates. Stage S4 coverage:
   [Public_key] codec gates (fixture pk0 round-trip against real Rust
   bytes, infinity rejection, 95/97-byte widths) and the self-hosted
   [Secret_key.derive] regression pins. Stage S5 coverage: [sign]/[verify]
   and the [Signature] codec — (a) the raw opam library reproduces the
   Rust sig0 bytes for the fixture IKM, (b) [verify] accepts the real
   Rust pk0/sig0 pair end to end and rejects wrong-message / wrong-key /
   sign-bit-flipped negatives, (c) a derived-key sign/verify round-trip,
   plus the six upstream subgroup-invalid G1 vectors that
   [Signature.of_bytes] must reject (design notes section 9 S5). Stage S6
   coverage: [aggregate]/[verify_aggregate] — point-sum aggregation
   reproduces the Rust agg012 bytes (order-irrelevant), the pairing core
   at N=3 accepts the real Rust pk/agg bytes end to end, the empty-signer
   guard rejects both the honest-aggregate and the narrow
   infinity-aggregate cases, the duplicate-pk pair rejects a single sig0
   and accepts the doubled one, and the eight upstream subgroup-invalid
   G2 vectors are rejected by [Public_key.of_bytes] (design notes
   section 9 S6). *)

(* Where a fixture may live, first hit wins: next to the executable (the
   dune rules below copy each fixture there, covering dune runtest), the
   source tree reached from the executable's own path (covering dune exec
   from any working directory: _build/default/test/crypto_blst -> workspace
   root is four levels up), and the workspace-root-relative source path. *)
let fixture_candidates name =
  let exe_dir = Filename.dirname Sys.executable_name in
  [ Filename.concat exe_dir name;
    List.fold_left Filename.concat exe_dir
      [ ".."; ".."; ".."; ".."; "test"; "fixtures"; name ];
    List.fold_left Filename.concat "test" [ "fixtures"; name ] ]

(* Total by guard: [with_open_bin]'s raising path (an absent file) is
   unreachable behind [Sys.file_exists]; a vanished file surfaces as the
   red count assertion of its group, never an exception. *)
let read_file_opt path =
  if Sys.file_exists path then
    Some (In_channel.with_open_bin path In_channel.input_all)
  else None

let read_fixture name =
  Option.value ~default:""
    (List.find_map read_file_opt (fixture_candidates name))

(* Comment/blank stripping shared by both fixture formats: '#' lines are
   dropped BEFORE any splitting. *)
let data_lines contents =
  contents |> String.split_on_char '\n'
  |> List.filter (fun l ->
         (not (String.equal l "")) && not (String.starts_with ~prefix:"#" l))

let fixture_contents = read_fixture "blake3_official_vectors.txt"

(* One data line is "<input_len> <64 hex chars>". Total: [int_of_string_opt]
   and explicit list shapes, no exceptions. *)
let parse_line line =
  match String.split_on_char ' ' line with
  | [ len; hex ] -> Option.map (fun n -> (n, hex)) (int_of_string_opt len)
  | [] | [ _ ] | _ :: _ :: _ :: _ -> None

let vectors = fixture_contents |> data_lines |> List.filter_map parse_line

(* The documented official-vector input pattern: byte [i] is [i mod 251]. *)
let base =
  "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
  ^ "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
  ^ "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
  ^ "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa"

(* Repeat [base] (251 bytes, 0x00..0xfa) enough times and slice: [reps]
   satisfies [reps * 251 > len] for every clamped [len >= 0], because
   251 * (len/128 + 1) > len, so the slice precondition holds. *)
let pattern_input len =
  let len = max 0 len in
  let reps = (len lsr 7) + 1 in
  let big = String.concat "" (List.init reps (fun _ -> base)) in
  if 0 <= len && len <= String.length big then String.sub big 0 len else big (* @total-accessor: 0 + len <= String.length big, guarded on this line *)

let vector_case (len, expected_hex) =
  Alcotest.test_case
    (Printf.sprintf "official vector len=%d" len)
    `Quick
    (fun () ->
      Alcotest.(check string)
        (Printf.sprintf "blake3 hex of the %d-byte pattern input" len)
        expected_hex
        (Tn_crypto.Digest.to_hex (Tn_crypto.Digest.hash (pattern_input len))))

(* Red when the fixture is missing, unreadable or malformed: the parser is
   total, so breakage shows up here as a wrong count, not an exception. *)
let count_case =
  Alcotest.test_case "official vector count" `Quick (fun () ->
      Alcotest.(check int) "35 parsed vector lines" 35 (List.length vectors))

(* ------------------------------------------------------------------ *)
(* Stage S3: [Digest] against the Rust golden fixture (S2 harness).   *)
(* ------------------------------------------------------------------ *)

(* One data line is "KEY = hex" (separator is '=' with surrounding spaces,
   absorbed by [String.trim]). Total: explicit list shapes, no exceptions. *)
let parse_kv line =
  match String.split_on_char '=' line with
  | [ key; value ] -> Some (String.trim key, String.trim value)
  | [] | [ _ ] | _ :: _ :: _ :: _ -> None

let rust_vectors =
  read_fixture "tn_crypto_blst_vectors.txt" |> data_lines
  |> List.filter_map parse_kv

(* Fail-closed lookup: a missing key yields a sentinel that can never equal
   a computed hex string, so the comparing assertion goes red instead of
   passing vacuously on an absent fixture. *)
let rust_lookup key =
  Option.value
    ~default:(Printf.sprintf "<missing %s>" key)
    (List.assoc_opt key rust_vectors)

(* Lowercase hex of raw bytes; total ([Char.code] is total on char). *)
let hex_encode s =
  String.to_seq s
  |> Seq.map (fun c -> Printf.sprintf "%02x" (Char.code c))
  |> List.of_seq |> String.concat ""

(* The harness input documented in the fixture header and design notes
   section 8: MSG = b"tn_crypto_blst chunk39 golden vector v1". The
   [rust_msg_hex_case] below pins this literal to the fixture's own
   [msg_hex], so the golden comparison hashes exactly the fixture input. *)
let rust_msg = "tn_crypto_blst chunk39 golden vector v1"

(* Red when the Rust fixture is missing or malformed: 17 KEY = hex lines
   are committed verbatim from the one S2 cargo run. *)
let rust_count_case =
  Alcotest.test_case "rust vector count" `Quick (fun () ->
      Alcotest.(check int) "17 parsed KEY = hex lines" 17
        (List.length rust_vectors))

let rust_msg_hex_case =
  Alcotest.test_case "documented msg matches fixture msg_hex" `Quick
    (fun () ->
      Alcotest.(check string)
        "hex encoding of the documented msg literal vs the fixture's msg_hex"
        (rust_lookup "msg_hex") (hex_encode rust_msg))

let rust_digest_case =
  Alcotest.test_case "hash msg = rust blake3_digest_hex" `Quick (fun () ->
      Alcotest.(check string)
        "Digest.hash over the fixture msg vs the Rust harness (blake3 1.8.3)"
        (rust_lookup "blake3_digest_hex")
        (Tn_crypto.Digest.to_hex (Tn_crypto.Digest.hash rust_msg)))

(* .mli:24-29: [zero] is the width, never a pre-image hash; BLAKE3 of the
   empty string must therefore differ from it. *)
let zero_not_hash_empty_case =
  Alcotest.test_case "zero is not hash of empty" `Quick (fun () ->
      Alcotest.(check bool) "Digest.equal zero (hash \"\")" false
        (Tn_crypto.Digest.equal Tn_crypto.Digest.zero
           (Tn_crypto.Digest.hash "")))

(* [of_bytes] is total across the 31/32/33-byte width boundary: [Some] only
   at exactly 32 bytes, round-tripping through [to_bytes]. *)
let of_bytes_case n expected =
  Alcotest.test_case (Printf.sprintf "of_bytes at %d bytes" n) `Quick
    (fun () ->
      Alcotest.(check (option string))
        (Printf.sprintf "of_bytes on a %d-byte input, mapped back to bytes" n)
        expected
        (Option.map Tn_crypto.Digest.to_bytes
           (Tn_crypto.Digest.of_bytes (String.make n '\x2a'))))

(* ------------------------------------------------------------------ *)
(* Stage S4: [Public_key] / [Secret_key] core.                        *)
(* ------------------------------------------------------------------ *)

(* Total hex decoder, lowercase-only (the fixture format). The nibble
   value IS the char's index in the alphabet ([String.index_opt] -- no
   per-char match at all), pair-folded with [Option] state: [None] on any
   non-hex char or an odd nibble count, fail-closed. *)
let hex_nibble c = String.index_opt "0123456789abcdef" c

let hex_decode s =
  (* 96 = the largest fixture width (a compressed G2 point); [Buffer]
     grows on demand, so this is a hint, not a bound. The buffer is local
     and nothing mutable escapes. *)
  let buf = Buffer.create 96 in
  let step acc c =
    Option.bind acc (fun pending ->
        Option.map
          (fun lo ->
            (* [hi]/[lo] are each 0..15 by construction, so [hi*16 + lo]
               is 0..255: [Buffer.add_uint8] truncation never engages and
               no partial accessor is involved. *)
            Option.fold ~none:(Some lo)
              ~some:(fun hi ->
                Buffer.add_uint8 buf ((hi * 16) + lo);
                None)
              pending)
          (hex_nibble c))
  in
  Option.bind (String.fold_left step (Some None) s) (fun pending ->
      Option.fold
        ~none:(Some (Buffer.contents buf))
        ~some:(fun (_ : int) -> None)
        pending)

(* Round-trip against REAL Rust bytes: decode the fixture's pk0, accept it
   through [Public_key.of_bytes], and re-encode. Fail-closed on a missing
   fixture: [rust_lookup]'s sentinel does not hex-decode, so the actual
   side collapses to [None] and the check goes red. *)
let pk0_roundtrip_case =
  Alcotest.test_case "pk0 round-trip = rust pk0_hex" `Quick (fun () ->
      Alcotest.(check (option string))
        "of_bytes on the fixture pk0 bytes, back through to_bytes, in hex"
        (Some (rust_lookup "pk0_hex"))
        (Option.map
           (fun pk -> hex_encode (Tn_crypto.Public_key.to_bytes pk))
           (Option.bind
              (hex_decode (rust_lookup "pk0_hex"))
              Tn_crypto.Public_key.of_bytes)))

(* The point at infinity (0xc0 || 0^95) is a length-96, on-curve, in-
   subgroup encoding, so only the explicit [G2.is_zero] filter inside
   [Public_key.of_bytes] can reject it (design notes section 3). The
   length control keeps this from passing vacuously when the fixture is
   absent (the sentinel would decode to [None], and [None |> bind] would
   satisfy a bare is-[None] check for the wrong reason). *)
let infinity_pk_case =
  Alcotest.test_case "infinity pk rejected" `Quick (fun () ->
      let decoded = hex_decode (rust_lookup "infinity_pk_hex") in
      Alcotest.(check (option int))
        "control: the fixture infinity_pk_hex decodes to 96 raw bytes"
        (Some 96)
        (Option.map String.length decoded);
      Alcotest.(check bool)
        "Public_key.of_bytes on the 0xc0 infinity encoding is None" true
        (Option.is_none (Option.bind decoded Tn_crypto.Public_key.of_bytes)))

(* [of_bytes] length gate on either side of the exact 96-byte compressed
   G2 width. *)
let pk_width_case n =
  Alcotest.test_case (Printf.sprintf "pk of_bytes at %d bytes" n) `Quick
    (fun () ->
      Alcotest.(check bool)
        (Printf.sprintf "of_bytes on a %d-byte input is None" n)
        true
        (Option.is_none
           (Tn_crypto.Public_key.of_bytes (String.make n '\x2a'))))

(* Self-hosted regression pins for [Secret_key.derive]: generated ONCE
   from this very implementation and asserted verbatim thereafter. These
   have NO Rust target (design notes section 11 item 3): no production
   Rust code derives a BLS secret key from an int64 seed -- the Rust
   reference always fills a full 32-byte IKM from a CSPRNG -- so the
   int64 -> BLAKE3 -> IKM recipe is a purely OCaml-side deterministic
   convention, pinned for self-consistency, never claimed to be
   Rust-byte-compatible. *)
let derive_pin_case name seed expected_pk_hex =
  Alcotest.test_case (Printf.sprintf "derive %s pk pin" name) `Quick
    (fun () ->
      Alcotest.(check string)
        (Printf.sprintf
           "compressed public key hex of Secret_key.derive %s (self-hosted)"
           name)
        expected_pk_hex
        (hex_encode
           (Tn_crypto.Public_key.to_bytes
              (Tn_crypto.Secret_key.public_key
                 (Tn_crypto.Secret_key.derive seed)))))

(* ------------------------------------------------------------------ *)
(* Stage S5: [sign] / [verify] (shared pairing core, N=1) and the     *)
(* [Signature] codec.                                                  *)
(* ------------------------------------------------------------------ *)

(* The harness input documented in the fixture header: wrong_msg = msg ++
   " (wrong)". The control assertion inside [wrong_msg_case] pins this
   literal to the fixture's own [wrong_msg_hex]. *)
let rust_wrong_msg = rust_msg ^ " (wrong)"

(* Decode a fixture entry into a validated key/signature; [None] on a
   missing fixture or a rejected encoding, fail-closed. *)
let fixture_pk key =
  Option.bind (hex_decode (rust_lookup key)) Tn_crypto.Public_key.of_bytes

let fixture_sig key =
  Option.bind (hex_decode (rust_lookup key)) Tn_crypto.Signature.of_bytes

(* Run [verify] under decoded operands; [false] when either side failed to
   decode, fail-closed. Vacuity of the [false]-expecting negatives is
   excluded by [verify_sig0_case]'s [true] expectation on the same decodes
   plus the per-case [is_some]/length controls below. *)
let verify_decoded pk_opt msg sig_opt =
  Option.value ~default:false
    (Option.bind pk_opt (fun pk ->
         Option.map (Tn_crypto.verify pk msg) sig_opt))

(* Gate (a), design section 9 S5: the raw opam library — no [Tn_crypto]
   involvement at all — reproduces Rust's sig0 bytes for the identical
   IKM, certifying [generate_sk]+[Basic.sign] byte-compatibility with
   blst's [key_gen]+[Signer::sign]. The 32-byte length guard keeps
   [generate_sk]'s ikm<32 raise unreachable even on a corrupted fixture. *)
let raw_sign_case =
  Alcotest.test_case "raw library sign = rust sig0_hex" `Quick (fun () ->
      Alcotest.(check (option string))
        "generate_sk over the fixture ikm0, Basic.sign, in hex"
        (Some (rust_lookup "sig0_hex"))
        (Option.map
           (fun ikm ->
             let sk =
               Bls12_381_signature.generate_sk ~key_info:Bytes.empty
                 (Bytes.of_string ikm)
             in
             hex_encode
               (Bytes.to_string
                  Bls12_381_signature.MinSig.(
                    signature_to_bytes
                      (Basic.sign sk (Bytes.of_string rust_msg)))))
           (Option.bind
              (hex_decode (rust_lookup "ikm0_hex"))
              (fun ikm -> if String.length ikm = 32 then Some ikm else None))))

(* [Signature] codec against real Rust bytes: decode the fixture sig0,
   re-encode, and compare. Fail-closed on a missing fixture (the sentinel
   does not hex-decode, so the actual side collapses to [None]). *)
let sig0_roundtrip_case =
  Alcotest.test_case "sig0 round-trip = rust sig0_hex" `Quick (fun () ->
      Alcotest.(check (option string))
        "of_bytes on the fixture sig0 bytes, back through to_bytes, in hex"
        (Some (rust_lookup "sig0_hex"))
        (Option.map
           (fun s -> hex_encode (Tn_crypto.Signature.to_bytes s))
           (fixture_sig "sig0_hex")))

(* Gate (b) positive, design section 9 S5: the hand-rolled pairing core's
   N=1 path accepts a REAL Rust-produced pk/sig pair end to end. This is
   also the load-bearing proof that [sign]'s ciphersuite (MinSig.Basic's
   private constant) and [verify]'s [dst_g1] literal agree. *)
let verify_sig0_case =
  Alcotest.test_case "verify pk0 msg sig0 (rust bytes)" `Quick (fun () ->
      Alcotest.(check bool)
        "verify over the fixture pk0/sig0 real Rust bytes" true
        (verify_decoded (fixture_pk "pk0_hex") rust_msg
           (fixture_sig "sig0_hex")))

let wrong_msg_case =
  Alcotest.test_case "wrong message rejected" `Quick (fun () ->
      Alcotest.(check string)
        "control: documented wrong_msg literal vs the fixture wrong_msg_hex"
        (rust_lookup "wrong_msg_hex")
        (hex_encode rust_wrong_msg);
      Alcotest.(check bool)
        "verify pk0 wrong_msg sig0 is false" false
        (verify_decoded (fixture_pk "pk0_hex") rust_wrong_msg
           (fixture_sig "sig0_hex")))

let wrong_key_case =
  Alcotest.test_case "wrong key rejected" `Quick (fun () ->
      Alcotest.(check bool)
        "control: the fixture pk1 decodes through Public_key.of_bytes" true
        (Option.is_some (fixture_pk "pk1_hex"));
      Alcotest.(check bool)
        "verify pk1 msg sig0 is false" false
        (verify_decoded (fixture_pk "pk1_hex") rust_msg
           (fixture_sig "sig0_hex")))

(* Flip the compressed-encoding sign bit (byte 0, bit 0x20) in HEX space:
   bit 5 of byte 0 is bit 1 of the LEADING hex nibble, so the leading hex
   char maps through the nibble alphabet at [n lxor 2]. The result encodes
   the NEGATED point — still on-curve, still in-subgroup — so it decodes
   to [Some] (the control below pins that) and genuinely reaches [verify],
   where the pairing must reject it. Total end to end: [hex_nibble]
   returns an option, the alphabet lookup is [List.nth_opt] over 16
   elements with an index that stays 0..15 under [lxor 2], and the string
   is rebuilt by sequence conversion, no partial accessor anywhere. *)
let hex_alphabet = List.of_seq (String.to_seq "0123456789abcdef")

let flip_sign_bit_hex hex =
  match List.of_seq (String.to_seq hex) with
  | [] -> None
  | c0 :: rest ->
      Option.map
        (fun c0' -> String.of_seq (List.to_seq (c0' :: rest)))
        (Option.bind (hex_nibble c0) (fun n ->
             List.nth_opt hex_alphabet (n lxor 2)))

let flipped_sig_case =
  Alcotest.test_case "sign-bit-flipped sig rejected" `Quick (fun () ->
      let flipped_sig =
        Option.bind
          (Option.bind
             (flip_sign_bit_hex (rust_lookup "sig0_hex"))
             hex_decode)
          Tn_crypto.Signature.of_bytes
      in
      Alcotest.(check bool)
        "control: the flipped encoding decodes (negated point reaches verify)"
        true
        (Option.is_some flipped_sig);
      Alcotest.(check bool)
        "verify pk0 msg (sign-flipped sig0) is false" false
        (verify_decoded (fixture_pk "pk0_hex") rust_msg flipped_sig))

(* Gate (c), design section 9 S5: the [Tn_crypto] wrapping itself is
   non-corrupting for a derived key. *)
let sign_roundtrip_case =
  Alcotest.test_case "sign/verify round-trip (derive 0L)" `Quick (fun () ->
      let sk = Tn_crypto.Secret_key.derive 0L in
      Alcotest.(check bool)
        "verify (public_key sk) msg (sign sk msg)" true
        (Tn_crypto.verify
           (Tn_crypto.Secret_key.public_key sk)
           rust_msg
           (Tn_crypto.sign sk rust_msg)))

(* [Signature.equal] discriminates: BLS signing is deterministic, so two
   signs of one message agree and different messages disagree. *)
let sign_deterministic_case =
  Alcotest.test_case "sign deterministic (Signature.equal)" `Quick (fun () ->
      let sk = Tn_crypto.Secret_key.derive 1L in
      Alcotest.(check bool)
        "Signature.equal on two signs of the same message" true
        (Tn_crypto.Signature.equal
           (Tn_crypto.sign sk rust_msg)
           (Tn_crypto.sign sk rust_msg));
      Alcotest.(check bool)
        "Signature.equal across different messages" false
        (Tn_crypto.Signature.equal
           (Tn_crypto.sign sk rust_msg)
           (Tn_crypto.sign sk rust_wrong_msg)))

(* Subgroup-invalid adversarial vectors, copied VERBATIM from the opam
   bls12-381-signature 1.0.0 package's own shipped test suite:
   /Users/oobi/Documents/telcoin-ocaml-chunk39-harness/src-bls-sig/test/
   test_signature.ml:1054-1061 ([let signature_not_in_subgroup], MinSig
   section) — six compressed 48-byte G1 points that are on-curve but NOT
   in the prime subgroup (upstream generated them by removing the cofactor
   multiplication and cross-checked against the bls_sigs_ref Python
   reference). [Signature.of_bytes] must reject every one, so a
   non-subgroup point can never even reach [verify] (design notes
   section 9 S5 M5.2, exercised here as a standing gate). *)
let signature_not_in_subgroup =
  [ "a4c9678ad327129f4388e7f7ff781fc8e98d181add820b79d15facdca422b3ee7fb20f7082a7f9b7c7915053191cb013";
    "97ae9b4dc6a05cda8bc833dfb983e41423d224bbf6954ce4721a50364a2b37643e18a276ce19b07b83a333f90e2de6c2";
    "b1be8c9f94c1435227b9a18fb57a6d9932c1670d16c514d2d9d67839cc0cc19afdcd114d6e06bf8eb8394061bf880bd4";
    "b173357ce7e2340dc64c6a5633e6800683fb0a6c0f4af92b383425bd76d915819252ac9459e79a1bae530ea0145338cb";
    "a53944773013669c2722949399322703c0b92d877e52b95e0309bdf286d8290314763d61952d6812da50c1826bcaf4c3";
    "8fd2557441f4076917ffe8dfb0e12270994351661600e72f48fe654198199f6cc625a041ce3c9b7c765b32cb53e77192"
  ]

let subgroup_sig_case i entry_hex =
  Alcotest.test_case
    (Printf.sprintf "non-subgroup sig %d rejected" i)
    `Quick
    (fun () ->
      let decoded = hex_decode entry_hex in
      Alcotest.(check (option int))
        "control: the upstream vector decodes to 48 raw bytes" (Some 48)
        (Option.map String.length decoded);
      Alcotest.(check bool)
        "Signature.of_bytes on a non-subgroup G1 point is None" true
        (Option.is_none (Option.bind decoded Tn_crypto.Signature.of_bytes)))

(* ------------------------------------------------------------------ *)
(* Stage S6: [aggregate] / [verify_aggregate] (shared pairing core,   *)
(* general N).                                                         *)
(* ------------------------------------------------------------------ *)

(* Decode a fixture entry through the [Aggregate] codec; [None] on a
   missing fixture or a rejected encoding, fail-closed. Unlike
   [fixture_sig] this is the codec [verify_aggregate] consumes, and it
   admits the infinity encoding (needed by the narrow guard case). *)
let fixture_agg key =
  Option.bind (hex_decode (rust_lookup key)) Tn_crypto.Aggregate.of_bytes

(* Total all-or-nothing sequencing: [Some] exactly when EVERY entry is
   [Some], preserving the original order; fail-closed on any missing
   fixture or rejected encoding. *)
let sequence_opt opts =
  Option.map List.rev
    (List.fold_left
       (fun acc opt ->
         Option.bind acc (fun tl -> Option.map (fun hd -> hd :: tl) opt))
       (Some []) opts)

let fixture_sigs012 =
  sequence_opt
    [ fixture_sig "sig0_hex"; fixture_sig "sig1_hex"; fixture_sig "sig2_hex" ]

let fixture_pks012 =
  sequence_opt
    [ fixture_pk "pk0_hex"; fixture_pk "pk1_hex"; fixture_pk "pk2_hex" ]

(* Run [verify_aggregate] under decoded operands; [false] when anything
   failed to decode, fail-closed. Vacuity of the [false]-expecting
   negatives is excluded by [verify_agg012_case]'s [true] expectation on
   the same decodes plus the per-case decode controls below. *)
let verify_aggregate_decoded pks_opt msg agg_opt =
  Option.value ~default:false
    (Option.bind pks_opt (fun pks ->
         Option.map (Tn_crypto.verify_aggregate pks msg) agg_opt))

(* Gate 1, design section 9 S6: point-sum aggregation over the three
   fixture signatures reproduces Rust's agg012 bytes exactly (real Rust
   bytes end to end). Fail-closed on a missing fixture: the sentinel does
   not hex-decode, so the actual side collapses to [None]. *)
let agg012_bytes_case =
  Alcotest.test_case "aggregate [sig0;sig1;sig2] = rust agg012_hex" `Quick
    (fun () ->
      Alcotest.(check (option string))
        "aggregate over the three fixture signatures, in hex"
        (Some (rust_lookup "agg012_hex"))
        (Option.map
           (fun sigs ->
             hex_encode
               (Tn_crypto.Aggregate.to_bytes (Tn_crypto.aggregate sigs)))
           fixture_sigs012))

(* G1 addition is commutative and associative, so aggregation must be
   order-irrelevant: the reversed signature list yields byte-identical
   output (design section 9 S6's [List.rev] gate). *)
let agg_rev_case =
  Alcotest.test_case "aggregate order-irrelevant (List.rev)" `Quick
    (fun () ->
      Alcotest.(check (option string))
        "aggregate over the REVERSED fixture signatures, in hex"
        (Some (rust_lookup "agg012_hex"))
        (Option.map
           (fun sigs ->
             hex_encode
               (Tn_crypto.Aggregate.to_bytes
                  (Tn_crypto.aggregate (List.rev sigs))))
           fixture_sigs012))

(* Gate 2: the hand-rolled pairing core at N=3 accepts the REAL
   Rust-produced pk0/pk1/pk2 + agg012 bytes end to end — the aggregate
   sibling of [verify_sig0_case], and the non-vacuity anchor for every
   [false]-expecting case that shares these decodes. *)
let verify_agg012_case =
  Alcotest.test_case "verify_aggregate pks012 msg agg012 (rust bytes)"
    `Quick
    (fun () ->
      Alcotest.(check bool)
        "verify_aggregate over the fixture pk0/pk1/pk2 and agg012" true
        (verify_aggregate_decoded fixture_pks012 rust_msg
           (fixture_agg "agg012_hex")))

(* The pairing terms are a product, so signer order cannot matter:
   the reversed pk list verifies the same aggregate. *)
let verify_agg_rev_case =
  Alcotest.test_case "verify_aggregate order-irrelevant (List.rev)" `Quick
    (fun () ->
      Alcotest.(check bool)
        "verify_aggregate over the REVERSED pks and agg012" true
        (verify_aggregate_decoded
           (Option.map List.rev fixture_pks012)
           rust_msg (fixture_agg "agg012_hex")))

(* Empty-signer GENERAL case (design notes section 4): against an honest
   non-infinity aggregate, [pks = []] is independently false by the
   pairing math — e(agg, g2) = 1 fails for any non-identity point — so
   this case stays false with or without the guard. The control excludes
   a vacuous pass through a failed decode. *)
let empty_pks_general_case =
  Alcotest.test_case "empty pks vs honest agg012 rejected" `Quick (fun () ->
      Alcotest.(check bool)
        "control: the fixture agg012 decodes through Aggregate.of_bytes"
        true
        (Option.is_some (fixture_agg "agg012_hex"));
      Alcotest.(check bool)
        "verify_aggregate [] msg agg012 is false" false
        (verify_aggregate_decoded (Some []) rust_msg
           (fixture_agg "agg012_hex")))

(* Empty-signer NARROW case: the one input the [[] -> false] guard is
   load-bearing for (design notes section 4). Without the guard,
   [pks = []] collapses to the single fixed term — e(agg, g2) = 1 —
   which the infinity-encoded aggregate satisfies. [Aggregate.of_bytes]
   deliberately admits the infinity encoding (blst's signature-side
   asymmetry), so the control proves this adversarial input genuinely
   reaches the guard rather than dying at the codec. *)
let empty_pks_infinity_case =
  Alcotest.test_case "empty pks vs infinity aggregate rejected" `Quick
    (fun () ->
      Alcotest.(check bool)
        "control: infinity_sig_hex decodes through Aggregate.of_bytes" true
        (Option.is_some (fixture_agg "infinity_sig_hex"));
      Alcotest.(check bool)
        "verify_aggregate [] msg infinity is false" false
        (verify_aggregate_decoded (Some []) rust_msg
           (fixture_agg "infinity_sig_hex")))

(* Duplicate-pk pair NEGATIVE (design notes section 4): [pk0; pk0]
   against the SINGLE sig0 requires e(h,pk0)^2 = e(sig0,g2) = e(h,pk0),
   false unless sk0 = 0 — a Set-deduplicating implementation would
   wrongly accept it (T28 is closed by omission, and this case is what
   detects any dedup creeping in). *)
let dup_pk_single_sig_case =
  Alcotest.test_case "duplicate pks vs single sig0 rejected" `Quick
    (fun () ->
      Alcotest.(check bool)
        "control: sig0 decodes through Aggregate.of_bytes" true
        (Option.is_some (fixture_agg "sig0_hex"));
      Alcotest.(check bool)
        "verify_aggregate [pk0;pk0] msg sig0 is false" false
        (verify_aggregate_decoded
           (sequence_opt [ fixture_pk "pk0_hex"; fixture_pk "pk0_hex" ])
           rust_msg (fixture_agg "sig0_hex")))

(* Duplicate-pk pair POSITIVE: [pk0; pk0] against 2·sig0 is the honest
   equation e(h,pk0)^2 = e(2·sig0, g2), so it must ACCEPT. The control
   pins the doubled fixture itself: aggregating [sig0; sig0] reproduces
   Rust's sig0_doubled bytes, so the accepting input is real Rust bytes
   end to end here too. *)
let dup_pk_doubled_sig_case =
  Alcotest.test_case "duplicate pks vs doubled sig0 accepted" `Quick
    (fun () ->
      Alcotest.(check (option string))
        "control: aggregate [sig0;sig0] = rust sig0_doubled_hex"
        (Some (rust_lookup "sig0_doubled_hex"))
        (Option.map
           (fun s ->
             hex_encode
               (Tn_crypto.Aggregate.to_bytes (Tn_crypto.aggregate [ s; s ])))
           (fixture_sig "sig0_hex"));
      Alcotest.(check bool)
        "verify_aggregate [pk0;pk0] msg sig0_doubled is true" true
        (verify_aggregate_decoded
           (sequence_opt [ fixture_pk "pk0_hex"; fixture_pk "pk0_hex" ])
           rust_msg (fixture_agg "sig0_doubled_hex")))

(* Subgroup-invalid adversarial G2 vectors, copied VERBATIM from the opam
   bls12-381-signature 1.0.0 package's own shipped test suite:
   /Users/oobi/Documents/telcoin-ocaml-chunk39-harness/src-bls-sig/test/
   test_signature.ml:1066-1075 ([let pk_not_in_subgroup], MinSig
   section) — eight compressed 96-byte G2 points that are on-curve but
   NOT in the prime subgroup. [Public_key.of_bytes] must reject every
   one (design notes section 9 S6): the G2 sibling of the S5 signature
   gate above, closing the aggregate path's other codec entrance. *)
let pk_not_in_subgroup =
  [ "a7da246233ad216e60ee03070a0916154ae9f9dc23310c1191dfb4e277fc757f58a5cf5bdf7a9f322775143c37539cb90798205fd56217b682d5656f7ac7bc0da111dee59d3f863f1b040be659eda7941afb9f1bc5d0fe2beb5e2385e2cfe9ee";
    "b112717bbcd089ea99e8216eab455ea5cd462b0b3e3530303b83477f8e1bb7abca269fec10b3eb998f7f6fd1799d58ff11ed0a53bf75f91d2bf73d11bd52d061f401ac6a6ec0ef4a163e480bac85e75b97cb556f500057b9ef4b28bfe196791d";
    "86e5fa411047d9632c95747bea64d973757904c935ac0741b9eeefa2c7c4e439baf1d2c1e8633ba6c884ed9fdf1ffbdd129a32c046f355c5126254973115d6df32904498db6ca959d5bf1869f235be4c0e60fc334ed493f864476907cadfef2c";
    "88c83e90520a5ea31733cc01e3589e10b2ed755e2faade29199f97645fbf73f52b29297c22a3b1c4fcd3379bceeec832091df6fb3b9d23f04e8267fc41e578002484155562e70f488c2a4c6b11522c66736bc977755c257478f3022656abb630";
    "a25099811f52ad463c762197466c476a03951afdb3f0a457efa2b9475376652fba7b2d56f3184dad540a234d471c53a113203f73dd661694586c75d9c418d34cd16504356253e3ba4618f61cbee02880a43efeacb8f9fe1fdc84ceec4f780ba2";
    "990f5e1d200d1b9ab842c516ce50992730917a8b2e95ee1a4b830d7d9507c6846ace7a0eed8831a8d1f1e233cd24581215fe8fe85a99f4ca3fe046dba8ac6377fc3c10d73fa94b25c2d534d7a587a507b498754a2534cd85777b2a7f2978eec6";
    "a29415562a1d18b11ec8ab2e0b347a9417f9e904cf25f9b1dc40f235507814371fb4568cc1070a0b8c7baf39e0039d1e0b49d4352b095883ccc262e23d8651c49c39c06d0a920d40b2765d550a78c4c1940c8a2b6843a0063402c169f079f0ae";
    "8a257ed6d95cb226c3eb57218bd075ba27164fc1b972c4230ee70c7b81c89d38253ccf7ed2896aa5eb3d9fd6021fac000e368080e705f2a65c919539e2d28e6dd1117296b4210fd56db8d96891f8586bd333e9c47f838ed436659a1dafaee16c"
  ]

let subgroup_pk_case i entry_hex =
  Alcotest.test_case
    (Printf.sprintf "non-subgroup pk %d rejected" i)
    `Quick
    (fun () ->
      let decoded = hex_decode entry_hex in
      Alcotest.(check (option int))
        "control: the upstream vector decodes to 96 raw bytes" (Some 96)
        (Option.map String.length decoded);
      Alcotest.(check bool)
        "Public_key.of_bytes on a non-subgroup G2 point is None" true
        (Option.is_none (Option.bind decoded Tn_crypto.Public_key.of_bytes)))

(* Signature-side infinity asymmetry, exercised at the SIGNATURE codec —
   the only other route for the 0xc0 encoding is [Aggregate.of_bytes]
   ([empty_pks_infinity_case]): [Signature.of_bytes] deliberately admits
   the infinity encoding, matching blst and Rust's
   [BlsSignature::default()] bytes (ground truth F6/F49), and the pairing
   core is what rejects it against any real key. A future "consistency
   fix" adding a [Public_key]-style is_zero filter here would break those
   default bytes at this boundary while every other case stayed green;
   this case is what detects it. *)
let infinity_sig_decode_case =
  Alcotest.test_case "Signature.of_bytes admits infinity; verify rejects it"
    `Quick (fun () ->
      Alcotest.(check bool)
        "control: infinity_sig_hex decodes through Signature.of_bytes" true
        (Option.is_some (fixture_sig "infinity_sig_hex"));
      Alcotest.(check (option bool))
        "verify pk0 msg infinity_sig is Some false" (Some false)
        (Option.bind (fixture_pk "pk0_hex") (fun pk ->
             Option.map
               (fun s -> Tn_crypto.verify pk rust_msg s)
               (fixture_sig "infinity_sig_hex"))))

(* ------------------------------------------------------------------ *)
(* Chunk 41 S1: the Batch golden vectors' blake3 column, now LIVE.    *)
(* ------------------------------------------------------------------ *)

(* [Tn_types.Batch.digest] is the BARE seam hash of the BCS pre-image, with no
   domain tag (batch.ml). test_batch.ml T1 pins the pre-image against the Rust
   oracle and T7 pins that formula seam-independently under the stub; here the
   seam IS blake3 1.8.3, so hashing the oracle's own pre-image row must
   reproduce the oracle's blake3 row. The three greens together are the
   byte-compat claim for [Batch_digest], and this executable needs no
   [tn_types] dependency to make it. *)
let batch_vector_case name preimage_hex blake3_hex =
  Alcotest.test_case (Printf.sprintf "batch %s" name) `Quick (fun () ->
      Alcotest.(check (option string))
        "blake3 of the oracle pre-image against the oracle digest row"
        (Some blake3_hex)
        (Option.map
           (fun bytes -> Tn_crypto.Digest.to_hex (Tn_crypto.Digest.hash bytes))
           (hex_decode preimage_hex)))

(* The negative control for the S1 tag removal. The retired formula,
   [hash ("tn:batch" ^ preimage)], must NOT reproduce the oracle row: without
   this the positive rows above would stay green if a tag came back and the
   vectors were re-pinned to it. [Some false] is the expectation, not [false],
   so a pre-image row that fails to decode is red rather than vacuously green. *)
let batch_retired_tag_case =
  Alcotest.test_case "the retired tn:batch tag does not reproduce V1" `Quick
    (fun () ->
      Alcotest.(check (option bool))
        "hash of \"tn:batch\" ^ V1 pre-image equals the oracle V1 row"
        (Some false)
        (Option.map
           (fun bytes ->
             String.equal Batch_vectors.v1_blake3
               (Tn_crypto.Digest.to_hex
                  (Tn_crypto.Digest.hash ("tn:batch" ^ bytes))))
           (hex_decode Batch_vectors.v1_preimage)))

(* ------------------------------------------------------------------ *)
(* Stage S8: the shared impl-agnostic conformance functor.            *)
(* ------------------------------------------------------------------ *)

(* The same [Crypto_conformance.Make] is instantiated against the stub
   default in test/crypto_stub_conformance; here [Tn_crypto] is the real
   implementation because this executable's dune stanza names
   telcoin_ocaml.crypto_blst. Green in both executables is the
   behavioral-parity claim for the seam's observable contract. *)
module Conformance = Crypto_conformance.Make (Tn_crypto)

(* ------------------------------------------------------------------ *)
(* Chunk 41 S4: the digest columns of header_vectors.ml,              *)
(* sealed_batch_vectors.ml, sub_dag_vectors.ml and                    *)
(* consensus_block_vectors.ml. Every other executable's seam is       *)
(* BLAKE2s, so these columns are UNASSERTED everywhere but here.      *)
(* ------------------------------------------------------------------ *)

module HV = Header_vectors
module SBV = Sealed_batch_vectors
module SDV = Sub_dag_vectors
module CBV = Consensus_block_vectors
module OH = Oracle_headers
module Sd = Tn_consensus.Sub_dag
module Rs = Tn_consensus.Reputation_scores
module Cb = Tn_execution.Consensus_block
module Digests = Tn_types.Digests

(* A hash of pinned bytes against a pinned digest, the same shape as
   {!batch_vector_case}. Used wherever there is no port VALUE to hash
   (the two malformed header rows, which {!Tn_vertex.Header.codec} refuses
   to decode by design, and the two retired-formula NEG rows), so what is
   asserted is the digest FORMULA over the oracle's own bytes, never this
   port's own decoder. *)
let hash_case name preimage_hex digest_hex =
  Alcotest.test_case name `Quick (fun () ->
      Alcotest.(check (option string))
        "blake3 of the oracle bytes against the oracle digest row"
        (Some digest_hex)
        (Option.map
           (fun bytes -> Tn_crypto.Digest.to_hex (Tn_crypto.Digest.hash bytes))
           (hex_decode preimage_hex)))

(* H1-H6: the header this port BUILDS from {!Oracle_headers} (not the
   oracle's bytes) must digest to the oracle's row -- construction, codec
   and hash all agreeing with Rust, not merely that hashing known-good bytes
   reproduces a known-good digest. *)
let header_digest_case name header expected =
  Alcotest.test_case name `Quick (fun () ->
      Alcotest.(check string) "Header.digest = the oracle's row" expected
        (Digests.Header_digest.to_hex (Tn_vertex.Header.digest header)))

let header_digest_cases =
  [ header_digest_case "H1" (OH.h1 ()) HV.h1_digest;
    header_digest_case "H2" (OH.h2 ()) HV.h2_digest;
    header_digest_case "H3" (OH.h3 ()) HV.h3_digest;
    header_digest_case "H4" (OH.h4 ()) HV.h4_digest;
    header_digest_case "H5" (OH.h5 ()) HV.h5_digest;
    header_digest_case "H6 (= H4, descending parents canonicalise)" (OH.h6 ())
      HV.h6_digest ]

(* MUT-CONTROL: H4 with author[31] flipped 0x01 -> 0x02, built the same way
   H4 is rather than by mutating bytes, so this exercises the port's OWN
   field wiring rather than a copy-pasted pre-image. *)
let mut_control_header () =
  Tn_vertex.Header.make
    ~author:(OH.author_of "MUT_CONTROL author" HV.mut_control_author)
    ~round:(OH.round_of "MUT_CONTROL round" 1)
    ~epoch:(OH.epoch_of "MUT_CONTROL epoch" 7)
    ~created_at:(OH.created_of "MUT_CONTROL created_at" 1_700_000_000L)
    ~payload:(OH.h4_payload ()) ~parents:(OH.h4_parents ())
    ~latest_execution_block:
      (OH.anchor "MUT_CONTROL anchor" ~number:0L ~hash:OH.zeros32)

let mut_control_case =
  header_digest_case "MUT_CONTROL: H4 with author[31] flipped"
    (mut_control_header ()) HV.mut_control_digest

(* H_NEG_A/H_NEG_B are the pre-fix, bare-digest shapes: not headers this port
   can build or decode, so the FORMULA is pinned by hashing the oracle's own
   malformed bytes. *)
let header_neg_cases =
  [ hash_case "H_NEG_A: bare payload/parent digests" HV.h_neg_a_bcs
      HV.h_neg_a_digest;
    hash_case "H_NEG_B: latest_execution_block omitted" HV.h_neg_b_bcs
      HV.h_neg_b_digest ]

(* H_DUP: the attacker's wire repeats one payload key. Rust collapses it on
   decode and digests the collapsed header, so the digest this port reaches
   from the SAME bytes must be the oracle's H_DUP row. This is the case that
   would go red if the port kept the repeat, which is why it decodes the wire
   rather than hashing a pinned pre-image. *)
let header_dup_case =
  Alcotest.test_case
    "H_DUP: repeated payload key digests as Rust's collapsed map" `Quick
    (fun () ->
      let digest_of_wire =
        hex_decode HV.h_dup_wire_bcs
        |> Option.to_result ~none:"H_DUP hex is malformed"
        |> Result.map (Tn_codec.Bcs.decode Tn_vertex.Header.codec)
        |> Result.map (Result.map_error Tn_codec.Bcs.error_to_string)
        |> Result.join
        |> Result.map (fun h ->
               Digests.Header_digest.to_hex (Tn_vertex.Header.digest h))
      in
      Alcotest.(check (result string string))
        "Header.digest of the decoded wire = the oracle's row"
        (Ok HV.h_dup_digest) digest_of_wire)

(* SB1-SB3: {!Tn_types.Batch.Sealed.claim} pairs an unverified digest, so the
   claim worth checking is not the type but the FORMULA -- that hashing the
   batch pre-image really does reproduce the digest the wire row claims. *)
let sealed_batch_digest_cases =
  [ hash_case "SB1 (= Batch V1)" SBV.sb1_batch_preimage SBV.sb1_digest;
    hash_case "SB2 (= Batch V4)" SBV.sb2_batch_preimage SBV.sb2_digest;
    hash_case "SB3 (= Batch V7)" SBV.sb3_batch_preimage SBV.sb3_digest ]

(* Sub-DAG rows, built exactly as test_byte_compat.ml's sd1/sd2/sd3, so the
   PRE-IMAGE and DIGEST columns activated here are over the identical values
   whose CODEC and STRUCTURE columns are already pinned there. *)
let scores_of bindings ~final =
  Rs.of_persisted
    ~bindings:
      (List.map (fun (id, s) -> (OH.author_of "score authority" id, s)) bindings)
    ~final

let stored_of secs = OH.force "stored timestamp" (Tn_types.Units.Timestamp.of_sec secs)

let sd1 () =
  Sd.of_persisted
    ~headers:(OH.force "SD1 sequence" (Tn_std.Nonempty.of_list [ OH.h1 () ]))
    ~scores:(scores_of [] ~final:false)
    ~stored:Tn_types.Units.Timestamp.zero
    ~randomness:(OH.hash32_of "SD1 randomness" OH.zeros32)

let sd2_scores () =
  scores_of [ (OH.repeat32 "01", 5); (OH.repeat32 "02", 9) ] ~final:true

let sd2 () =
  Sd.of_persisted
    ~headers:
      (OH.force "SD2 sequence"
         (Tn_std.Nonempty.of_list [ OH.h2 (); OH.h4 (); OH.h5 () ]))
    ~scores:(sd2_scores ())
    ~stored:(stored_of 1_700_000_001L)
    ~randomness:(OH.hash32_of "SD2 randomness" SDV.sd_rand1_keccak256)

let sd3 () =
  Sd.of_persisted
    ~headers:
      (OH.force "SD3 sequence"
         (Tn_std.Nonempty.of_list [ OH.h2 (); OH.h4 (); OH.h5 () ]))
    ~scores:
      (scores_of [ (OH.repeat32 "01", 5); (OH.repeat32 "02", 9) ] ~final:false)
    ~stored:Tn_types.Units.Timestamp.zero
    ~randomness:(OH.hash32_of "SD3 randomness" SDV.sd_rand1_keccak256)

let sub_dag_preimage_and_digest_case name sd preimage_hex digest_hex =
  Alcotest.test_case name `Quick (fun () ->
      Alcotest.(check string) "preimage = the oracle's bytes" preimage_hex
        (Hex_bytes.encode (Sd.preimage sd));
      Alcotest.(check string) "digest = the oracle's row" digest_hex
        (Digests.Sub_dag_digest.to_hex (Sd.digest sd)))

let sub_dag_digest_cases =
  [ sub_dag_preimage_and_digest_case "SD1" (sd1 ()) SDV.sd1_preimage
      SDV.sd1_digest;
    sub_dag_preimage_and_digest_case "SD2" (sd2 ()) SDV.sd2_preimage
      SDV.sd2_digest;
    sub_dag_preimage_and_digest_case "SD3" (sd3 ()) SDV.sd3_preimage
      SDV.sd3_digest ]

(* SD-NEG: the retired "tn:subdag" domain tag must reproduce the oracle's
   OWN tagged row, not merely differ from SD2's real digest -- the stronger
   claim, since a wrong tag could differ from SD2 for the wrong reason. *)
let sub_dag_neg_domain_tag_case =
  Alcotest.test_case "SD-NEG: the retired tn:subdag tag reproduces the row"
    `Quick (fun () ->
      let pre = Sd.preimage (sd2 ()) in
      Alcotest.(check string) "hash(tag ^ preimage) = the oracle's SD_NEG row"
        SDV.sd_neg_digest
        (Tn_crypto.Digest.to_hex
           (Tn_crypto.Digest.hash (SDV.sd_neg_domain_tag ^ pre)));
      Alcotest.(check bool) "and it differs from SD2's real digest" false
        (String.equal SDV.sd_neg_digest SDV.sd2_digest))

(* Consensus-block rows, built exactly as test_byte_compat.ml's cb1/cb2/cb3. *)
let output_digest label h = Digests.Output_digest.of_digest (OH.crypto_digest label h)
let number_of n = OH.force "block number" (Cb.Number.of_int n)

let cb1 () =
  Cb.of_persisted
    ~parent_hash:(output_digest "CB1 parent" CBV.cb1_parent_hash)
    ~sub_dag:(sd1 ()) ~number:Cb.Number.genesis
    ~extra:(OH.hash32_of "CB1 extra" CBV.cb1_extra)

let cb2 () =
  Cb.of_persisted
    ~parent_hash:(output_digest "CB2 parent" CBV.cb2_parent_hash)
    ~sub_dag:(sd2 ()) ~number:(number_of 1)
    ~extra:(OH.hash32_of "CB2 extra" CBV.cb2_extra)

let cb3 () =
  Cb.of_persisted
    ~parent_hash:(output_digest "CB3 parent" CBV.cb2_parent_hash)
    ~sub_dag:(sd2 ()) ~number:(number_of 1)
    ~extra:(OH.hash32_of "CB3 extra" CBV.cb3_extra)

let cb_digest_case name cb expected =
  Alcotest.test_case name `Quick (fun () ->
      Alcotest.(check string) "Consensus_block.digest = the oracle's row"
        expected
        (Digests.Output_digest.to_hex (Cb.digest cb)))

let consensus_block_digest_cases =
  [ cb_digest_case "CB1" (cb1 ()) CBV.cb1_digest;
    cb_digest_case "CB2" (cb2 ()) CBV.cb2_digest;
    cb_digest_case "CB3 (= CB2, extra off the digest)" (cb3 ()) CBV.cb3_digest
  ]

(* Drop the trailing [n] characters of [s] by filtering the indexed
   sequence, so no partial accessor is involved. *)
let drop_suffix s ~n =
  String.to_seqi s
  |> Seq.filter (fun (i, (_ : char)) -> i < String.length s - n)
  |> Seq.map snd |> String.of_seq

(* CB-NEG: CB2's digest over a THREE-field pre-image, the trailing 32
   zero bytes (the [extra] slot) dropped. *)
let consensus_block_neg_case =
  Alcotest.test_case "CB-NEG: three-field pre-image (no trailing zero extra)"
    `Quick (fun () ->
      let three_field = drop_suffix (Cb.preimage (cb2 ())) ~n:32 in
      Alcotest.(check string)
        "hash(three-field pre-image) = the oracle's CB_NEG row"
        CBV.cb_neg_digest
        (Tn_crypto.Digest.to_hex (Tn_crypto.Digest.hash three_field)))

(* CB-GENESIS: the chain anchor, computed rather than pinned (spec risk 5).
   The default sub-DAG shares SD1's single default header but NOT its
   randomness, so its own digest is checked first to rule out the anchor
   accidentally landing on SD1's value. *)
let default_sub_dag () =
  Sd.of_persisted
    ~headers:(OH.force "genesis sequence" (Tn_std.Nonempty.of_list [ OH.h1 () ]))
    ~scores:(scores_of [] ~final:false)
    ~stored:Tn_types.Units.Timestamp.zero ~randomness:Sd.default_randomness

let cb_genesis_case =
  Alcotest.test_case
    "CB-GENESIS: genesis_parent = ConsensusHeader::default().digest()" `Quick
    (fun () ->
      Alcotest.(check string) "the default sub-DAG's digest = the oracle's row"
        CBV.cb_genesis_sub_dag_digest
        (Digests.Sub_dag_digest.to_hex (Sd.digest (default_sub_dag ())));
      Alcotest.(check bool) "the genesis sub-DAG differs from SD1" false
        (Digests.Sub_dag_digest.equal (Sd.digest (default_sub_dag ()))
           (Sd.digest (sd1 ())));
      Alcotest.(check string) "genesis_parent = the oracle's row"
        CBV.cb_genesis_digest
        (Digests.Output_digest.to_hex Cb.genesis_parent))

let () =
  Alcotest.run "tn_crypto_blst"
    [ ("blake3", count_case :: List.map vector_case vectors);
      ( "digest",
        [ rust_count_case; rust_msg_hex_case; rust_digest_case;
          zero_not_hash_empty_case;
          of_bytes_case 31 None;
          of_bytes_case 32 (Some (String.make 32 '\x2a'));
          of_bytes_case 33 None ] );
      ( "keys",
        [ pk0_roundtrip_case; infinity_pk_case;
          pk_width_case 95; pk_width_case 97;
          derive_pin_case "0L" 0L
            "b3db07e8ed307ca4faecb6c6c722dffec30a65349f1d3bb5119f6c87be073a1e361acac12dbbb2530d2d12439745b84e07c9ecbd8b38d66134407fdf8a53ba4c1066fcd2c2b9ad906a7a25e2088c969333431a87bdd1a45c84786565cb377ec8";
          derive_pin_case "1L" 1L
            "b9dc04c4bc51f4e2ac198b8bbb52c742477dab7fc7891387902724cc44c9ad4b0794b6c7ad22502ade7a05a899d91de10bedd1ae1afa2a8c9374e8ee82880cda047f775e83c2613f323e7c7a6332914fc0925ef3a3e08b2f527af67cf249f72e";
          derive_pin_case "-1L" (-1L)
            "af02b91def35d985759a56db967ed77764e699b635972de14558ac041b1214d9c839bc7fa7a6052abb85d48b6c8c34391734503fc34430f8e28f86e562671c2306c4ec9dd9324cb2be72919f3ae97fe22210c85fb019340bb4fab292d84a4c8a" ] );
      ( "sign_verify",
        [ raw_sign_case; sig0_roundtrip_case; verify_sig0_case;
          wrong_msg_case; wrong_key_case; flipped_sig_case;
          infinity_sig_decode_case;
          sign_roundtrip_case; sign_deterministic_case ] );
      ( "subgroup",
        List.mapi subgroup_sig_case signature_not_in_subgroup
        @ List.mapi subgroup_pk_case pk_not_in_subgroup );
      ( "aggregate",
        [ agg012_bytes_case; agg_rev_case; verify_agg012_case;
          verify_agg_rev_case; empty_pks_general_case;
          empty_pks_infinity_case; dup_pk_single_sig_case;
          dup_pk_doubled_sig_case ] );
      ( "batch_vectors",
        [ batch_vector_case "V1" Batch_vectors.v1_preimage
            Batch_vectors.v1_blake3;
          batch_vector_case "V2" Batch_vectors.v2_preimage
            Batch_vectors.v2_blake3;
          batch_vector_case "V3" Batch_vectors.v3_preimage
            Batch_vectors.v3_blake3;
          batch_vector_case "V4" Batch_vectors.v4_preimage
            Batch_vectors.v4_blake3;
          batch_vector_case "V5" Batch_vectors.v5_preimage
            Batch_vectors.v5_blake3;
          batch_vector_case "V6 (serde-skip proof, V5's row)"
            Batch_vectors.v6_preimage Batch_vectors.v6_blake3;
          batch_vector_case "V7" Batch_vectors.v7_preimage
            Batch_vectors.v7_blake3;
          batch_retired_tag_case ] );
      ("conformance", Conformance.tests);
      ( "chunk41 header digests",
        header_digest_cases
        @ [ mut_control_case; header_dup_case ]
        @ header_neg_cases );
      ("chunk41 sealed batch digests", sealed_batch_digest_cases);
      ( "chunk41 sub-DAG digests",
        sub_dag_digest_cases @ [ sub_dag_neg_domain_tag_case ] );
      ( "chunk41 consensus-block digests",
        consensus_block_digest_cases
        @ [ consensus_block_neg_case; cb_genesis_case ] ) ]
