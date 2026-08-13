(* Byte-level conformance for the BCS codec.

   The expected byte strings are the canonical outputs documented for the Rust
   [bcs] crate and the upstream BCS specification, so a green run here is
   evidence of wire compatibility, not merely of round-trip self-consistency.

   This is a plain executable that exits non-zero on the first failure, so it
   is runnable with `dune exec` and as a dune test without any test framework
   dependency. *)

let failures = ref 0

let hex s =
  String.concat ""
    (List.map (fun c -> Printf.sprintf "%02x" (Char.code c))
       (List.init (String.length s) (String.get s)))

let check name got expected =
  if got = expected then Printf.printf "ok   %s\n" name
  else begin
    incr failures;
    Printf.printf "FAIL %s\n     got      %s\n     expected %s\n" name
      (hex got) (hex expected)
  end

let check_decode name codec bytes expected =
  match Tn_codec.Bcs.decode codec bytes with
  | Ok v when v = expected -> Printf.printf "ok   %s\n" name
  | Ok _ ->
      incr failures;
      Printf.printf "FAIL %s: decoded to an unexpected value\n" name
  | Error e ->
      incr failures;
      Printf.printf "FAIL %s: %s\n" name (Tn_codec.Bcs.error_to_string e)

let check_reject name codec bytes =
  match Tn_codec.Bcs.decode codec bytes with
  | Error _ -> Printf.printf "ok   %s (rejected as expected)\n" name
  | Ok _ ->
      incr failures;
      Printf.printf "FAIL %s: accepted a non-canonical encoding\n" name

(* Rejection with the EXACT message, for the rows where "some error" would be
   vacuous: a length prefix the port merely fails to have bytes for is refused
   too, just at a different offset and for a different reason. *)
let check_error name codec bytes expected =
  Result.fold
    ~ok:(fun _ ->
      incr failures;
      Printf.printf "FAIL %s: accepted\n" name)
    ~error:(fun e ->
      let got = Tn_codec.Bcs.error_to_string e in
      if String.equal got expected then Printf.printf "ok   %s\n" name
      else begin
        incr failures;
        Printf.printf "FAIL %s\n     got      %s\n     expected %s\n" name got
          expected
      end)
    (Tn_codec.Bcs.decode codec bytes)

let b = Bytes.of_string
let s = Bytes.to_string

let () =
  let open Tn_codec.Bcs in
  (* Fixed-width little-endian integers. *)
  check "u8 0x01" (encode u8 1) "\x01";
  check "u16 0x0102" (encode u16 0x0102) "\x02\x01";
  check "u32 0x01020304" (encode u32 0x01020304) "\x04\x03\x02\x01";
  check "u64 1" (encode u64 1L) "\x01\x00\x00\x00\x00\x00\x00\x00";
  check "u64 max"
    (encode u64 (-1L))
    "\xff\xff\xff\xff\xff\xff\xff\xff";

  (* ULEB128 canonical vectors (from the BCS spec / bcs crate). *)
  check "uleb 0" (encode uleb128 0) "\x00";
  check "uleb 127" (encode uleb128 127) "\x7f";
  check "uleb 128" (encode uleb128 128) "\x80\x01";
  check "uleb 16384" (encode uleb128 16384) "\x80\x80\x01";
  check "uleb 0xffffffff" (encode uleb128 0xffffffff) "\xff\xff\xff\xff\x0f";

  (* bool. *)
  check "bool false" (encode bool false) "\x00";
  check "bool true" (encode bool true) "\x01";

  (* option. *)
  check "option none" (encode (option u8) None) "\x00";
  check "option some" (encode (option u8) (Some 5)) "\x01\x05";

  (* Length-prefixed bytes: "bcs" is 3 bytes. *)
  check "bytes \"bcs\"" (encode bytes "bcs") "\x03bcs";

  (* Lists carry a ULEB128 count then each element. *)
  check "list [1;2;3]" (encode (list u8) [ 1; 2; 3 ]) "\x03\x01\x02\x03";
  check "list empty" (encode (list u8) []) "\x00";

  (* A three-field struct encodes in declaration order with no tags:
     { round : u32; epoch : u32; author : bytes }. *)
  let hdr = triple u32 u32 bytes in
  check "struct in field order"
    (encode hdr (7, 2, "id"))
    "\x07\x00\x00\x00\x02\x00\x00\x00\x02id";

  (* Round-trip decode. *)
  check_decode "decode u64" u64 "\x01\x00\x00\x00\x00\x00\x00\x00" 1L;
  check_decode "decode struct" hdr "\x07\x00\x00\x00\x02\x00\x00\x00\x02id"
    (7, 2, "id");

  (* Non-canonical encodings must be rejected on decode. *)
  check_reject "reject overlong uleb (0x80 0x00)" uleb128 "\x80\x00";
  check_reject "reject trailing bytes" u8 "\x01\x02";
  check_reject "reject invalid bool" bool "\x02";
  check_reject "reject truncated u32" u32 "\x01\x02";

  (* ---------------------------------------------------------------------
     Chunk-44 additions: map canonicality, set permissiveness, and the
     comparator bcs itself sorts map keys by.

     The byte strings below are the chunk-44 oracle harness's own probe rows
     (`chunk44-oracle bcs-probes`, kept output bcs-probes.txt), run against
     bcs 0.1.6, the version telcoin-network @ 31cc4e90 pins. They settle a
     question the ground truth got wrong (GT:26, GT:176): maps are canonical
     BOTH ways, and sequences are canonical NEITHER way.

       BCSPROBE map_sorted            OK {1: 10, 2: 11}
       BCSPROBE map_swapped           ERR ... unique and in increasing order
       BCSPROBE map_duplicate_key     ERR ... unique and in increasing order
       BCSPROBE hashmap_*             identical verdicts (serde erases the
                                      HashMap/BTreeMap distinction)
       BCSPROBE set_unsorted          OK [1, 2]      (accepted and RESORTED)
       BCSPROBE set_duplicate         OK [1]         (silently collapsed)
       BCSPROBE map_serializer_sorts  0302bb05cc09aa (ascending by key bytes)

     A strict set decoder would refuse byte strings every Rust node accepts,
     so the permissive decode is the parity-preserving choice, not laxity. *)
  let new_cases = ref 0 in
  let nc f = incr new_cases; f in
  let byte_map = sorted_map u8 u8 ~compare:Int.compare in
  let digest_set = btree_set u8 ~compare:Int.compare in

  nc check_decode "map: sorted keys accepted" byte_map "\x02\x01\x0a\x02\x0b"
    [ (1, 10); (2, 11) ];
  nc check_reject "map: swapped key order rejected" byte_map
    "\x02\x02\x0b\x01\x0a";
  nc check_reject "map: duplicate key rejected" byte_map "\x02\x01\x0a\x01\x0b";
  nc check "map: encoding sorts by key"
    (encode byte_map [ (9, 0xaa); (2, 0xbb); (5, 0xcc) ])
    "\x03\x02\xbb\x05\xcc\x09\xaa";

  nc check_decode "set: ascending elements accepted" digest_set "\x02\x01\x02"
    [ 1; 2 ];
  nc check_decode "set: descending elements accepted and resorted" digest_set
    "\x02\x02\x01" [ 1; 2 ];
  nc check_decode "set: duplicate elements collapsed" digest_set "\x02\x01\x01"
    [ 1 ];
  nc check "set: encoding sorts and dedups"
    (encode digest_set [ 2; 1; 2 ])
    "\x02\x01\x02";

  (* HashSet and Vec share the sequence layout, order and all. *)
  nc check "unordered_list keeps the wire order"
    (encode (unordered_list u8) [ 2; 1 ])
    "\x02\x02\x01";
  nc check "string_utf8 is the bytes layout" (encode string_utf8 "tn") "\x02tn";

  (* The comparator bcs sorts map keys by: encoded bytes, not element order.
     For a uniform sized_bytes 96 key (a BLS public key) the two orders
     coincide, which is what lets a BlsPublicKey-keyed map be sorted by the
     OCaml value; for a variable-length key they DIVERGE, and the second row
     is the discriminating one. *)
  let key96 = sized_bytes 96 in
  let a96 = String.make 96 '\x01' and b96 = String.make 96 '\x02' in
  nc check "encoded_compare agrees with element order at sized_bytes 96"
    (Printf.sprintf "%d %d %d"
       (compare (encoded_compare key96 a96 b96) 0)
       (compare (encoded_compare key96 b96 a96) 0)
       (encoded_compare key96 a96 a96))
    "-1 1 0";
  nc check "encoded_compare differs from element order for variable lengths"
    (Printf.sprintf "%d %d"
       (compare (encoded_compare bytes "b" "aa") 0)
       (compare (String.compare "b" "aa") 0))
    "-1 1";

  (* Every SEQUENCE, map and byte-string length prefix is bounded by bcs's
     MAX_SEQUENCE_LENGTH = 2^31 - 1, one step stricter than the u32 ceiling the
     ULEB128 reader enforces on its own: [parse_length] refuses anything above
     it with [ExceededMaxLen] BEFORE a single element is read
     (bcs-0.1.6 lib.rs:312, de.rs:283-290). Both polarities, straight off the
     oracle probe against bcs 0.1.6:

       F5 bcs Vec<u8> len=2^31   -> ERR exceeded max sequence length: 2147483648
       F5 bcs Vec<u8> len=2^31-1 -> ERR unexpected end of input

     The exact message is asserted because the u32 ceiling alone also fails
     these rows, just later and for the missing bytes, and for a zero-width
     element type it would not fail at all. [btree_set], [unordered_list] and
     [string_utf8] are [list] and [bytes], so they inherit the bound. *)
  let over_max = "\x80\x80\x80\x80\x08" (* ULEB128 of 2^31 *)
  and at_max = "\xff\xff\xff\xff\x07" (* ULEB128 of 2^31 - 1 *) in
  nc check_error "bytes: a length past MAX_SEQUENCE_LENGTH" bytes over_max
    "length 2147483648 out of range at offset 0";
  nc check_error "bytes: MAX_SEQUENCE_LENGTH itself is still a length" bytes
    at_max "unexpected end of input at offset 5 (wanted 2147483647 bytes)";
  nc check_error "list: a length past MAX_SEQUENCE_LENGTH" (list u8) over_max
    "length 2147483648 out of range at offset 0";
  nc check_error "map: a length past MAX_SEQUENCE_LENGTH" byte_map over_max
    "length 2147483648 out of range at offset 0";
  (* [sized_bytes] reads its prefix with the plain u32 reader and then
     demands [len = n]. bcs routes every serialize_bytes field through
     [parse_length] (de.rs:283-289, 404-409), so it refuses a prefix past
     MAX_SEQUENCE_LENGTH there; the port's [len = n] comparison refuses the
     same prefix at the same offset, and no width the port can declare tells
     the two apart. This row pins that refusal. *)
  nc check_error "sized_bytes: a length past MAX_SEQUENCE_LENGTH"
    (sized_bytes 32) over_max "length 2147483648 out of range at offset 0";
  (* And the ENUM tag keeps the plain u32 ceiling: bcs reads variant indices
     with [parse_u32_from_uleb128], never [parse_length] (de.rs:262-292), so
     the generic reader must still hand back this very value. *)
  nc check_decode "uleb128: the generic reader keeps the u32 ceiling" uleb128
    over_max 2147483648;

  (* Vacuous-green guard for the chunk-44 additions (design section 4, line
     198): the count is asserted against a literal floor, so dropping a case
     turns this program red instead of silently shrinking it. *)
  if !new_cases >= 18 then
    Printf.printf "ok   chunk-44 case floor (%d new cases >= 18)\n" !new_cases
  else begin
    incr failures;
    Printf.printf "FAIL chunk-44 case floor: %d new cases, expected >= 18\n"
      !new_cases
  end;

  ignore b;
  ignore s;
  if !failures = 0 then print_endline "\nAll BCS conformance checks passed."
  else begin
    Printf.printf "\n%d BCS conformance check(s) failed.\n" !failures;
    exit 1
  end
