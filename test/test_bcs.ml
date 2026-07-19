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

  ignore b;
  ignore s;
  if !failures = 0 then print_endline "\nAll BCS conformance checks passed."
  else begin
    Printf.printf "\n%d BCS conformance check(s) failed.\n" !failures;
    exit 1
  end
