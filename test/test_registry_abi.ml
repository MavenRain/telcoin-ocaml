(* Tests for Tn_evm.Registry_abi: the ConsensusRegistry calldata encoders and
   strict return decoders of the epoch-close surface
   ([crates/tn-reth/src/system_calls.rs:26-228]).

   Selector pins are hand-derived: keccak-256 of the canonical signature
   (parameter TYPES only, structs as tuples, no names), first 4 bytes:

     concludeEpoch(address[])              -> keccak-256
       7b55a300b4d6ef452f29c2f8c3f408dfa3b8911494f44b7cafc2170b866882ab
       selector 7b55a300
     applyIncentives((address,uint256)[])  -> keccak-256
       0a36cdefad8635008281d703f3cae4da836eda739adfbe1e202257e013610462
       selector 0a36cdef
     getValidatorsInfo(uint8)              -> keccak-256
       2870259de17bcbaee68728be1475e06c589b45b88cfdae0a29b7255f0a897179
       selector 2870259d
     getNextCommitteeSize()                -> keccak-256
       eb8535c2b5d64b55cf2a4702c7c0f5c76df41cea4a329e4bc9cab3b97230a552
       selector eb8535c2
     getValidators(uint8)                  -> keccak-256
       8cc05eda0e43bcdc348aa78952f9c473441d004f63318f244b9b7125fe8e8393
       selector 8cc05eda

   The digests were computed with pycryptodome's keccak (digest_bits=256)
   and each selector cross-checked with `cast sig "<signature>"` (foundry
   cast 0.3.0), which printed the same four bytes.

   Every full-calldata golden vector below is hand-derived in its own
   comment (head offset word, length word, tail packing) and was
   additionally cross-checked byte-for-byte with `cast calldata` /
   `cast abi-encode` (cast 0.3.0); the exact command is cited beside each
   vector. *)

module Registry_abi = Tn_evm.Registry_abi
module Validator_status = Registry_abi.Validator_status
module Eligible_status = Registry_abi.Eligible_status
module Validator_info = Registry_abi.Validator_info
module Address = Tn_types.Units.Address

(* ---------- helpers ---------- *)

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
    (fun i ->
      Char.chr ((digit (String.get s (2 * i)) lsl 4) lor digit (String.get s ((2 * i) + 1))))

let to_hex s =
  String.concat ""
    (List.map (fun c -> Printf.sprintf "%02x" (Char.code c)) (List.of_seq (String.to_seq s)))

let addr h =
  match Address.of_bytes (hex h) with
  | Some a -> a
  | None -> Alcotest.failf "address fixture %s is not 20 bytes" h

let check_bytes name expected_hex actual =
  Alcotest.(check string) name expected_hex (to_hex actual)

let check_error name expected actual =
  match actual with
  | Ok _ -> Alcotest.failf "%s: expected an error, got Ok" name
  | Error e ->
      Alcotest.(check string) name
        (Registry_abi.error_to_string expected)
        (Registry_abi.error_to_string e)

let a1 = "1111111111111111111111111111111111111111"
let a2 = "2222222222222222222222222222222222222222"
let a3 = "3333333333333333333333333333333333333333"
let pad12 = "000000000000000000000000"
let w n = Printf.sprintf "%064x" n

(* ---------- selectors ---------- *)

let test_selectors () =
  let prefix s = to_hex (String.sub s 0 4) in
  check_bytes "getNextCommitteeSize is the bare selector" "eb8535c2"
    Registry_abi.get_next_committee_size_calldata;
  Alcotest.(check string) "concludeEpoch selector" "7b55a300"
    (prefix (Registry_abi.conclude_epoch_calldata []));
  Alcotest.(check string) "applyIncentives selector" "0a36cdef"
    (prefix (Registry_abi.apply_incentives_calldata []));
  Alcotest.(check string) "getValidatorsInfo selector" "2870259d"
    (prefix (Registry_abi.get_validators_info_calldata Eligible_status.Active));
  Alcotest.(check string) "legacy getValidators selector" "8cc05eda"
    (prefix (Registry_abi.get_validators_calldata Eligible_status.Active))

(* ---------- concludeEpoch ---------- *)

(* Hand derivation, three addresses (block.rs:394-398 passes the sorted
   committee; the encoder must not sort, see the next test):
     7b55a300                     selector
     ..0020                       head: offset of address[] tail = 32,
                                  measured from after the selector (one
                                  argument, so its tail starts right after
                                  the single head word)
     ..0003                       length = 3
     pad12 ++ a1                  each address left-padded to 32 bytes
     pad12 ++ a2
     pad12 ++ a3
   164 bytes. Cross-check: cast calldata "concludeEpoch(address[])"
   "[0x1111...,0x2222...,0x3333...]" (cast 0.3.0) printed these bytes. *)
let test_conclude_epoch_golden () =
  check_bytes "three addresses"
    ("7b55a300" ^ w 32 ^ w 3 ^ pad12 ^ a1 ^ pad12 ^ a2 ^ pad12 ^ a3)
    (Registry_abi.conclude_epoch_calldata [ addr a1; addr a2; addr a3 ]);
  (* Empty committee: head word then length 0, no tail. Cross-check:
     cast calldata "concludeEpoch(address[])" "[]". *)
  check_bytes "empty committee" ("7b55a300" ^ w 32 ^ w 0)
    (Registry_abi.conclude_epoch_calldata []);
  (* Order AS GIVEN: the ascending sort is the caller's step
     (block.rs:394-395), so a descending input must encode descending. *)
  check_bytes "order as given, never sorted"
    ("7b55a300" ^ w 32 ^ w 2 ^ pad12 ^ a2 ^ pad12 ^ a1)
    (Registry_abi.conclude_epoch_calldata [ addr a2; addr a1 ])

(* ---------- applyIncentives ---------- *)

(* Hand derivation, two RewardInfo entries. RewardInfo is
   (address validatorAddress, uint256 consensusHeaderCount)
   (system_calls.rs:105-110), a STATIC tuple, so RewardInfo[] packs its
   elements inline, two words each, with NO per-element offset words:
     0a36cdef                     selector
     ..0020                       head: offset of the array tail = 32
     ..0002                       length = 2
     pad12 ++ a1                  element 0, word 0: validatorAddress
     ..0003                       element 0, word 1: count 3, unscaled
     pad12 ++ a2                  element 1, word 0
     ..0001                       element 1, word 1: count 1
   196 bytes. Cross-check: cast calldata
   "applyIncentives((address,uint256)[])" "[(0x1111...,3),(0x2222...,1)]"
   (cast 0.3.0) printed these bytes. *)
let test_apply_incentives_golden () =
  check_bytes "two reward entries"
    ("0a36cdef" ^ w 32 ^ w 2 ^ pad12 ^ a1 ^ w 3 ^ pad12 ^ a2 ^ w 1)
    (Registry_abi.apply_incentives_calldata [ (addr a1, 3); (addr a2, 1) ]);
  (* Cross-check: cast calldata "applyIncentives((address,uint256)[])" "[]". *)
  check_bytes "empty rewards" ("0a36cdef" ^ w 32 ^ w 0)
    (Registry_abi.apply_incentives_calldata [])

(* ---------- status-argument encoders ---------- *)

(* The uint8 argument is a full word; the enum values are the declaration
   order of system_calls.rs:33-50: PendingActivation=2, Active=3,
   PendingExit=4. Cross-check for Active:
   cast calldata "getValidatorsInfo(uint8)" 3 (cast 0.3.0). *)
let test_status_arg_encoding () =
  check_bytes "getValidatorsInfo(Active)" ("2870259d" ^ w 3)
    (Registry_abi.get_validators_info_calldata Eligible_status.Active);
  check_bytes "getValidatorsInfo(PendingActivation)" ("2870259d" ^ w 2)
    (Registry_abi.get_validators_info_calldata Eligible_status.Pending_activation);
  check_bytes "getValidatorsInfo(PendingExit)" ("2870259d" ^ w 4)
    (Registry_abi.get_validators_info_calldata Eligible_status.Pending_exit);
  (* Legacy pre-fork read: same argument word, different selector.
     Cross-check: cast calldata "getValidators(uint8)" 3. *)
  check_bytes "legacy getValidators(Active)" ("8cc05eda" ^ w 3)
    (Registry_abi.get_validators_calldata Eligible_status.Active)

(* ---------- Validator_status bytes ---------- *)

let all_statuses =
  Validator_status.
    [ Undefined; Staked; Pending_activation; Active; Pending_exit; Exited; Any ]

let test_status_bytes () =
  (* to_byte is the declaration order 0..6 and of_byte inverts it. *)
  List.iteri
    (fun i s ->
      Alcotest.(check int)
        (Printf.sprintf "to_byte %d" i)
        i
        (Char.code (Validator_status.to_byte s));
      match Validator_status.of_byte (Char.chr i) with
      | Some s' ->
          Alcotest.(check bool)
            (Printf.sprintf "of_byte %d round-trips" i)
            true
            (Validator_status.equal s s')
      | None -> Alcotest.failf "of_byte %d returned None" i)
    all_statuses;
  Alcotest.(check bool) "of_byte 7 is None" true
    (Option.is_none (Validator_status.of_byte '\007'));
  Alcotest.(check bool) "of_byte 255 is None" true
    (Option.is_none (Validator_status.of_byte '\255'));
  (* The Eligible_status embedding hits exactly 3, 2, 4. *)
  Alcotest.(check int) "Active embeds as 3" 3
    (Char.code (Validator_status.to_byte (Eligible_status.to_status Eligible_status.Active)));
  Alcotest.(check int) "PendingActivation embeds as 2" 2
    (Char.code
       (Validator_status.to_byte
          (Eligible_status.to_status Eligible_status.Pending_activation)));
  Alcotest.(check int) "PendingExit embeds as 4" 4
    (Char.code
       (Validator_status.to_byte (Eligible_status.to_status Eligible_status.Pending_exit)))

(* ---------- decode_validator_info_array ---------- *)

(* Return encoding of ValidatorInfo[] with two elements. ValidatorInfo is a
   static 7-field tuple (address, uint32 activationEpoch, uint32 exitEpoch,
   uint8 currentStatus, bool isRetired, uint8 stakeVersion, uint8 region)
   (system_calls.rs:54-74), so elements are inline, 7 words each:
     ..0020    head: offset of the array = 32
     ..0002    length = 2
     element 0: pad12++a1 | 5 | 0 | 3 (Active) | 0 (false) | 1 | 2
     element 1: pad12++a2 | 2 | 9 | 4 (PendingExit) | 1 (true) | 0 | 7
   512 bytes. Cross-check: cast abi-encode
   "f((address,uint32,uint32,uint8,bool,uint8,uint8)[])"
   "[(0x1111...,5,0,3,false,1,2),(0x2222...,2,9,4,true,0,7)]"
   (cast 0.3.0) printed these bytes. *)
let elem0 = pad12 ^ a1 ^ w 5 ^ w 0 ^ w 3 ^ w 0 ^ w 1 ^ w 2
let elem1 = pad12 ^ a2 ^ w 2 ^ w 9 ^ w 4 ^ w 1 ^ w 0 ^ w 7
let golden_array_hex = w 32 ^ w 2 ^ elem0 ^ elem1

let expected_info ~address ~activation ~exit_ ~status ~retired ~version ~region =
  match
    Validator_info.make ~validator_address:(addr address)
      ~activation_epoch:activation ~exit_epoch:exit_ ~current_status:status
      ~is_retired:retired ~stake_version:version ~region
  with
  | Some info -> info
  | None -> Alcotest.fail "expected fixture rejected by make"

let test_decode_golden () =
  match Registry_abi.decode_validator_info_array (hex golden_array_hex) with
  | Error e -> Alcotest.fail (Registry_abi.error_to_string e)
  | Ok infos -> (
      Alcotest.(check int) "two elements" 2 (List.length infos);
      match infos with
      | [ i0; i1 ] ->
          let e0 =
            expected_info ~address:a1 ~activation:5 ~exit_:0
              ~status:Validator_status.Active ~retired:false ~version:1 ~region:2
          in
          let e1 =
            expected_info ~address:a2 ~activation:2 ~exit_:9
              ~status:Validator_status.Pending_exit ~retired:true ~version:0
              ~region:7
          in
          Alcotest.(check bool) "element 0 field-for-field" true
            (Validator_info.equal e0 i0);
          Alcotest.(check bool) "element 1 field-for-field" true
            (Validator_info.equal e1 i1);
          Alcotest.(check string) "element 0 address accessor" a1
            (to_hex (Address.to_bytes (Validator_info.validator_address i0)));
          Alcotest.(check int) "element 1 status accessor" 4
            (Char.code (Validator_status.to_byte (Validator_info.current_status i1)))
      | [] | [ _ ] | _ :: _ :: _ -> Alcotest.fail "unreachable: length checked above")

let test_decode_empty_array () =
  (* cast abi-encode "f((address,uint32,uint32,uint8,bool,uint8,uint8)[])"
     "[]" is 0x20 then length 0. *)
  match Registry_abi.decode_validator_info_array (hex (w 32 ^ w 0)) with
  | Error e -> Alcotest.fail (Registry_abi.error_to_string e)
  | Ok infos -> Alcotest.(check int) "no elements" 0 (List.length infos)

(* PORT-CHOICE, NOT FIDELITY: whether alloy 1.5.7's abi_decode rejects
   trailing bytes, loose head offsets and dirty padding is unverified for
   this pinned version; the port implements the strict choice and these
   tests pin the port's own contract, not observed alloy behavior. If the
   alloy probe lands, revisit here first. *)
let test_decode_strictness () =
  let base = hex golden_array_hex in
  check_error "one trailing byte" (Registry_abi.Trailing_bytes 1)
    (Registry_abi.decode_validator_info_array (base ^ "\x00"));
  check_error "head offset 0x40" Registry_abi.Head_offset_not_32
    (Registry_abi.decode_validator_info_array (hex (w 64 ^ w 2 ^ elem0 ^ elem1)));
  check_error "shorter than one word"
    (Registry_abi.Truncated { need = 32; got = 31 })
    (Registry_abi.decode_validator_info_array (String.sub base 0 31));
  check_error "offset word only"
    (Registry_abi.Truncated { need = 64; got = 32 })
    (Registry_abi.decode_validator_info_array (String.sub base 0 32));
  check_error "length says 2, one element present"
    (Registry_abi.Truncated { need = 64 + (2 * 224); got = 64 + 224 })
    (Registry_abi.decode_validator_info_array (String.sub base 0 (64 + 224)));
  check_error "length word above u32" Registry_abi.Length_word_overflow
    (Registry_abi.decode_validator_info_array
       (hex (w 32 ^ "0000000000000000000000000000000000000000000000000000000100000000" ^ elem0 ^ elem1)));
  (* Status byte 7 in element 0 (word 3 of the tuple). *)
  check_error "status byte 7" (Registry_abi.Status_byte 7)
    (Registry_abi.decode_validator_info_array
       (hex (w 32 ^ w 2 ^ (pad12 ^ a1 ^ w 5 ^ w 0 ^ w 7 ^ w 0 ^ w 1 ^ w 2) ^ elem1)));
  (* Dirty byte inside the address padding of element 1. *)
  check_error "nonzero address padding" Registry_abi.Padding_nonzero
    (Registry_abi.decode_validator_info_array
       (hex (w 32 ^ w 2 ^ elem0 ^ ("0000000000000000000000ff" ^ a2 ^ w 2 ^ w 9 ^ w 4 ^ w 1 ^ w 0 ^ w 7))));
  (* Bool word 2: nonzero bits outside {0,1}, reported as padding. *)
  check_error "bool word above one" Registry_abi.Padding_nonzero
    (Registry_abi.decode_validator_info_array
       (hex (w 32 ^ w 2 ^ elem0 ^ (pad12 ^ a2 ^ w 2 ^ w 9 ^ w 4 ^ w 2 ^ w 0 ^ w 7))))

(* ---------- decode_uint16 ---------- *)

let test_decode_uint16 () =
  (* Golden: cast abi-encode "f(uint16)" 11 is one word, value 0x0b
     (cast 0.3.0); getNextCommitteeSize returns uint16
     (system_calls.rs:203, decoded as u16 at block.rs:630-638). *)
  (match Registry_abi.decode_uint16 (hex (w 11)) with
  | Ok v -> Alcotest.(check int) "eleven" 11 v
  | Error e -> Alcotest.fail (Registry_abi.error_to_string e));
  (match Registry_abi.decode_uint16 (hex (w 0xffff)) with
  | Ok v -> Alcotest.(check int) "u16 max" 65535 v
  | Error e -> Alcotest.fail (Registry_abi.error_to_string e));
  (* PORT-CHOICE, NOT FIDELITY: strictness pins as above. *)
  check_error "short word" (Registry_abi.Truncated { need = 32; got = 2 })
    (Registry_abi.decode_uint16 (hex "000b"));
  check_error "trailing word" (Registry_abi.Trailing_bytes 32)
    (Registry_abi.decode_uint16 (hex (w 11 ^ w 0)));
  check_error "value above u16" Registry_abi.Padding_nonzero
    (Registry_abi.decode_uint16 (hex (w 0x10000)))

(* ---------- Validator_info.make bounds ---------- *)

let test_make_bounds () =
  let try_make ~activation ~exit_ ~version ~region =
    Validator_info.make ~validator_address:(addr a1) ~activation_epoch:activation
      ~exit_epoch:exit_ ~current_status:Validator_status.Active ~is_retired:false
      ~stake_version:version ~region
  in
  Alcotest.(check bool) "u32 and u8 maxima accepted" true
    (Option.is_some (try_make ~activation:0xffffffff ~exit_:0xffffffff ~version:255 ~region:255));
  Alcotest.(check bool) "negative epoch rejected" true
    (Option.is_none (try_make ~activation:(-1) ~exit_:0 ~version:0 ~region:0));
  Alcotest.(check bool) "epoch above u32 rejected" true
    (Option.is_none (try_make ~activation:0x1_0000_0000 ~exit_:0 ~version:0 ~region:0));
  Alcotest.(check bool) "version above u8 rejected" true
    (Option.is_none (try_make ~activation:0 ~exit_:0 ~version:256 ~region:0));
  Alcotest.(check bool) "region above u8 rejected" true
    (Option.is_none (try_make ~activation:0 ~exit_:0 ~version:0 ~region:256))

let () =
  Alcotest.run "registry_abi"
    [
      ( "selectors",
        [ Alcotest.test_case "pins vs hand-derived keccak" `Quick test_selectors ] );
      ( "encoders",
        [
          Alcotest.test_case "concludeEpoch golden" `Quick test_conclude_epoch_golden;
          Alcotest.test_case "applyIncentives golden" `Quick test_apply_incentives_golden;
          Alcotest.test_case "status argument words" `Quick test_status_arg_encoding;
        ] );
      ( "statuses",
        [
          Alcotest.test_case "uint8 round-trips" `Quick test_status_bytes;
          Alcotest.test_case "make bounds" `Quick test_make_bounds;
        ] );
      ( "decoders",
        [
          Alcotest.test_case "ValidatorInfo[] golden" `Quick test_decode_golden;
          Alcotest.test_case "empty array" `Quick test_decode_empty_array;
          Alcotest.test_case "strictness (port-choice)" `Quick test_decode_strictness;
          Alcotest.test_case "uint16 return" `Quick test_decode_uint16;
        ] );
    ]
