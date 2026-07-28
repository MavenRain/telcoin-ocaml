(* The ConsensusRegistry ABI restricted to the epoch-close surface
   ([system_calls.rs:26-228]). Selectors are keccak-256 of the canonical
   signature strings, computed once at module initialisation via Tn_keccak;
   the byte layout is alloy-sol-types 1.5.7's canonical form for these
   shapes: selector, one 0x20 head word for the single dynamic-array
   argument, a length word, then inline static-tuple elements with no
   per-element offsets. Decoders are strict (exact offset, exact length,
   zero padding, zero trailing); alloy 1.5.7's exact leniency is unverified,
   so that strictness is a labelled port choice, pinned in the test suite as
   such. *)

module Validator_status = struct
  type t =
    | Undefined
    | Staked
    | Pending_activation
    | Active
    | Pending_exit
    | Exited
    | Any

  (* Declaration order defines the uint8 values ([system_calls.rs:33-50]). *)
  let to_byte s =
    match s with
    | Undefined -> '\000'
    | Staked -> '\001'
    | Pending_activation -> '\002'
    | Active -> '\003'
    | Pending_exit -> '\004'
    | Exited -> '\005'
    | Any -> '\006'

  let of_byte c =
    match Char.code c with
    | 0 -> Some Undefined
    | 1 -> Some Staked
    | 2 -> Some Pending_activation
    | 3 -> Some Active
    | 4 -> Some Pending_exit
    | 5 -> Some Exited
    | 6 -> Some Any
    | _ -> None

  (* [to_byte] is injective by inspection, so byte equality is constructor
     equality (the [opcode.ml:307] pattern). *)
  let equal a b = Char.equal (to_byte a) (to_byte b)
end

module Eligible_status = struct
  type t = Active | Pending_activation | Pending_exit

  let to_status s =
    match s with
    | Active -> Validator_status.Active
    | Pending_activation -> Validator_status.Pending_activation
    | Pending_exit -> Validator_status.Pending_exit
end

module Validator_info = struct
  type t = {
    validator_address : Tn_types.Units.Address.t;
    activation_epoch : int;
    exit_epoch : int;
    current_status : Validator_status.t;
    is_retired : bool;
    stake_version : int;
    region : int;
  }

  let fits_u32 n = n >= 0 && n < 0x1_0000_0000
  let fits_u8 n = n >= 0 && n < 0x100

  let make ~validator_address ~activation_epoch ~exit_epoch ~current_status
      ~is_retired ~stake_version ~region =
    match
      fits_u32 activation_epoch && fits_u32 exit_epoch
      && fits_u8 stake_version && fits_u8 region
    with
    | false -> None
    | true ->
        Some
          {
            validator_address;
            activation_epoch;
            exit_epoch;
            current_status;
            is_retired;
            stake_version;
            region;
          }

  let validator_address t = t.validator_address
  let current_status t = t.current_status

  let equal a b =
    Tn_types.Units.Address.equal a.validator_address b.validator_address
    && Int.equal a.activation_epoch b.activation_epoch
    && Int.equal a.exit_epoch b.exit_epoch
    && Validator_status.equal a.current_status b.current_status
    && Bool.equal a.is_retired b.is_retired
    && Int.equal a.stake_version b.stake_version
    && Int.equal a.region b.region
end

type decode_error =
  | Truncated of { need : int; got : int }
  | Head_offset_not_32
  | Length_word_overflow
  | Status_byte of int
  | Padding_nonzero
  | Trailing_bytes of int

let error_to_string e =
  match e with
  | Truncated { need; got } ->
      Printf.sprintf "return truncated: need %d bytes, got %d" need got
  | Head_offset_not_32 -> "head offset word is not 0x20"
  | Length_word_overflow -> "array length word exceeds the u32 range"
  | Status_byte b -> Printf.sprintf "validator status byte %d outside 0..6" b
  | Padding_nonzero -> "nonzero bytes outside a static value's width"
  | Trailing_bytes n ->
      Printf.sprintf "%d trailing bytes after the encoded value" n

(* ---------- words ---------- *)

let word_size = 32

(* One 32-byte big-endian word from a native int, arithmetically
   sign-extended: for the non-negative offsets, lengths and uint8 values
   every internal caller passes this is the plain unsigned encoding, and a
   negative applyIncentives count (no Rust image; the source is a u32
   counter, [gas_accumulator.rs:94-106]) widens totally to its 256-bit two's
   complement. Shifts are clamped to 62 because OCaml leaves [asr] beyond
   [Sys.int_size - 1] unspecified; [n asr 62] is exactly the sign byte. *)
let word_of_int n =
  String.init word_size (fun i ->
      let shift = (31 - i) * 8 in
      Char.chr ((n asr min shift 62) land 0xff))

let word_of_address a =
  String.make 12 '\000' ^ Tn_types.Units.Address.to_bytes a

let word_of_status s = word_of_int (Char.code (Validator_status.to_byte s))

(* ---------- selectors ---------- *)

(* First 4 bytes of keccak-256 of the canonical signature: parameter TYPES
   only, tuples for structs, no parameter names ([RewardInfo] canonicalises
   to [(address,uint256)], [system_calls.rs:105-110]). *)
let selector signature =
  String.sub (Tn_keccak.to_bytes (Tn_keccak.digest signature)) 0 4

let conclude_epoch_selector = selector "concludeEpoch(address[])"
let apply_incentives_selector = selector "applyIncentives((address,uint256)[])"
let get_validators_info_selector = selector "getValidatorsInfo(uint8)"
let get_validators_selector = selector "getValidators(uint8)"
let get_next_committee_size_selector = selector "getNextCommitteeSize()"

(* ---------- encoders ---------- *)

(* address[]: head word 0x20 (offset of the tail from the start of the
   argument block), length, then one left-padded word per address, order as
   given ([block.rs:394-398] sorts before calling). *)
let conclude_epoch_calldata addresses =
  String.concat ""
    (conclude_epoch_selector
    :: word_of_int word_size
    :: word_of_int (List.length addresses)
    :: List.map word_of_address addresses)

(* RewardInfo[] where RewardInfo = (address,uint256) is a static tuple:
   elements pack inline as two words each, no per-element offsets
   ([block.rs:414-424]). *)
let apply_incentives_calldata rewards =
  String.concat ""
    (apply_incentives_selector
    :: word_of_int word_size
    :: word_of_int (List.length rewards)
    :: List.concat_map
         (fun (address, count) -> [ word_of_address address; word_of_int count ])
         rewards)

let get_validators_info_calldata status =
  get_validators_info_selector ^ word_of_status (Eligible_status.to_status status)

let get_validators_calldata status =
  get_validators_selector ^ word_of_status (Eligible_status.to_status status)

let get_next_committee_size_calldata = get_next_committee_size_selector

(* ---------- decoders ---------- *)

let ( let* ) = Result.bind

(* Every byte before [k] is zero: the strict-padding gate. *)
let zero_prefix w k =
  String.for_all (fun c -> Char.equal c '\000') (String.sub w 0 k)

(* Big-endian value of [len] bytes at [start]; every caller keeps
   [len <= 4], so the result fits a native int with no overflow. *)
let be_int w start len =
  String.fold_left
    (fun acc c -> (acc lsl 8) lor Char.code c)
    0
    (String.sub w start len)

(* A uintN occupying the last [width] bytes of its word. *)
let decode_uint w width =
  match zero_prefix w (word_size - width) with
  | false -> Error Padding_nonzero
  | true -> Ok (be_int w (word_size - width) width)

let decode_address w =
  match zero_prefix w 12 with
  | false -> Error Padding_nonzero
  | true ->
      (* [of_bytes] on an exactly-20-byte slice is always [Some]; the zero
         default is unreachable, the same collapse as
         [system_contracts.ml]'s [address_of_hex]. *)
      Ok
        (Option.value ~default:Tn_types.Units.Address.zero
           (Tn_types.Units.Address.of_bytes (String.sub w 12 20)))

let decode_status w =
  match zero_prefix w 31 with
  | false -> Error Padding_nonzero
  | true ->
      let b = Char.code (String.get w 31) in
      Option.to_result ~none:(Status_byte b)
        (Validator_status.of_byte (Char.chr b))

(* Strict bool: the word must be the uint256 0 or 1. A last byte above one
   is nonzero bits outside the value's width, which is what
   [Padding_nonzero] names. *)
let decode_bool w =
  match zero_prefix w 31 with
  | false -> Error Padding_nonzero
  | true -> (
      match Char.code (String.get w 31) with
      | 0 -> Ok false
      | 1 -> Ok true
      | _ -> Error Padding_nonzero)

(* Seven static words per ValidatorInfo ([system_calls.rs:54-74]). *)
let element_size = 7 * word_size

(* One inline element; the caller has already proven
   [64 + (index + 1) * element_size <= String.length data]. *)
let element data index =
  let base = 64 + (index * element_size) in
  let word j = String.sub data (base + (j * word_size)) word_size in
  let* validator_address = decode_address (word 0) in
  let* activation_epoch = decode_uint (word 1) 4 in
  let* exit_epoch = decode_uint (word 2) 4 in
  let* current_status = decode_status (word 3) in
  let* is_retired = decode_bool (word 4) in
  let* stake_version = decode_uint (word 5) 1 in
  let* region = decode_uint (word 6) 1 in
  Ok
    {
      Validator_info.validator_address;
      activation_epoch;
      exit_epoch;
      current_status;
      is_retired;
      stake_version;
      region;
    }

let decode_validator_info_array data =
  let got = String.length data in
  let* () = if got >= word_size then Ok () else Error (Truncated { need = word_size; got }) in
  let* () =
    match String.equal (String.sub data 0 word_size) (word_of_int word_size) with
    | true -> Ok ()
    | false -> Error Head_offset_not_32
  in
  let* () = if got >= 64 then Ok () else Error (Truncated { need = 64; got }) in
  let length_word = String.sub data word_size word_size in
  (* A length above u32 could never be satisfied by bytes that exist, and
     bounding it keeps [need] far from native-int overflow. *)
  let* n =
    match zero_prefix length_word 28 with
    | false -> Error Length_word_overflow
    | true -> Ok (be_int length_word 28 4)
  in
  let need = 64 + (n * element_size) in
  let* () = if got >= need then Ok () else Error (Truncated { need; got }) in
  let* () = if got = need then Ok () else Error (Trailing_bytes (got - need)) in
  List.fold_left
    (fun acc index ->
      let* rev = acc in
      let* info = element data index in
      Ok (info :: rev))
    (Ok []) (List.init n Fun.id)
  |> Result.map List.rev

let decode_uint16 data =
  let got = String.length data in
  let* () = if got >= word_size then Ok () else Error (Truncated { need = word_size; got }) in
  let* () = if got = word_size then Ok () else Error (Trailing_bytes (got - word_size)) in
  decode_uint (String.sub data 0 word_size) 2
