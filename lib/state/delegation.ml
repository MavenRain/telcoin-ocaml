(* EIP-7702 delegation designators. A port of revm-bytecode 8.0.0
   [src/eip7702.rs] (the layout and the decode order) and [src/bytecode.rs:101-110]
   (the two-byte classification), plus the write-path half of
   revm-context-interface 14.0.0 [src/journaled_state/account.rs:448-459] (the
   zero-address special case).

   Nothing here needs RLP, the curve or a hash, which is why it can sit in
   [tn_state] beside [Account] and let an account classify its own code. *)

open Tn_types

type t = Units.Address.t

(* [pub static EIP7702_MAGIC_BYTES: Bytes = bytes!("ef01");] -- revm-bytecode
   [eip7702.rs:12]. Two bytes, deliberately: [bytecode.rs:101-110] slices
   [bytes.get(..2)] and compares against exactly this. *)
let magic = "\xef\x01"

(* [pub const EIP7702_VERSION: u8 = 0;] -- revm-bytecode [eip7702.rs:20]. *)
let version = 0

(* 23, as [eip7702.rs:36] writes it, but assembled from the three widths that
   produce it rather than restated, so [to_bytes] and this cannot disagree. *)
let length = String.length magic + 1 + Units.Address.length
let version_byte = "\x00"
let target t = t
let to_bytes t = magic ^ version_byte ^ Units.Address.to_bytes t

type decode_error = Invalid_length of int | Unsupported_version of int

let decode_error_to_string e =
  match e with
  | Invalid_length n ->
      Printf.sprintf "0xef01-prefixed code is %d bytes, not the %d a delegation designator has" n
        length
  | Unsupported_version v ->
      Printf.sprintf "delegation designator version 0x%02x is not the supported 0x%02x" v version

type code_class =
  | Codeless
  | Contract
  | Delegated of t
  | Undecodable of decode_error

(* revm's order, and it is observable. [Bytecode::new_raw_checked] switches on
   the FIRST TWO BYTES alone ([bytecode.rs:101-110]): anything else, [0xef]
   included, is legacy code and cannot error. Only inside the magic branch does
   [Eip7702Bytecode::new_raw] run its checks, and it checks LENGTH before
   VERSION ([eip7702.rs:36-53]), so a 22-byte [ef0101..] blob is an
   [Invalid_length] and never an [Unsupported_version].

   The final [Option.fold] discharges [Address.of_bytes] on a slice this branch
   has already proved is exactly [Units.Address.length] bytes long (the total
   length is [length] and the slice drops the three-byte header), so its [~none]
   is unreachable; it is written rather than asserted away because a partial
   [Option.get] would be the only exception in this library. *)
let classify code =
  let n = String.length code in
  if n = 0 then Codeless
  else if n < String.length magic || not (String.equal (String.sub code 0 (String.length magic)) magic)
  then Contract
  else if n <> length then Undecodable (Invalid_length n)
  else if Char.code code.[String.length magic] <> version then
    Undecodable (Unsupported_version (Char.code code.[String.length magic]))
  else
    Option.fold ~none:(Undecodable (Invalid_length n))
      ~some:(fun address -> Delegated address)
      (Units.Address.of_bytes (String.sub code (String.length magic + 1) Units.Address.length))

let of_code code =
  match classify code with
  | Delegated d -> Some d
  | Codeless -> None
  | Contract -> None
  | Undecodable _ -> None

(* [if !bytecode.is_empty() && !bytecode.is_eip7702()] -- revm-handler
   [pre_execution.rs:241-244] for check 5, and the same condition again at
   [pre_execution.rs:92-102] for EIP-3607. [Undecodable] answers [true] because
   it is not a designator; revm never has such an account to ask about, since
   the database load that would have produced it failed. *)
let is_contract_code code =
  match classify code with
  | Codeless -> false
  | Delegated _ -> false
  | Contract -> true
  | Undecodable _ -> true

type assignment = Assign of t | Revoke

(* [let (bytecode, hash) = if address.is_zero() { (Bytecode::default(), KECCAK_EMPTY) }]
   -- revm-context-interface [journaled_state/account.rs:449-455].
   [Bytecode::default()] has [original_len: 0] ([legacy/analyzed.rs:39-48]), so
   the cleared account's code is EMPTY, not 23 bytes of anything. *)
let assignment address = if Units.Address.equal address Units.Address.zero then Revoke else Assign address

let code_of_assignment a = match a with Assign d -> to_bytes d | Revoke -> ""
let equal = Units.Address.equal
