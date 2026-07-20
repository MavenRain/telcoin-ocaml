module Push_bytes = struct
  (* The immediate width of a [PUSH], held as the width itself; [of_int] is the
     only way in, so a value of this type is always within [1, 32]. *)
  type t = int

  let min_width = 1
  let max_width = 32
  let of_int n = if n >= min_width && n <= max_width then Some n else None
  let to_int t = t
  let all = List.init max_width (fun i -> i + min_width)
  let equal = Int.equal
end

type t =
  | Stop
  | Add
  | Mul
  | Sub
  | Div
  | Sdiv
  | Mod
  | Smod
  | Addmod
  | Mulmod
  | Exp
  | Signextend
  | Lt
  | Gt
  | Slt
  | Sgt
  | Eq
  | Iszero
  | And
  | Or
  | Xor
  | Not
  | Byte
  | Shl
  | Shr
  | Sar
  | Pop
  | Mload
  | Mstore
  | Mstore8
  | Jump
  | Jumpi
  | Pc
  | Msize
  | Gas
  | Jumpdest
  | Push0
  | Push of Push_bytes.t
  | Dup of Depth.t
  | Swap of Depth.t
  | Return
  | Revert
  | Invalid
  | Address
  | Balance
  | Origin
  | Caller
  | Callvalue
  | Calldataload
  | Calldatasize
  | Calldatacopy
  | Codesize
  | Codecopy
  | Extcodesize
  | Extcodecopy
  | Extcodehash
  | Gasprice
  | Coinbase
  | Timestamp
  | Number
  | Prevrandao
  | Gaslimit
  | Chainid
  | Selfbalance
  | Basefee
  | Sload
  | Sstore
  | Mcopy
  | Keccak256
  | Tload
  | Tstore
  | Log of Topic_count.t
  | Returndatasize
  | Returndatacopy
  | Call
  | Callcode
  | Delegatecall
  | Staticcall

(* The first byte of each contiguous family, from which the family's operand is
   recovered by subtraction. *)
let push1_byte = 0x60
let dup1_byte = 0x80
let swap1_byte = 0x90
let log0_byte = 0xa0

let to_byte = function
  | Stop -> 0x00
  | Add -> 0x01
  | Mul -> 0x02
  | Sub -> 0x03
  | Div -> 0x04
  | Sdiv -> 0x05
  | Mod -> 0x06
  | Smod -> 0x07
  | Addmod -> 0x08
  | Mulmod -> 0x09
  | Exp -> 0x0a
  | Signextend -> 0x0b
  | Lt -> 0x10
  | Gt -> 0x11
  | Slt -> 0x12
  | Sgt -> 0x13
  | Eq -> 0x14
  | Iszero -> 0x15
  | And -> 0x16
  | Or -> 0x17
  | Xor -> 0x18
  | Not -> 0x19
  | Byte -> 0x1a
  | Shl -> 0x1b
  | Shr -> 0x1c
  | Sar -> 0x1d
  | Address -> 0x30
  | Balance -> 0x31
  | Origin -> 0x32
  | Caller -> 0x33
  | Callvalue -> 0x34
  | Calldataload -> 0x35
  | Calldatasize -> 0x36
  | Calldatacopy -> 0x37
  | Codesize -> 0x38
  | Codecopy -> 0x39
  | Extcodesize -> 0x3b
  | Extcodecopy -> 0x3c
  | Extcodehash -> 0x3f
  | Gasprice -> 0x3a
  | Coinbase -> 0x41
  | Timestamp -> 0x42
  | Number -> 0x43
  | Prevrandao -> 0x44
  | Gaslimit -> 0x45
  | Chainid -> 0x46
  | Selfbalance -> 0x47
  | Basefee -> 0x48
  | Pop -> 0x50
  | Mload -> 0x51
  | Mstore -> 0x52
  | Mstore8 -> 0x53
  | Sload -> 0x54
  | Sstore -> 0x55
  | Jump -> 0x56
  | Jumpi -> 0x57
  | Pc -> 0x58
  | Msize -> 0x59
  | Gas -> 0x5a
  | Jumpdest -> 0x5b
  | Mcopy -> 0x5e
  | Keccak256 -> 0x20
  | Tload -> 0x5c
  | Tstore -> 0x5d
  | Push0 -> 0x5f
  | Push n -> push1_byte + Push_bytes.to_int n - 1
  | Dup d -> dup1_byte + Depth.to_int d - 1
  | Swap d -> swap1_byte + Depth.to_int d - 1
  | Log n -> log0_byte + Topic_count.to_int n
  | Returndatasize -> 0x3d
  | Returndatacopy -> 0x3e
  | Call -> 0xf1
  | Callcode -> 0xf2
  | Delegatecall -> 0xf4
  | Staticcall -> 0xfa
  | Return -> 0xf3
  | Revert -> 0xfd
  | Invalid -> 0xfe

(* A family member from its byte: the operand is the offset from the family's
   first byte, one-based, and the smart constructor rejects anything outside the
   family — so a byte outside the sixteen or thirty-two slots yields [None]
   rather than a nonsensical instruction. *)
let family first make of_int byte = Option.map make (of_int (byte - first + 1))

let decode byte =
  match byte with
  | 0x00 -> Some Stop
  | 0x01 -> Some Add
  | 0x02 -> Some Mul
  | 0x03 -> Some Sub
  | 0x04 -> Some Div
  | 0x05 -> Some Sdiv
  | 0x06 -> Some Mod
  | 0x07 -> Some Smod
  | 0x08 -> Some Addmod
  | 0x09 -> Some Mulmod
  | 0x0a -> Some Exp
  | 0x0b -> Some Signextend
  | 0x10 -> Some Lt
  | 0x11 -> Some Gt
  | 0x12 -> Some Slt
  | 0x13 -> Some Sgt
  | 0x14 -> Some Eq
  | 0x15 -> Some Iszero
  | 0x16 -> Some And
  | 0x17 -> Some Or
  | 0x18 -> Some Xor
  | 0x19 -> Some Not
  | 0x1a -> Some Byte
  | 0x1b -> Some Shl
  | 0x1c -> Some Shr
  | 0x1d -> Some Sar
  | 0x20 -> Some Keccak256
  | 0x30 -> Some Address
  | 0x31 -> Some Balance
  | 0x32 -> Some Origin
  | 0x33 -> Some Caller
  | 0x34 -> Some Callvalue
  | 0x35 -> Some Calldataload
  | 0x36 -> Some Calldatasize
  | 0x37 -> Some Calldatacopy
  | 0x38 -> Some Codesize
  | 0x39 -> Some Codecopy
  | 0x3a -> Some Gasprice
  | 0x3b -> Some Extcodesize
  | 0x3c -> Some Extcodecopy
  | 0x3d -> Some Returndatasize
  | 0x3e -> Some Returndatacopy
  | 0x3f -> Some Extcodehash
  | 0x41 -> Some Coinbase
  | 0x42 -> Some Timestamp
  | 0x43 -> Some Number
  | 0x44 -> Some Prevrandao
  | 0x45 -> Some Gaslimit
  | 0x46 -> Some Chainid
  | 0x47 -> Some Selfbalance
  | 0x48 -> Some Basefee
  | 0x50 -> Some Pop
  | 0x51 -> Some Mload
  | 0x52 -> Some Mstore
  | 0x53 -> Some Mstore8
  | 0x54 -> Some Sload
  | 0x55 -> Some Sstore
  | 0x56 -> Some Jump
  | 0x57 -> Some Jumpi
  | 0x58 -> Some Pc
  | 0x59 -> Some Msize
  | 0x5a -> Some Gas
  | 0x5b -> Some Jumpdest
  | 0x5c -> Some Tload
  | 0x5d -> Some Tstore
  | 0x5e -> Some Mcopy
  | 0x5f -> Some Push0
  | 0xa0 -> Some (Log Topic_count.Zero)
  | 0xa1 -> Some (Log Topic_count.One)
  | 0xa2 -> Some (Log Topic_count.Two)
  | 0xa3 -> Some (Log Topic_count.Three)
  | 0xa4 -> Some (Log Topic_count.Four)
  | 0xf1 -> Some Call
  | 0xf2 -> Some Callcode
  | 0xf4 -> Some Delegatecall
  | 0xfa -> Some Staticcall
  | 0xf3 -> Some Return
  | 0xfd -> Some Revert
  | 0xfe -> Some Invalid
  | b when b >= push1_byte && b < push1_byte + 32 ->
      family push1_byte (fun n -> Push n) Push_bytes.of_int b
  | b when b >= dup1_byte && b < dup1_byte + 16 ->
      family dup1_byte (fun d -> Dup d) Depth.of_int b
  | b when b >= swap1_byte && b < swap1_byte + 16 ->
      family swap1_byte (fun d -> Swap d) Depth.of_int b
  | _ -> None

(* Only a [PUSH1]–[PUSH32] carries immediate data, and its width is its operand.
   [PUSH0] pushes a constant and carries none. *)
let immediate_bytes = function
  | Push n -> Push_bytes.to_int n
  | Stop | Add | Mul | Sub | Div | Sdiv | Mod | Smod | Addmod | Mulmod | Exp
  | Signextend | Lt | Gt | Slt | Sgt | Eq | Iszero | And | Or | Xor | Not | Byte
  | Shl | Shr | Sar | Pop | Mload | Mstore | Mstore8 | Jump | Jumpi | Pc | Msize
  | Gas | Jumpdest | Push0 | Dup _ | Swap _ | Return | Revert | Invalid | Address
  | Balance | Origin | Caller | Callvalue | Calldataload | Calldatasize
  | Calldatacopy | Codesize | Codecopy | Extcodesize | Extcodecopy | Extcodehash
  | Gasprice | Coinbase | Timestamp | Number
  | Prevrandao | Gaslimit | Chainid | Selfbalance | Basefee | Sload | Sstore
  | Mcopy | Keccak256 | Tload | Tstore | Log _ | Returndatasize | Returndatacopy
  | Call | Callcode | Delegatecall | Staticcall ->
      0

(* Two instructions are equal exactly when they encode to the same byte — the
   encoding is injective, so this needs no case analysis. *)
let equal a b = Int.equal (to_byte a) (to_byte b)

let to_string = function
  | Stop -> "STOP"
  | Add -> "ADD"
  | Mul -> "MUL"
  | Sub -> "SUB"
  | Div -> "DIV"
  | Sdiv -> "SDIV"
  | Mod -> "MOD"
  | Smod -> "SMOD"
  | Addmod -> "ADDMOD"
  | Mulmod -> "MULMOD"
  | Exp -> "EXP"
  | Signextend -> "SIGNEXTEND"
  | Lt -> "LT"
  | Gt -> "GT"
  | Slt -> "SLT"
  | Sgt -> "SGT"
  | Eq -> "EQ"
  | Iszero -> "ISZERO"
  | And -> "AND"
  | Or -> "OR"
  | Xor -> "XOR"
  | Not -> "NOT"
  | Byte -> "BYTE"
  | Shl -> "SHL"
  | Shr -> "SHR"
  | Sar -> "SAR"
  | Pop -> "POP"
  | Mload -> "MLOAD"
  | Mstore -> "MSTORE"
  | Mstore8 -> "MSTORE8"
  | Jump -> "JUMP"
  | Jumpi -> "JUMPI"
  | Pc -> "PC"
  | Msize -> "MSIZE"
  | Gas -> "GAS"
  | Jumpdest -> "JUMPDEST"
  | Push0 -> "PUSH0"
  | Push n -> Printf.sprintf "PUSH%d" (Push_bytes.to_int n)
  | Dup d -> Printf.sprintf "DUP%d" (Depth.to_int d)
  | Swap d -> Printf.sprintf "SWAP%d" (Depth.to_int d)
  | Return -> "RETURN"
  | Revert -> "REVERT"
  | Invalid -> "INVALID"
  | Address -> "ADDRESS"
  | Balance -> "BALANCE"
  | Origin -> "ORIGIN"
  | Caller -> "CALLER"
  | Callvalue -> "CALLVALUE"
  | Calldataload -> "CALLDATALOAD"
  | Calldatasize -> "CALLDATASIZE"
  | Calldatacopy -> "CALLDATACOPY"
  | Codesize -> "CODESIZE"
  | Codecopy -> "CODECOPY"
  | Extcodesize -> "EXTCODESIZE"
  | Extcodecopy -> "EXTCODECOPY"
  | Extcodehash -> "EXTCODEHASH"
  | Gasprice -> "GASPRICE"
  | Coinbase -> "COINBASE"
  | Timestamp -> "TIMESTAMP"
  | Number -> "NUMBER"
  | Prevrandao -> "PREVRANDAO"
  | Gaslimit -> "GASLIMIT"
  | Chainid -> "CHAINID"
  | Selfbalance -> "SELFBALANCE"
  | Basefee -> "BASEFEE"
  | Sload -> "SLOAD"
  | Sstore -> "SSTORE"
  | Mcopy -> "MCOPY"
  | Keccak256 -> "KECCAK256"
  | Tload -> "TLOAD"
  | Tstore -> "TSTORE"
  | Log n -> Printf.sprintf "LOG%d" (Topic_count.to_int n)
  | Returndatasize -> "RETURNDATASIZE"
  | Returndatacopy -> "RETURNDATACOPY"
  | Call -> "CALL"
  | Callcode -> "CALLCODE"
  | Delegatecall -> "DELEGATECALL"
  | Staticcall -> "STATICCALL"
