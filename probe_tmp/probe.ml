open Tn_types
module U256 = Tn_state.U256
module Env = Tn_evm.Env
module Gas = Tn_evm.Gas
module Code = Tn_evm.Code
module Opcode = Tn_evm.Opcode
module Interpreter = Tn_evm.Interpreter
module Effects = Tn_evm.Effects
module Access = Tn_evm.Access
module Data = Tn_evm.Data
module Mutability = Tn_evm.Mutability
module Memory = Tn_evm.Memory
module Topic_count = Tn_evm.Topic_count
module World_state = Tn_state.World_state

let address_of b = Option.get (Units.Address.of_bytes (String.make 20 (Char.chr b)))
let self = address_of 0x11
let caller = address_of 0x22
let origin = address_of 0x33
let coinbase = address_of 0xc0
let u n = Option.get (U256.of_int n)

let base_block =
  Env.Block.make ~coinbase ~timestamp:(u 1) ~number:(u 2) ~prevrandao:U256.zero
    ~gas_limit:(u 30_000_000) ~basefee:(u 7) ~chain_id:(u 1)

let base_tx = Env.Tx.make ~origin ~gas_price:(u 1) ~access_list:[]

let env mut =
  Env.make ~block:base_block ~tx:base_tx
    ~call:
      (Env.Call.make ~target:self ~caller ~value:U256.zero ~data:Data.empty
         ~mutability:mut)

let byte b = String.make 1 (Char.chr b)
let op o = byte (Opcode.to_byte o)
let width_of n = Option.get (Opcode.Push_bytes.of_int n)
let push1 n = op (Opcode.Push (width_of 1)) ^ byte n
let push32 w = op (Opcode.Push (width_of 32)) ^ U256.to_be_bytes w
let asm parts = Code.of_string (String.concat "" parts)
let effects () = Effects.start ~world:World_state.empty ~access:Access.empty

let run ?(mut = Mutability.Mutable) ~gas code =
  Interpreter.run ~env:(env mut) ~code ~gas:(Option.get (Gas.of_int gas))
    ~effects:(effects ())

let () =
  (* 256 MiB KECCAK256 window. Expansion for 2^23 words is 137_464_119_296 gas,
     which is a legal Gas.t but ~4600 whole block limits. *)
  let len = 1 lsl 28 in
  let t0 = Unix.gettimeofday () in
  let outcome =
    run ~gas:200_000_000_000
      (asm [ push32 (u len); push1 0x00; op Opcode.Keccak256 ])
  in
  Printf.printf "keccak len=2^28 gas=2e11 -> %s   (%.1fs)\n%!"
    (Interpreter.outcome_to_string outcome)
    (Unix.gettimeofday () -. t0)
