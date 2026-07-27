open Tn_types

type halt_reason =
  | Frame_halt of Interpreter.error
  | Create_collision
  | Create_reserved_prefix
  | Create_code_size_limit of int
  | Create_deposit_out_of_gas
  | Create_nonce_exhausted
  | Value_overflow

let halt_reason_to_string = function
  | Frame_halt error -> "frame halt: " ^ Interpreter.error_to_string error
  | Create_collision -> "create collision"
  | Create_reserved_prefix -> "create reserved prefix (0xEF)"
  | Create_code_size_limit length ->
      Printf.sprintf "create code size limit (%d bytes)" length
  | Create_deposit_out_of_gas -> "create deposit out of gas"
  | Create_nonce_exhausted -> "create nonce exhausted"
  | Value_overflow -> "value overflow"

type t =
  | Success of {
      output : string;
      created : Units.Address.t option;
      gas_used : int;
      gas_refunded : int;
      logs : Log.t list;
    }
  | Reverted of { output : string; gas_used : int }
  | Halted of { reason : halt_reason; gas_used : int }

let gas_used = function
  | Success s -> s.gas_used
  | Reverted r -> r.gas_used
  | Halted h -> h.gas_used

(* Three arms and no wildcard: a revert rolls the journal back and a halt
   forfeits everything, so both are the empty list rather than a case every
   caller has to remember. *)
let logs = function Success s -> s.logs | Reverted _ -> [] | Halted _ -> []

let to_string = function
  | Success s ->
      Printf.sprintf "Success{gas_used=%d; gas_refunded=%d; logs=%d}" s.gas_used
        s.gas_refunded (List.length s.logs)
  | Reverted r -> Printf.sprintf "Reverted{gas_used=%d}" r.gas_used
  | Halted h ->
      Printf.sprintf "Halted{%s; gas_used=%d}" (halt_reason_to_string h.reason)
        h.gas_used
