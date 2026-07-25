open Tn_types
module U256 = Tn_state.U256

type word = U256.t

type kind = Call | Create

(* The number of 32-byte words a byte length spans, rounded up, with zero words
   for an empty length ([gas_params.rs:50-52]). Written with integer arithmetic
   rather than a division helper so the [div_ceil] and the [len = 0 -> 0] cases
   are both visible. *)
let num_words len = if len <= 0 then 0 else (len + 31) / 32

let tokens data =
  let zero_bytes =
    String.fold_left (fun acc c -> if Char.equal c '\000' then acc + 1 else acc) 0 data
  in
  let nonzero_bytes = String.length data - zero_bytes in
  zero_bytes + (4 * nonzero_bytes)

let initial_gas ~kind ~data ~access_list =
  let addresses = List.length access_list in
  let slots =
    List.fold_left (fun acc (_, slots) -> acc + List.length slots) 0 access_list
  in
  let shared =
    (tokens data * 4) + (2400 * addresses) + (1900 * slots) + 21000
  in
  match kind with
  | Call -> shared
  | Create -> shared + 32000 + (2 * num_words (String.length data))

let floor_gas ~data = (tokens data * 10) + 21000
