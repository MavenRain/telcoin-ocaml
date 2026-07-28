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

(* PER_EMPTY_ACCOUNT_COST ([revm-primitives] [eip7702.rs:5-9]), wired under
   PRAGUE at [cfg/gas_params.rs:306-311]. Not 12500: PER_AUTH_BASE_COST is never
   charged, it is only the refund difference. *)
let per_empty_account_cost = 25000

let initial_gas ~kind ~data ~access_list ~authorizations =
  let addresses = List.length access_list in
  let slots =
    List.fold_left (fun acc (_, slots) -> acc + List.length slots) 0 access_list
  in
  (* The authorization term counts the LISTED entries, never the applied ones:
     [calculate_initial_tx_gas] receives [tx.authorization_list_len()]
     ([cfg/gas.rs:181-188]) and sums it at [cfg/gas_params.rs:729-731], so a
     later-skipped entry still costs the full 25000. *)
  let shared =
    (tokens data * 4) + (2400 * addresses) + (1900 * slots) + 21000
    + (List.length authorizations * per_empty_account_cost)
  in
  match kind with
  | Call -> shared
  | Create -> shared + 32000 + (2 * num_words (String.length data))

let floor_gas ~data = (tokens data * 10) + 21000
