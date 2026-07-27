(* The close-epoch decision and the three header fields it decides. The
   [commitment] record is deliberately built in one match, so the extra data,
   the withdrawal list and the withdrawals root are produced together or not at
   all. *)

type t = Open | Closing of { randomness : Hash32.t; withdrawals : Withdrawal.t list }

let is_closing = function Open -> false | Closing _ -> true

(* Four arms over the product of two two-constructor sums: no wildcard, so
   adding a third boundary shape is a compile error here. *)
let equal a b =
  match (a, b) with
  | Open, Open -> true
  | Open, Closing _ -> false
  | Closing _, Open -> false
  | Closing x, Closing y ->
      Hash32.equal x.randomness y.randomness
      && List.equal Withdrawal.equal x.withdrawals y.withdrawals

type error = Extra_data_length of int | Withdrawals_without_close of int

let error_to_string = function
  | Extra_data_length length ->
      Printf.sprintf "extra data length %d (expected 0 or 32)" length
  | Withdrawals_without_close count ->
      Printf.sprintf "%d withdrawals on an open boundary" count

(* The 0/32/error length discipline of [config.rs:157-167]. The [Hash32.of_bytes]
   below cannot be [None] on this branch (the length was just tested), but it is
   threaded with [Option.to_result] rather than defaulted, so the width stays a
   checked fact and the impossible case names a length rather than fabricating
   a randomness value. *)
let of_extra_data extra ~withdrawals =
  let length = String.length extra in
  if length = 0 then
    match withdrawals with
    | [] -> Ok Open
    | _ :: _ -> Error (Withdrawals_without_close (List.length withdrawals))
  else if length = Hash32.length then
    Hash32.of_bytes extra
    |> Option.to_result ~none:(Extra_data_length length)
    |> Result.map (fun randomness -> Closing { randomness; withdrawals })
  else Error (Extra_data_length length)

type commitment = {
  extra_data : string;
  withdrawals : Withdrawal.t list;
  withdrawals_root : string;
}

(* [Trie.empty_root] rather than [Block_roots.withdrawals_root []] on the open
   branch: it is the constant telcoin writes ([EMPTY_WITHDRAWALS]), and the two
   agree by [ordered_trie_root]'s own empty case. The inline record is
   destructured in the pattern so no field access has to be disambiguated
   against this record's [withdrawals] label. *)
let commitment = function
  | Open ->
      { extra_data = ""; withdrawals = []; withdrawals_root = Tn_trie.Trie.empty_root }
  | Closing { randomness; withdrawals } ->
      {
        extra_data = Hash32.to_bytes randomness;
        withdrawals;
        withdrawals_root = Block_roots.withdrawals_root withdrawals;
      }

let extra_data c = c.extra_data
let withdrawals c = c.withdrawals
let withdrawals_root c = c.withdrawals_root
