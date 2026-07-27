(* The packed difficulty word. Storing the word rather than the pair is what
   makes [of_word] total and [is_first_batch] telcoin's own comparison. *)

type t = Tn_state.U256.t

let worker_id_bits = 16
let of_word word = word
let word t = t

(* The packing is done in the native [int] and then lifted, so the two failure
   modes ([batch_index] negative, or its shift leaving the [int]) are decided
   before any word exists. [max_int lsr worker_id_bits] is the largest index
   whose shift stays non-negative, so [U256.of_int] below is always [Some]; it
   is returned as the option rather than collapsed, since fabricating a default
   word here would fabricate a position. *)
let of_batch ~batch_index ~worker_id =
  match batch_index >= 0 && batch_index <= max_int lsr worker_id_bits with
  | false -> None
  | true ->
      Tn_state.U256.of_int
        ((batch_index lsl worker_id_bits)
        lor Tn_types.Units.Worker_id.to_int worker_id)

(* [U256.two_pow 16] is total and exactly 65536, so the bound needs no option
   to dispose of. *)
let first_batch_bound = Tn_state.U256.two_pow worker_id_bits
let is_first_batch t = Tn_state.U256.compare t first_batch_bound < 0

let batch_index t =
  Option.map (fun n -> n lsr worker_id_bits) (Tn_state.U256.to_int t)

let worker_id t =
  Option.bind (Tn_state.U256.to_int t) (fun n ->
      Tn_types.Units.Worker_id.of_int (n land 0xffff))

let equal = Tn_state.U256.equal
