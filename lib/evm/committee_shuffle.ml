(* shuffle_new_committee (block.rs:428-482), transliterated. Everything that
   consumes randomness happens in Rust's exact order on Rust's exact values:
   the optional choose_multiple top-up first, then the Fisher-Yates over the
   assembled VALIDATOR STRUCTS (addresses are extracted only after the
   shuffle, block.rs:474-475), then the truncate. No sort anywhere: the
   ascending sort telcoin applies to the committee is an encode-time step of
   the concludeEpoch calldata (block.rs:394-395), not part of the shuffle. *)

module Std_rng = Tn_rand.Std_rng
module Rand_seq = Tn_rand.Rand_seq

(* The partition predicate of block.rs:448-450: PendingExit peels off,
   everything else (Active AND PendingActivation) stays on the shuffle side. *)
let is_pending_exit v =
  Registry_abi.Validator_status.equal
    (Registry_abi.Validator_info.current_status v)
    Registry_abi.Validator_status.Pending_exit

(* A persistent swap of slots [i] and [j]: a gather where each output
   position reads the element it needs (the discipline of u256.ml:95-99).
   [Option.value ~default:x] keeps the reads total although they cannot miss:
   both indices are within the list on every call ([j <= i <= len - 1]). *)
let swap i j l =
  List.mapi
    (fun k x ->
      if k = i then Option.value (List.nth_opt l j) ~default:x
      else if k = j then Option.value (List.nth_opt l i) ~default:x
      else x)
    l

(* `for i in (1..len).rev() { let j = rng.random_range(0..=i); swap(i, j) }`
   (block.rs:466-470). [i >= 1] on every draw, so [Negative_bound] is
   unreachable; its fold arm returns the list as it stands, keeping the
   function total without inventing an error surface Rust does not have. *)
let rec fisher_yates l rng i =
  if i < 1 then (l, rng)
  else
    Std_rng.random_range_inclusive rng ~bound:i
    |> Result.fold
         ~ok:(fun (j, rng) -> fisher_yates (swap i j l) rng (i - 1))
         ~error:(fun (Std_rng.Negative_bound _) -> (l, rng))

(* Vec::truncate: the first [n] elements; total, a non-positive [n] keeps
   nothing. *)
let truncate n l = List.filteri (fun i _ -> i < n) l

let shuffle ~pool ~committee_size ~randomness =
  let rng = Std_rng.of_randomness randomness in
  let pending_exit, active = List.partition is_pending_exit pool in
  let active_count = List.length active in
  (* block.rs:453-464: enough active validators means the pending-exit side
     is dropped whole and the RNG is untouched; otherwise the top-up draw
     consumes the RNG BEFORE the shuffle. No size check in either arm. *)
  let for_shuffle, rng =
    if active_count >= committee_size then (active, rng)
    else
      let picked, rng =
        Rand_seq.choose_multiple rng ~amount:(committee_size - active_count) pending_exit
      in
      (active @ picked, rng)
  in
  let shuffled, _rng = fisher_yates for_shuffle rng (List.length for_shuffle - 1) in
  truncate committee_size (List.map Registry_abi.Validator_info.validator_address shuffled)
