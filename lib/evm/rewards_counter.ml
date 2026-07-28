(* RewardsCounter (gas_accumulator.rs:94-174) as a persistent record. The
   Rust value is a pair of shared handles (Arc<Mutex<HashMap>> counts,
   Arc<RwLock<Option<Committee>>> committee) mutated in place; here the
   engine's fold threads a new value instead, and every operation is the
   image of exactly one Rust method. *)

module Address_map = Map.Make (Tn_types.Units.Address)

type t = {
  committee : Tn_types.Committee.t option;
  counts : int Tn_types.Authority_id.Map.t;
}

let empty = { committee = None; counts = Tn_types.Authority_id.Map.empty }

(* inc_leader_count (gas_accumulator.rs:100-107): +1, inserting 1 if absent. *)
let inc_leader_count t leader =
  {
    t with
    counts =
      Tn_types.Authority_id.Map.update leader
        (fun c -> Some (Option.value c ~default:0 + 1))
        t.counts;
  }

let set_committee t committee = { t with committee = Some committee }

(* clear (gas_accumulator.rs:109-113) takes only the counts lock: the
   committee survives the epoch-boundary reset. *)
let clear t = { t with counts = Tn_types.Authority_id.Map.empty }

(* get_address_counts (gas_accumulator.rs:122-142). The source HashMap's
   iteration order is arbitrary in Rust and ascending-id here; neither can be
   observed, because a shared-address collision merges by SUM (order-blind)
   and the output order is the address-keyed map's own ascending byte order,
   which is BTreeMap<Address>'s ordering. An authority the committee cannot
   resolve contributes nothing (the `if let Some(auth)` skip), and a missing
   committee yields the empty map (the silent None arm). *)
let address_counts t =
  Option.fold ~none:[]
    ~some:(fun committee ->
      Tn_types.Authority_id.Map.fold
        (fun leader count merged ->
          Tn_types.Committee.authority committee leader
          |> Option.fold ~none:merged ~some:(fun auth ->
                 Address_map.update
                   (Tn_types.Authority.execution_address auth)
                   (fun c -> Some (Option.value c ~default:0 + count))
                   merged))
        t.counts Address_map.empty
      |> Address_map.bindings)
    t.committee

type error = Negative_amount of { address : Tn_types.Units.Address.t; amount : int }

let error_to_string (Negative_amount { address; amount }) =
  Printf.sprintf "generate_withdrawals: negative amount %d for 0x%s" amount
    (Hex.of_bytes (Tn_types.Units.Address.to_bytes address))

(* generate_withdrawals (gas_accumulator.rs:144-158): the address_counts
   entries in their ascending-address order, each becoming a record with
   index 0, validator_index 0 and the RAW count as amount. Withdrawal.make
   refuses negatives, which counts cannot be; the refusal is surfaced as the
   error rather than discharged. *)
let generate_withdrawals t =
  List.fold_left
    (fun acc (address, amount) ->
      Result.bind acc (fun ws ->
          Withdrawal.make ~index:0 ~validator_index:0 ~address ~amount
          |> Option.to_result ~none:(Negative_amount { address; amount })
          |> Result.map (fun w -> w :: ws)))
    (Ok []) (address_counts t)
  |> Result.map List.rev
