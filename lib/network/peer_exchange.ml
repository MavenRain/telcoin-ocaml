module Bcs = Tn_codec.Bcs

type entry = {
  key : Bls_public_key.t;
  network_key : Var_bytes.t;
  multiaddrs : Var_bytes.t list;
}

type t = entry list
type error = Duplicate_key

let error_to_string = function
  | Duplicate_key -> "peer exchange: duplicate map key"

(* First-occurrence order, duplicates dropped: what Rust's HashSet collect
   does to a sequence, without imposing an order the wire does not carry. *)
let dedup addrs =
  List.rev
    (List.fold_left
       (fun acc a ->
         if List.exists (fun b -> Var_bytes.equal a b) acc then acc else a :: acc)
       [] addrs)

let make_entry ~key ~network_key ~multiaddrs =
  { key; network_key; multiaddrs = dedup multiaddrs }

let empty = []

(* bcs orders map keys by their ENCODED bytes (ser.rs:545). For a uniform
   96-byte key that is the same order as the raw bytes, but the codec-derived
   comparator states the rule rather than relying on the coincidence. *)
let key_compare = Bcs.encoded_compare Bls_public_key.codec

let of_entries es =
  let sorted = List.stable_sort (fun a b -> key_compare a.key b.key) es in
  let rec check = function
    | [] -> Ok sorted
    | [ _ ] -> Ok sorted
    | a :: (b :: _ as rest) ->
        if Bls_public_key.equal a.key b.key then Error Duplicate_key
        else check rest
  in
  check sorted

let entries t = t

let value_codec : (Var_bytes.t * Var_bytes.t list) Bcs.t =
  Bcs.pair Var_bytes.codec (Bcs.unordered_list Var_bytes.codec)

let codec : t Bcs.t =
  Bcs.iso
    ~inject:(fun pairs ->
      List.map
        (fun (key, (network_key, multiaddrs)) ->
          { key; network_key; multiaddrs = dedup multiaddrs })
        pairs)
    ~project:(List.map (fun e -> (e.key, (e.network_key, e.multiaddrs))))
    (Bcs.sorted_map Bls_public_key.codec value_codec ~compare:key_compare)

let entry_equal a b =
  Bls_public_key.equal a.key b.key
  && Var_bytes.equal a.network_key b.network_key
  && List.equal Var_bytes.equal a.multiaddrs b.multiaddrs

let equal a b = List.equal entry_equal a b
