(* Merkle-Patricia-Trie roots. The builder is the recursive group-by-nibble
   construction over the complete, sorted, de-duplicated key set; it yields the
   same roots as reth's streaming HashBuilder but is total and terminating. The
   root is always keccak256 of the root node's RLP (alloy-trie 0.9.5
   src/hash_builder/mod.rs:212-218); the inline-versus-hash rule applies to
   children only, never to the top. *)

module Rlp = Tn_rlp.Rlp
module U256 = Tn_state.U256

type error = Duplicate_key of string

let error_to_string = function Duplicate_key k -> "duplicate key: " ^ k

(* keccak256(rlp("")) = keccak256(0x80). A hard-coded literal in reth
   (src/lib.rs:50-51); computed here so the wiring test can cross-check it
   against that published constant. *)
let empty_root = Tn_keccak.to_bytes (Tn_keccak.digest "\x80")

(* The last element of a list, or [None] when empty. *)
let rec last_of = function [] -> None | [ x ] -> Some x | _ :: tl -> last_of tl

(* Build a node from the [(nibble path, value)] pairs of a group, all of which
   already share their first [depth] nibbles. The list is sorted and duplicate
   free, so a singleton is a leaf, a positive shared prefix is an extension, and
   divergence is a branch — with a key that ends exactly at [depth] taking the
   branch's value slot. *)
let rec build depth pairs =
  match pairs with
  | [] -> Node.Empty (* reached only by [root []], never as a child *)
  | [ (k, v) ] -> Node.Leaf { path = Nibbles.drop k depth; value = v }
  | (first_k, _) :: _ :: _ -> (
      (* [pairs] has at least two elements, so [last_of] is [Some]; the sorted
         order makes first and last the lexicographic extremes, whose common
         prefix is the whole group's. *)
      match last_of pairs with
      | None -> Node.Empty
      | Some (last_k, _) ->
          let lcp = Nibbles.common_prefix_len first_k last_k ~from:depth in
          if lcp > 0 then
            Node.Extension
              {
                path = Nibbles.sub first_k ~pos:depth ~len:lcp;
                child = Node.to_ref (build (depth + lcp) pairs);
              }
          else
            (* A key exhausted at [depth] (length = depth) forced [lcp] to 0; it
               takes the value slot, the rest are grouped by their nibble at
               [depth]. Post-dedup at most one key is exhausted. *)
            let exhausted, rest =
              List.partition (fun (k, _) -> Nibbles.length k = depth) pairs
            in
            let value16 = match exhausted with [] -> None | (_, v) :: _ -> Some v in
            let children =
              Array.init 16 (fun i ->
                  match List.filter (fun (k, _) -> Nibbles.nth_opt k depth = Some i) rest with
                  | [] -> None
                  | _ :: _ as group -> Some (Node.to_ref (build (depth + 1) group)))
            in
            Node.Branch { children; value = value16 })

(* The offending key of the first adjacent-equal pair in a sorted list. *)
let rec find_dup = function
  | [] -> None
  | [ _ ] -> None
  | (a, _) :: (((b, _) :: _) as tl) -> if Nibbles.compare a b = 0 then Some a else find_dup tl

let check_unique sorted =
  Option.fold ~none:(Ok sorted)
    ~some:(fun k -> Error (Duplicate_key (Nibbles.to_hex k)))
    (find_dup sorted)

let cmp (a, _) (b, _) = Nibbles.compare a b

(* Hash an already-sorted, unique group. Always keccak256 of the root RLP, even
   under 32 bytes; the empty group is the empty root. *)
let hash_sorted = function
  | [] -> empty_root
  | _ :: _ as sorted -> Tn_keccak.to_bytes (Tn_keccak.digest (Node.encode (build 0 sorted)))

let hash_pairs pairs = hash_sorted (List.sort cmp pairs)

let root kvs =
  let sorted = List.sort cmp (List.map (fun (k, v) -> (Nibbles.unpack k, v)) kvs) in
  Result.map hash_sorted (check_unique sorted)

let secure_root_of kvs =
  root (List.map (fun (k, v) -> (Tn_keccak.to_bytes (Tn_keccak.digest k), v)) kvs)

(* alloy-trie src/root.rs:8-16. RLP(index) does not sort in index order across
   the one-byte/multi-byte boundary; this permutation visits the keys in
   nibble-sorted order so the streaming builder's strictly-ascending precondition
   holds. The recursive builder sorts anyway, so the permutation only needs to
   preserve the (index, value) pairing. *)
let adjust_index_for_rlp i len =
  if i > 0x7f then i else if i = 0x7f || i + 1 = len then 0 else i + 1

let ordered_pairs ~wrap items =
  let arr = Array.of_list items in
  let n = Array.length arr in
  let get j = if j >= 0 && j < n then Array.get arr j else "" in
  List.init n (fun i ->
      let j = adjust_index_for_rlp i n in
      (Nibbles.unpack (Rlp.encode_nat j), wrap (get j)))

let ordered_trie_root items = hash_pairs (ordered_pairs ~wrap:Fun.id items)
let ordered_trie_root_rlp items = hash_pairs (ordered_pairs ~wrap:Rlp.encode_bytes items)

let account_rlp ~nonce ~balance ~storage_root ~code_hash =
  Rlp.encode_list
    [
      Rlp.encode_nat nonce;
      Rlp.encode_scalar (U256.to_be_bytes balance);
      Rlp.encode_bytes storage_root;
      Rlp.encode_bytes code_hash;
    ]
