(* Hex-prefix (compact) encoding, ported from alloy-trie 0.9.5
   src/nodes/mod.rs:224-244. The flag high nibble is [0x20] for a leaf plus
   [0x10] for an odd length; an odd path folds its first nibble into the flag
   byte's low nibble and packs the rest. *)

type error = Empty_input

let error_to_string = function Empty_input -> "hex-prefix decode of empty input"

let leaf_flag = 0x20
let odd_flag = 0x10

let encode path ~is_leaf =
  let odd = Nibbles.length path land 1 = 1 in
  let flag = (if is_leaf then leaf_flag else 0) lor if odd then odd_flag else 0 in
  (* On an odd path the first nibble is real (length >= 1); the [None] branch is
     only reached on an even path, where [first] is unused. *)
  let first = match Nibbles.nth_opt path 0 with Some x -> x | None -> 0 in
  let byte0 = if odd then flag lor first else flag in
  let rest = Nibbles.pack (if odd then Nibbles.drop path 1 else path) in
  String.make 1 (Char.chr byte0) ^ rest

let decode s =
  if String.length s = 0 then Error Empty_input
  else
    let flag = Char.code (String.get s 0) in
    let is_leaf = flag land leaf_flag <> 0 in
    let odd = flag land odd_flag <> 0 in
    let rest = Nibbles.to_list (Nibbles.unpack (String.sub s 1 (String.length s - 1))) in
    let nibbles = if odd then (flag land 0x0f) :: rest else rest in
    Ok (Nibbles.of_int_list nibbles, is_leaf)
