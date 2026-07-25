(* Trie node RLP and the child-collapse rule, ported from alloy-trie 0.9.5
   (src/nodes/{leaf,extension,branch,rlp}.rs). A value is wrapped once with
   [encode_bytes] (never the scalar rule); a child under 32 bytes is inlined,
   else replaced by its [0xa0]-prefixed hash. *)

module Rlp = Tn_rlp.Rlp

type child_ref = string

type t =
  | Empty
  | Leaf of { path : Nibbles.t; value : string }
  | Extension of { path : Nibbles.t; child : child_ref }
  | Branch of { children : child_ref option array; value : string option }

(* The empty node is the empty string's RLP. *)
let empty_encoding = "\x80"

(* An absent branch child and an empty value slot both encode as [0x80]. *)
let absent = "\x80"

let encode = function
  | Empty -> empty_encoding
  | Leaf { path; value } ->
      Rlp.encode_list
        [ Rlp.encode_bytes (Hex_prefix.encode path ~is_leaf:true); Rlp.encode_bytes value ]
  | Extension { path; child } ->
      (* The child reference is already RLP; it is spliced verbatim, not
         re-wrapped (alloy-trie extension.rs:108). *)
      Rlp.encode_list [ Rlp.encode_bytes (Hex_prefix.encode path ~is_leaf:false); child ]
  | Branch { children; value } ->
      let slot = function None -> absent | Some c -> c in
      let value_slot = match value with None -> absent | Some v -> Rlp.encode_bytes v in
      Rlp.encode_list (Array.to_list (Array.map slot children) @ [ value_slot ])

let to_ref n =
  let r = encode n in
  if String.length r < 32 then r else "\xa0" ^ Tn_keccak.to_bytes (Tn_keccak.digest r)
