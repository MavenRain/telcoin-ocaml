module W = Tn_state.U256

let depth_limit = 256

(* Newest first, already truncated to [depth_limit] by {!of_recent}, so the
   index of a hash is one less than the difference between the current block and
   the one it belongs to. *)
type t = Tn_keccak.t list

let empty = []
let of_recent hashes = List.filteri (fun i _ -> i < depth_limit) hashes

(* The word a digest reads as. The default is unreachable: a digest is
   [Tn_keccak.length] bytes, exactly the width [of_be_bytes] accepts. *)
let word_of_digest digest =
  Option.value ~default:W.zero (W.of_be_bytes (Tn_keccak.to_bytes digest))

let lookup t ~current ~requested =
  Option.fold ~none:W.zero
    ~some:(fun difference ->
      (* A difference too large to be an [int] is far past [depth_limit], so it
         reads zero by the same rule that rejects a difference of 257. *)
      Option.fold ~none:W.zero
        ~some:(fun d ->
          if d < 1 || d > depth_limit then W.zero
          else Option.fold ~none:W.zero ~some:word_of_digest (List.nth_opt t (d - 1)))
        (W.to_int difference))
    (W.checked_sub current requested)

let equal a b = List.equal Tn_keccak.equal a b
