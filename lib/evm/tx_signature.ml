(* The transaction signature and the EIP-155 [v] mapping, a port of
   alloy-primitives 1.5.7 [src/signature/sig.rs:14-22,113-117] and
   alloy-consensus 1.8.3 [src/transaction/legacy.rs:398-422]. No validation
   anywhere: the reference performs none at this layer and a stricter
   constructor would reject transactions the network accepts. *)

module W = Tn_state.U256

type word = W.t
type t = { parity : bool; r : word; s : word }

let make ~parity ~r ~s = { parity; r; s }
let parity t = t.parity
let r t = t.r
let s t = t.s

(* Small constants. Every literal below is a non-negative native [int], which is
   exactly what [of_int] accepts, so each default is unreachable. *)
let word_of_int n = Option.value ~default:W.zero (W.of_int n)
let two = word_of_int 2
let twenty_seven = word_of_int 27
let twenty_eight = word_of_int 28
let thirty_five = word_of_int 35

(* [2^64 - 1]. alloy's [ChainId] is a [u64], so a chain id derived from [v] above
   this is rejected ([legacy.rs:414-416]). The literal is exactly the 32 bytes
   [of_be_bytes] accepts, so the default is unreachable. *)
let u64_max =
  Option.value ~default:W.zero
    (W.of_be_bytes (String.make 24 '\000' ^ String.make 8 '\255'))

let to_eip155_value ~parity ~chain_id =
  let bit = if parity then W.one else W.zero in
  Option.fold
    ~none:(if parity then twenty_eight else twenty_seven)
    ~some:(fun id -> W.add thirty_five (W.add (W.mul two id) bit))
    chain_id

let of_eip155_value v =
  if W.equal v twenty_seven then Some (false, None)
  else if W.equal v twenty_eight then Some (true, None)
  else if W.compare v thirty_five < 0 then None
  else
    (* [(v - 35)] split into its low bit (the parity) and the rest halved (the
       chain id) — alloy's [% 2] and [/ 2] over the same difference. *)
    let d = W.sub v thirty_five in
    let chain_id = W.shr d W.one in
    if W.compare chain_id u64_max > 0 then None
    else Some (W.equal (W.logand d W.one) W.one, Some chain_id)
