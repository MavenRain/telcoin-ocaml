(* The EIP-4895 withdrawal record. The three scalars are native ints checked
   non-negative at construction, because [Rlp.encode_nat] is total and would
   encode a negative value as the number zero ([rlp.mli:82-86]) rather than
   refuse it. *)

type t = {
  index : int;
  validator_index : int;
  address : Tn_types.Units.Address.t;
  amount : int;
}

let make ~index ~validator_index ~address ~amount =
  match index >= 0 && validator_index >= 0 && amount >= 0 with
  | false -> None
  | true -> Some { index; validator_index; address; amount }

let index t = t.index
let validator_index t = t.validator_index
let address t = t.address
let amount t = t.amount

(* Scalars take the number rule ([encode_nat], leading zeros stripped) and the
   address takes the byte-string rule ([encode_bytes], leading zeros PRESERVED,
   so a low address still occupies its 20 bytes). Conflating the two is the
   classic RLP bug [rlp.mli:15-17] names. *)
let encode_rlp t =
  Tn_rlp.Rlp.encode_list
    [
      Tn_rlp.Rlp.encode_nat t.index;
      Tn_rlp.Rlp.encode_nat t.validator_index;
      Tn_rlp.Rlp.encode_bytes (Tn_types.Units.Address.to_bytes t.address);
      Tn_rlp.Rlp.encode_nat t.amount;
    ]

let equal a b =
  a.index = b.index
  && a.validator_index = b.validator_index
  && Tn_types.Units.Address.equal a.address b.address
  && a.amount = b.amount

let hex_digit n = String.get "0123456789abcdef" n

let to_hex s =
  String.init
    (2 * String.length s)
    (fun j ->
      let b = Char.code (String.get s (j / 2)) in
      let nibble = if j land 1 = 0 then b lsr 4 else b land 0x0f in
      hex_digit nibble)

let to_string t =
  Printf.sprintf "Withdrawal{index=%d; validator_index=%d; address=%s; amount=%d}"
    t.index t.validator_index
    (to_hex (Tn_types.Units.Address.to_bytes t.address))
    t.amount
