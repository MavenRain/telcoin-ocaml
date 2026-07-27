(* The EIP-2718 receipt leaf encoder, a port of alloy-consensus'
   [eip2718_encode_with_bloom] ([src/receipt/receipt2.rs:95-100,144-156]). The
   field order is [status, cumulative_gas_used, bloom, logs]; the inner list is
   NOT re-wrapped; legacy carries no type byte, typed prepends exactly one. *)

let status r =
  match r with
  | Receipt.Success _ -> true
  | Receipt.Reverted _ | Receipt.Halted _ -> false

(* Only a success carries logs: a revert keeps none and a halt keeps none. The
   three-arm match is exhaustive over {!Receipt.t}. *)
let logs_of r =
  match r with
  | Receipt.Success { logs; _ } -> logs
  | Receipt.Reverted _ | Receipt.Halted _ -> []

(* One log is [RLP([address, topics, data])]: address a 20-byte string, each
   topic a FIXED 32-byte string (not scalar-trimmed), data a byte string
   (alloy-primitives [src/log/mod.rs:191-201]). *)
let encode_log log =
  let addr = Tn_rlp.Rlp.encode_bytes (Tn_types.Units.Address.to_bytes (Log.address log)) in
  let topics =
    Log.Topics.to_list (Log.topics log)
    |> List.map (fun topic -> Tn_rlp.Rlp.encode_bytes (Tn_state.U256.to_be_bytes topic))
    |> Tn_rlp.Rlp.encode_list
  in
  let data = Tn_rlp.Rlp.encode_bytes (Log.data log) in
  Tn_rlp.Rlp.encode_list [ addr; topics; data ]

let encode_2718 ~type_byte ~cumulative_gas_used r =
  let logs = logs_of r in
  let inner =
    Tn_rlp.Rlp.encode_list
      [
        Tn_rlp.Rlp.encode_nat (if status r then 1 else 0);
        (* true -> 0x01, false -> 0x80 *)
        Tn_rlp.Rlp.encode_nat cumulative_gas_used;
        Tn_rlp.Rlp.encode_bytes (Bloom.to_bytes (Bloom.of_logs logs));
        (* 0xb90100 || 256B *)
        Tn_rlp.Rlp.encode_list (List.map encode_log logs);
      ]
  in
  (* The type-byte rule is {!Eip2718.frame}, shared verbatim with the
     transaction envelope so the two sides cannot drift. *)
  Eip2718.frame ~type_byte inner
