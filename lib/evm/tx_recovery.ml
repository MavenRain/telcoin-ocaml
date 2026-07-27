(* Sender recovery, a port of alloy-consensus 1.8.3 [src/signed.rs:480-516] and
   [src/crypto.rs:219-251]. Policy only: the EIP-2 gate, the digest re-derived
   from the payload, and the raw 0/1 parity as the recovery id. The curve is
   {!Secp256k1} and the address derivation is {!Public_key}. *)

module W = Tn_state.U256

type error = High_s | Unrecoverable

let error_to_string e =
  match e with
  | High_s -> "signature s exceeds secp256k1n/2 (EIP-2)"
  | Unrecoverable -> "no public key recovers this signature"

let recover_signer env =
  let sg = Tx_envelope.signature env in
  (* FIXED 32-byte scalars here, unlike the RLP path, which trims them
     ([crypto.rs:223-226]). *)
  let s_bytes = W.to_be_bytes (Tx_signature.s sg) in
  if Secp256k1.s_is_high s_bytes then Error High_s
  else
    Secp256k1.recover
      ~msg:(Tx_envelope.signature_hash (Tx_envelope.payload env))
      ~recid:(if Tx_signature.parity sg then 1 else 0)
      ~r:(W.to_be_bytes (Tx_signature.r sg))
      ~s:s_bytes
    |> fun key ->
    Option.bind key Public_key.to_address
    |> Option.fold ~none:(Error Unrecoverable) ~some:Result.ok

let recover env =
  Result.map
    (fun sender -> Tx_payload.to_transaction (Tx_envelope.payload env) ~sender)
    (recover_signer env)
