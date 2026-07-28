(* Tests for sender recovery (Tn_evm.Tx_recovery): the EIP-2 low-s gate, the
   digest re-derived from the payload, and the recovered address.

   Independent oracle: Tx_vectors, whose `sender` field is what alloy's
   `recover_signer` returned for each fixture, and whose fixture 1 is the EIP-155
   specification's own published example (see tx_vectors.ml). The low-s boundary
   pair below is not from the oracle — it is the one distinction `>` versus `>=`
   decides, so it is pinned directly. *)

module Tx_envelope = Tn_evm.Tx_envelope
module Tx_payload = Tn_evm.Tx_payload
module Tx_signature = Tn_evm.Tx_signature
module Tx_recovery = Tn_evm.Tx_recovery
module Secp256k1 = Tn_evm.Secp256k1
module Public_key = Tn_evm.Public_key
module Transaction = Tn_evm.Transaction
module Executor = Tn_evm.Executor
module Receipt = Tn_evm.Receipt
module Env = Tn_evm.Env
module Block_hashes = Tn_evm.Block_hashes
module U256 = Tn_state.U256
module Nonce = Tn_state.Nonce
module Account = Tn_state.Account
module World_state = Tn_state.World_state
module Address = Tn_types.Units.Address

let to_hex = Tx_vectors.to_hex
let w = Tx_vectors.w_of_hex

let envelope_of (c : Tx_vectors.case) =
  Tx_envelope.make ~payload:c.payload
    ~signature:(Tx_signature.make ~parity:c.parity ~r:(w c.r) ~s:(w c.s))

let signed payload ~parity ~r ~s =
  Tx_envelope.make ~payload ~signature:(Tx_signature.make ~parity ~r:(w r) ~s:(w s))

let render_signer =
  Result.fold
    ~ok:(fun addr -> to_hex (Address.to_bytes addr))
    ~error:Tx_recovery.error_to_string

(* ------------------------------------------------------------------ *)
(* 1. Recovery goldens                                                 *)
(* ------------------------------------------------------------------ *)

let test_golden_signers () =
  List.iter
    (fun (c : Tx_vectors.case) ->
      Alcotest.(check string)
        (c.name ^ ": recover_signer") c.sender
        (render_signer (Tx_recovery.recover_signer (envelope_of c))))
    Tx_vectors.cases

(* The sender must be a function of the transaction, not of the bytes it arrived
   in: decode the envelope and recover from the DECODED payload. *)
let test_signers_after_decode () =
  List.iter
    (fun (c : Tx_vectors.case) ->
      let got =
        Result.fold
          ~ok:(fun e -> render_signer (Tx_recovery.recover_signer e))
          ~error:Tx_envelope.error_to_string
          (Tx_envelope.decode_2718 (Tx_vectors.hex c.encoded_2718))
      in
      Alcotest.(check string) (c.name ^ ": decode then recover") c.sender got)
    Tx_vectors.cases

(* ------------------------------------------------------------------ *)
(* 2. recover: the executable transaction                              *)
(* ------------------------------------------------------------------ *)

let kind_hex kind =
  match kind with
  | Transaction.Call addr -> to_hex (Address.to_bytes addr)
  | Transaction.Create -> "create"

let test_recover_to_transaction () =
  List.iter
    (fun (c : Tx_vectors.case) ->
      let tx = Tx_recovery.recover (envelope_of c) in
      let ok =
        Result.fold ~error:(fun _ -> false)
          ~ok:(fun t ->
            String.equal (to_hex (Address.to_bytes (Transaction.sender t))) c.sender
            && Nonce.equal (Transaction.nonce t) (Tx_payload.nonce c.payload)
            && Int.equal (Transaction.gas_limit t) (Tx_payload.gas_limit c.payload)
            && String.equal (kind_hex (Transaction.kind t)) (kind_hex (Tx_payload.kind c.payload))
            && U256.equal (Transaction.value t) (Tx_payload.value c.payload)
            && String.equal (Transaction.data t) (Tx_payload.data c.payload)
            && Option.equal U256.equal (Transaction.chain_id t) (Tx_payload.chain_id c.payload))
          tx
      in
      Alcotest.(check bool) (c.name ^ ": recover carries every field plus the sender") true ok)
    Tx_vectors.cases

(* The fee-tag bridge no golden vector can see (D-9): the three payload types map
   to the three Transaction.fee constructors, and EIP-1559's priority fee is
   carried as Some. *)
let fee_tag fee =
  match fee with
  | Transaction.Legacy { gas_price } -> "legacy:" ^ U256.to_hex gas_price
  | Transaction.Access_list { gas_price } -> "access_list:" ^ U256.to_hex gas_price
  | Transaction.Dynamic { max_fee; max_priority } ->
      "dynamic:" ^ U256.to_hex max_fee ^ ":"
      ^ Option.fold ~none:"none" ~some:U256.to_hex max_priority
  | Transaction.Set_code { max_fee; max_priority; target = _; authorizations } ->
      "set_code:" ^ U256.to_hex max_fee ^ ":" ^ U256.to_hex max_priority ^ ":"
      ^ string_of_int (List.length authorizations)

let test_fee_bridge () =
  let of_case (c : Tx_vectors.case) =
    Result.fold ~error:Tx_recovery.error_to_string
      ~ok:(fun t -> fee_tag (Transaction.fee t))
      (Tx_recovery.recover (envelope_of c))
  in
  Alcotest.(check string)
    "Legacy -> Transaction.Legacy (gas_price 20 gwei)"
    ("legacy:" ^ U256.to_hex (Tx_vectors.w_of_int 20_000_000_000))
    (of_case Tx_vectors.legacy_eip155_spec_vector);
  Alcotest.(check string)
    "Eip2930 -> Transaction.Access_list (gas_price 7)"
    ("access_list:" ^ U256.to_hex (Tx_vectors.w_of_int 7))
    (of_case Tx_vectors.eip2930_with_access_list);
  Alcotest.(check string)
    "Eip1559 -> Transaction.Dynamic with the priority fee as Some"
    ("dynamic:"
    ^ U256.to_hex (Tx_vectors.w_of_int 100_000_000_000)
    ^ ":"
    ^ U256.to_hex (Tx_vectors.w_of_int 2_000_000_000))
    (of_case Tx_vectors.eip1559_with_access_list);
  (* chain_id = None is a distinct state from Some 0, and it survives the
     bridge. *)
  Alcotest.(check bool)
    "a pre-EIP-155 legacy keeps chain_id = None through to_transaction" true
    (Result.fold ~error:(fun _ -> false)
       ~ok:(fun t -> Option.is_none (Transaction.chain_id t))
       (Tx_recovery.recover (envelope_of Tx_vectors.legacy_pre155_no_chain_id)));
  Alcotest.(check bool)
    "an EIP-155 legacy with chain id 1 keeps Some 1" true
    (Result.fold ~error:(fun _ -> false)
       ~ok:(fun t -> Option.equal U256.equal (Transaction.chain_id t) (Some (Tx_vectors.w_of_int 1)))
       (Tx_recovery.recover (envelope_of Tx_vectors.legacy_eip155_spec_vector)))

(* ------------------------------------------------------------------ *)
(* 3. The EIP-2 low-s boundary — the whole content of > versus >=      *)
(* ------------------------------------------------------------------ *)

let secp256k1n = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
let secp256k1n_half = "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0"
let secp256k1n_half_plus_1 = "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1"

(* A valid curve r, reused from fixture 1 so the point really exists. *)
let good_r = Tx_vectors.legacy_eip155_spec_vector.r
let base_payload = Tx_vectors.legacy_eip155_spec_vector.payload

let test_low_s_boundary () =
  Alcotest.(check bool)
    "s = floor(n/2) is accepted (the comparison is strictly >)" true
    (Result.is_ok
       (Tx_recovery.recover_signer
          (signed base_payload ~parity:false ~r:good_r ~s:secp256k1n_half)));
  Alcotest.(check string)
    "s = floor(n/2) + 1 is High_s"
    (Tx_recovery.error_to_string Tx_recovery.High_s)
    (render_signer
       (Tx_recovery.recover_signer
          (signed base_payload ~parity:false ~r:good_r ~s:secp256k1n_half_plus_1)));
  Alcotest.(check bool)
    "Secp256k1.s_is_high agrees at both sides of the boundary" true
    ((not (Secp256k1.s_is_high (Tx_vectors.hex secp256k1n_half)))
    && Secp256k1.s_is_high (Tx_vectors.hex secp256k1n_half_plus_1))

(* ------------------------------------------------------------------ *)
(* 4. Unrecoverable — the curve's rejections, which the decoder let by *)
(* ------------------------------------------------------------------ *)

let zero32 = String.make 64 '0'
let n_plus_1 = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142"

let test_unrecoverable () =
  let unrecoverable = Tx_recovery.error_to_string Tx_recovery.Unrecoverable in
  let check label ~r ~s =
    Alcotest.(check string) label unrecoverable
      (render_signer (Tx_recovery.recover_signer (signed base_payload ~parity:false ~r ~s)))
  in
  (* These four are the guard at lib/evm/secp256k1.ml:103, which Tx_recovery
     relies on rather than duplicating. Each one DECODES fine — see
     test_tx_envelope's must-accept table — and fails only here. *)
  check "r = 0" ~r:zero32 ~s:(Tx_vectors.legacy_eip155_spec_vector.s);
  check "s = 0" ~r:good_r ~s:zero32;
  check "r = n" ~r:secp256k1n ~s:(Tx_vectors.legacy_eip155_spec_vector.s);
  check "r = n + 1" ~r:n_plus_1 ~s:(Tx_vectors.legacy_eip155_spec_vector.s)

(* ------------------------------------------------------------------ *)
(* 5. The high-s malleation: a policy rejection, not an arithmetic one *)
(* ------------------------------------------------------------------ *)

let test_malleation_is_policy () =
  let c = Tx_vectors.legacy_eip155_spec_vector in
  let s_hi = U256.sub (w secp256k1n) (w c.s) in
  let malleated =
    Tx_envelope.make ~payload:c.payload
      ~signature:(Tx_signature.make ~parity:(not c.parity) ~r:(w c.r) ~s:s_hi)
  in
  Alcotest.(check string)
    "(r, n - s, flipped parity) is rejected as High_s"
    (Tx_recovery.error_to_string Tx_recovery.High_s)
    (render_signer (Tx_recovery.recover_signer malleated));
  (* ... and the curve would happily have returned the SAME key, so the
     rejection is EIP-2 policy rather than an arithmetic accident. *)
  let msg = Tx_envelope.signature_hash c.payload in
  let key_of ~recid ~s =
    Option.fold ~none:"no key" ~some:to_hex
      (Secp256k1.recover ~msg ~recid ~r:(U256.to_be_bytes (w c.r)) ~s)
  in
  Alcotest.(check string)
    "Secp256k1.recover gives the same key for the signature and its high-s image"
    (key_of ~recid:0 ~s:(U256.to_be_bytes (w c.s)))
    (key_of ~recid:1 ~s:(U256.to_be_bytes s_hi))

(* ------------------------------------------------------------------ *)
(* 6. End to end: decode -> recover -> execute                         *)
(* ------------------------------------------------------------------ *)

let outcome r =
  match r with
  | Receipt.Success _ -> "success"
  | Receipt.Reverted _ -> "reverted"
  | Receipt.Halted _ -> "halted"

let gas_used_of r =
  match r with
  | Receipt.Success { gas_used; _ } -> gas_used
  | Receipt.Reverted { gas_used; _ } -> gas_used
  | Receipt.Halted { gas_used; _ } -> gas_used

(* Fixture 1 is a plain 1 ETH transfer on chain 1: nonce 9, 20 gwei, 21000 gas.
   Fund its recovered sender at nonce 9 and run it. *)
let test_end_to_end () =
  let c = Tx_vectors.legacy_eip155_spec_vector in
  let decoded = Tx_envelope.decode_2718 (Tx_vectors.hex c.encoded_2718) in
  let tx = Result.map_error Tx_envelope.error_to_string decoded in
  let tx =
    Result.bind tx (fun e ->
        Result.map_error Tx_recovery.error_to_string (Tx_recovery.recover e))
  in
  let report =
    Result.fold ~error:Fun.id
      ~ok:(fun tx ->
        let sender = Transaction.sender tx in
        let recipient = Tx_vectors.addr Tx_vectors.to_a in
        let world =
          World_state.set_account World_state.empty sender
            (Account.make ~nonce:(Tx_vectors.nonce_of 9)
               ~balance:(Tx_vectors.w_of_int 2_000_000_000_000_000_000))
        in
        let block =
          Env.Block.make ~coinbase:Address.zero
            ~timestamp:(Tx_vectors.w_of_int 1_600_000_000)
            ~number:(Tx_vectors.w_of_int 1000) ~prevrandao:U256.zero
            ~gas_limit:(Tx_vectors.w_of_int 30_000_000)
            ~basefee:(Tx_vectors.w_of_int 1_000_000_000) ~basefee_address:Tn_evm.System_contracts.governance_safe_address
            ~chain_id:(Tx_vectors.w_of_int 1) ~hashes:Block_hashes.empty
        in
        Result.fold ~error:Executor.error_to_string
          ~ok:(fun (receipt, world') ->
            Printf.sprintf "%s gas=%d nonce=%d recipient=%s"
              (outcome receipt) (gas_used_of receipt)
              (Nonce.to_int (World_state.nonce world' sender))
              (U256.to_hex (World_state.balance world' recipient)))
          (Executor.execute world ~block tx))
      tx
  in
  Alcotest.(check string)
    "decode -> recover -> execute: a 1 ETH transfer at the intrinsic cost"
    (Printf.sprintf "success gas=21000 nonce=10 recipient=%s"
       (U256.to_hex (Tx_vectors.w_of_int 1_000_000_000_000_000_000)))
    report

(* [Public_key.to_address] is shared by [ECRECOVER] and by sender recovery, and
   neither caller can reach its [None]: the curve only ever hands it a 64-byte
   key. So its width guard is unexercised unless something calls it directly.

   The positive case is not self-referential: the key comes from the port's own
   curve, but the address it must produce is the sender alloy recovered for
   fixture 1, which is in turn the address the EIP-155 specification publishes
   for its example transaction. *)
let test_public_key_to_address () =
  let c = Tx_vectors.legacy_eip155_spec_vector in
  let key =
    Option.value ~default:""
      (Secp256k1.recover
         ~msg:(Tx_vectors.hex c.signing_hash)
         ~recid:(Bool.to_int c.parity) ~r:(Tx_vectors.hex c.r) ~s:(Tx_vectors.hex c.s))
  in
  Alcotest.(check int) "the curve returns a 64-byte uncompressed key" 64 (String.length key);
  let render k =
    Option.fold ~none:"None" ~some:(fun a -> to_hex (Address.to_bytes a)) (Public_key.to_address k)
  in
  Alcotest.(check string) "64-byte key -> the EIP-155 example's sender" c.sender (render key);
  (* Every other width is refused, including the two shapes a caller is most
     likely to pass by mistake: the SEC1 tag byte left on, and a compressed key. *)
  Alcotest.(check string) "65-byte SEC1-tagged key -> None" "None" (render ("\x04" ^ key));
  Alcotest.(check string) "33-byte compressed key -> None" "None"
    (render ("\x02" ^ String.sub key 0 32));
  Alcotest.(check string) "63-byte key -> None" "None" (render (String.sub key 0 63));
  Alcotest.(check string) "empty key -> None" "None" (render "")

let () =
  Alcotest.run "tx_recovery"
    [
      ( "goldens",
        [
          Alcotest.test_case "recover_signer matches alloy for every fixture" `Quick
            test_golden_signers;
          Alcotest.test_case "decode then recover gives the same sender" `Quick
            test_signers_after_decode;
          Alcotest.test_case "recover builds the executable transaction" `Quick
            test_recover_to_transaction;
          Alcotest.test_case "the fee-tag bridge to Transaction.fee" `Quick test_fee_bridge;
        ] );
      ( "eip-2",
        [
          Alcotest.test_case "s = floor(n/2) accepted, +1 rejected" `Quick test_low_s_boundary;
          Alcotest.test_case "the high-s malleation is policy, not arithmetic" `Quick
            test_malleation_is_policy;
        ] );
      ( "curve",
        [ Alcotest.test_case "r = 0, s = 0, r = n, r = n+1" `Quick test_unrecoverable ] );
      ( "end-to-end",
        [ Alcotest.test_case "decode -> recover -> Executor.execute" `Quick test_end_to_end ] );
      ( "public key",
        [
          Alcotest.test_case "64-byte key -> address, every other width -> None" `Quick
            test_public_key_to_address;
        ] );
    ]
