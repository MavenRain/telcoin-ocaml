open Tn_types

type t = {
  sender : Units.Address.t;
  recipient : Units.Address.t;
  value : U256.t;
  nonce : Nonce.t;
}

let make ~sender ~recipient ~value ~nonce = { sender; recipient; value; nonce }
let sender t = t.sender
let recipient t = t.recipient
let value t = t.value
let nonce t = t.nonce

type error =
  | Nonce_mismatch of { expected : Nonce.t; actual : Nonce.t }
  | Insufficient_balance of { balance : U256.t; value : U256.t }
  | Balance_overflow

let error_to_string = function
  | Nonce_mismatch { expected; actual } ->
      Printf.sprintf "nonce mismatch: account nonce %s, transfer nonce %s"
        (Nonce.to_string expected) (Nonce.to_string actual)
  | Insufficient_balance { balance; value } ->
      Printf.sprintf "insufficient balance: have %s, need %s" (U256.to_hex balance)
        (U256.to_hex value)
  | Balance_overflow -> "balance overflow crediting recipient"

let apply state t =
  let sender_acct = World_state.account state t.sender in
  let account_nonce = Account.nonce sender_acct in
  if not (Nonce.equal account_nonce t.nonce) then
    Error (Nonce_mismatch { expected = account_nonce; actual = t.nonce })
  else
    (* Debit and advance the sender, write it back, then credit the recipient
       from the updated state — so a self-transfer reads its own debited account
       and nets to zero while still advancing the nonce. Any failure returns
       [Error] carrying no state, so the transfer reverts atomically. *)
    Option.fold
      ~none:
        (Error
           (Insufficient_balance
              { balance = Account.balance sender_acct; value = t.value }))
      ~some:(fun debited ->
        let debited = Account.increment_nonce debited in
        let state = World_state.set_account state t.sender debited in
        let recipient_acct = World_state.account state t.recipient in
        Option.fold ~none:(Error Balance_overflow)
          ~some:(fun credited ->
            Ok (World_state.set_account state t.recipient credited))
          (Account.credit recipient_acct t.value))
      (Account.debit sender_acct t.value)
