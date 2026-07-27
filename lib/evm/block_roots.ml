(* The four block-header roots and the state-root agreement oracle, wired onto
   the existing {!Tn_trie.Trie} builder and {!Tn_rlp.Rlp} codec. Encodings are
   pinned in the chunk-28 spec. *)

(* [secure_root_of]'s only error is [Duplicate_key], unreachable here because a
   canonical [Storage]/[World_state] yields unique keys. [Result.fold] keeps the
   function total without [unwrap]/[assert]; on the impossible error it yields an
   error STRING (never a 32-byte root), so a downstream root comparison fails
   loudly rather than matching silently. *)
let collapse = Result.fold ~ok:Fun.id ~error:Tn_trie.Trie.error_to_string

let storage_root acct =
  Tn_state.Storage.bindings (Tn_state.Account.storage acct)
  |> List.map (fun (slot, value) ->
         ( Tn_state.U256.to_be_bytes slot (* 32-byte key preimage; keccak'd inside secure_root_of *),
           Tn_rlp.Rlp.encode_scalar (Tn_state.U256.to_be_bytes value) (* scalar RLP value *) ))
  |> Tn_trie.Trie.secure_root_of
  |> collapse

(* A codeless account's [code_hash] is already [KECCAK_EMPTY], so the reth
   [TrieAccount] default falls out with no special-casing; likewise an
   empty-storage account gets [empty_root] from [storage_root]. *)
let account_leaf acct =
  Tn_trie.Trie.account_rlp
    ~nonce:(Tn_state.Nonce.to_int (Tn_state.Account.nonce acct))
    ~balance:(Tn_state.Account.balance acct)
    ~storage_root:(storage_root acct)
    ~code_hash:(Tn_keccak.to_bytes (Tn_state.Account.code_hash acct))

let state_root ws =
  Tn_state.World_state.accounts ws
  |> List.map (fun (addr, acct) ->
         (Tn_types.Units.Address.to_bytes addr (* raw 20 bytes; keccak'd inside secure_root_of *), account_leaf acct))
  |> Tn_trie.Trie.secure_root_of
  |> collapse

let transactions_root envelopes = Tn_trie.Trie.ordered_trie_root envelopes

(* [ordered_trie_root] (verbatim, [wrap = Fun.id]), never [ordered_trie_root_rlp]:
   the leaf node already wraps the value exactly once, so RLP-wrapping the
   envelope first would commit to a different root. *)
let transactions_root_of envelopes =
  transactions_root (List.map Tx_envelope.encode_2718 envelopes)

let type_byte tx =
  match Transaction.fee tx with
  | Transaction.Legacy _ -> 0
  | Transaction.Access_list _ -> 1
  | Transaction.Dynamic _ -> 2

(* [cumulative_gas_used] is the running prefix-sum of [Receipt.gas_used] (NET of
   refund), threaded by [fold_left] with no mutation. The root uses
   [ordered_trie_root] (verbatim, [wrap = Fun.id]), never [ordered_trie_root_rlp]
   which would double-wrap each envelope. *)
let receipts_root pairs =
  List.fold_left
    (fun (cum, envs) (ty, r) ->
      let cum = cum + Receipt.gas_used r in
      (cum, Receipt_envelope.encode_2718 ~type_byte:ty ~cumulative_gas_used:cum r :: envs))
    (0, []) pairs
  |> fun (_, envs) -> Tn_trie.Trie.ordered_trie_root (List.rev envs)

(* The boolean guard is a two-arm match on [bool], a finite sum — not a match on
   Option/Result — and it makes [List.map2] total by ensuring equal lengths. *)
let receipts_root_of_block txs receipts =
  match List.length txs = List.length receipts with
  | false -> None
  | true -> Some (receipts_root (List.map2 (fun tx r -> (type_byte tx, r)) txs receipts))

let agree a b = String.equal (state_root a) (state_root b)
