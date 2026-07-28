(* The EIP-4788 and EIP-2935 genesis fixture. The bytecode is carried as hex
   because that is the form the pinned source states it in
   ([alloy-eips-1.8.3/src/eip4788.rs:14-15], [src/eip2935.rs:10-11]), so a
   reader can diff the literal against the crate without decoding anything. *)

let hex_value c =
  if c >= '0' && c <= '9' then Some (Char.code c - Char.code '0')
  else if c >= 'a' && c <= 'f' then Some (Char.code c - Char.code 'a' + 10)
  else if c >= 'A' && c <= 'F' then Some (Char.code c - Char.code 'A' + 10)
  else None

(* Total by construction: validity is decided first, so the [~default:0] inside
   the gather is unreachable, and an invalid literal collapses to the EMPTY
   string rather than to silently wrong bytes. Empty code reads back as an
   undeployed contract, which [is_deployed] and the pin test both see. The body
   is a pure [String.init] gather (gather not scatter, [bloom.ml:5-7]). *)
let bytes_of_hex hex =
  let valid =
    String.length hex land 1 = 0
    && String.for_all (fun c -> Option.is_some (hex_value c)) hex
  in
  match valid with
  | false -> ""
  | true ->
      let digit j = Option.value ~default:0 (hex_value (String.get hex j)) in
      String.init
        (String.length hex / 2)
        (fun i -> Char.chr ((digit (2 * i) lsl 4) lor digit ((2 * i) + 1)))

(* [Units.Address.of_bytes] is the only width-checking constructor and it is
   partial, so a literal's width is pinned by the test suite and not by the
   type. The default is the zero address: loud in any state root, and never a
   plausible system contract. *)
let address_of_hex hex =
  Option.value ~default:Tn_types.Units.Address.zero
    (Tn_types.Units.Address.of_bytes (bytes_of_hex hex))

let system_address = address_of_hex "fffffffffffffffffffffffffffffffffffffffe"
let beacon_roots_address = address_of_hex "000f3df6d732807ef1319fb7b8bb8522d0beac02"

let history_storage_address =
  address_of_hex "0000f90827f1c53a10cb7a02335b175320002935"

let governance_safe_address =
  address_of_hex "00000000000000000000000000000000000007a0"

let consensus_registry_address =
  address_of_hex "07e17e17e17e17e17e17e17e17e17e17e17e17e1"

let history_serve_window = 8191

(* 97 bytes. Write path (caller = SYSTEM_ADDRESS): sstore(ts mod 8191, ts) and
   sstore((ts mod 8191) + 8191, calldata[0:32]). *)
let beacon_roots_code =
  bytes_of_hex
    "3373fffffffffffffffffffffffffffffffffffffffe14604d57602036146024575f5ffd5b5f35801560495762001fff810690815414603c575f5ffd5b62001fff01545f5260205ff35b5f5ffd5b62001fff42064281555f359062001fff015500"

(* 83 bytes. Write path (caller = SYSTEM_ADDRESS):
   sstore((NUMBER - 1) mod 8191, calldata[0:32]), i.e. the PARENT's number keys
   the PARENT's hash. Indexing by the current number is the off-by-one. *)
let history_storage_code =
  bytes_of_hex
    "3373fffffffffffffffffffffffffffffffffffffffe14604657602036036042575f35600143038111604257611fff81430311604257611fff9006545f5260205ff35b5f5ffd5b5f35611fff60014303065500"

let deployer_accounts =
  [
    address_of_hex "0b799c86a49deeb90402691f1041aa3af2d3c875";
    address_of_hex "3462413af4609098e1e27a490f554f260213d685";
  ]

(* [World_state.set_account] prunes an [Account.is_absent] entry
   ([world_state.ml:16-17]). A contract account carries code and a deployer
   carries nonce 1, so neither is absent and both survive the seating.
   [Nonce.succ Nonce.zero] is the total route to one; [Nonce.of_int 1] is an
   option whose default would silently seat nonce zero, and a nonce-zero
   deployer would be pruned back out. *)
let contract_account code =
  Tn_state.Account.with_code
    (Tn_state.Account.make ~nonce:Tn_state.Nonce.zero ~balance:Tn_state.U256.zero)
    code

let deployer_account =
  Tn_state.Account.make
    ~nonce:(Tn_state.Nonce.succ Tn_state.Nonce.zero)
    ~balance:Tn_state.U256.zero

let predeploy world =
  let seats =
    [
      (beacon_roots_address, contract_account beacon_roots_code);
      (history_storage_address, contract_account history_storage_code);
    ]
    @ List.map (fun addr -> (addr, deployer_account)) deployer_accounts
  in
  List.fold_left
    (fun world (addr, account) -> Tn_state.World_state.set_account world addr account)
    world seats

let is_deployed world addr =
  Tn_state.Account.code_length (Tn_state.World_state.account world addr) > 0
