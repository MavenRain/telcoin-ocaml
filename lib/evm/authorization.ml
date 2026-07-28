(* One EIP-7702 authorization. A port of alloy-eip7702 0.6.3
   [src/auth_list.rs] and [src/constants.rs] for the value, its encoders and its
   signature, and of revm-handler 15.0.0 [src/pre_execution.rs:217-232] for the
   three pure checks.

   No state, no [Effects], no error type: every failure in this module is the
   same silent per-entry skip revm writes as [continue]. *)

open Tn_types
module U256 = Tn_state.U256
module Delegation = Tn_state.Delegation
module Rlp = Tn_rlp.Rlp

type word = U256.t
type t = { chain_id : word; address : Units.Address.t; nonce : word }

(* The authorization nonce is a [u64] ([auth_list.rs:52]) while the chain id is
   a full [U256] ([auth_list.rs:47]). Only the nonce is bounded here. *)
let nonce_bound = U256.two_pow 64

let make ~chain_id ~address ~nonce =
  if U256.compare nonce nonce_bound >= 0 then None else Some { chain_id; address; nonce }

let chain_id t = t.chain_id
let address t = t.address
let nonce t = t.nonce

(* The DERIVED [RlpEncodable] for [Authorization] ([auth_list.rs:45-58]): a list
   header and three items in declaration order. [chain_id] and [nonce] are
   scalars, so they are minimal-length; [address] is a fixed twenty-byte string,
   so its leading zeros survive. *)
let encode t =
  Rlp.encode_list
    [
      Rlp.encode_scalar (U256.to_be_bytes t.chain_id);
      Rlp.encode_bytes (Units.Address.to_bytes t.address);
      Rlp.encode_scalar (U256.to_be_bytes t.nonce);
    ]

(* [pub const MAGIC: u8 = 0x05;] -- alloy-eip7702 [constants.rs:14]. The two
   spellings are the same byte; [authorization_signing_preimage_literal] checks
   that the preimage really begins with [magic], so they cannot drift. *)
let magic = 0x05
let magic_byte = "\x05"

(* [buf.put_u8(MAGIC); self.encode(&mut buf); keccak256(buf)] --
   [auth_list.rs:83-93]. The magic is OUTSIDE the list and the list holds the
   three unsigned fields only. *)
let signature_hash t = Tn_keccak.to_bytes (Tn_keccak.digest (magic_byte ^ encode t))

type signed = { unsigned : t; y_parity : word; r : word; s : word }

let sign unsigned ~y_parity ~r ~s = { unsigned; y_parity; r; s }
let unsigned sg = sg.unsigned
let y_parity sg = sg.y_parity
let r sg = sg.r
let s sg = sg.s

(* The HAND-WRITTEN six-item encoder ([auth_list.rs:224-233]). Parity first of
   the three signature items, not last. Every item is a scalar but the address,
   so a zero parity is [0x80] and never a literal [0x00]. *)
let encode_signed sg =
  Rlp.encode_list
    [
      Rlp.encode_scalar (U256.to_be_bytes sg.unsigned.chain_id);
      Rlp.encode_bytes (Units.Address.to_bytes sg.unsigned.address);
      Rlp.encode_scalar (U256.to_be_bytes sg.unsigned.nonce);
      Rlp.encode_scalar (U256.to_be_bytes sg.y_parity);
      Rlp.encode_scalar (U256.to_be_bytes sg.r);
      Rlp.encode_scalar (U256.to_be_bytes sg.s);
    ]

(* [SignedAuthorization::signature] ([auth_list.rs:135-141]): a parity outside
   {0, 1} is [InvalidParity], which the revm bridge turns into [None] and hence
   a skip ([revm-context-interface] [transaction/alloy_types.rs:20-23]). This is
   the ONLY narrowing of the wire's [U8] to [Tx_signature]'s [bool]. *)
let signature sg =
  let is_one = U256.equal sg.y_parity U256.one in
  if U256.is_zero sg.y_parity || is_one then
    Some (Tx_signature.make ~parity:is_one ~r:sg.r ~s:sg.s)
  else None

(* [SECP256K1N_HALF] ([constants.rs:30-31]) READ from the curve module rather
   than restated. [Secp256k1.s_is_high] is [s > floor(n / 2)], monotone in the
   scalar, so the set it answers [false] on is downward closed and the greatest
   member of that set IS the bound. Setting bits from the most significant down,
   keeping each only when the result stays non-high, walks straight to it in 256
   steps at module initialisation.

   Writing it this way keeps the group order in [secp256k1.ml] alone;
   [high_s_is_strict] pins the answer against alloy's decimal literal, so a
   derivation that went wrong would fail loudly rather than shift a consensus
   boundary by one. *)
let secp256k1n_half =
  List.fold_left
    (fun acc bit ->
      let candidate = U256.logor acc (U256.two_pow bit) in
      if Secp256k1.s_is_high (U256.to_be_bytes candidate) then acc else candidate)
    U256.zero
    (List.init 256 (fun i -> 255 - i))

type screened = { screened_auth : t; screened_authority : Units.Address.t }

(* Check 2 is an equality against [u64::MAX] ([pre_execution.rs:223-226]), not a
   bound: [make] already refuses anything wider. *)
let nonce_saturated = U256.sub nonce_bound U256.one

(* Checks 1, 2 and 3 ([pre_execution.rs:217-232]), in revm's order and with no
   state touched. Check 3 is alloy's [recover_authority]
   ([auth_list.rs:248-256]): the strict low-[s] gate first, then recovery, then
   the keccak-and-truncate that turns a key into an address. Failure at any of
   the three is the same [None], because revm writes the same [continue]. *)
let screen ~chain_id sg =
  let auth_chain = sg.unsigned.chain_id in
  let chain_ok = U256.is_zero auth_chain || U256.equal auth_chain chain_id in
  let nonce_ok = not (U256.equal sg.unsigned.nonce nonce_saturated) in
  if not (chain_ok && nonce_ok) then None
  else
    Option.bind (signature sg) (fun sig_ ->
        let s_bytes = U256.to_be_bytes (Tx_signature.s sig_) in
        if Secp256k1.s_is_high s_bytes then None
        else
          Option.map
            (fun authority -> { screened_auth = sg.unsigned; screened_authority = authority })
            (Option.bind
               (Secp256k1.recover ~msg:(signature_hash sg.unsigned)
                  ~recid:(if Tx_signature.parity sig_ then 1 else 0)
                  ~r:(U256.to_be_bytes (Tx_signature.r sig_))
                  ~s:s_bytes)
               Public_key.to_address))

let authority s = s.screened_authority
let screened_nonce s = s.screened_auth.nonce
let screened_assignment s = Delegation.assignment s.screened_auth.address
