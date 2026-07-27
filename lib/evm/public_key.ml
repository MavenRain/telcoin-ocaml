(* [keccak256(64-byte uncompressed public key)][12..32] — the address derivation
   shared by the ECRECOVER precompile and transaction sender recovery
   (alloy-consensus 1.8.3 [src/crypto.rs:349-356], alloy-primitives 1.5.7
   [src/bits/address.rs:495-515]). *)

(* The uncompressed key with its SEC1 [0x04] tag stripped: X then Y, 32 bytes
   each. alloy asserts this width; here it is a guard. *)
let key_length = 64

let to_address key =
  if String.length key <> key_length then None
  else
    (* A digest is [Tn_keccak.length] = 32 bytes, so bytes 12..31 always exist
       and are always exactly the width [Address.of_bytes] accepts: the width
       check above is the only way this function yields [None]. *)
    Tn_types.Units.Address.of_bytes
      (String.sub (Tn_keccak.to_bytes (Tn_keccak.digest key)) 12 20)
