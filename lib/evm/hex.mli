(** Lowercase hex for the debug printers in this library.

    Three modules ({!Log}, {!Withdrawal}, {!Rewards_counter}) had rewritten the
    same nibble gather for their [to_string]; this is that gather, once. It is
    a formatting helper only: nothing consensus-visible reads it, and the
    sibling copies in the libraries {e below} this one ({!Tn_keccak},
    {!Tn_hash32.Hash32}, {!Tn_state.U256}) stay where they are, since a module
    of [tn_evm] is not visible from them. *)

val of_bytes : string -> string
(** [of_bytes s] is [s] rendered as [2 * String.length s] lowercase hex
    digits, high nibble of each byte first and no ["0x"] prefix. *)
