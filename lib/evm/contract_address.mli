(** Where a contract lands: the address [CREATE] and [CREATE2] deploy to.

    The two opcodes answer the same question by opposite means. [CREATE] derives
    the address from the creator's {e nonce}, so it depends on how many accounts
    that creator has already made and cannot be known before the transaction
    runs. [CREATE2] derives it from a caller-chosen salt and the init code's
    hash, so it can be computed years in advance by anyone holding those three
    values, which is the whole point of EIP-1014: an address can be reasoned
    about before the code exists.

    Both take the low twenty bytes of a Keccak-256 digest, and that truncation
    is {!Tn_state.Address_word.of_word}'s rule rather than a second
    implementation of it.

    This module holds the port's only RLP encoding. A general RLP library is not
    needed and is deliberately not offered: the one preimage the consensus rule
    names is a two-item list of a twenty-byte string and a nonce, whose encoding
    is short enough to be total and small enough to be read at a glance. A
    general encoder would have length-prefix cases this call site can never
    reach, and each of them would be an untested branch sitting under a
    consensus-critical hash. *)

open Tn_types

type scheme =
  | From_nonce of Tn_state.Nonce.t
      (** [CREATE]: the creator's nonce {e before} it is incremented for this
          creation. *)
  | From_salt of { salt : Tn_state.U256.t; init_code : string }
      (** [CREATE2]: EIP-1014's salt and the init code it commits to. The two
          travel in the same constructor because neither is meaningful to
          [CREATE], so a salt cannot be handed to a nonce-based derivation and
          a nonce cannot be handed to a salted one. *)

val derive : creator:Units.Address.t -> scheme -> Units.Address.t
(** The address a creation deploys to.

    [From_nonce nonce] is [keccak256(rlp [creator; nonce])] truncated to its low
    twenty bytes, with the nonce RLP-encoded as a minimal big-endian integer: an
    empty string for zero, a bare byte below [0x80], and a length-prefixed
    string otherwise.

    [From_salt] is
    [keccak256(0xff ++ creator ++ salt ++ keccak256 init_code)] truncated the
    same way, over a preimage of exactly eighty-five bytes
    ([revm-handler] [frame.rs:296-303]).

    Total, and injective in neither argument: two different creators can never
    collide in practice but nothing in the types says so, because the truncation
    to twenty bytes is what the consensus rule specifies. *)
