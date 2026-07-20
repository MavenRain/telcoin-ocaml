(** The two conversions between a 20-byte address and a 256-bit word, both
    total.

    [ADDRESS], [ORIGIN], [CALLER] and [COINBASE] push an address as a word;
    [BALANCE] reads a word as an address. The EVM makes both directions total,
    and this module reproduces that exactly rather than offering an [option] the
    interpreter would have to invent a halt for. It lives in {!Tn_state} because
    it must see both {!Tn_types.Units.Address} and {!U256}, and neither of those
    owns the other.

    The narrowing direction is where a port goes wrong. A word with dirt in its
    high twelve bytes is not an error for [BALANCE]; it is a balance query for
    the truncated address, and revm's [Address::from_word] simply keeps the low
    twenty bytes ([revm-interpreter] [instructions/utility.rs]). If a later
    reviewer "hardens" {!of_word} into a partial function, valid mainnet
    transactions start halting. *)

val to_word : Tn_types.Units.Address.t -> U256.t
(** An address as a word: its twenty bytes left-padded with twelve zero bytes,
    so the address occupies the low 160 bits. Injective. *)

val of_word : U256.t -> Tn_types.Units.Address.t
(** The address a word names: its low twenty bytes, the high twelve discarded
    without complaint. Total, and lossy on purpose. Not injective:
    [to_word (of_word w)] is [w] with its top twelve bytes cleared, and that
    idempotence is a property test. *)
