(** The 256-bit unsigned integer — the EVM word.

    Balances, gas amounts and storage slots are all 256-bit unsigned integers.
    This is the port of alloy's [U256] (reth's [ruint::Uint<256, 4>]): its
    canonical serialisation is 32 bytes big-endian, matching [U256::to_be_bytes]
    and [U256::from_be_slice], and its ordering is unsigned. This chunk provides
    the operations a value transfer needs — construction, the additive group,
    checked add and subtract, the unsigned ordering and the byte and hex codec.
    Multiplication, division and the bitwise opcodes arrive with the interpreter
    chunk, which is the first to need them. *)

type t
(** A 256-bit unsigned integer. The representation is canonical — two equal
    values have equal bytes — so {!equal} and {!compare} are exactly the
    comparison of {!to_be_bytes}. *)

val zero : t
val one : t

val max_value : t
(** [2^256 - 1] — every bit set. Rust funds each genesis validator with this
    ([GenesisAccount::with_balance(U256::MAX)]). *)

val of_int : int -> t option
(** A value from a non-negative native [int], [None] for a negative one. Total
    over the naturals a native [int] can represent; larger literals enter through
    {!of_be_bytes} or {!of_hex}. *)

val to_be_bytes : t -> string
(** The 32-byte big-endian encoding — the canonical wire form and the pre-image a
    later digest will hash. *)

val of_be_bytes : string -> t option
(** Read a 32-byte big-endian value, [None] unless the input is exactly 32 bytes.
    Every 32-byte string is a valid value. *)

val to_hex : t -> string
(** 64 lowercase hex digits, no [0x] prefix — {!to_be_bytes} rendered. *)

val of_hex : string -> t option
(** Parse 64 hex digits (no prefix), [None] on a wrong length or a non-hex
    character. *)

val add : t -> t -> t
(** Addition modulo [2^256] (wrapping) — the EVM's [ADD]. *)

val sub : t -> t -> t
(** Subtraction modulo [2^256] (wrapping) — the EVM's [SUB]. *)

val checked_add : t -> t -> t option
(** [Some (a + b)] when the sum fits in 256 bits, [None] on overflow. *)

val checked_sub : t -> t -> t option
(** [Some (a - b)] when [a >= b], [None] on underflow. *)

val is_zero : t -> bool
val equal : t -> t -> bool

val compare : t -> t -> int
(** Unsigned ordering. *)
