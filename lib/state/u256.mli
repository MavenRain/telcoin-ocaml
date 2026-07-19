(** The 256-bit unsigned integer — the EVM word.

    Balances, gas amounts and storage slots are all 256-bit unsigned integers.
    This is the port of alloy's [U256] (reth's [ruint::Uint<256, 4>]): its
    canonical serialisation is 32 bytes big-endian, matching [U256::to_be_bytes]
    and [U256::from_be_slice], and its ordering is unsigned. It provides
    construction, the additive group, checked add and subtract, the unsigned
    ordering and the byte and hex codec, and — added with the EVM interpreter,
    the first caller to need them — wrapping multiplication and exponentiation,
    unsigned division, remainder and modular add/multiply, and the bitwise and
    shift operations. This module stays mathematically honest: division and
    remainder are [None] on a zero divisor rather than silently defined. The
    total EVM semantics that map those to zero, and the signed opcodes, live in
    {!Tn_evm.Alu}. *)

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

val mul : t -> t -> t
(** Multiplication modulo [2^256] (wrapping) — the EVM's [MUL]. The full 512-bit
    product is formed and reduced to its low 256 bits. *)

val udiv : t -> t -> t option
(** Truncating unsigned division [a / b], [None] exactly when [b] is zero. *)

val urem : t -> t -> t option
(** Unsigned remainder [a mod b], [None] exactly when [b] is zero. Paired with
    {!udiv}: [a = (a / b) * b + a mod b] and [a mod b < b]. *)

val add_mod : t -> t -> t -> t option
(** [(a + b) mod n] computed over the true 257-bit sum, so no intermediate wrap
    loses information; [None] exactly when [n] is zero — the EVM's [ADDMOD]. *)

val mul_mod : t -> t -> t -> t option
(** [(a * b) mod n] computed over the true 512-bit product; [None] exactly when
    [n] is zero — the EVM's [MULMOD]. *)

val pow : t -> t -> t
(** Exponentiation [a ^ b] modulo [2^256] (wrapping), by square-and-multiply.
    [pow a zero] is [one] for every [a], including [pow zero zero]. *)

val logand : t -> t -> t
(** Bitwise conjunction of the 256 bits — the EVM's [AND]. *)

val logor : t -> t -> t
(** Bitwise disjunction — the EVM's [OR]. *)

val logxor : t -> t -> t
(** Bitwise exclusive-or — the EVM's [XOR]. *)

val lognot : t -> t
(** Bitwise complement — the EVM's [NOT]. *)

val shl : t -> t -> t
(** [shl value shift] — logical left shift of [value] by [shift] bits, [zero]
    when [shift >= 256]. The EVM's [SHL] (whose stack order names the shift
    first). *)

val shr : t -> t -> t
(** [shr value shift] — logical right shift of [value] by [shift] bits, [zero]
    when [shift >= 256]. The EVM's [SHR]. *)

val two_pow : int -> t
(** [2^n] modulo [2^256] — a single set bit at position [n], and [zero] for
    [n < 0] or [n >= 256]. *)

val of_byte : int -> t
(** The word whose only nonzero byte is the least-significant one, set to
    [n mod 256]. *)

val is_zero : t -> bool
val equal : t -> t -> bool

val compare : t -> t -> int
(** Unsigned ordering. *)
