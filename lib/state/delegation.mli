(** EIP-7702 delegation designators: the 23 bytes an authorized account stores
    in place of code, and the classification revm performs on every account code
    it loads.

    A designator is [0xEF 0x01 || 0x00 || <20 address bytes>] ([revm-bytecode]
    [eip7702.rs:8-20,55-65]). It is {e not} produced only by an authorization
    list: revm classifies any code it loads from the database whose {b first two
    bytes} are [0xEF 0x01] ([bytecode.rs:101-110]), so a genesis allocation
    carrying that prefix is a live designator with no authorization anywhere in
    sight. A port that models designators as "whatever the authorization loop
    wrote" is wrong about a state a chain can actually be born in.

    This module lives in {!Tn_state} rather than {!Tn_evm} for one reason:
    {!Tn_state.Account} has to be able to say what its own code {e is}, and a
    designator needs nothing but an address to say it - no RLP, no elliptic
    curve, no hash of its own. Recovery, the [0x05] signing preimage and the
    authorization loop all stay in {!Tn_evm}, one library up, where the curve
    already lives. That asymmetry is the whole of the cycle argument, and it is
    why this chunk adds no dependency to any library.

    What this module deliberately does not do: it never decides whether a
    designator {e should} be followed. Resolution is per-operation - [CALL] and
    [EXTCODE*] disagree, and both live in {!Tn_evm} - so all that is offered
    here is the classification the two of them share. *)

open Tn_types

type t
(** A well-formed designator. Abstract, and {!classify} and {!assignment} are
    its only producers, so its 23 bytes and the address they encode can never
    disagree and a designator of any other length cannot be written down. *)

val magic : string
(** ["\xef\x01"] ([revm-bytecode] [eip7702.rs:12]). {b Two} bytes, and
    classification keys on exactly these two ([bytecode.rs:101-110]). A
    three-byte [0xEF 0x01 0x00] test would silently read a bad-version
    [ef0101..] blob as ordinary code, which is the one classification mistake
    that changes what an account {e is} rather than merely what it costs. *)

val version : int
(** [0] ([eip7702.rs:20]). The only version that exists; a designator-shaped
    blob carrying any other is {!Undecodable}, never code. *)

val length : int
(** [23]: the two {!magic} bytes, the {!version} byte, and twenty address bytes.
    Computed from those three widths rather than written as a literal, so the
    number cannot drift away from the layout {!to_bytes} actually emits. *)

val target : t -> Units.Address.t
(** The address a designator points at. Total: a {!t} always has one. *)

val to_bytes : t -> string
(** The {!length} stored bytes. They {e are} the account's code, which is why
    [EXTCODESIZE] reads 23, [EXTCODECOPY] copies these and [EXTCODEHASH]
    reports their Keccak, with no designator-awareness at any of the three
    sites ([revm-interpreter] [instructions/host.rs:61-64,86-103,140-142]), and
    why {!Tn_state.Account.code_hash} needs no change and no [EIP7702_MAGIC_HASH]
    special case. That constant is {e defined} at [eip7702.rs:4-6] and
    referenced nowhere in the pinned revm crates; special-casing [EXTCODEHASH]
    to it diverges. *)

type decode_error =
  | Invalid_length of int
      (** Magic-prefixed code that is not {!length} bytes, carrying the length
          it did have. Checked {b first} ([eip7702.rs:36-38]), so a 22-byte
          [ef0101..] blob reports this and never {!Unsupported_version}. *)
  | Unsupported_version of int
      (** {!length} bytes and the right magic, but a third byte that is not
          {!version}, carrying the byte it was ([eip7702.rs:50-52]). *)

val decode_error_to_string : decode_error -> string
(** Render a {!decode_error} as a short human-readable string, for diagnostics
    and test failure messages. *)

type code_class =
  | Codeless
      (** No code at all: an externally owned account, or one that has revoked
          its delegation - revocation stores the {e empty} string, so the two
          are the same class and must be. *)
  | Contract
      (** Genuine code. Anything not magic-prefixed lands here, [0xEF] first
          bytes included, because classification looks at two bytes and not
          one. *)
  | Delegated of t
  | Undecodable of decode_error
      (** Magic-prefixed bytes that are not a designator. revm cannot reach
          this {e as executable code}: [Bytecode::new_raw_checked] returns
          [Err] and the database load fails ([bytecode.rs:101-110]).
          {!Tn_state.World_state.of_genesis_alloc} refuses such an allocation
          for the same reason, which is what keeps this arm unreachable from
          any world a transaction runs against.

          It is named rather than folded into {!Contract} because folding it
          there is precisely the bug [bytecode.rs:101-110] guards against, and
          it stays reachable through the public {!Tn_state.Account.with_code},
          so every consumer keeps a real arm for it and none may assert it
          away. *)

val classify : string -> code_class
(** What arbitrary account code is, in the four-way classification every reader
    of account code must make. Total, four-way, no wildcard.

    The internal order is revm's and is observable: the two-byte magic decides
    which branch, then {b length} ([eip7702.rs:36-38]), then {b version}
    ([eip7702.rs:50-52]). Swapping the last two changes which error a 22-byte
    [ef0101..] blob reports. *)

val of_code : string -> t option
(** {!classify} with all three non-designator arms collapsed to [None]. The one
    place that collapse is taken, so no consumer takes it twice and no two
    consumers take it differently. *)

val is_contract_code : string -> bool
(** Whether this code blocks a delegation: it is neither empty nor a
    designator.

    The {b shared} predicate of EIP-3607's sender check ([revm-handler]
    [pre_execution.rs:92-102]) and the authorization loop's check 5
    ([pre_execution.rs:239-245]). In revm they are literally the same
    condition, written twice; one function here is how they stay that way.

    An {!Undecodable} blob answers [true]: it is not a designator, so it blocks.
    That is a documented divergence rather than a derivation, because revm never
    has such an account to ask about - the database load that would have
    produced it failed. The direction is the conservative one: refuse to
    delegate over bytes we cannot classify. *)

type assignment =
  | Assign of t
      (** A nonzero target: store the {!length} designator bytes. *)
  | Revoke
      (** The zero address: store the {b empty} string, whose hash is
          [KECCAK_EMPTY] ([revm-context-interface]
          [journaled_state/account.rs:448-459]).

          Not alloy's 23-byte [EIP7702_CLEARED_DELEGATION], and not
          [ef0100 || 0x00*20]: either would leave the account 23 bytes of code,
          a nonzero [EXTCODESIZE] and the wrong code hash, forever. *)

val assignment : Units.Address.t -> assignment
(** What an authorization for this address installs, and the {e only} producer
    of an {!assignment} - so the write path cannot express a designator that
    points at the zero address.

    The read path can, and must. Twenty-three bytes of [ef0100 || 0x00*20] in a
    genesis allocation {e are} a designator to revm, and they resolve to the
    codeless zero account. {!classify} therefore accepts what {!assignment}
    refuses to produce, and that asymmetry is the whole of the zero-address
    special case. *)

val code_of_assignment : assignment -> string
(** The code an {!assignment} installs: the designator bytes, or the empty
    string for a {!Revoke}. Total, and the only bridge from an assignment to
    the bytes {!Tn_state.Account.with_code} stores. *)

val equal : t -> t -> bool
(** Two designators are equal when they point at the same address. Their bytes
    are a function of that address, so this is also byte equality. *)
