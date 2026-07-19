(** Signing-intent domain separation.

    Every signed message is prefixed with a three-byte intent before hashing,
    so a signature produced in one context (a consensus vote) can never be
    replayed as a signature in another. The prefix is a closed variant rather
    than a raw byte triple, which makes cross-domain replay unrepresentable:
    there is no way to sign "no scope". *)

type scope =
  | Consensus_vote
      (** A vote over a header digest — the only scope the slice signs in. Rust
          intent bytes [\[2; 0; 1\]] (scope=consensus, version=0, app=telcoin). *)

val prefix : scope -> string
(** The three-byte prefix for a scope. *)

val wrap : scope -> string -> string
(** [wrap scope msg] is [prefix scope ^ msg]: the exact byte string that gets
    hashed and signed. *)
