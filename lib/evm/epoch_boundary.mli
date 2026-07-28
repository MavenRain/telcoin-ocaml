(** [close_epoch] as one value, and the THREE header fields it decides as one
    derived value.

    telcoin reads [ctx.close_epoch] in two separate expressions
    ([block.rs:970] for [extra_data], [:971-978] for the withdrawals pair), so a
    header whose [extra_data] says the epoch is closing while its
    [withdrawals_root] says it is not is a two-line edit away. Here the three
    cannot come apart: {!commitment} is one match and there is no way to obtain
    one of the three fields without the other two. *)

type t =
  | Open  (** The epoch continues. Telcoin's [close_epoch = None]. *)
  | Closing of { randomness : Hash32.t; withdrawals : Withdrawal.t list }
      (** The last batch of a closing epoch. [randomness] is [keccak256] of the
          leader certificate's aggregate BLS signature
          ([crates/types/src/primary/output.rs:258-265]), the 32 bytes that go
          verbatim into [extra_data]. [withdrawals] must already be in ASCENDING
          EXECUTION-ADDRESS order, which is what
          [RewardsCounter::get_address_counts]'s [BTreeMap<Address, u32>]
          iteration produces ([gas_accumulator.rs:123-158]) and what the
          withdrawals root commits to; {!Rewards_counter.generate_withdrawals}
          produces exactly that list, and {!Block_execution.finish} derives
          the [applyIncentives] reward pairs FROM these records, so the
          payment and the header commitment cannot name different rewards.

          Exposed rather than abstract because a boundary is a SHAPE and not a
          capability, which is {!Mutability.t}'s argument. What must be
          unforgeable is the {!commitment} below, not the constructor. *)

val is_closing : t -> bool
(** Whether this is the last batch of a closing epoch. *)

val equal : t -> t -> bool
(** Structural equality: the randomness and the withdrawal list, in order. *)

type error =
  | Extra_data_length of int
      (** A header's [extra_data] was neither 0 nor 32 bytes. Telcoin raises
          [TnRethError::EVMCustom] here and explicitly declines to
          [B256::from_slice] a wrong-length slice ([config.rs:157-167]); this
          port declines for the same reason. *)
  | Withdrawals_without_close of int
      (** An open boundary carrying a nonempty withdrawal list, carrying the
          list's length. Telcoin's open branch is [Withdrawals::default()]
          ([block.rs:977]), so this pairing is refused rather than silently
          rooted. *)

val error_to_string : error -> string
(** Render an {!error} as a short human-readable string, for diagnostics and
    test failure messages. *)

val of_extra_data : string -> withdrawals:Withdrawal.t list -> (t, error) result
(** The replay-path decode: [""] with no withdrawals is {!Open}, 32 bytes is
    {!Closing}, any other length is an {!error}. This is the 0/32/error
    length discipline of [config.rs:157-167], and it is what makes
    {!Block_execution.finish}'s single-sourcing coherent on replay: a
    header's [extra_data] and withdrawals decode back to the boundary whose
    commitment they came from. *)

type commitment
(** The three header fields a boundary decides, derived together. Abstract and
    constructorless, so the only source of one is {!commitment}, which computes
    all three from a single match. There is no way to obtain one of the three
    without the other two. *)

val commitment : t -> commitment
(** The one match. {!Open} gives EMPTY extra data (telcoin's
    [unwrap_or_default()]: empty, {e not} thirty-two zero bytes), the empty
    withdrawal list, and {!Tn_trie.Trie.empty_root}, which is alloy's
    [EMPTY_WITHDRAWALS] [0x56e81f...b421]. {!Closing} gives the 32 bytes of
    [randomness], the list, and {!Block_roots.withdrawals_root} of it
    ([block.rs:969-978]). *)

val extra_data : commitment -> string
(** The header's [extra_data]: empty on an open boundary, the 32 randomness
    bytes on a closing one. *)

val withdrawals : commitment -> Withdrawal.t list
(** The block body's withdrawal list, in the order the boundary carried it. *)

val withdrawals_root : commitment -> string
(** Always a root, never absent: telcoin's [withdrawals_root] is [Some] in BOTH
    branches ([block.rs:971-978]). It comes back as a plain [string], which is
    {!Block_roots}'s convention; gating it into a {!Hash32.t} is the header
    assembler's job. *)
