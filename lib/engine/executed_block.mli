(** One block the engine produced, with everything the block's execution
    established.

    Not a bare header. Telcoin persists an [ExecutedBlock] carrying the block,
    its receipts, its gas and its state bundle once per output
    ([crates/engine/src/payload_builder.rs:229-238]), and a header alone drops
    the bodies and the receipts with no later chunk able to reconstruct them.
    The {!Tn_evm.Block_execution.Pre_block.t} rides along for the same reason:
    it is the only evidence of which system calls the block made, so the
    once-per-output EIP-4788 consensus-root write is assertable without
    re-running the block. *)

type t
(** A produced block. Abstract: every field is established by one execution and
    none of them is settable afterwards. *)

val make :
  header:Tn_evm.Block_header.t ->
  number:Block_number.t ->
  pre_block:Tn_evm.Block_execution.Pre_block.t ->
  transactions:Tn_evm.Tx_envelope.t list ->
  receipts:(int * Tn_evm.Receipt.t) list ->
  skipped:Tn_evm.Block_execution.Invalid_tx.t list ->
  world:Tn_state.World_state.t ->
  close_disposition:Tn_evm.Epoch_close.disposition option ->
  t
(** Gather one finished block. Called by the engine's per-block step, which is
    the only place all of these exist at once. *)

val header : t -> Tn_evm.Block_header.t
(** The assembled header, the one thing that commits to all the rest. *)

val number : t -> Block_number.t
(** The block's height on the execution chain. *)

val pre_block : t -> Tn_evm.Block_execution.Pre_block.t
(** What the pre-block system calls did: whether the EIP-4788 consensus-root
    write ran for this block, and whether the EIP-2935 blockhashes write did.

    {b Divergence, stated once here:} both calls fire on every block this engine
    builds, with no fork gate anywhere on the path. That is exact for the chain
    the port models, TN testnet, whose genesis activates Shanghai, Cancun and
    Prague all at timestamp 0 ([lib/evm/block_execution.mli:156-171]), and it is
    a real divergence against TN MAINNET, which stops at Shanghai: upstream gates
    the 4788 call on [is_cancun_active_at_timestamp]
    ([tn-reth/src/evm/block.rs:610-612]) and the 2935 call on Prague, so a
    mainnet node makes neither and this engine would diverge in [state_root] from
    block 1. The gate is not added here because it belongs with a chain-spec fork
    schedule the port does not have, and half a gate hard-coded at one call site
    would be worse than the honest absence of one. *)

val transactions : t -> Tn_evm.Tx_envelope.t list
(** The block's body, in the order it executed, and therefore the order the
    transactions root commits to. A transaction the builder skipped is not
    here. *)

val receipts : t -> (int * Tn_evm.Receipt.t) list
(** The receipts, paired with the index of the transaction that produced each.
    *)

val skipped : t -> Tn_evm.Block_execution.Invalid_tx.t list
(** The transactions the builder skipped rather than executed, each carrying
    its INPUT position and the executor's reason. Empty for a block whose whole
    batch executed. *)

val world : t -> Tn_state.World_state.t
(** The world as of the end of this block, which is the world the next block
    starts from. *)

val close_disposition : t -> Tn_evm.Epoch_close.disposition option
(** What the epoch-closing system call decided, or [None] for a block that did
    not close an epoch. *)

val hash : t -> Tn_keccak.t
(** The block's hash: the header's, and the next block's parent hash. *)
