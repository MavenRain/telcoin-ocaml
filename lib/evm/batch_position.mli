(** TN's repurposed [difficulty] field: a batch's position in its consensus
    output.

    The PACKED WORD is canonical here, which buys two things. No header
    [difficulty] is refusable, because telcoin copies the word without
    validating it ([config.rs:169-177]); and {!is_first_batch} is telcoin's
    comparison verbatim rather than an extraction someone could reimplement.
    The [(batch_index, worker_id)] pair is a pair of fallible projections off
    the word, not the representation. Both the EIP-4788 gate and the header's
    [difficulty] are reads of this one value, so they cannot disagree. *)

type t
(** A batch's position in its consensus output, carried as the packed word TN
    writes into the header: [worker_id] in bits 0-15, [batch_index] in bits 16
    and above ([block.rs:78-104], packed at [config.rs:191]). Abstract, so the
    packing is not a fact a caller restates. *)

val of_word : Tn_state.U256.t -> t
(** The replay path: a sealed header's [difficulty] verbatim
    ([config.rs:169-177]). TOTAL, because telcoin copies the word without
    validating it, and any 256-bit word is a header difficulty, including one
    no packing of a pair could produce. That totality is why
    {!is_first_batch} is a predicate on the word. *)

val of_batch :
  batch_index:int -> worker_id:Tn_types.Units.Worker_id.t -> t option
(** The build path's packing, [(batch_index lsl 16) lor worker_id]
    ([config.rs:191]). [None] for a negative index or one whose shift would
    leave the native [int]. {!Tn_types.Units.Worker_id} is a [u16] by
    construction, so the low sixteen bits can never collide with the index. *)

val word : t -> Tn_state.U256.t
(** The value to write into the header ([block.rs:967, 995]). It is {e not} what
    the EVM sees: the build path puts the UNSHIFTED [U256::from(batch_index)] in
    the block env ([config.rs:99]) and the replay path puts [U256::ZERO]
    ([config.rs:135]). Neither mistake is reachable here, because {!Env.Block}
    models opcode [0x44] solely as [prevrandao] and declares the pre-merge
    reading not representable ([env.mli:21-24]). *)

val is_first_batch : t -> bool
(** [word t < 65536], telcoin's [first_batch] verbatim ([block.rs:105-107]), a
    comparison on the word and not an extraction. A [bool] is safe to expose
    for {!Access.mem_account}'s reason: nothing prices or gates from a [bool],
    and the one consumer ({!Block_execution.apply_pre_block}) takes a
    {!Block_context.t}, so a fabricated [true] has nowhere to go. A
    non-fabricable witness here would be ceremony: it would prove something to
    a consumer that does not exist. *)

val batch_index : t -> int option
(** The index of this batch within the consensus output, [None] above the
    native [int] range. See {!worker_id} for why this is a projection. *)

val worker_id : t -> Tn_types.Units.Worker_id.t option
(** The producing worker, [None] above the native [int] range. These are
    projections and not the representation: a design that stored the pair would
    have to refuse the header difficulties telcoin executes
    ([config.rs:169-177]), and would put the gate and the header value in two
    places again. *)

val equal : t -> t -> bool
(** Equality of the packed word. *)
