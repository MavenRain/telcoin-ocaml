(** The verbatim EIP-2718 receipt bytes used as a receipts-trie leaf value.

    For a typed receipt this is [type_byte :: RLP([status; cgu; bloom; logs])];
    for legacy ([type_byte = 0]) it is the bare RLP list with NO type byte and NO
    outer string wrapper. The port's {!Receipt.t} stores no tx type and no bloom,
    so the type byte is supplied by the caller and the bloom is derived from the
    receipt's own logs via {!Bloom.of_logs}. *)

val status : Receipt.t -> bool
(** EIP-658 status: [true] only for {!Receipt.Success}; [false] for
    {!Receipt.Reverted} and {!Receipt.Halted}. Exposed so the polarity can be
    unit-tested directly. *)

val encode_2718 : type_byte:int -> cumulative_gas_used:int -> Receipt.t -> string
(** The trie-leaf bytes. [status] as an RLP bool ([true -> 0x01], [false ->
    0x80]); [cumulative_gas_used] as an RLP scalar; [bloom] as the 256-byte string
    {!Bloom.of_logs} of the receipt's logs ([0xb90100 || 256 bytes]); [logs] as an
    RLP list of [\[address; topics; data\]]. A [type_byte] of [0] emits the bare
    list; [1] or [2] prepends that single byte. No outer [Header{list:false}] wrap
    is added — that network form must never reach the trie. *)
