(** The one EIP-2718 framing rule: a typed envelope carries its type byte, and
    type 0 carries none.

    Both consensus envelopes this port encodes — the receipt leaf
    ({!Receipt_envelope.encode_2718}) and the transaction envelope
    ({!Tx_envelope.encode_2718}) — end in the same two lines: emit the inner RLP
    list, and prepend exactly one raw type byte unless the type is [0], in which
    case emit the bare list. Legacy is not "type byte [0x00]": the byte is absent
    entirely, and alloy's legacy encoders take the type argument and {e discard}
    it (alloy-consensus 1.8.3 [src/transaction/legacy.rs:150-168], receipts
    [src/receipt/receipt2.rs:144-156], the typed path
    [alloy-eips-1.8.3/src/eip2718.rs:246-249]).

    The rule is here, once, so that the transaction and receipt sides cannot
    drift: a [0x00] prefix would change a transaction hash and a trie leaf, and
    nothing downstream would notice. What this deliberately does {e not} do is
    add the outer [Header{list:false}] wrapper of the p2p "network" form — that
    is a different byte string, and neither the trie nor a hash may ever see
    it. *)

val frame : type_byte:int -> string -> string
(** [frame ~type_byte body] is [body] unchanged when [type_byte] is [0], and the
    single byte [type_byte] followed by [body] otherwise. [body] is an
    already-encoded RLP list, and no outer header is added around the result.

    Total: [type_byte] is reduced modulo [256] so that no input can drive it to a
    partial branch. Every call site in this port passes [0], [1] or [2]. *)
