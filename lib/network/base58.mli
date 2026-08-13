(** Base58 encoding in the Bitcoin alphabet.

    The one place the port needs it is the gossipsub message id, which
    libp2p-gossipsub 0.49.4 builds as [base58(peer id bytes)] followed by the
    sequence number (GT:565). The design (line 103) leaves the placement open
    between [tn_std] and [tn_network]; it lives here, because [tn_std] holds
    no encoding of any kind today and nothing outside this library needs
    base58.

    Only the encoder is ported: {!Gossip.message_id} never parses a message id
    back, and an unused decoder would be untested surface. *)

val alphabet : string
(** The 58 characters, in value order:
    ["123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"]. The four
    ambiguous glyphs [0], [O], [I] and [l] are absent. *)

val encode : string -> string
(** [encode s] is the base58btc rendering of [s] read as a big-endian
    integer, with one leading ['1'] per leading NUL byte. Total: every byte
    string has a rendering, and the empty string renders as [""]. *)
