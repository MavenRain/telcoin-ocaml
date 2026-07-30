(* The engine-side drop layer (tn-reth/src/lib.rs:808-848 at
   telcoin-network 5dbb764e): filter, never error, so every honest node
   derives the same block content from the same certified bytes. *)

module Batch = Tn_types.Batch
module Tx_envelope = Tn_evm.Tx_envelope

(* Strip the 0x00 legacy tag alloy accepts on TN's decode path (the
   exhibit-24 framing): TN executes such a transaction as its untagged
   twin (tagged and untagged share one tx hash, pinned empirically against
   the vendored pinned crates), so the canonical bytes handed to the
   executable decoder drop the tag. *)
let canonical_bytes raw =
  String.to_seq raw |> Seq.uncons
  |> Option.fold ~none:raw ~some:(fun (first, rest) ->
         if Char.equal first '\x00' then String.of_seq rest else raw)

(* One transaction's fate: kept iff TN's recover gate accepts AND the
   canonical bytes are port-representable. The second bind drops exactly
   the well-formed-4844 and [2^62, 2^64) nonce/gas classes TN executes
   and then skips as InvalidTx (lib.rs:855-866): same block content,
   reached one layer earlier. *)
let executable raw =
  Option.bind
    (Result.to_option (Tx_shape.decode_and_recover raw))
    (fun (_ : Tx_shape.t) ->
      Result.to_option (Tx_envelope.decode_2718 (canonical_bytes raw)))

let executable_txs batch = List.filter_map executable (Batch.transactions batch)
