(* The port of alloy [BlockNumHash] (alloy-eips-1.8.3/src/eip1898.rs:758-767),
   carried by [Header.latest_execution_block]. *)

module Bcs = Tn_codec.Bcs
module Hash32 = Tn_hash32.Hash32

type t = { number : int64; hash : Hash32.t }

let make ~number ~hash = { number; hash }
let zero = { number = 0L; hash = Hash32.zero }
let number t = t.number
let hash t = t.hash

(* [B256] serializes through [serialize_bytes], so bcs LENGTH-PREFIXES it: the
   hash leg is 0x20 then 32 bytes, never a bare 32. [sized_bytes] refuses any
   other prefix on decode, so a raw 32-byte encoding is rejected instead of
   being re-read as a 0x?? length followed by shifted bytes. *)
let hash_codec : Hash32.t Bcs.t =
  Bcs.refine
    ~inject:(fun s ->
      Hash32.of_bytes s
      |> Option.to_result ~none:"block hash is not exactly 32 bytes")
    ~project:Hash32.to_bytes
    (Bcs.sized_bytes Hash32.length)

let codec : t Bcs.t =
  Bcs.iso
    ~inject:(fun (number, hash) -> { number; hash })
    ~project:(fun t -> (t.number, t.hash))
    (Bcs.pair Bcs.u64 hash_codec)

let equal a b = Int64.equal a.number b.number && Hash32.equal a.hash b.hash

let compare a b =
  match Int64.compare a.number b.number with
  | 0 -> Hash32.compare a.hash b.hash
  | c -> c
