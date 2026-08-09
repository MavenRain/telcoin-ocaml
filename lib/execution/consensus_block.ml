open Tn_types
open Tn_consensus
module Bcs = Tn_codec.Bcs

module Number = struct
  (* The count of ancestor blocks — Rust [u64]. A native [int] is 63-bit, far
     beyond any reachable block height, and [succ] saturates rather than wrap. *)
  type t = int

  let genesis = 0
  let succ n = if n = max_int then n else n + 1
  let to_int n = n
  let to_int64 = Int64.of_int
  let of_int n = if n < 0 then None else Some n
  let equal = Int.equal
  let compare = Int.compare
  let to_string = string_of_int

  (* A wire u64 the host int cannot hold is refused rather than wrapped, and a
     negative one is below genesis, which is not a height at all. *)
  let of_int64 v =
    if Int64.compare v 0L < 0 || Int64.compare v (Int64.of_int max_int) > 0 then
      None
    else of_int (Int64.to_int v)

  let codec : t Bcs.t =
    Bcs.refine
      ~inject:(fun v ->
        Option.to_result ~none:"consensus block number out of range" (of_int64 v))
      ~project:to_int64 Bcs.u64
end

type t = {
  parent_hash : Digests.Output_digest.t;
  sub_dag : Sub_dag.t;
  number : Number.t;
  digest : Digests.Output_digest.t; (* computed once in create and cached *)
}

let parent_hash t = t.parent_hash
let sub_dag t = t.sub_dag
let number t = t.number
let digest t = t.digest

(* The [extra] field: Rust hashes [B256::default()] — 32 zero bytes — into the
   pre-image even though the field is unused, so the port folds the same zero
   bytes in to keep the layout aligned. *)
let extra_bytes = String.make 32 '\000'

(* The frozen pre-image: 32-byte parent digest, 32-byte sub-DAG digest, 8-byte LE
   number, the zero extra field — no domain tag, no separators. Matches the
   update order of Rust's [ConsensusHeader::digest_from_parts]. *)
let preimage_bytes ~parent_hash ~sub_dag ~number =
  Tn_crypto.Digest.to_bytes (Digests.Output_digest.to_digest parent_hash)
  ^ Tn_crypto.Digest.to_bytes
      (Digests.Sub_dag_digest.to_digest (Sub_dag.digest sub_dag))
  ^ Bcs.encode Bcs.u64 (Number.to_int64 number)
  ^ extra_bytes

let preimage t =
  preimage_bytes ~parent_hash:t.parent_hash ~sub_dag:t.sub_dag ~number:t.number

let digest_of ~parent_hash ~sub_dag ~number =
  Digests.Output_digest.of_digest
    (Tn_crypto.Digest.hash
       (Digests.Output_digest.domain
       ^ preimage_bytes ~parent_hash ~sub_dag ~number))

(* The chain anchor. See the .mli: Rust's exact default-header digest is
   byte-compat-deferred, so this is a distinct constant routed through the same
   digest seam — the domain tag over an empty pre-image. *)
let genesis_parent =
  Digests.Output_digest.of_digest
    (Tn_crypto.Digest.hash (Digests.Output_digest.domain ^ ""))

let create ~parent_hash ~sub_dag ~number =
  { parent_hash; sub_dag; number; digest = digest_of ~parent_hash ~sub_dag ~number }

(* [fixed_bytes] fixes the width at the codec, so [of_bytes] cannot miss and the
   eager default is a constant. *)
let output_digest_codec =
  Bcs.iso
    ~inject:(fun raw ->
      Digests.Output_digest.of_digest
        (Option.value (Tn_crypto.Digest.of_bytes raw)
           ~default:Tn_crypto.Digest.zero))
    ~project:(fun d -> Tn_crypto.Digest.to_bytes (Digests.Output_digest.to_digest d))
    (Bcs.fixed_bytes Tn_crypto.Digest.length)

let codec : t Bcs.t =
  Bcs.iso
    ~inject:(fun (parent_hash, sub_dag, number) ->
      create ~parent_hash ~sub_dag ~number)
    ~project:(fun t -> (t.parent_hash, t.sub_dag, t.number))
    (Bcs.triple output_digest_codec Sub_dag.codec Number.codec)

let equal a b = Digests.Output_digest.equal a.digest b.digest
let compare a b = Digests.Output_digest.compare a.digest b.digest
