open Tn_std
open Tn_types
open Tn_vertex
open Tn_consensus
module Bcs = Tn_codec.Bcs
module Hash32 = Tn_hash32.Hash32

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
  extra : Hash32.t; (* on the wire, never in the digest *)
  digest : Digests.Output_digest.t; (* computed once in create and cached *)
}

let parent_hash t = t.parent_hash
let sub_dag t = t.sub_dag
let number t = t.number
let extra t = t.extra
let digest t = t.digest

(* The [extra] field's DIGEST contribution: Rust hashes [B256::default()] — 32
   zero bytes — whatever the field actually holds (block.rs:51-53, "in prep"),
   so the constant, not [t.extra], is what the pre-image folds in. *)
let extra_bytes = String.make 32 '\000'

(* The frozen pre-image: 32-byte parent digest, 32-byte sub-DAG digest, 8-byte LE
   number, the zero extra field, with no separators between them. Matches the
   update order of Rust's [ConsensusHeader::digest_from_parts]. *)
let preimage_bytes ~parent_hash ~sub_dag ~number =
  Tn_crypto.Digest.to_bytes (Digests.Output_digest.to_digest parent_hash)
  ^ Tn_crypto.Digest.to_bytes
      (Digests.Sub_dag_digest.to_digest (Sub_dag.digest sub_dag))
  ^ Bcs.encode Bcs.u64 (Number.to_int64 number)
  ^ extra_bytes

let preimage t =
  preimage_bytes ~parent_hash:t.parent_hash ~sub_dag:t.sub_dag ~number:t.number

(* The BARE pre-image, no tag: Rust's [ConsensusHeader::digest_from_parts]
   feeds the four parts straight into the hasher (primary/block.rs:42-55). *)
let digest_of ~parent_hash ~sub_dag ~number =
  Digests.Output_digest.of_digest
    (Tn_crypto.Digest.hash (preimage_bytes ~parent_hash ~sub_dag ~number))

let zero_digest = Digests.Output_digest.of_digest Tn_crypto.Digest.zero

(* Rust's [ConsensusHeader::default()] (block.rs:58-75) field for field: a
   default [Certificate], which resolves to a default [Header] — author zero,
   round genesis, epoch zero, created_at zero, no payload, no parents, a zero
   execution anchor. This is the H1 row of the header vectors. *)
let default_header =
  Header.make ~author:Authority_id.zero ~round:Round.genesis
    ~epoch:Units.Epoch.zero ~created_at:Units.Timestamp.zero ~payload:[]
    ~parents:[] ~latest_execution_block:Block_num_hash.zero

(* [CommittedSubDag::new(vec![default_cert], default_cert, 0, default_scores,
   None)]: one default header, empty non-final scores, a stored timestamp of
   zero, and the missing-signature randomness. Both the [Unsigned(default)]
   state and the [unwrap_or] fallback give those same bytes, so the branch Rust
   takes does not matter. *)
let default_sub_dag =
  Sub_dag.of_persisted
    ~headers:(Nonempty.singleton default_header)
    ~scores:(Reputation_scores.of_persisted ~bindings:[] ~final:false)
    ~stored:Units.Timestamp.zero ~randomness:Sub_dag.default_randomness

(* The chain anchor, COMPUTED rather than pinned: Rust has no hardcoded
   constant either, it digests [ConsensusHeader::default()] (block.rs:58-75),
   and [last_consensus_parent] resolves to that value on a fresh chain
   (crates/state-sync/src/lib.rs:138-151). Computing it here keeps it tracking
   the {!Tn_crypto} seam, so the stub and blst builds each anchor to their own
   hash of the same pre-image. *)
let genesis_parent =
  digest_of ~parent_hash:zero_digest ~sub_dag:default_sub_dag
    ~number:Number.genesis

let of_persisted ~parent_hash ~sub_dag ~number ~extra =
  {
    parent_hash;
    sub_dag;
    number;
    extra;
    digest = digest_of ~parent_hash ~sub_dag ~number;
  }

(* Every producer in this port, like Rust's [into_consensus_header] on a
   freshly built output, carries the default [extra]; only a decoder can see
   another value. *)
let create ~parent_hash ~sub_dag ~number =
  of_persisted ~parent_hash ~sub_dag ~number ~extra:Hash32.zero

(* [pfx32], not a bare 32: [ConsensusHeaderDigest] wraps [Digest<32>], whose
   serde routes through [serialize_bytes], and bcs always length-prefixes that
   (crypto/mod.rs:39-49). [sized_bytes] fixes the width at the codec, so
   [of_bytes] cannot miss and the eager default is a constant. *)
let output_digest_codec =
  Bcs.iso
    ~inject:(fun raw ->
      Digests.Output_digest.of_digest
        (Option.value (Tn_crypto.Digest.of_bytes raw)
           ~default:Tn_crypto.Digest.zero))
    ~project:(fun d -> Tn_crypto.Digest.to_bytes (Digests.Output_digest.to_digest d))
    (Bcs.sized_bytes Tn_crypto.Digest.length)

(* [extra: B256], likewise length-prefixed by alloy's [serialize_bytes]. *)
let extra_codec =
  Bcs.iso
    ~inject:(fun raw -> Option.value (Hash32.of_bytes raw) ~default:Hash32.zero)
    ~project:Hash32.to_bytes
    (Bcs.sized_bytes Hash32.length)

let codec : t Bcs.t =
  Bcs.iso
    ~inject:(fun ((parent_hash, sub_dag, number), extra) ->
      of_persisted ~parent_hash ~sub_dag ~number ~extra)
    ~project:(fun t -> ((t.parent_hash, t.sub_dag, t.number), t.extra))
    (Bcs.pair
       (Bcs.triple output_digest_codec Sub_dag.codec Number.codec)
       extra_codec)

let equal a b = Digests.Output_digest.equal a.digest b.digest
let compare a b = Digests.Output_digest.compare a.digest b.digest
