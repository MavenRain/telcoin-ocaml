(* The port of Rust [Batch] / [SealedBatch]
   (crates/types/src/worker/sealed_batch.rs:61-200, telcoin-network @
   5dbb764e).

   The codec is assembled from Tn_codec.Bcs combinators over the field
   nesting (pair (list bytes) (pair u32 (pair bytes (pair u64 u16)))): BCS
   structs are bare field concatenation in declaration order, so the nested
   pairs are byte-identical to the Rust struct. [received_at] is deliberately
   absent from the codec (#[serde(skip)], sealed_batch.rs:86-88): encoding
   never reads it and decoding rebuilds with [None], which is what makes the
   golden-vector V6 skip-proof hold. *)

module Bcs = Tn_codec.Bcs

type t = {
  transactions : string list;
  epoch : Units.Epoch.t;
  beneficiary : Units.Address.t;
  base_fee_per_gas : Units.Base_fee.t;
  worker_id : Units.Worker_id.t;
  received_at : Units.Timestamp.t option;
}

let make ~transactions ~epoch ~beneficiary ~base_fee_per_gas ~worker_id =
  {
    transactions;
    epoch;
    beneficiary;
    base_fee_per_gas;
    worker_id;
    received_at = None;
  }

(* Rust Batch::default() (sealed_batch.rs:165-176); its preimage is golden
   vector V1, which pins MIN_PROTOCOL_BASE_FEE = 7 through the fee field. *)
let default =
  make ~transactions:[] ~epoch:Units.Epoch.zero
    ~beneficiary:Units.Address.zero
    ~base_fee_per_gas:Units.Base_fee.min_protocol
    ~worker_id:Units.Worker_id.zero

let transactions t = t.transactions
let epoch t = t.epoch
let beneficiary t = t.beneficiary
let base_fee_per_gas t = t.base_fee_per_gas
let worker_id t = t.worker_id
let received_at t = t.received_at
let with_received_at t at = { t with received_at = Some at }

(* A u32 wire scalar refined into the Epoch newtype. The reject branch is
   unreachable (Bcs.u32 yields exactly the u32 range) but refine keeps the
   read total without inventing a default. *)
let epoch_codec : Units.Epoch.t Bcs.t =
  Bcs.refine
    ~inject:(fun n ->
      Units.Epoch.of_int n |> Option.to_result ~none:"epoch outside u32")
    ~project:Units.Epoch.to_int Bcs.u32

(* The alloy Address serde routes through serialize_bytes, so bcs
   LENGTH-PREFIXES it: 0x14 then the 20 raw bytes, not a bare fixed array.
   Bcs.bytes gives exactly that layout; the refine step rejects any decoded
   width but 20, as alloy's deserializer does. *)
let beneficiary_codec : Units.Address.t Bcs.t =
  Bcs.refine
    ~inject:(fun s ->
      Units.Address.of_bytes s
      |> Option.to_result ~none:"beneficiary is not exactly 20 bytes")
    ~project:Units.Address.to_bytes Bcs.bytes

(* Raw u64 bits on the wire; every pattern is legal, so a plain iso. *)
let base_fee_codec : Units.Base_fee.t Bcs.t =
  Bcs.iso ~inject:Units.Base_fee.of_int64 ~project:Units.Base_fee.to_int64
    Bcs.u64

(* A u16 wire scalar refined into Worker_id; reject unreachable as for the
   epoch. *)
let worker_id_codec : Units.Worker_id.t Bcs.t =
  Bcs.refine
    ~inject:(fun n ->
      Units.Worker_id.of_int n
      |> Option.to_result ~none:"worker id outside u16")
    ~project:Units.Worker_id.to_int Bcs.u16

let codec : t Bcs.t =
  Bcs.iso
    ~inject:(fun
        (transactions, (epoch, (beneficiary, (base_fee_per_gas, worker_id))))
      ->
      {
        transactions;
        epoch;
        beneficiary;
        base_fee_per_gas;
        worker_id;
        received_at = None;
      })
    ~project:(fun t ->
      ( t.transactions,
        (t.epoch, (t.beneficiary, (t.base_fee_per_gas, t.worker_id))) ))
    (Bcs.pair (Bcs.list Bcs.bytes)
       (Bcs.pair epoch_codec
          (Bcs.pair beneficiary_codec
             (Bcs.pair base_fee_codec worker_id_codec))))

let preimage t = Bcs.encode codec t

(* The byte-compat digest: the Tn_crypto seam hash over the BARE preimage, no
   tag and no prefix, exactly Rust's blake3(bcs(Batch)) (sealed_batch.rs:
   116-124). Under tn_crypto_blst the seam IS blake3, so this equals the Rust
   digest byte for byte; under the stub it is the same formula over BLAKE2s.
   The preimage itself is frozen by the golden vectors. *)
let digest t = Digests.Batch_digest.of_digest (Tn_crypto.Digest.hash (preimage t))

(* Fork-blind bounds: the epoch is accepted and ignored exactly as upstream
   (sealed_batch.rs:190-200, "can change in the future at a fork"). *)
let max_batch_gas (_ : Units.Epoch.t) = 30_000_000L
let max_batch_size (_ : Units.Epoch.t) = 1_000_000

let equal a b =
  List.equal String.equal a.transactions b.transactions
  && Units.Epoch.equal a.epoch b.epoch
  && Units.Address.equal a.beneficiary b.beneficiary
  && Units.Base_fee.equal a.base_fee_per_gas b.base_fee_per_gas
  && Units.Worker_id.equal a.worker_id b.worker_id
  && Option.equal Units.Timestamp.equal a.received_at b.received_at

module Sealed = struct
  type nonrec batch = t

  (* The claim is stored, never checked here: SealedBatch::new "does not
     verify the provided digest matches" (sealed_batch.rs:26-31); rule 1 of
     the batch validator is where a wrong claim is caught. *)
  type t = { batch : batch; claimed : Digests.Batch_digest.t }

  let seal b = { batch = b; claimed = digest b }
  let claim ~batch ~digest = { batch; claimed = digest }
  let batch t = t.batch
  let digest t = t.claimed
  let split t = (t.batch, t.claimed)

  (* The outer Batch codec, named before the inner [codec] shadows it. *)
  let batch_codec : batch Bcs.t = codec

  (* The claimed digest is a Rust [BlockHash] = [FixedBytes<32>], whose serde
     routes through [serialize_bytes], so bcs LENGTH-PREFIXES it: 0x20 then the
     32 bytes. [sized_bytes] rejects a bare 32-byte leg rather than re-reading
     it as a 0x?? length with the remainder shifted. *)
  let digest_codec : Digests.Batch_digest.t Bcs.t =
    Bcs.refine
      ~inject:(fun s ->
        Tn_crypto.Digest.of_bytes s
        |> Option.map Digests.Batch_digest.of_digest
        |> Option.to_result ~none:"batch digest is not exactly 32 bytes")
      ~project:(fun d ->
        Tn_crypto.Digest.to_bytes (Digests.Batch_digest.to_digest d))
      (Bcs.sized_bytes Tn_crypto.Digest.length)

  (* Rust derives the codec on [SealedBatch { batch, digest }]
     (sealed_batch.rs:17-31), and a BCS struct is bare field concatenation in
     declaration order, so the wire is bcs(Batch) then the prefixed digest. The
     claim is still unverified on decode, exactly as [SealedBatch::new] leaves
     it: a wrong claim is a validator rejection, not a decode error. *)
  let codec : t Bcs.t =
    Bcs.iso
      ~inject:(fun (batch, claimed) -> { batch; claimed })
      ~project:(fun t -> (t.batch, t.claimed))
      (Bcs.pair batch_codec digest_codec)

  let equal a b =
    equal a.batch b.batch && Digests.Batch_digest.equal a.claimed b.claimed
end
