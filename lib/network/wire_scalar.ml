open Tn_types
module Bcs = Tn_codec.Bcs
module D = Tn_crypto.Digest

(* [sized_bytes] already refuses any other width, so the [of_bytes] failure
   arm is unreachable and the zero digest stands in without hiding a short
   read: a wrong width fails one layer down, at its own offset. *)
let to_digest s = Option.value ~default:D.zero (D.of_bytes s)

let digest : D.t Bcs.t =
  Bcs.iso ~inject:to_digest ~project:D.to_bytes (Bcs.sized_bytes D.length)

let header_digest : Digests.Header_digest.t Bcs.t =
  Bcs.iso ~inject:Digests.Header_digest.of_digest
    ~project:Digests.Header_digest.to_digest digest

let batch_digest : Digests.Batch_digest.t Bcs.t =
  Bcs.iso ~inject:Digests.Batch_digest.of_digest
    ~project:Digests.Batch_digest.to_digest digest

let epoch : Units.Epoch.t Bcs.t =
  Bcs.refine
    ~inject:(fun i ->
      Option.to_result ~none:"epoch out of range" (Units.Epoch.of_int i))
    ~project:Units.Epoch.to_int Bcs.u32

let round : Round.t Bcs.t =
  Bcs.refine
    ~inject:(fun i -> Option.to_result ~none:"round out of range" (Round.of_int i))
    ~project:Round.to_int Bcs.u32

let authority_id : Authority_id.t Bcs.t =
  Bcs.refine
    ~inject:(fun s ->
      Option.to_result ~none:"authority id: not 32 bytes" (Authority_id.of_bytes s))
    ~project:Authority_id.to_bytes (Bcs.fixed_bytes 32)
