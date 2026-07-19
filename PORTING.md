# Porting map: telcoin-network (Rust) → telcoin-ocaml

This file is the re-sync contract. Each row maps a Rust source area to the
OCaml module that models it, so the OCaml can be diffed against upstream as the
Rust node moves. The port is **protocol-first**, not file-for-file: the OCaml is
organised around the DAG-consensus protocol itself, with a pure functional core
and an imperative shell, so one OCaml module may correspond to several Rust
files and vice versa.

Upstream reference: `~/Documents/telcoin-network`, a Narwhal + Bullshark DAG
consensus layer over a reth (Ethereum) execution client, tag context around
`v1.11.3` reth deps.

## Status legend

- **done** — implemented and tested in this milestone
- **partial** — modelled, with documented simplifications
- **planned** — signature/plan exists, implementation pending

## Foundation

| OCaml module | Rust source | Status | Notes |
|---|---|---|---|
| `tn_codec` (`Bcs`) | `bcs` crate (external) | done | Canonical BCS encoder/decoder combinators. 24 golden-vector conformance checks against the BCS spec. Digest/signature byte-compatibility with the Rust node depends on this. |
| `tn_std` (`Nonempty`, `Prng`) | — (port infrastructure) | done | `Nonempty` gives total `head`/`last` for quorum-bearing collections; `Prng` is SplitMix64 for replayable simulator latency. |
| `tn_crypto` (virtual) | `crates/types/src/crypto` | done | The single crypto seam. Interface only; implementation chosen at link time. |
| `tn_crypto_stub` | — (simulation only) | done | Deterministic, **forgeable** stub: BLAKE2s-256 digest, structural signatures. Exercises every path without a native dependency. |
| `tn_crypto_blst` | `crates/types/src/crypto`, `crates/config/src/keys.rs` | planned | Real BLAKE3 + BLS12-381 min-sig via `bls12-381`/`blst`. DST `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_`, 96-byte G2 pubkeys, 48-byte G1 sigs, infinity-point default, subgroup checks. |

## Core types (`crates/types`)

| OCaml module | Rust type(s) | Status | Notes |
|---|---|---|---|
| `Tn_types.Round` | `Round = u32` (`primary/mod.rs`) | done | Abstract; parity as a variant, saturating GC arithmetic. |
| `Tn_types.Leader_round` | (the `round % 2 == 0` asserts) | done | Even-and-≥2 by type; makes `LeaderSchedule::leader` total. |
| `Tn_types.Units.Epoch` | `Epoch = u32` (`committee.rs`) | done | |
| `Tn_types.Units.Stake` | `VotingPower = u64` | done | Always `one` per authority (`EQUAL_VOTING_POWER`). |
| `Tn_types.Units.Timestamp` | `TimestampSec = u64` | done | Whole seconds; enters digest pre-images. |
| `Tn_types.Units.Duration` | (tokio `Interval` delays) | done | Simulator milliseconds; never hashed. |
| `Tn_types.Units.Sequence_number` | `SequenceNumber` / leader nonce | done | `(epoch << 32) | round`; split recoverable for the reputation schedule counter. |
| `Tn_types.Units.Worker_id` | `WorkerId = u16` | done | One worker per validator in current protocol. |
| `Tn_types.Units.Address` | `alloy Address` | done | 20-byte execution address. |
| `Tn_types.Authority_id` | `AuthorityIdentifier` (`committee.rs`) | done | `hash(protocol_key)`; byte order drives all committee traversal. `zero` = Rust `Default`. |
| `Tn_types.Digests.*` | `digest_newtype!` macro outputs | done | `Header_digest`, `Batch_digest`, `Sub_dag_digest`, `Output_digest`; distinct abstract types + domain tags. |
| `Tn_types.Authority` | `Authority`/`AuthorityInner` | done | |
| `Tn_types.Committee` | `Committee`/`CommitteeInner` | done | Smart constructor enforces size ≥ 2, no dup keys; derives 2f+1 / f+1. Bitmap index = id-sorted position. |

## Vertices (`crates/types/src/primary`)

| OCaml module | Rust type(s) | Status | Notes |
|---|---|---|---|
| `Tn_vertex.Intent` | `IntentMessage`/`Intent` | done | 3-byte domain prefix `[2;0;1]`; closed variant. |
| `Tn_vertex.Header` | `Header`/`HeaderInner`/`HeaderBuilder` (`header.rs`) | partial | Digest cached at construction. **Omitted for the slice:** `latest_execution_block: BlockNumHash` (execution coupling) — add before wire-compat. |
| `Tn_vertex.Vote` | `Vote`/`VoteInfo` (`vote.rs`) | done | Signs the intent-wrapped header digest. |
| `Tn_vertex.Certificate` | `Certificate` + `SignatureVerificationState` (`certificate.rs`) | done | Verified-by-construction. The 5-state enum collapses into the type; only genesis-vs-aggregate is retained. `signed_authorities` `RoaringBitmap` → `Authority_id.Set`. |

## Consensus (`crates/consensus`) — part 1 done

| OCaml module | Rust source | Status | Notes |
|---|---|---|---|
| `Tn_consensus.Vote_aggregator` | `aggregators/votes.rs` (`VotesAggregator`) | done | Claims an author's slot on first sight (before validating, so a rejected vote burns the author for this header, matching Rust's `authorities_seen`), then validates (wrong header, non-member, bad signature); only accepted votes count toward quorum. `add` always returns the advanced state plus a result, and certifies via `Certificate.assemble` the moment accepted signers reach 2f+1. Fresh per proposal. Errors reported in `Certificate.error`. |
| `Tn_consensus.Parent_aggregator` | `aggregators/certificates.rs` (`CertificatesAggregator`) | done | Per-round parent accumulator. A `seen` author set gives equivocation protection and a **weight that never resets** (only added to); a `pending` buffer holds certificates since the last release and is drained on each release, so each release carries the delta, matching Rust's `drain(..)`. Releases at 2f+1 and re-releases on every later straggler; a post-quorum duplicate author releases nothing. The proposer appends deltas, so a cumulative re-release would double-count parent stake there. |
| `Tn_consensus.Dag` | `consensus/state.rs` (`ConsensusState` DAG half) | done | `Round.Map` of `Authority_id.Map` of `Certificate.t` plus a `Header_digest`-keyed secondary index. Equivocation guard (one certificate per (round, author); same digest idempotent), parent existence check with the round-1 genesis-parent skip (`round <= gc_round + 1`), GC horizon (`committed_round - gc_depth`, purge on `update`). Bullshark commit bookkeeping (`last_committed_sub_dag`, ordering) arrives in part 2. |
| `Tn_consensus.Leader_schedule` | `LeaderSchedule`/`LeaderSwapTable` | planned | Slice: identity swap table. Full: ChaCha12 `StdRng` swap for a mixed fleet. |
| `Tn_consensus.Sub_dag` | `CommittedSubDag` (`primary/output.rs`) | planned | Digest pre-image **must reserve** the reputation-scores field for retrofit. |
| `Tn_consensus.Bullshark` | `bullshark.rs` (`process_certificate`, `commit_leader`, `order_leaders`, `linked`) | planned | The commit rule. Replay the Rust `bullshark_tests` scenarios. |
| `Tn_consensus.Proposer` | primary `Proposer` task | planned | Timer **generation counters** to kill stale re-arms (critic HIGH). |
| `Tn_consensus.Voter` | primary certifier vote-once logic | planned | Vote-once, parent checks, round-1 genesis-parent rule. |
| `Tn_consensus.Node` | primary event loops (all tasks) | planned | Composes the Mealy machines; `step : t -> now -> Event.t -> (t * Command.t list, Error.t) result`. Error **only** for equivocation/invariant breaks, not protocol-normal events (critic HIGH). |

## Shell, execution, network, storage — planned

| OCaml module | Rust source | Status | Notes |
|---|---|---|---|
| `Tn_execution` (`EXECUTION` sig, `Noop`) | `crates/consensus/executor`, `crates/engine` | planned | Abstract execution seam; `Noop` with uninhabited `type error = |`. Real OCaml EVM slots in here (full-node goal). |
| `Tn_sim` | tokio runtime (port-only) | planned | Deterministic discrete-event simulator: `(timestamp, seq)` queue, seeded latency, batch injection. The vertical-slice shell. |
| `bin/tn_sim` | `bin/telcoin-network` | planned | CLI: `dune exec tn_sim -- --validators 4 --seed 7 --until-s 60`. |
| `Tn_network` | `crates/network-libp2p`, `crates/network-types` | planned | Message types behind `Command`/`Event`. No mature OCaml libp2p exists — largest open risk (see README). |
| `Tn_storage` | `crates/storage` (`tn-storage`, 14 tables) | planned | Persistence signature; MDBX has no OCaml equivalent (candidate: `irmin`). |
