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

## Consensus (`crates/consensus`) — parts 1, 2 and 3 done

| OCaml module | Rust source | Status | Notes |
|---|---|---|---|
| `Tn_consensus.Vote_aggregator` | `aggregators/votes.rs` (`VotesAggregator`) | done | Claims an author's slot on first sight (before validating, so a rejected vote burns the author for this header, matching Rust's `authorities_seen`), then validates (wrong header, non-member, bad signature); only accepted votes count toward quorum. `add` always returns the advanced state plus a result, and certifies via `Certificate.assemble` the moment accepted signers reach 2f+1. Fresh per proposal. Errors reported in `Certificate.error`. |
| `Tn_consensus.Parent_aggregator` | `aggregators/certificates.rs` (`CertificatesAggregator`) | done | Per-round parent accumulator. A `seen` author set gives equivocation protection and a **weight that never resets** (only added to); a `pending` buffer holds certificates since the last release and is drained on each release, so each release carries the delta, matching Rust's `drain(..)`. Releases at 2f+1 and re-releases on every later straggler; a post-quorum duplicate author releases nothing. The proposer appends deltas, so a cumulative re-release would double-count parent stake there. |
| `Tn_consensus.Dag` | `consensus/state.rs` (`ConsensusState` DAG half) | done | `Round.Map` of `Authority_id.Map` of `Certificate.t` plus a `Header_digest`-keyed secondary index. Equivocation guard (one certificate per (round, author); same digest idempotent), parent existence check with the round-1 genesis-parent skip (`round <= gc_round + 1`), GC horizon (`committed_round - gc_depth`, purge on `update`). Part 2 adds the `gc_depth` and `last_committed_round` read accessors the commit traversal needs; a parent-check-disabled `insert_recovered` is reserved (in the `.mli`) for the storage/recovery chunk. |
| `Tn_consensus.Reputation_scores` | `tn-types` `reputation.rs` (`ReputationScores`) | done | Per-authority leader-support tallies for one schedule window plus a `final_of_schedule` flag. Rust's two asserts (full committee coverage; `total_authorities == size`) become smart-constructor invariants: `fresh` seeds every member, `bump` (`Map.update … (Option.map succ)`) can only touch existing keys. `by_score_desc` breaks ties by **descending** id, fixing the swap-table carve order. |
| `Tn_consensus.Leader_schedule` | `LeaderSchedule`/`LeaderSwapTable` | done | Round-robin `(r/2 - 1) mod size` over the id-sorted committee, plus a reputation-derived swap table (bad = low scorers within a descending std-ceiling capped at `size * pct / 100`; good = high scorers). Three Rust panics vanish into types (odd-round `Leader_round.t`, non-empty good list, `Threshold.of_percent ∈ [0,33]`). **Documented divergence:** the swap RNG is the house SplitMix64 `Prng` seeded by the queried round, not Rust's ChaCha12; determinism and the good/bad sets are identical, the concrete pick differs only when >1 good node exists — deferred behind the `Prng` seam. |
| `Tn_consensus.Sub_dag` | `CommittedSubDag` (`primary/output.rs`) | done | One commit's flattened certificates as bare headers (ascending round, leader last, so `Nonempty.last` is total), running scores, monotone commit timestamp (raw `stored` for the digest, zero-fallback getter for the view — kept as two functions), and signature-derived randomness. `preimage : t -> string` is factored out and documented as the frozen wire-compat byte layout (header digests ++ BCS scores ++ 8-byte-LE timestamp ++ randomness); `digest` domain-tags and hashes it. |
| `Tn_consensus.Bullshark` | `bullshark.rs` (`process_certificate`, `commit_leader`, `order_leaders`, `linked`) + `utils.rs` (`order_dag`) | done | The commit rule. `outcome = Committed of Sub_dag.t Nonempty.t \| No_commit of reason` makes Rust's commit-with-empty-list override unrepresentable; `Schedule_changed` is an internal bounded recursion that never escapes. Replays the Rust `bullshark_tests` scenarios (commit-one, round-robin, missing/dead leaders, weak/not-enough support, GC, reputation-reset cadence, and both schedule-change cases incl. the singleton-good swap) as alcotest cases. Two upstream-test expected multisets were corrected where they assumed a watermark of 6 for round-6 siblings that are only committed at 5. |
| `Tn_consensus.Proposer` | `proposer.rs` (`Proposer` task) | done | Pure Mealy machine `step : t -> now -> input -> t * action list`. Timer **generation counters** kill stale re-arms (critic HIGH): every re-arm bumps a monotone `gen`, a `Timer_fired` with a stale `gen` is discarded — the pure stand-in for `Interval::reset`. Propose condition `enough_parents && (max_timed_out \|\| enough_digests \|\| min_timed_out)`; parents jump/extend/ignore by round comparison; sticky timeout flags cleared only on a proposal; `process_committed_headers` digest re-queue (skipped headers' payloads prepended, oldest-round-first). **Documented slice simplifications** (both timing-domain, no safety effect): uniform min/max delays (the leader-fast-path that halves them is deferred with the timing chunk, keeping the proposer schedule-independent), and the equivocation-guard re-emit of a stored header is present for the recovery chunk but unreachable in forward operation, so `step` needs no error result. |
| `Tn_consensus.Voter` | `certifier.rs` + `state_sync/header_validator.rs` | done | Pure `vote : t -> dag -> now -> Header.t -> t * decision`. **Vote-once** keyed by author (latest vote): identical re-request → `Recast` the stored vote, a different header for a voted round → `Reject Equivocating_header`, a lower round → `Reject Already_voted_higher`. Parents resolved genesis-first then the DAG (the round-1 genesis-parent rule falls out), checked for one-round-below layering, `2f+1` quorum over distinct origins, and `created_at` monotonicity. A Byzantine peer is protocol-normal, so **every outcome is a `decision`, never an error** — the genuine invariant break (two conflicting *certificates*) is the DAG's, surfaced at the Node. Slice-deferred (IO): batch sync, evaluation timeout, execution-result waits — an unresolved parent yields `Need_parents` and the peer re-requests. |
| `Tn_consensus.Node` | `primary.rs` + `consensus/mod.rs` | done | Composes Proposer + Voter + `Vote_aggregator` + per-round `Parent_aggregator`s + `Bullshark` into `step : t -> now -> event -> (t * command list, error) result`. Every intra-node channel collapses into direct composition; only true message crossings are events/commands. **`error` is reserved ONLY for the three DAG invariant breaks** (certificate equivocation, missing parent / parent-round) (critic HIGH): wrong-epoch and below-GC certificates are `Ok` no-ops, invalid/duplicate/superseded votes and equivocating peer *headers* produce a command or nothing. A formed certificate is self-inserted through the same spine as gossip and broadcast; released parent quorums drive the next proposal; committed sub-DAGs are emitted in order and prune the proposer + GC the aggregators. |

## Shell, execution, network, storage — planned

| OCaml module | Rust source | Status | Notes |
|---|---|---|---|
| `Tn_execution` (`EXECUTION` sig, `Noop`) | `crates/consensus/executor`, `crates/engine` | planned | Abstract execution seam; `Noop` with uninhabited `type error = |`. Real OCaml EVM slots in here (full-node goal). |
| `Tn_sim` | tokio runtime (port-only) | planned | Deterministic discrete-event simulator: `(timestamp, seq)` queue, seeded latency, batch injection. The vertical-slice shell. |
| `bin/tn_sim` | `bin/telcoin-network` | planned | CLI: `dune exec tn_sim -- --validators 4 --seed 7 --until-s 60`. |
| `Tn_network` | `crates/network-libp2p`, `crates/network-types` | planned | Message types behind `Command`/`Event`. No mature OCaml libp2p exists — largest open risk (see README). |
| `Tn_storage` | `crates/storage` (`tn-storage`, 14 tables) | planned | Persistence signature; MDBX has no OCaml equivalent (candidate: `irmin`). |
