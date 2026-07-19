# telcoin-ocaml

An OCaml port of [telcoin-network](https://github.com/telcoin) — a Narwhal +
Bullshark DAG-consensus layer over an Ethereum-compatible execution layer.

The end goal is a **full standalone OCaml node**, including an EVM reimplemented
in OCaml. That is a large, multi-stage effort; this repository is the
foundation and the first vertical slice toward it, built so that the hard parts
(networking, storage, execution) slot in behind module signatures without
disturbing the consensus core.

Licensed under **MIT OR Apache-2.0** (`LICENSE-MIT`, `LICENSE-APACHE`).

## Architecture: functional core, imperative shell

The port is organised around the DAG-consensus protocol, not the Rust crate
graph. Every protocol role (proposer, voter, aggregators, the Bullshark commit
rule) is modelled as a **pure state-transition machine**

```
step : t -> now:Timestamp.t -> input -> t * action list
```

that performs no IO: time arrives as an input event, timers are armed as output
commands, network sends are output commands, and committed consensus output is
an output command. A thin **shell** interprets those commands — for the slice, a
deterministic discrete-event simulator; later, an Eio-based node with real
networking and storage.

Illegal protocol states are made unrepresentable by types rather than guarded at
runtime:

- `Certificate.t` exists only via `assemble` / `genesis` / `check`, so holding
  one is proof a verified quorum signed the header. Rust's 5-state
  `SignatureVerificationState` enum disappears into the type.
- `Leader_round.t` (even, ≥ 2) makes leader election total — no
  `assert!(round % 2 == 0)`.
- Committee thresholds live only inside a smart-constructed `Committee.t`
  (size ≥ 2 enforced at creation), so 2f+1 / f+1 cannot be forged or forgotten.
- `Nonempty.t` bans empty collections where the protocol guarantees a quorum.

Everything is written to type-driven, functional conventions: `result`/`option`
over exceptions (no `raise` in library code), no partial functions, combinators
over imperative loops, exhaustive matches, per-module error variants, abstract
types in `.mli`, and each library reusable via dune.

## Layering

Strict dependency direction, lower never sees higher:

```
tn_std ──► tn_codec ──► tn_crypto (virtual) ──► tn_types ──► tn_vertex ──► tn_consensus ──► tn_execution ──► tn_sim ──► bin/tn_sim
                              │
                              └── tn_crypto_stub (default impl)
```

| Library | What it is | State |
|---|---|---|
| `tn_std` | `Nonempty`, `Prng` (SplitMix64) | ✅ done + tested |
| `tn_codec` | BCS canonical encoder combinators | ✅ done + 24 conformance checks |
| `tn_crypto` | virtual crypto interface (the seam) | ✅ done |
| `tn_crypto_stub` | deterministic forgeable crypto for simulation | ✅ done + tested |
| `tn_types` | scalars, ids, digests, `Authority`, `Committee` | ✅ done + tested |
| `tn_vertex` | `Intent`, `Header`, `Vote`, `Certificate` | ✅ done + tested |
| `tn_consensus` | DAG, Bullshark commit rule, proposer/voter/node machines | ✅ done + tested (parts 1–3) |
| `tn_execution` | execution seam: the `Noop` engine folds committed sub-DAGs into the consensus chain (later an OCaml EVM) | ✅ done + tested |
| `tn_state` | EVM execution-state foundation: `U256`, `Account`, `World_state`, and the value-transfer state transition | ✅ done + tested |
| `tn_evm` | the EVM itself: `Alu` (total opcode arithmetic), and the interpreter machine — `Opcode`, `Stack`, `Memory`, `Gas`, `Code`, `Interpreter` | ✅ done + tested |
| `tn_sim` + `bin/tn_sim` | discrete-event simulator + runnable slice | ✅ done + tested |

See [`PORTING.md`](./PORTING.md) for the full Rust→OCaml module map.

## Build and test

Requires OCaml 5.3 with dune. On this machine, the toolchain lives in the
`tn-ocaml` opam switch:

```sh
eval $(opam env --switch=tn-ocaml)
dune build      # builds all libraries
dune test       # runs all test suites
```

Current suite: **123 test cases green** (as `dune test` reports) plus 24 BCS
golden-vector conformance checks (a standalone runner) — 12 foundation cases
(crypto, scalars, committee threshold table), 9 vertex/certificate cases (the
full assembly rejection matrix), 36 consensus cases (vote and parent aggregators, the
DAG equivocation / parent / garbage-collection invariants from the Rust
`dag_state_tests`, and the Bullshark `bullshark_tests` scenarios), 19 primary
cases (the proposer/voter/node machines, including the leader fast path, the
`advance_round` readiness gate, the header drift-tolerance window, and the
forward-jump max-timer re-arm from the timing chunk), 6 end-to-end simulator
cases (an honest committee reaches
consensus, all nodes agree on the committed prefix, the committed leaders follow
the round-robin schedule, a seed replays identically, a larger committee also
commits, and the agreement oracle detects a constructed fork), 6 randomised
property tests (qcheck) that hold over hundreds of seed-driven runs (an honest
committee is always safe and live; committed logs advance in round and never
regress in timestamp; the committed leader schedule is invariant to delivery
timing; committed output is invariant to `gc_depth`; crash faults up to `f`
preserve safety and liveness while `f+1` still preserves safety; and message loss
never breaks safety), 12 recovery cases (the storage/recovery seam), and 7
execution cases (the `Noop` engine folds committed sub-DAGs into a hash-linked
consensus chain, one block per commit, and honest nodes derive the same chain),
and 16 execution-state cases (the `U256` byte layout, carry/borrow across byte
boundaries, wrapping versus checked overflow/underflow and unsigned ordering; the
EIP-161 canonical world state; and the value-transfer state transition — exact
nonce and balance checks, the exact-spend boundary, atomic revert, and a
self-transfer that nets zero while advancing the nonce).

The committee threshold tests pin the exact Narwhal table against the Rust node:
size 4 → quorum 3 / validity 2; 7 → 5 / 3; 10 → 7 / 4.

## Roadmap (Milestone 1: the vertical slice)

A simulated committee reaching consensus and emitting ordered output, runnable
as `dune exec bin/tn_sim.exe -- --validators 4 --seed 7 --until-s 60` (all flags
optional; defaults are a 4-validator, seed-42, 20 s honest run). The latency band
lives on `Sim.config`. **Milestone 1 is complete** (steps 1–13), and four
post-slice chunks have since landed (14 recovery/storage, 15 timing, 16 execution
seam, 17 execution-state foundation). This plan was produced and adversarially
reviewed by a multi-agent architecture pass; the HIGH-severity traps it surfaced
are noted.

1. ✅ Scaffold, licenses, layout, this README + PORTING.md
2. ✅ `tn_std` — Nonempty, Prng
3. ✅ `tn_crypto` virtual + `tn_crypto_stub`
4. ✅ `tn_codec` — BCS + conformance vectors
5. ✅ `tn_types` — scalars, ids, committee thresholds
6. ✅ `tn_vertex` — Intent, Header, Vote, Certificate
7. ✅ `tn_consensus` part 1 — `Vote_aggregator`, `Parent_aggregator` (no weight
   reset on post-quorum stragglers), `Dag` (equivocation guard, digest-keyed
   secondary index, GC horizon, round-1 genesis-parent rule)
8. ✅ `tn_consensus` part 2 — `Leader_schedule`, `Sub_dag` (with the
   reputation-scores digest field), `Bullshark`, output chain; replayed the Rust
   `bullshark_tests`
9. ✅ `tn_consensus` part 3 — the machines: `Proposer` (**timer generation
   counters** discard stale re-arms), `Voter` (vote-once, parent checks)
10. ✅ `Node` composition — outcome taxonomy: silently ignore late/duplicate/
    stale messages; `Error` **only** for equivocation and invariant breaks;
    self-vote before broadcast
11. ✅ `tn_sim` — `(delivery_ms, seq)` event queue, seeded latency, tail-recursive
    run loop; end-to-end tests (consensus reached, prefix agreement, deterministic
    replay)
12. ✅ `bin/tn_sim` — the runnable vertical slice (all nodes commit an identical
    round-robin leader sequence; exits non-zero on any invariant break or
    disagreement)
13. ✅ property tests (qcheck) — over hundreds of randomised seed-driven runs:
    safety and liveness, round/timestamp monotonicity, leader-schedule invariance
    to delivery timing, GC-equivalence. `Sim.config` gained an
    honest-node-preserving **fault model** (crash-stop authorities and per-message
    loss) so the suite also proves crash tolerance up to `f` and safety under
    message loss; with the faults off a run is byte-for-byte the reliable slice

**Post-slice chunks landed (beyond Milestone 1):**

14. ✅ recovery/storage seam — `ConsensusState::new_from_store` (`Bullshark.of_store`),
    `LeaderSchedule::from_store`, parent-check-disabled `Dag.insert_recovered`,
    proposer `LastProposed` re-emit and voter `VoteInfo` restore, `Node.snapshot`/
    `recover`; a coordinated restart reconstructs the frontier parent quorum and
    resumes without re-gossip
15. ✅ timing chunk — the proposer **leader fast path** (halved max / zero min
    header delay when this node leads the next even round) and the **`advance_round`
    readiness gate** (an early proposal waits for the round's leader certificate on
    even rounds, or settled leader votes on odd rounds; the max deadline overrides,
    so liveness is unchanged), plus the voter **drift-tolerance window** (accept a
    header stamped up to `max_header_time_drift_tolerance` seconds ahead). The
    honest slice stays deterministic; the leader fast path lets more rounds commit
    within the same horizon (the demo prefix grows 19 → 23)
16. ✅ execution seam (`tn_execution`) — the port of Rust's `ConsensusHeader`
    chain: a `Noop` engine folds the ordered stream of committed sub-DAGs into a
    hash-linked ledger (`parent_hash`, monotone `number`, the frozen
    `digest_from_parts` pre-image), each committed sub-DAG extending it by one
    block. It **cannot fail** — its error type is the uninhabited `Nothing.t` —
    which is the seam a real OCaml EVM slots into later. The simulator derives
    each node's chain on demand, and the demo prints its height and tip
17. ✅ execution-state foundation (`tn_state`) — the EVM state model the future
    interpreter stands on: `U256` (the 256-bit word, canonical 32-byte big-endian,
    unsigned, wrapping and checked add/sub), `Nonce`, `Account` (nonce + balance,
    EIP-161 emptiness), `World_state` (an address-keyed map kept canonical so
    equality is exact — the state-level execution-agreement corollary), and
    `Transfer`: a value-transfer transaction plus its pure state transition with a
    genuine `error` (nonce mismatch, insufficient balance, credit overflow), the
    first engine behind the seam to carry a real failure in place of `Noop`'s
    uninhabited one. Pure and not yet wired into the running slice (it awaits batch
    payloads, which are networking-deferred)

18. ✅ EVM arithmetic and logic unit (`tn_evm.Alu`) — the pure word operations
    every arithmetic, comparison, bitwise and shift opcode dispatches to. The
    raw arithmetic (wrapping multiply, binary long division, modular add and
    multiply over the true 257- and 512-bit intermediates, exponentiation,
    bitwise and shifts) was added to `U256`, which stays mathematically honest —
    division by zero is `None`, not a silently defined value — and `Alu` layers
    the EVM's *total* semantics over it, including the signed opcodes and the
    `-2^255 / -1` overflow. Held to an independent zarith oracle by property test
19. ✅ EVM interpreter (`tn_evm.Interpreter`) — the machine on top of the ALU: a
    1024-word `Stack`, byte-addressed `Memory` with the quadratic expansion
    price, `Gas` metering against revm's Cancun/Prague schedule, `Code` with
    jump-destination analysis that steps over push data, and the dispatch loop
    for the stack, memory, introspection and control-flow opcodes
    (`PUSH0`–`PUSH32`, `DUP`, `SWAP`, `POP`, `MLOAD`/`MSTORE`/`MSTORE8`/`MSIZE`,
    `PC`, `GAS`, `JUMP`/`JUMPI`/`JUMPDEST`, `STOP`, `RETURN`, `REVERT`,
    `INVALID`) alongside the ALU opcodes. It runs any pure computation, and it is
    **total**: every instruction that continues costs at least one gas, so a
    finite allowance is itself the termination argument — no step limit, no
    program that hangs it

**Still planned:** the opcodes that reach outside the frame — storage
(`SLOAD`/`SSTORE` and the account storage trie), the environment and context
opcodes, calls, contract creation (which needs keccak) — and the block-execution
layer that folds each committed sub-DAG's transactions through the state
transition; all of them need batch payloads wired first, which is networking.
Also: real crypto spike + golden vectors from a Rust harness; the
pending-certificate fetcher (buffer-and-fetch on a missing parent — needs the
network layer); the Eio shell; codec/crypto byte-compat alignment.

## OCaml ecosystem for the full-node goal

Research done up front, since the full-node path depends on what exists:

**Available on opam (green):**
- `bls12-381` (blst-backed, min-sig G1) — validator BLS keys and aggregation
- `secp256k1-internal`, `hacl-star` — execution keys, verified primitives
- `digestif` (BLAKE2, Keccak-256), plus `blake3` bindings — hashing
- `rlp` — Ethereum RLP encoding
- `eio` — the effects-based direct-style IO stack for the node shell
- `irmin` — candidate persistence layer
- `zarith` — bignum for EVM arithmetic

**Gaps that are real work (open risks):**
- **libp2p** — no mature native OCaml implementation. The Rust node's 18.7k-line
  `network-libp2p` is the single hardest piece to replace; options are a native
  implementation or a C/Go wrapper. The slice sidesteps this behind the
  simulator.
- **EVM** — no production OCaml EVM. Precedent exists (a Lem/Why3-derived EVM in
  OCaml passed the standard VM test suite), but a production interpreter is a
  large sub-project.
- **BCS byte-compatibility** — no BCS package on opam; `tn_codec` is a from-
  scratch implementation. It is verified against spec vectors, but exact parity
  with the Rust `bcs` crate over real consensus structs needs golden vectors
  generated from a small Rust harness (step 14).
- **MDBX storage** — no OCaml binding; the storage layer will target a different
  backend (likely `irmin`) behind the persistence signature.

## Provenance

The architecture and slice plan were produced by a multi-agent pass that mapped
the Rust consensus layer (9 subsystem readers), generated three independent
OCaml designs, scored them through fidelity / idiom / tractability lenses, and
ran an adversarial completeness critic. The winning design is the
functional-core / imperative-shell approach implemented here.
