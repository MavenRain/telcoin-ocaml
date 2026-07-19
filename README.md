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
tn_std ──► tn_codec ──► tn_crypto (virtual) ──► tn_types ──► tn_vertex ──► tn_consensus ──► tn_sim ──► bin/tn_sim
                              │
                              └── tn_crypto_stub (default impl)   tn_execution ┘
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
| `tn_execution` | execution seam (`Noop`, later an OCaml EVM) | ⏳ planned |
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

Current suite: **102 checks green** — 24 BCS golden-vector conformance checks,
12 foundation cases (crypto, scalars, committee threshold table), 9
vertex/certificate cases (the full assembly rejection matrix), 36 consensus
cases (vote and parent aggregators, the DAG equivocation / parent /
garbage-collection invariants from the Rust `dag_state_tests`, the Bullshark
`bullshark_tests` scenarios, and the proposer/voter/node machines), and 6
end-to-end simulator cases (an honest committee reaches consensus, all nodes
agree on the committed prefix, the committed leaders follow the round-robin
schedule, a seed replays identically, a larger committee also commits, and the
agreement oracle detects a constructed fork).

The committee threshold tests pin the exact Narwhal table against the Rust node:
size 4 → quorum 3 / validity 2; 7 → 5 / 3; 10 → 7 / 4.

## Roadmap (Milestone 1: the vertical slice)

A simulated committee reaching consensus and emitting ordered output, runnable
as `dune exec bin/tn_sim.exe -- --validators 4 --seed 7 --until-s 60` (all flags
optional; defaults are a 4-validator, seed-42, 20 s honest run). The latency band
lives on `Sim.config`. **Milestone 1 is complete:** steps 1–12 below are done;
13–14 remain. This plan
was produced and adversarially reviewed by a multi-agent architecture pass; the
HIGH-severity traps it surfaced are noted.

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
13. ⏳ property tests (qcheck) — agreement, monotone timestamps, causal-delivery
    invariance, GC-equivalence on long runs
14. ⏳ post-slice ledger — real crypto spike, golden vectors from a Rust harness,
    pending-certificate manager, Eio shell

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
