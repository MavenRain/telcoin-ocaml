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
| `tn_state` | EVM execution-state foundation: `U256`, `Storage`, `Account`, `World_state`, `Address_word`, and the value-transfer state transition | ✅ done + tested |
| `tn_evm` | the EVM itself: `Alu` (total opcode arithmetic), the interpreter machine — `Opcode`, `Stack`, `Memory`, `Gas`, `Code`, `Interpreter` — and the host seam — `Env`, `Data`, `Access`, `Sstore_state`, `Refund`, `Effects` | ✅ done + tested |
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

Current suite: **274 test cases green** (as `dune test` reports) plus 24 BCS
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
never breaks safety), 12 recovery cases (the storage/recovery seam), 7
execution cases (the `Noop` engine folds committed sub-DAGs into a hash-linked
consensus chain, one block per commit, and honest nodes derive the same chain),
24 execution-state cases (the `U256` byte layout, carry/borrow across byte
boundaries, wrapping versus checked overflow/underflow and unsigned ordering; the
saturating `Nonce`; canonical `Storage` — a total read, write-then-clear landing
back at exactly `empty`, slot-ascending `bindings`; the `is_empty`/`is_absent`
predicate split and the world-state canonicity and account-removal rules that
rest on it; the total, lossy `Address_word` narrowing; and the value-transfer
state transition — exact nonce and balance checks, the exact-spend boundary,
atomic revert, and a self-transfer that nets zero while advancing the nonce), 36
EVM ALU cases (11 hand-computed vector cases over the signed, modular and
boundary opcodes plus 25 qcheck properties holding `Alu` against an independent
zarith oracle), 66 interpreter cases (4 stack, 3 memory, 4 gas-schedule and 2
jump-analysis units; 20 whole-program runs covering every dispatch class,
out-of-gas, stack underflow/overflow, invalid jumps and deferred opcodes; 3
encoding round-trips over all 256 bytes; and 30 qcheck properties holding the
machine against the ALU, the memory curve against an exact rational oracle, and
arbitrary bytecode against termination), and 41 host-seam cases (storage
canonicity and the two pruning rules; the access set going cold-then-warm, and a
declared EIP-2930 access list warming exactly what it names; 9 whole-program runs
of `SLOAD`, `BALANCE`, `SELFBALANCE`, `CALLDATALOAD`, `CALLDATACOPY`, `CODECOPY`
and `MCOPY`, plus one pinning each of the fourteen flat context opcodes to its
own environment field against fixtures chosen so that swapping two arms fails;
the full 7-case `SSTORE` cost-and-refund
matrix, including the negative refund and a check that 2000, 2100 and 2500 are
three distinct constants; 6 ordering cases pinning the EIP-2200 sentry at exactly
2300/2301, the pop-before-sentry order, a zero-length copy at a wild destination,
`MCOPY` expanding at `max(dst, src)`, that a revert discards everything, and that
an `SSTORE` loop terminates; and 13 qcheck properties including cold and warm
`SSTORE` pricing against a revm-derived oracle, `store_bytes` and `MCOPY` against
a flat-buffer `Bytes.blit` oracle, `Data.read` against a naive padded reader, and
a reverting run changing nothing).

The committee threshold tests pin the exact Narwhal table against the Rust node:
size 4 → quorum 3 / validity 2; 7 → 5 / 3; 10 → 7 / 4.

## Roadmap (Milestone 1: the vertical slice)

A simulated committee reaching consensus and emitting ordered output, runnable
as `dune exec bin/tn_sim.exe -- --validators 4 --seed 7 --until-s 60` (all flags
optional; defaults are a 4-validator, seed-42, 20 s honest run). The latency band
lives on `Sim.config`. **Milestone 1 is complete** (steps 1–13), and seven
post-slice chunks have since landed (14 recovery/storage, 15 timing, 16 execution
seam, 17 execution-state foundation, 18 EVM ALU, 19 EVM interpreter, 20 the host
seam). This plan was produced and adversarially
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
    EIP-161 emptiness; storage arrived with chunk 20), `World_state` (an
    address-keyed map kept canonical so equality is exact — the state-level
    execution-agreement corollary), and
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
20. ✅ host seam (`tn_evm` + `tn_state`) — the instructions that reach outside the
    machine but not outside the frame: account storage (`SLOAD`/`SSTORE` with the
    full EIP-2200/2929/3529 cost and refund tables), the block and transaction
    context (`COINBASE`…`BASEFEE`, `ORIGIN`, `GASPRICE`, `CHAINID`), the frame's
    own context (`ADDRESS`, `CALLER`, `CALLVALUE`, `BALANCE`, `SELFBALANCE`), and
    the copy family (`CALLDATALOAD`/`CALLDATASIZE`/`CALLDATACOPY`,
    `CODESIZE`/`CODECOPY`, `MCOPY`). `Account` gained a canonical `Storage`,
    `tn_state` gained the total two-way `Address_word` narrowing,
    `Interpreter.run` gained `~env` and `~effects`, and six new `tn_evm` modules
    carry the seam: `Env`, `Data`, `Access`, `Sstore_state`, `Refund`, `Effects`.

    Four things become unrepresentable. A cold surcharge computed without a
    lookup: `Access.warmth` is abstract and constructorless, obtainable only from
    a `touch_*` that returns the grown set with it, and it is the only type the
    pricing functions accept — the query-and-then-warm pair a naive interface
    offers is exactly the shape the module was written to forbid. A revert that
    keeps its effects: only the `Stopped` and `Returned` constructors carry an
    `Effects.t`, so "a revert discards its writes, its warmings *and* its refunds"
    is a fact of the type rather than a rule the code has to remember. A refund
    added to an allowance: the signed `Refund.t` and the non-negative `Gas.t` are
    separate types with no arithmetic between them. And orphan storage: a slot
    lives inside its account's entry, so `remove_account` cannot forget half its
    job.

    Three subtleties were worth the chunk. **The predicate split** — `is_empty` is
    the literal EIP-161 test and deliberately ignores storage, because EIP-161
    ignores it, but `World_state` prunes on the strictly stronger `is_absent`
    (`is_empty && Storage.is_empty`); pruning on `is_empty` would silently drop an
    `SSTORE` into a zero-nonce zero-balance account and `equal` would stop being
    exact content equality, which is the property the whole state model rests on.
    **The `SSTORE` cold surcharge is 2100, not `SLOAD`'s 2000** — revm charges
    `SSTORE`'s cold cost in full rather than net of the warm 100, so the two
    constants differ by exactly the static charge; conflating them leaves both
    numbers looking plausible while every cold `SSTORE` undercharges by 100, and a
    unit test pins that they are three distinct constants (with 2500) rather than
    one. **A checkpoint is just the persistent value** — revm reverts by replaying
    a mutable undo journal backwards, and needs one because its state is a mutable
    map with no older version to return to; here the world, the access set and the
    refund counter are all persistent, so a checkpoint is a binding, a revert is
    using the old binding, and undoing is not an operation but the absence of one.
    revm's `JournalEntry` has no counterpart in this port, and the entire class of
    bug where an undo entry is pushed for one change and forgotten for another is
    absent because there is no undo code to get wrong. Un-warming on revert, which
    revm implements with `mark_cold` replay, falls out for free
21. ✅ the hash and the rest of the single frame (`tn_keccak` + `tn_evm`) —
    Ethereum's Keccak-256 as a leaf library wrapping `Digestif.KECCAK_256`
    (pinned to published vectors, and to *not* being SHA3-256, whose functor has
    the identical signature), and the three instruction families it unblocks
    that still fit inside one frame: `KECCAK256` (`0x20`), the logs
    (`LOG0`–`LOG4`) and EIP-1153 transient storage (`TLOAD`/`TSTORE`). Five new
    `tn_evm` modules — `Topic_count`, `Log`, `Log_journal`, `Transient`,
    `Mutability` — and `Effects` grew from four fields to six.

    Three more things become unrepresentable. **A write in a static frame**:
    EIP-214's check does not gate a write, it *produces the argument the write
    demands* — `Mutability.permit` is abstract and constructorless, and
    `Effects.plan_store`, `Effects.log` and `Effects.transient_store` each take
    one, so an instruction author who forgets the guard fails to compile rather
    than silently permitting it. That closed a hole the previous chunk had
    written down: `SSTORE` carried a comment saying its guard was absent.
    **More than four topics**: `Log.Topics.t` is a five-constructor sum of
    *tuples*, so a five-topic log is not rejected, it has no value to be — and
    because `Opcode.Log` carries the same `Topic_count.t`, one value determines
    the byte encoded, the words popped, the constructor built and the price
    charged. **Logs and transient writes surviving a revert**: both ride inside
    `Effects.t`, which `Reverted` and `Failed` structurally do not carry, so
    EIP-1153's revert semantics cost zero lines.

    The chunk's own trap, found by mutation rather than by review: the topics
    are popped *after* the gas charge and after the memory expansion, so a
    doomed `LOG4` reports `Out_of_gas` and not `Stack_underflow`. Hoisting the
    pop is invisible on every program except that one
22. ✅ code on an account and the external-code readers (`tn_state` + `tn_evm`) —
    a `Bytecode.t` field on `Account`, and the three instructions that reading it
    makes expressible without a second frame: `EXTCODESIZE` (`0x3b`),
    `EXTCODECOPY` (`0x3c`) and `EXTCODEHASH` (`0x3f`). Code needed a home before
    the calls could run a callee's own code; this is that home, landed on its own
    so the migration is reviewable apart from the recursion it unblocks. Two
    things it makes unrepresentable. **A code hash that pretends to be a digest**:
    `Tn_keccak` has no constructor but `digest`, so EIP-1052's zero for an account
    that does not exist is a bare word the interpreter produces and never a
    `Tn_keccak.t` — which keeps it distinct from the `KECCAK_EMPTY` a codeless
    *but existing* account really hashes to, the one distinction the opcode turns
    on. **A hash out of step with its code**: it is derived (`Bytecode.hash`),
    never stored, so there is no invariant to break. The chunk's own trap, pinned
    by absolute gas: `EXTCODECOPY` warms its account and pays the cold surcharge
    *even for a zero-length copy* — revm's account load sits after the resize
    guard — so a zero-length `EXTCODECOPY` of a cold account is 2500 gas dearer
    than of a warm one, where the frame-local copies would have done nothing at all
23. ✅ the sub-frame calls (`tn_evm.Interpreter`): `CALL`, `CALLCODE`,
    `DELEGATECALL` and `STATICCALL`, with the `Call_depth` and return-data buffer
    `Env` had deliberately omitted and the `RETURNDATASIZE`/`RETURNDATACOPY`
    readers. A frame now opens a *second* frame, recursing into a callee's code
    through the `let rec ... and ...` seam of `run`, in revm's exact charge order
    (memory windows, warm-and-charge the target, value cost, new-account cost, the
    EIP-150 63/64 cap plus stipend, the depth guard, then the transfer). A
    reverting or halting child is a dropped `Effects.t`, so its writes, warmings
    and refunds are undone by construction. The one caveat is EIP-7702: a call
    executes its target's own code and resolves no delegation designator, because
    the account model has none yet
24. ✅ contract creation, destruction and history (`tn_evm` + `tn_state`):
    `CREATE`/`CREATE2` (keccak-derived addresses, the EIP-684 collision check, the
    EIP-3541/EIP-170 code validation and the 200-per-byte deposit), `SELFDESTRUCT`
    (on `World_state.remove_account`), and `BLOCKHASH` (reading a `Block_hashes`
    history). A creation clears the storage of the address it lands on, and its
    init run deposits the code it returns; this is the second frame that lets a run
    deploy code at last
25. ✅ the Prague precompile set (`tn_evm.Precompile`): `ECRECOVER` (`0x01`),
    `SHA256` (`0x02`), `RIPEMD160` (`0x03`), `IDENTITY` (`0x04`), `MODEXP` (`0x05`,
    EIP-2565 repricing) and `BLAKE2F` (`0x09`), dispatched on the callee address
    from the `CALL` family and reported abstractly (`Succeeded`/`Rejected`/
    `Not_a_precompile`) so the interpreter turns a builtin into an outcome without
    knowing which ran. The bn254 pair (`0x06`-`0x08`), KZG point evaluation
    (`0x0a`) and the BLS12-381 range are deferred to their own chunks and answer
    `Not_a_precompile`, running the (empty) account code exactly as before
26. ✅ the transaction executor (`tn_evm`: `Transaction`, `Intrinsic`, `Receipt`,
    `Executor`): the Prague mainnet single-transaction state transition, the piece
    `Transfer` and this README deferred to as "the gas and block-execution chunk
    that owns transaction inclusion." `Executor.execute : World_state.t →
    block:Env.Block.t → Transaction.t → (Receipt.t * World_state.t, error) result`
    runs revm's handler end to end: validate the environment and the caller's state
    (chain id, the per-type fee checks, the block gas limit, EIP-3860 initcode,
    intrinsic and EIP-7623-floor against the limit, EIP-3607 sender-has-code
    *before* the nonce, and the balance against `gas_limit * max_fee + value`);
    deduct the gas fee at the **effective** price while the balance check used the
    max, bumping the nonce for a call (a creation bumps inside its frame); warm the
    EIP-2929/2930/3651 set (caller, coinbase, target, precompiles, and the typed
    access list); run the first frame, a call that transfers value then runs the
    target's code (or dispatches a precompile at the top frame, as revm does), or a
    creation that endows and runs the init code then deposits it; then apply the
    EIP-3529 one-fifth refund cap **before** the EIP-7623 calldata floor, reimburse
    the caller at the effective price and pay the beneficiary the effective price
    less the burned base fee. Success, revert and halt are all *committed* (nonce
    and fee persist; only a revert or halt rolls back value, storage and logs); a
    validation *rejection* changes nothing. EIP-7702 set-code and EIP-4844 blob
    transactions are deferred, as `Transaction` carries no field for either. Every
    load-bearing rule is pinned by a hand-computed gas vector and confirmed by
    mutation
27. ✅ RLP and the Merkle-Patricia-Trie root builder (`tn_rlp`, `tn_trie`): a
    leaf RLP codec (`Rlp`, ported byte-for-byte from alloy-rlp 0.3.13 — the five
    encoding forms, the scalar-versus-byte-string distinction that keeps the
    number zero (`0x80`) apart from the one-byte string `0x00`, and a
    canonicity-enforcing decoder) and a pure trie root over a complete key/value
    set. `Trie.root` builds the hexary trie recursively (leaf, extension, and a
    17-slot branch whose slot 16 carries the value of a key that is a strict
    prefix of another), hex-prefix-encodes each path, and collapses a child to
    its RLP when that is under 32 bytes or to a `0xa0`-prefixed keccak otherwise,
    always hashing the root. `secure_root_of` hashes each key first (the state
    and storage tries), `ordered_trie_root` keys by `RLP(index)` (the
    transactions and receipts roots), and `account_rlp` lays the account out as
    `[nonce, balance, storage_root, code_hash]`. This is the piece the port
    deferred to as "blocked on the trie": it is what will replace `World_state`
    content equality with the real Ethereum state, storage, receipts and
    transactions roots. The eleven canonical `ethereum/tests` trie fixtures pass,
    and byte-compatibility is independently confirmed against the reth pin
    alloy-trie 0.9.5 — an out-of-tree oracle reproduces every tested root
    (ordered, state and storage) — with each load-bearing rule confirmed by
    mutation

**Still planned.** The single frame and the top-level per-transaction state
transition are now complete; what remains is mostly the layers around them.
The trie root builder now exists (step 27); what remains on that track is wiring
its state and storage roots in as the agreement check, in place of `World_state`
content equality. Blocked on networking: the block-execution layer
that folds each committed sub-DAG's transactions through `Executor.execute` (the
executor is pure and ready, but the batch payloads it would fold are
networking-deferred), plus EIP-7702 set-code and EIP-4844 blob transactions and
the blob instructions. Also: real crypto spike + golden vectors from a Rust
harness; the pending-certificate fetcher (buffer-and-fetch on a missing parent —
needs the network layer); the Eio shell; codec/crypto byte-compat alignment.

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
