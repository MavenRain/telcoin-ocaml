(** The EIP-4788 and EIP-2935 system contracts as a genesis fixture: the three
    addresses, the verbatim runtime bytecode of [alloy-eips 1.8.3], the ring
    window, the two canonical deployer EOAs telcoin pins at nonce 1, and the
    predeploy.

    One module, so the two call sites cannot drift on an address. That is the
    {!Eip2718} precedent: a constant that two places restate is a constant two
    places can disagree about.

    Both contracts are run, not modelled. Their runtime bytecode uses only
    opcodes {!Interpreter} already implements, so the port executes the real
    bytes and the slot arithmetic stays where the deployed contract put it,
    rather than being restated here as an easily inverted [(n - 1) mod 8191].

    {2 The honest limit on the address constants}

    The 20-byte width of an address literal is {e not} a type fact in this
    module. {!Tn_types.Units.Address.of_bytes} is the only width-checking
    constructor and it is partial, so each constant below is a hex literal
    decoded and then collapsed with
    [Option.value ~default:Units.Address.zero]. A typo in a literal therefore
    yields the {e zero} address rather than a compile error, and a typo in a
    bytecode literal yields the {e empty} code, which reads back as an
    undeployed contract. Both are caught by the [system_contracts_are_pinned]
    test, which asserts the exact hex and the exact byte lengths (97 and 83);
    the pin lives in the test suite because it cannot live in the type. *)

val system_address : Tn_types.Units.Address.t
(** [0xfffffffffffffffffffffffffffffffffffffffe]
    ([crates/tn-reth/src/system_calls.rs:10], byte-identical to
    [alloy-eips-1.8.3/src/eip4788.rs:9] and
    [revm-handler-15.0.0/src/system_call.rs:33]). *)

val beacon_roots_address : Tn_types.Units.Address.t
(** [0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02]
    ([alloy-eips-1.8.3/src/eip4788.rs:12]). *)

val history_storage_address : Tn_types.Units.Address.t
(** [0x0000F90827F1C53a10cb7A02335B175320002935]
    ([alloy-eips-1.8.3/src/eip2935.rs:8]). *)

val governance_safe_address : Tn_types.Units.Address.t
(** [0x00000000000000000000000000000000000007a0]
    ([crates/config/src/genesis.rs:37]): telcoin's governance safe, the
    compile-time default of the chain's basefee address
    ([tn-reth/src/lib.rs:198-210]), the account [TNEvmHandler] credits with
    every transaction's base fee and gas-limit penalty. Not a system contract
    (it holds no code and is never called); it is chain configuration, kept in
    this module because this is the port's module of well-known addresses. A
    genesis-config seam owns it whenever one exists. *)

val consensus_registry_address : Tn_types.Units.Address.t
(** [0x07E17e17E17e17E17e17E17E17E17e17e17E17e1]
    ([crates/tn-reth/src/system_calls.rs:22-23]): the ConsensusRegistry, the
    contract every epoch-close system call targets. Unlike the two EIP
    contracts above, its runtime bytecode is not a constant of this module: it
    is a 28381-byte alloc entry of the committed testnet genesis (pinned by
    keccak as [CONSENSUS_REGISTRY_PRE_FORK_CODE_HASH],
    [crates/types/src/forks.rs:23-24], re-derived in
    [test_genesis_registry.ml]), seeded through
    [Tn_state.World_state.of_genesis_alloc] from a fixture rather than baked
    in here. Same pinned-literal honesty note as the other addresses: the
    exact hex is asserted by test, not by the type. *)

val history_serve_window : int
(** [8191] ([alloy-eips-1.8.3/src/eip2935.rs:19-20]; changed from 8192 by
    ethereum/EIPs PR 9144, so a port hardcoding 8192 is wrong). Exposed for
    tests only. Nothing in this port computes a slot from it: both contracts
    bake it into their own bytecode as the immediates [0x001fff] and [0x1fff],
    and running that bytecode is what keeps the arithmetic in one place. *)

val beacon_roots_code : string
(** The 97 deployed runtime bytes of EIP-4788, verbatim from
    [alloy-eips-1.8.3/src/eip4788.rs:14-15]. *)

val history_storage_code : string
(** The 83 deployed runtime bytes of EIP-2935, verbatim from
    [alloy-eips-1.8.3/src/eip2935.rs:10-11]. *)

val deployer_accounts : Tn_types.Units.Address.t list
(** [0x0B799C86a49DEeb90402691F1041aa3AF2d3C875] and
    [0x3462413Af4609098e1E27A490f554f260213D685], the two canonical deployer
    EOAs telcoin's genesis pins at nonce 1
    ([tn-contracts/deployments/genesis/precompile-config.yaml:29-42]). They
    carry no code and no balance, but a nonzero nonce makes them non-empty under
    EIP-161, so they {e are} in the state trie and a genesis that omits them has
    a different state root from block zero onward. *)

val predeploy : Tn_state.World_state.t -> Tn_state.World_state.t
(** Seat both contracts (nonce 0, balance 0, runtime code) and both deployers
    (nonce 1). Total and idempotent; it overwrites rather than merges, so it is
    a genesis step and not a repair. A world that skips it is not an error: a
    system call into a codeless account succeeds and writes nothing, which is
    exactly what telcoin's non-success-checking callers accept
    ([block.rs:672-681]). *)

val is_deployed : Tn_state.World_state.t -> Tn_types.Units.Address.t -> bool
(** Whether the account holds nonempty code. Exposed so a test can assert that
    the {e uninstalled} case is really the case being exercised. Safe to expose
    for {!Access}'s reason: it returns a [bool], and nothing in this port
    branches execution on it. *)
