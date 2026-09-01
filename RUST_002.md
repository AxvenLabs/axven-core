# RUST-002 — Test-Only Native State-Root Mirror

RUST-002 implements the first measured native hotspot as a **test-only mirror**. It does not route production Axven consensus, block validation, mining, replay, RPC, P2P, wallet, or persistence through Rust.

## Why this target

PERF-001 identified the full Sparse-Merkle reference recomputation as the dominant measured Python hotspot. RUST-001 established a dormant Rust/PyO3 boundary without changing production behavior. RUST-002 now mirrors the existing Python `smt_root_reference` algorithm so we can prove semantic equivalence before considering any production use.

The Python implementation remains the canonical oracle.

## Mirror contract

The native function accepts UTXO records as deterministic values:

`(outpoint, amount, recipient, coinbase, height)`

and returns one lowercase 64-hex Sparse-Merkle root.

The Rust mirror reproduces the existing Axven domains exactly:

- key: `SHA256("axven-smt-key-v1|" || outpoint)`
- leaf: `SHA256("axven-smt-leaf-v1|<outpoint>|<amount>|<recipient>|<coinbase-int>|<height>")`
- empty leaf: 32 zero bytes
- 256 levels, with each missing child replaced by the canonical default at that depth
- parent: `SHA256(left || right)`

SHA-256 is supplied by the upstream `sha2` crate. RUST-002 does not implement a cryptographic hash primitive itself.

## Differential gates

`rust_002_state_root_differential_spec.py` checks:

1. canonical empty, one-leaf, and two-leaf vectors;
2. 96 seeded randomized UTXO states against `axven.smt_root_reference`;
3. a 48-step insert/update/delete state sequence;
4. a 1,000-entry state with repeated input-order shuffling;
5. duplicate UTXO records fail closed at the FFI boundary;
6. production Axven modules still do not import `axven_native`;
7. canonical chain, genesis, SMT activation, and PQ activation values remain unchanged.

Rust unit tests also pin the fixed oracle vectors independently of Python execution.

The clean review head must pass the ordinary Axven Validation suite, Axven Fuzz Smoke, and Axven Native Smoke. Native Smoke builds the PyO3 extension from the locked Rust dependency graph before executing both the RUST-001 boundary contract and the RUST-002 differential contract.

## Trust boundary

The mirror remains pure and side-effect free. It opens no sockets or files, reads no environment variables, clocks, randomness, process state, or persistent state, and contains no Ed25519, ML-DSA, or ML-KEM implementation.

RUST-002 is evidence only. A future decision to route consensus state-root computation through Rust is a separate irreversible/consensus-adjacent review boundary and requires explicit approval after differential fuzzing, replay testing, and performance evidence.

## Next checkpoint

RUST-003 will fuzz the native FFI/state-root mirror, including malformed records and resource-boundary cases, while the production consensus path remains Python.

RUST-002 changes no chain identity, genesis, monetary rules, P2P protocol, PQ activation heights, ML-DSA behavior, or signature-acceptance semantics.
