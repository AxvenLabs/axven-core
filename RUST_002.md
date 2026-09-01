# RUST-002 — Test-only Sparse-Merkle State-Root Mirror

## Goal

Implement the first measured native hotspot as a **test-only Rust mirror** without changing Axven consensus routing.

PERF-001 identified the full sparse-Merkle state-root reference path as the dominant measured CPU hotspot. RUST-001 established a dormant deterministic PyO3 boundary. RUST-002 combines those two facts but deliberately stops before production integration.

## Oracle and trust boundary

The authoritative implementation remains:

`axven.smt_root_reference(utxo)`

and production `expected_state_root()` continues to call the Python oracle for sparse state roots. `axven_native.smt_root_mirror()` exists only for differential testing and measurement.

The Rust mirror accepts canonical UTXO tuples:

`(outpoint, amount_u64, recipient, coinbase_bool, height_u64)`

and returns one lowercase 64-hex sparse-Merkle root.

## Implementation rules

1. Match the existing Axven domain-separated `smt_key` and `smt_value` bytes exactly.
2. Match the 256-level default-node construction exactly.
3. Match Python's full recompute semantics, independent of input ordering.
4. Reject duplicate outpoints at the FFI boundary.
5. Keep all filesystem, socket, RPC, process, thread, clock, randomness, wallet-key, and persistent-state behavior outside the native crate.
6. Do not implement Ed25519, ML-DSA, ML-KEM, or custom cryptographic primitives. SHA-256 is supplied by the pinned RustCrypto `sha2` crate rather than handwritten Axven code.
7. Production Axven modules must not import or call `axven_native` in RUST-002.

## Differential gate

The RUST-002 native smoke must prove:

- empty-root equality;
- fixed-vector equality;
- input-order independence;
- at least 200 deterministic randomized state fixtures;
- insert/update/delete mutation-sequence equality after every mutation;
- deterministic replay;
- duplicate and invalid integer FFI inputs fail closed;
- canonical chain identity and activation heights remain unchanged.

## What RUST-002 does not authorize

RUST-002 is not permission to route block validation, replay, mining, persistence, RPC, or P2P consensus decisions through Rust. Production consensus integration is a separate explicit-review checkpoint after differential testing, native fuzzing, and benchmark evidence.

No chain identity, genesis, monetary/reward rules, P2P protocol, SMT activation, PQ activation, ML-DSA behavior, wallet-key semantics, or signature-acceptance semantics change in this checkpoint.
