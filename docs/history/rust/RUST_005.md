# RUST-005 — Replay / shadow state-root equivalence

RUST-005 is a **test-only shadow checkpoint**. It exercises the real Python `Blockchain` transition, mempool, side-chain, reorg, and replay paths while independently recomputing the Sparse-Merkle root with the Rust mirror.

## Purpose

RUST-002 proved differential equality on fixed, randomized, and mutation-generated UTXO maps. RUST-003 added bounded native fuzzing. RUST-004 measured a material speedup. RUST-005 moves one step closer to integration by proving that UTXO maps produced by real Axven state transitions remain byte-for-byte equivalent under the Python Sparse-Merkle oracle and the Rust mirror.

## Contract

For every shadowed state:

1. `axven.smt_root_reference(chain.utxo)` is computed as the authoritative sparse oracle.
2. `axven_native.smt_root_mirror(...)` independently computes the same root.
3. `axven.expected_state_root(chain.utxo, 10000)` is required to equal that same sparse root.
4. The real low-height block header remains governed by the existing legacy state-root scheme; RUST-005 does not rewrite or reinterpret it.

The rehearsal covers genesis, more than 100 real mined blocks, a mature signed Ed25519 spend through the production mempool path, a competing valid side branch, a heavier-chain reorg, and a fresh full replay from genesis.

## Non-change boundary

Production modules do not import `axven_native`. `expected_state_root()`, `_transition()`, `_apply_forward()`, block validation, mining, reorg, replay, persistence, RPC, P2P, wallets, ML-DSA, and signature acceptance remain unchanged. Rust is an observer only in this checkpoint.

No chain identity, genesis, reward/monetary rule, P2P protocol, SMT activation height, PQ activation height, ML-DSA behavior, wallet-key semantics, or signature-acceptance semantics are changed.

A successful RUST-005 is evidence for a later routing proposal; it is **not** authorization to switch production consensus execution to Rust.
