# RUST-006 — Cross-platform native ABI gate

RUST-006 proves that the existing dormant `axven_native` PyO3 extension can be built and imported from the committed Cargo lockfile on the three desktop/server OS families Axven currently cares about: Linux, Windows, and macOS.

This checkpoint is **build/ABI-only**. It does not place a native binary in the canonical Axven release, does not change the main `axven-core` setuptools package, and does not route any production consensus operation through Rust.

## Contract

Each matrix runner must:

1. use CPython `3.13.15`;
2. install and select Rust `1.98.0`;
3. build `native/axven_native/Cargo.toml` with `--release --locked --features extension-module`;
4. rename only the just-built platform library to Python's local extension suffix and import it from the checkout root;
5. require `boundary_version() == "rust-001"`;
6. recompute the fixed RUST-002 single-leaf Sparse-Merkle vector and obtain exactly `f9c17f4ac4ffe9b72aaebc1ed3a4c241f0316c29883a8adcbef610a92170e45d`;
7. reject a duplicate-outpoint record fail-closed;
8. verify that production Python modules still contain no `axven_native` import.

The workflow is read-only (`contents: read`), checkout credentials are not persisted, and no built binary is uploaded or committed. The test therefore proves build/import compatibility without silently creating a distribution channel.

## Distribution boundary

The canonical `axven-core` package remains setuptools-based and Python-only. The native crate remains its own maturin project. RUST-006 intentionally does **not** modify `pyproject.toml`, `build_release_package.py`, `release_manifest.json`, runtime provenance, or installer behavior.

A later checkpoint may design authenticated native wheel/package distribution only after this matrix is green. Shipping a native binary must include exact artifact identity and runtime provenance; a successful RUST-006 alone does not authorize production consensus routing.

## Consensus non-change boundary

No chain identity, genesis, reward/monetary rule, P2P protocol, SMT/PQ activation height, ML-DSA behavior, wallet-key semantics, or signature-acceptance semantics change. `expected_state_root()` remains the authoritative Python implementation path.