# RUST-004 — Native Sparse-Merkle Benchmark

RUST-004 measures the already differential-tested and fuzzed Rust Sparse-Merkle mirror against the canonical Python reference. It is **benchmark-only**: production Axven consensus continues to use `axven.smt_root_reference()`.

## Required ordering

Correctness is checked before timing. Every deterministic fixture must produce the exact same lowercase 64-hex root under Python and the PyO3/Rust mirror. Reordered rows must also preserve the same root. A mismatch aborts the benchmark immediately and no performance result is accepted.

## Measurements

The dedicated benchmark reports three paths over the same deterministic UTXO state:

- `python_reference`: `axven.smt_root_reference(utxo)`;
- `rust_prepared_rows`: `axven_native.smt_root_mirror(rows)` with the Python row list already prepared;
- `rust_end_to_end`: row projection plus the PyO3 call, representing the simplest production-style Python-to-Rust boundary.

Fixtures cover 0, 1, 100, and 1,000 UTXOs. Each path receives an unmeasured warmup and then multiple timed samples; reported time is the median per operation. The 1,000-UTXO Python iteration count matches the existing PERF-001 reference benchmark scale.

## Interpretation

GitHub-hosted runners are noisy. Timings and speedup ratios are diagnostic evidence only: they are not consensus inputs, release requirements, SLA promises, or protocol parameters. RUST-004 intentionally has **no minimum-speedup gate**. A slow native result is valid evidence and must not be hidden or converted into a semantics change.

Both prepared-row and end-to-end numbers are retained so FFI/projection overhead is visible rather than excluded from the decision.

## Toolchain boundary

The benchmark builds the existing native crate in release mode from its committed Cargo lockfile using the reviewed Rust `1.98.0` toolchain and Python `3.13.15`. No new Rust dependency is introduced by RUST-004.

## Production boundary

RUST-004 does not modify or route `expected_state_root()`, block validation, replay, mining, persistence, RPC, P2P, wallet code, or release runtime provenance through Rust. Production modules continue to contain no `axven_native` import.

No chain identity, genesis, monetary/reward rules, P2P protocol, SMT/PQ activation heights, ML-DSA behavior, wallet-key semantics, or signature-acceptance semantics change in this checkpoint.

A later production-routing checkpoint may proceed only after benchmark evidence is recorded and a separate replay/shadow-equivalence gate proves the native and Python state roots remain identical across state transitions.
