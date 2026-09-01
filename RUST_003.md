# RUST-003 — Native Sparse-Merkle Fuzzing

RUST-003 fuzzes the **test-only** Rust Sparse-Merkle mirror introduced by RUST-002. Production Axven consensus continues to use the Python state-root oracle.

## Scope

The native fuzzer exercises the pure Rust state-root computation only. It does not fuzz or reimplement Ed25519, ML-DSA, ML-KEM, wallet key handling, networking, RPC, persistence, process control, clocks, randomness, or filesystem behavior.

The parent crate exposes a fuzz helper only when the `fuzzing` Cargo feature is explicitly enabled. Normal library and PyO3 extension builds do not enable that feature.

## Toolchain pins

- production/native review toolchain: Rust `1.98.0`
- fuzz-only toolchain: `nightly-2026-08-20`
- cargo-fuzz: `0.13.2`
- libfuzzer-sys: `0.4.13`
- PyO3: `0.29.2`
- RustCrypto sha2: `0.10.9`

The fuzz crate uses an exact `libfuzzer-sys` dependency and a committed Cargo lockfile with registry checksums.

## Input and resource boundary

The `smt_mirror` target consumes at most 4096 input bytes and decodes no more than 32 UTXO records. Each fuzz-generated text field is capped at 96 bytes before UTF-8 lossy normalization. CI runs libFuzzer with explicit run-count, per-input timeout, and RSS limits.

These bounds keep fuzzing focused on algorithmic and memory-safety behavior rather than allowing the harness itself to create unbounded allocations.

## Invariants asserted under fuzzing

For every decoded record set:

1. repeated evaluation must be deterministic;
2. reversing the input order must preserve the same success/error result and root;
3. a deterministic rotation of the same records must preserve the same result;
4. duplicate outpoints and any discovered SMT-key collision remain fail-closed;
5. no panic, sanitizer failure, undefined-behavior report, or resource-limit violation is acceptable.

## Production boundary

RUST-003 does not route `expected_state_root()`, block validation, replay, mining, persistence, RPC, or P2P through Rust. The Python implementation remains the production consensus oracle.

No chain identity, genesis, monetary/reward rules, P2P protocol, SMT/PQ activation heights, ML-DSA behavior, wallet-key semantics, or signature-acceptance semantics change in this checkpoint.

## Exit gate

Before RUST-003 can merge, the exact review head must pass ordinary Axven Validation, existing Python Fuzz Smoke, Native Smoke, and the new Native Fuzz workflow. Production routing remains a separate approved checkpoint and must additionally have benchmark and replay-equivalence evidence.
