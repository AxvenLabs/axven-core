# RUST-001 — Axven Native Boundary Skeleton

## Why Rust now

FUZZ-001 established the hostile-input baseline. PERF-001 then measured the current Python implementation before any native optimization. The measurements show that the main optimization target is **not** the ML-DSA wrapper.

PERF-001 PR run `33474374834` on Python 3.13.15 / ubuntu-latest reported these representative medians:

| Workload | Median |
|---|---:|
| `smt_reference.1000` | 226.340 ms |
| `utxo_root.10000` | 13.590 ms |
| `block.serialized_size.1000_txs` | 1.092 ms |
| `merkle_root.1000_hashes` | 0.643 ms |
| `smt_incremental.single_update` | 0.254 ms |
| `p2p.json_preflight` | 0.206 ms |
| `smt_proof_verify` | 0.186 ms |
| `verify.hybrid` | 0.177 ms |
| `verify.mldsa44` | 0.096 ms |
| `verify.ed25519` | 0.081 ms |
| `tx.txid` | 0.005 ms |

The mixed cProfile workload likewise put `smt_root_reference` first by cumulative time. A 1,000-entry `SparseMerkleTree` rebuild also showed about 61 MB of Python-visible peak allocation, while an incremental single update remained sub-millisecond.

These shared-runner measurements are diagnostic only. They are not consensus inputs, performance promises, or SLA gates.

## Hotspot decision

The first native candidate family is **state-root computation**, especially the full sparse-Merkle reference path. The current Python reference function remains the consensus oracle, and `expected_state_root` selects it for the sparse state-root scheme. That makes this path high-value but consensus-adjacent.

Therefore RUST-001 intentionally adds **no production hook**. The native extension is dormant and contains only a deterministic binding probe.

## Native boundary

`Python Axven Core -> PyO3 -> axven_native Rust crate`

Initial boundary rules:

1. Bytes/value inputs in; deterministic values out.
2. No sockets, files, RPC servers, clocks, randomness, environment lookup, or persistent state.
3. Do not rewrite Ed25519 or ML-DSA primitives.
4. Keep production Python behavior unchanged until differential tests are exhaustive enough for the candidate path.
5. Fuzz the FFI boundary independently before production routing.

## Toolchain pins

- Rust: `1.98.0`
- PyO3: `0.29.0`
- maturin: `1.15.0`

The Rust dependency graph must be committed through `Cargo.lock` before RUST-001 is eligible to merge.

## RUST-002 gate

The next checkpoint may implement a **test-only native state-root mirror**. Before any production use it must pass:

- byte-for-byte differential tests against the Python reference;
- randomized/property-based state fixtures, including insert/update/delete ordering;
- malformed/boundary FFI fuzzing;
- deterministic replay across repeated runs;
- performance measurements against PERF-001;
- explicit review before routing consensus validation through the native implementation.

RUST-001 changes no chain identity, genesis, monetary rules, P2P protocol, PQ activation heights, ML-DSA behavior, or signature-acceptance semantics.
