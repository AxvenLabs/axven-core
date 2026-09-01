# axven_native — RUST-001

`axven_native` is a dormant PyO3/maturin native boundary. RUST-001 does **not** import it from production Axven code and does not alter consensus, networking, wallet behavior, or cryptographic primitive selection.

Design constraints for the native boundary:

- deterministic inputs and outputs;
- no sockets, RPC listeners, filesystem mutation, environment discovery, clocks, randomness, or hidden global state;
- no reimplementation of Ed25519 or ML-DSA primitives;
- no production consensus hook until differential tests prove byte-for-byte equivalence with the Python reference implementation;
- keep the FFI surface small enough to fuzz independently.

The `native_probe` function exists only to prove the Python/Rust binding shape. It is not a hash, checksum, consensus function, or security primitive.

PERF-001 identifies state-root computation as the first candidate family for later native acceleration. RUST-002 should implement a test-only native mirror and differential/fuzz coverage before any production routing decision.
