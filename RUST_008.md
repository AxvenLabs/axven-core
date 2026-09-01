# RUST-008 — Native artifact provenance candidate gate

RUST-008 binds each unpublished `axven_native` wheel to a machine-readable canonical provenance candidate. It is a supply-chain evidence checkpoint only: no wheel or provenance file is uploaded, published, added to the Axven canonical release, or consumed by production consensus.

## Purpose

RUST-007 proved that the dormant native extension can be packaged and clean-installed on Linux, Windows, and macOS. RUST-008 adds traceability from each generated wheel back to the exact source commit, locked build inputs, and exact toolchain used to create it.

For each OS matrix runner, CI builds one release wheel from committed sources and emits `native-provenance.json`. The manifest is canonical JSON (`sort_keys=True`, compact separators, UTF-8, one trailing newline) and is immediately re-verified against the wheel, repository files, current GitHub Actions identity, and locally reported toolchain versions.

## Provenance contents

The candidate manifest records:

- schema `axven-native-artifact-provenance-v1`;
- repository and exact 40-hex `GITHUB_SHA` source identity;
- GitHub Actions run id and attempt;
- wheel filename, byte length, complete SHA-256, package name/version, Python requirement, and wheel tags;
- SHA-256 of `native/axven_native/Cargo.toml`, `native/axven_native/Cargo.lock`, `native/axven_native/src/lib.rs`, and `requirements-native-build.lock`;
- exact CPython, `rustc`, `cargo`, and maturin versions;
- native `boundary_version()` and the fixed RUST-002 one-leaf Sparse-Merkle root probe;
- explicit `production_consensus: python`.

The verifier rejects malformed hashes, unexpected source identity, changed build inputs, toolchain drift, artifact drift, metadata drift, duplicate or unsafe wheel archive members, incorrect native behavior, or a production Python module importing `axven_native`.

## Authentication boundary

This checkpoint creates a provenance **candidate**, not a cryptographically signed release attestation. The manifest remains an ephemeral runner file beside an unpublished wheel. A later checkpoint may add keyless/signed attestation and canonical release/runtime-provenance integration after the signing mechanism itself is reviewed and pinned.

The workflow remains `contents: read`, disables checkout credential persistence, and contains no artifact upload, package publish, release creation, or external deployment step.

## Consensus boundary

Production `expected_state_root()`, `_transition()`, `_apply_forward()`, block validation, mining, reorg, replay, persistence, RPC, P2P, wallet behavior, ML-DSA, and signature acceptance remain unchanged and Python-authoritative.

No chain identity, genesis, reward/monetary rule, P2P protocol, SMT/PQ activation height, ML-DSA behavior, wallet-key semantics, or signature-acceptance semantics change in RUST-008.
