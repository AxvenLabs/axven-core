# RUST-012 — Detached offline native consumer verifier

RUST-012 turns the RUST-011 portable evidence chain into a source-independent consumer check. A verifier copied into a clean directory receives only the portable wheel, canonical provenance statement, and canonical TEST-ONLY attestation envelope. It validates the complete artifact → provenance → attestation chain without a repository checkout, GitHub environment variables, `git`, Docker, network access, or Axven production modules.

This checkpoint still does **not** publish a wheel, upload an artifact, create a release, request OIDC, publish an attestation, modify the canonical release manifest, or route production consensus through Rust.

## Consumer input contract

The detached directory contains exactly:

- `rust_012_offline_consumer_verify.py`;
- `axven_native-0.1.0-cp313-abi3-manylinux_2_28_x86_64.whl`;
- `portable-provenance.json`;
- `portable-attestation.json`.

The verifier rejects symlink inputs and requires canonical JSON. It does not infer artifact paths from untrusted provenance; the explicitly supplied wheel basename must equal the signed artifact filename.

## Policy pinned by the consumer

The verifier independently pins:

- repository `AxvenLabs/axven-core`;
- provenance schema `axven-native-portable-provenance-v1`;
- attestation schema `axven-native-portable-attestation-envelope-v1`;
- payload type `application/vnd.axven.native-portable-provenance.v1+json`;
- Ed25519 algorithm, TEST-ONLY key id, domain separator, and public key;
- immutable manylinux builder image digest;
- `manylinux_2_28` / `x86_64`;
- builder CPython `3.13.13`, Rust `1.98.0`, maturin `1.15.0`, and PyO3 `0.29.2`;
- exact wheel filename/tag;
- the exact set of RUST-011 build-input claim keys;
- `production_consensus: python`.

The consumer recomputes the wheel SHA-256 and byte length from the supplied wheel. Build-input hashes are authenticated signer claims: a detached consumer cannot recompute repository-file hashes without the source tree. Reproducible source rebuilding is therefore a separate future gate.

## Detached verification boundary

RUST-012 verifies two distinct things:

1. **artifact binding** — the supplied portable wheel exactly matches the signed provenance hash, size, and filename;
2. **attestation binding** — the canonical provenance bytes and canonical policy header are jointly authenticated by the independently pinned TEST-ONLY Ed25519 trust root.

The verifier does not read `GITHUB_*`, does not call `git`, does not inspect a checkout, and does not import `axven`, `rust_011_portable_attestation`, or any production module. CI executes it under `env -i` from a clean temporary directory that has no `.git` directory or source files.

## Fail-closed consumer mutations

The detached self-test requires rejection of:

1. wheel byte mutation;
2. renamed wheel/path confusion;
3. artifact digest mutation;
4. builder-image substitution;
5. source-repository substitution;
6. unexpected provenance fields;
7. non-canonical provenance JSON;
8. signature mutation;
9. key-id substitution;
10. embedded attacker-supplied `public_key`;
11. non-canonical envelope JSON.

The original evidence triple is reverified after mutation tests.

## Authentication status

The RUST-011/RUST-012 signing seed remains deliberately committed and TEST-ONLY. Passing RUST-012 proves detached verifier structure, policy pinning, canonical encoding, artifact binding, and fail-closed behavior; it is **not production release authentication**.

Replacing the TEST-ONLY trust root with a protected production release-signing mechanism, publishing artifacts, and production Rust routing each remain separate explicit gates.

## Consensus boundary

Production `expected_state_root()`, `_transition()`, `_apply_forward()`, block validation, mining, reorg, replay, persistence, RPC, P2P, wallet behavior, ML-DSA, and signature acceptance remain Python-authoritative and unchanged.

No chain identity, genesis, reward/monetary rule, P2P protocol, SMT/PQ activation height, ML-DSA behavior, wallet-key semantics, or transaction/block signature-acceptance semantics change in RUST-012.
