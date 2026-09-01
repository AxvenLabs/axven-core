# RUST-026 — TEST-ONLY signed native build-material attestation

RUST-025 closed the native build's source, dependency and Rust-toolchain consumption boundaries, but those independently verified material identities were still spread across separate checks. RUST-026 binds the final native artifact and its critical supply-chain material identities into one canonical TEST-ONLY signed statement and verifies it from a detached consumer context.

## Bound material identities

The canonical `axven-native-build-materials-v1` payload binds:

- source repository and exact commit SHA;
- final portable wheel filename, SHA-256 and byte length;
- immutable manylinux image digest and pinned Python/Rust/Cargo/Maturin/PyO3 versions;
- exact Rust Project 1.98.0 standalone distribution URL and SHA-256;
- SHA-256, byte length and file count of the independently verified RUST-023 toolchain-closure manifest;
- SHA-256 of detached `Cargo.lock` and `requirements-native-build.lock`;
- canonical recursive inventory digest and exact counts for the RUST-019 Cargo archive + Maturin dependency closure;
- canonical recursive inventory digest and package/file counts for the RUST-020 verified Cargo vendor closure;
- the explicit statement that production consensus remains Python-authoritative.

Directory inventories reject symlinks and unsupported file types and bind each regular file's canonical relative path, SHA-256, byte length and Unix mode before hashing the canonical inventory.

## TEST-ONLY attestation

The material payload is signed with a dedicated RUST-026 TEST-ONLY Ed25519 key and domain separation string. The envelope pins its own schema, algorithm, key id, payload type and payload SHA-256. The verifier pins the independent public key and never trusts a public key supplied by the envelope.

This key is intentionally embedded test material. It is not a release key, production signing key, OIDC identity, HSM key or external trust service.

## Detached verification

CI first runs the complete RUST-025 upstream-authenticated fully detached build. RUST-026 then generates and seals the material statement from the resulting `/tmp` evidence.

A copy of only the RUST-026 verifier, materials JSON and envelope is staged outside the repository. Verification runs under `env -i` from `/tmp` against the already detached final wheel, Rust archive, RUST-023 toolchain manifest, dependency closure, vendor closure and detached lock files. It does not require Git, GitHub environment variables or producer-module imports.

A 9/9 fail-closed mutation contract covers source commit, Rust distribution identity, toolchain-manifest identity, dependency closure, vendor closure, builder image, Ed25519 signature, canonical JSON and final wheel bytes. The pristine evidence is verified again after mutation testing.

## Non-goals

RUST-026 does not upload or publish artifacts or attestations, create a GitHub Release, enable OIDC, add a production signing key, create GitHub-hosted attestations, push packages or containers, deploy code, change chain identity or consensus semantics, or route production execution through Rust.

Production consensus remains Python-authoritative. Production Rust routing, production signing and artifact publication remain separate explicit approval gates.
