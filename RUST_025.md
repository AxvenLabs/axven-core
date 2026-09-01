# RUST-025 — Upstream-authenticated fully detached native rebuild

RUST-025 integrates the upstream-authenticated Rust 1.98.0 distribution proven by RUST-024 into the fully detached source + verified dependency build boundary established by RUST-022.

## Construction

The workflow pins the same Rust Project standalone distribution URL and SHA-256 used by RUST-024. The archive is downloaded only as a temporary CI input, locally hashed and structurally verified before extraction or execution. Its installer is then run inside the immutable manylinux image with Docker networking disabled and writes only to an unprivileged temporary prefix.

The resulting toolchain must report exactly:

- `rustc 1.98.0 (88d9e12ae 2026-08-18)`
- `cargo 1.98.0 (797e8a9bc 2026-08-05)`

RUST-023 captures and verifies the complete installed toolchain filesystem closure before native build consumption.

RUST-025 then reproduces the RUST-022 trust chain:

1. create two deterministic reference wheels and prove byte-for-byte reproducibility;
2. generate and verify the existing RUST-014 reproducibility provenance and TEST-ONLY attestation;
3. stage the detached native source, raw Git commit/tree proof and exact source-input set with no `.git` directory;
4. authenticate that detached source with the RUST-018 verifier;
5. collect and verify the RUST-019 Cargo archive + Maturin dependency closure;
6. rebuild and verify the RUST-020 Cargo vendor tree;
7. run the final native build with Docker `--network none`, a fresh Cargo home, verified vendor, verified Maturin wheel, detached source and the RUST-024 authenticated Rust toolchain mounted read-only;
8. require the final wheel to match the reference wheel byte-for-byte and reapply RUST-018, RUST-021, RUST-013 and RUST-009 contracts;
9. re-verify the Rust upstream archive, installed RUST-023 toolchain closure, Cargo/Maturin closure and Cargo vendor closure after final consumption.

The final builder does not mount the producer Rustup tree, producer Cargo registry/cache, repository checkout, `.git`, or GitHub environment variables. Its Rust compiler and Cargo executable come only from the read-only upstream-authenticated toolchain prefix.

## Trust boundary

RUST-025 closes the specific gap left by RUST-024: the Rust toolchain used for the fully detached native wheel is now connected to the repository-pinned official Rust distribution digest instead of being accepted only as a post-install filesystem identity.

The repository still pins the expected upstream SHA-256. This checkpoint does not introduce a separate Rust Project signature-verification trust root; that can remain a future hardening layer if desired.

## Non-goals

RUST-025 does not upload or publish artifacts, create a GitHub Release, enable OIDC, add a production signing key, create GitHub attestations, push packages or containers, deploy code, change chain identity or consensus semantics, or route production execution through Rust.

Production consensus remains Python-authoritative. Production Rust routing, production signing and artifact publication remain separate explicit approval gates.
