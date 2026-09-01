# RUST-022 — Fully detached authenticated source + verified dependency rebuild

RUST-022 joins the two trust boundaries that RUST-018 and RUST-021 deliberately proved separately.

RUST-018 proves that an exact five-file native source closure can be authenticated from signed reproducibility evidence plus detached Git commit/tree/blob membership and rebuilt with the network disabled. RUST-021 proves that the exact Cargo dependency graph and Maturin build tool can be consumed from authenticated, verified local inputs without a Cargo registry/source cache, Git dependency cache, PyPI, crates.io, or any network service.

RUST-022 requires both properties in the same final builder.

## Final builder inputs

The final build container receives only the following project/build inputs:

- the RUST-018-authenticated five-file native source closure, mounted read-only at `/work/native/axven_native`;
- the RUST-020 verified Cargo vendor tree, mounted read-only at `/vendor`;
- the RUST-019 verified Maturin 1.15.0 wheel, mounted read-only at `/python-wheels`;
- the pinned Rust 1.98.0 toolchain, mounted read-only;
- the Cargo executable directory, mounted read-only;
- fresh writable Cargo-home, Maturin-tools, target, and wheel-output locations.

It does **not** receive the repository checkout, `.git`, the producer Cargo registry/cache/source tree, a Cargo Git cache, the producer-installed Maturin tree, or network access.

The container runs with Docker `--network none`, `CARGO_NET_OFFLINE=true`, Cargo `--locked`, and installs Maturin only from the verified wheel with `pip --no-index --no-deps --no-cache-dir`.

## Source authentication

The final native source is the exact RUST-018 rebuild closure:

1. `native/axven_native/Cargo.toml`
2. `native/axven_native/Cargo.lock`
3. `native/axven_native/src/lib.rs`
4. `native/axven_native/pyproject.toml`
5. `native/axven_native/rust-toolchain.toml`

Before the final build, RUST-018 verifies the signed reproducibility evidence, source commit, detached Git object graph, exact path set, blob membership, and byte identity required by the earlier signed build-input closure. No source file is taken from the repository checkout inside the final builder.

## Dependency authentication

After source authentication, RUST-019 collects the exact crates.io archive closure required by the detached `Cargo.lock` and verifies every archive checksum and archive structure. The exact Maturin wheel is checked against `requirements-native-build.lock` from the authenticated source-input evidence.

RUST-020 converts those authenticated crate archives into a fresh Cargo directory source and verifies its exact file tree and `.cargo-checksum.json` material. The final Cargo home replaces crates.io with that verified `/vendor` source and starts without registry index/cache/src or Git dependency state.

RUST-019 and RUST-020 fail-closed mutation contracts are run before the final build, and both dependency closures are reverified after the build.

## Reproducibility boundary

The reference build and the fully detached build use the same source-bound `SOURCE_DATE_EPOCH`, immutable manylinux image, Rust 1.98.0, CPython 3.13.13, Maturin 1.15.0, canonical native source path, and deterministic build environment.

Crates.io source paths and verified-vendor source paths are compiler-remapped to the same canonical `/axven/vendor` namespace. This preserves the RUST-021 lesson that dependency storage layout must not leak machine-specific paths into the native binary.

The fully detached wheel must match the reference wheel byte-for-byte, SHA-256-for-SHA-256, and length-for-length. RUST-018 rebuild verification, RUST-021 dependency-consumption verification, RUST-013 reproducible-wheel verification, and RUST-009 portable-wheel verification are all reapplied.

## Security boundary

RUST-022 is a build-integrity checkpoint, not a release or production-routing checkpoint. It does **not** upload or publish artifacts, create a GitHub Release, enable OIDC, introduce a production signing key, create GitHub attestations, push packages or containers, deploy code, change chain identity or consensus, or route production execution through Rust.

Production consensus remains Python-authoritative. Release publication, production signing, deployment, and production Rust routing remain separate explicit approval gates.
