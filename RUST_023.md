# RUST-023 — Verified Rust toolchain filesystem closure

RUST-022 proved that Axven's native wheel can be rebuilt from an authenticated detached five-file source closure plus verified Cargo and Maturin dependencies with the network disabled. One remaining build-input boundary is the Rust toolchain itself.

RUST-023 captures and verifies the exact filesystem closure of the minimal Rust 1.98.0 toolchain used by CI:

- `rustc 1.98.0 (88d9e12ae 2026-08-18)`
- `cargo 1.98.0 (797e8a9bc 2026-08-05)`
- target `x86_64-unknown-linux-gnu`
- minimal installed component set: Cargo, rustc and rust-std

## Construction

The workflow installs Rust 1.98.0 with rustup's minimal profile, resolves the exact `1.98.0-x86_64-unknown-linux-gnu` toolchain directory and creates a canonical JSON manifest for every regular file in that directory.

For each file the manifest records:

- canonical repository-independent relative path;
- SHA-256;
- byte length;
- Unix permission mode.

The verifier requires the manifest to be canonical JSON, requires an exact sorted file set and rejects missing files, extra files, duplicate paths, path confusion, symlinks, unsupported filesystem entries, digest changes, size changes and mode changes.

The fail-closed mutation contract is 10/10. The pristine closure is verified before and after isolated consumption.

## Isolated consumption

The verified toolchain root is mounted read-only as `/rust-toolchain` inside the same immutable `manylinux_2_28_x86_64` image family used by the portable native build series. Docker networking is disabled.

The isolated consumer receives the verified Rust toolchain only through that read-only mount, checks the exact rustc and Cargo identities, and compiles and executes a tiny `x86_64-unknown-linux-gnu` Rust program. This proves the captured closure contains a usable compiler, Cargo executable and target standard library rather than only a version string.

## Explicit trust boundary

RUST-023 **does not independently authenticate the upstream Rust distribution**. The canonical closure manifest is created after rustup has installed the toolchain in CI. This checkpoint therefore closes exact post-install filesystem identity and mutation detection, but it does not yet prove that those installed bytes are the official Rust Project distribution bytes.

RUST-024 is reserved for binding the toolchain closure to independently pinned upstream distribution/component digests before allowing the fully detached RUST-022 builder to consume that authenticated toolchain.

This distinction is intentional: RUST-023 must not overclaim upstream authenticity merely because `rustc --version` and `cargo --version` match.

## Non-goals

RUST-023 does not publish artifacts, create a GitHub Release, enable OIDC, introduce a production signing key, create GitHub attestations, push packages or containers, deploy code, alter chain identity, change consensus semantics, or route production execution through Rust.

Production consensus remains Python-authoritative. Production Rust routing, production release signing and publication remain separate explicit approval gates.
