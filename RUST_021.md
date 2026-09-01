# RUST-021 — Verified dependency-consumed offline wheel rebuild

RUST-021 closes the dependency-consumption gap left deliberately open by RUST-020.

RUST-019 authenticates every crates.io archive against `Cargo.lock` and the exact Maturin 1.15.0 wheel against `requirements-native-build.lock`. RUST-020 converts the authenticated crate archives into a verified Cargo directory source and proves Cargo can resolve the locked graph from that source with the network disabled and without registry or Git dependency caches.

RUST-021 now proves those verified dependency inputs are sufficient for a real native wheel build.

## Construction

The workflow first creates a reference native wheel under the existing pinned reproducible-build policy. It then independently collects and verifies the RUST-019 dependency closure, builds and re-verifies the RUST-020 Cargo vendor tree, and creates a fresh Cargo home whose crates.io source is replaced by `/vendor` with Cargo offline mode enabled.

The Maturin wheel is not installed from the network for the offline candidate. The exact RUST-019-verified wheel is mounted read-only into the isolated builder and installed with `pip --no-index --no-deps` into a fresh tool directory.

The candidate build runs in the immutable manylinux image with:

- Docker `--network none`;
- `CARGO_NET_OFFLINE=true`;
- a clean Cargo home with no registry index/cache/source or Git dependency cache;
- the RUST-020 verified vendor tree mounted read-only;
- the RUST-019 verified Maturin wheel mounted read-only;
- Rust 1.98.0 mounted read-only;
- CPython 3.13.13 and Maturin 1.15.0;
- Cargo `--locked`;
- the same source-bound `SOURCE_DATE_EPOCH` and deterministic environment used by the reproducible-build series;
- the native crate mounted read-only at the canonical `/work/native/axven_native` source path so source-path identity matches the reference build.

### Canonical dependency source paths

The first dependency-consumption experiment successfully produced the offline wheel but exposed an 11-byte artifact difference: the reference build compiled registry dependencies from Cargo's physical `/cargo/registry/src/index.crates.io-...` tree, while the authenticated offline build compiled the same dependency bytes from `/vendor`. Rust can retain those absolute source paths in native output even though the source bytes and compiler inputs are otherwise equivalent.

RUST-021 therefore treats dependency source location as a reproducibility input and canonicalizes it rather than weakening artifact equality. Before the reference build, CI materializes the Cargo registry source tree and fails unless there is exactly one `index.crates.io-*` source root. The reference compiler remaps that exact root to `/axven/vendor`; the offline compiler independently remaps `/vendor` to the same `/axven/vendor` namespace using `--remap-path-prefix`.

This does not authorize or substitute any dependency bytes. RUST-019 checksum verification and RUST-020 vendor verification still determine which dependency content is accepted. The remap removes only non-semantic physical build-host path variation. Full wheel SHA-256, length and byte equality remain mandatory and fail closed.

The resulting wheel must be byte-for-byte, SHA-256-for-SHA-256 and length-for-length identical to the reference wheel. RUST-013 reproducible-wheel checks and the portable-wheel contract are re-applied to the offline candidate.

## Security boundary

RUST-021 specifically proves dependency **consumption**. The offline candidate is not allowed to use the producer Cargo registry cache, Cargo source cache, Cargo Git cache, PyPI, crates.io, or any network service. The only third-party build inputs available to it are the verified Cargo vendor tree and the verified Maturin wheel.

The source itself is mounted from the checked-out commit at the canonical source path in this checkpoint. RUST-018 separately proves detached authenticated native source closure and a network-disabled rebuild. Combining the RUST-018 detached source proof with the RUST-021 verified dependency consumption into one fully detached build is intentionally left to the next checkpoint rather than changing two trust boundaries at once.

## Non-goals

RUST-021 does **not** publish artifacts, upload build outputs, create a GitHub Release, enable OIDC, introduce a production signing key, create GitHub attestations, push a package/container, deploy code, change chain identity, or route production consensus through Rust.

Production consensus remains Python-authoritative. Real release trust, publication, fully detached source-plus-dependency consumption, and production Rust routing remain separate explicit gates.
