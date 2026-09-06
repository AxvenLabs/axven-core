# RUST-024 — Upstream-authenticated Rust 1.98.0 distribution

RUST-023 proved exact post-install filesystem identity for the Rust toolchain used by Axven CI, but deliberately did not claim that the installed bytes were independently authenticated as an official Rust Project distribution.

RUST-024 closes that upstream-distribution boundary for the Linux x86_64 standalone Rust 1.98.0 distribution.

## Pinned upstream input

The checkpoint pins the date-qualified Rust Project distribution URL:

`https://static.rust-lang.org/dist/2026-08-20/rust-1.98.0-x86_64-unknown-linux-gnu.tar.xz`

and the exact SHA-256:

`ed8ee2df70909c88cbaf87a6cfa3920dac00b537de12a6abe6906641e0f5952f`

The archive is downloaded only into a temporary CI location. Before extraction or execution, the RUST-024 verifier requires the exact filename, exact SHA-256 and a safe archive structure rooted only at `rust-1.98.0-x86_64-unknown-linux-gnu`.

Archive members with absolute paths, path traversal, a different top-level root, duplicate paths, device/FIFO entries, or escaping symbolic/hard-link targets are rejected. Extraction uses Python's hardened `tarfile` data filter after the complete archive has passed the structural verifier.

## Authenticated installation and closure

Only after the pinned archive hash and structure have been verified is its included `install.sh` allowed to execute. Installation occurs in the immutable manylinux image with Docker networking disabled and writes only to an unprivileged temporary prefix named `1.98.0-x86_64-unknown-linux-gnu`.

The installed distribution must report exactly:

- `rustc 1.98.0 (88d9e12ae 2026-08-18)`
- `cargo 1.98.0 (797e8a9bc 2026-08-05)`

RUST-023 then captures and verifies the complete installed filesystem closure. That closure is mounted read-only into a second network-disabled manylinux consumer, where it must compile and execute a small `x86_64-unknown-linux-gnu` program. Both the original upstream archive and the installed RUST-023 closure are re-verified after consumption.

This proves a chain from a repository-pinned upstream distribution digest to an exact installed toolchain closure and usable offline compiler environment.

## Trust and checkpoint boundary

RUST-024 authenticates the standalone distribution by a SHA-256 value pinned in the Axven repository and checked against the bytes fetched from the Rust Project static distribution host. The pinned digest is also independently corroborated during engineering review, but CI acceptance depends on Axven's pinned digest and local hashing rather than trusting HTTP metadata or an external package manager.

RUST-024 intentionally does **not** yet replace the Rust toolchain used by the fully detached RUST-022 Axven native wheel rebuild. Integrating this upstream-authenticated toolchain into that final detached build is reserved for RUST-025 so toolchain authentication and final native-build consumption remain separate reviewable trust-boundary changes.

## Non-goals

RUST-024 does not upload or publish the downloaded Rust archive, installed toolchain, manifest, or native artifacts. It does not create a GitHub Release, enable OIDC, add a production signing key, create GitHub attestations, push packages or containers, deploy code, change chain identity or consensus semantics, or route production execution through Rust.

Production consensus remains Python-authoritative. Production Rust routing, production signing and artifact publication remain separate explicit approval gates.
