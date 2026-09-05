# RUST-020 — Verified offline Cargo vendor closure

RUST-019 authenticates the exact external dependency archives used by the native Rust build: every crates.io `.crate` archive is bound to `Cargo.lock`, and the Maturin wheel is bound to `requirements-native-build.lock`.

RUST-020 proves that the authenticated Rust archive closure is not merely inspectable but can be converted into a fresh Cargo directory source and consumed without any registry cache or network access.

This checkpoint deliberately stops at dependency resolution. A full native wheel rebuild using the verified vendor tree and the RUST-019 Maturin wheel is a separate checkpoint so vendor construction/resolution failures remain distinguishable from compiler/linker/reproducibility failures.

## Vendor construction

The RUST-020 builder first reuses the RUST-019 verifier to authenticate the supplied `.crate` directory against `Cargo.lock`.

It then creates a new vendor tree from scratch. For each locked registry package:

- the exact `<name>-<version>.crate` archive is opened as gzip-compressed tar;
- only regular files and directories under the canonical `<name>-<version>/` archive root are accepted;
- symlinks, hardlinks, devices, FIFOs, absolute paths, traversal components, duplicate paths and unsupported member types are rejected;
- file bytes are copied into a fresh `vendor/<name>-<version>/` directory;
- a Cargo directory-source `.cargo-checksum.json` is generated from the extracted file bytes;
- its `package` value is the SHA-256 archive checksum already authorized by `Cargo.lock`;
- its `files` map contains a SHA-256 for every extracted regular source file.

The generated vendor tree is then independently re-read. Package directories must be an exact set match to the registry package identities in `Cargo.lock`. Every source file hash and every package checksum is recomputed. Missing, extra, renamed, modified or symlinked files fail closed.

## Clean Cargo resolution

CI creates a brand-new Cargo home containing only a source-replacement configuration:

- `crates-io` is replaced with the generated `vendored-sources` directory;
- Cargo networking is configured offline;
- there is no Cargo registry cache, registry source tree or registry index in that Cargo home.

Cargo resolution then runs inside the immutable manylinux container with Docker `--network none`, `CARGO_NET_OFFLINE=true`, the pinned Rust 1.98.0 toolchain, the vendor tree mounted read-only, and the native manifest mounted read-only.

`cargo metadata --offline --locked` must succeed against the exact `Cargo.lock`. This proves Cargo can resolve the locked dependency graph from only the verified local directory source.

The clean resolution step does not install Maturin and does not build the wheel; those are intentionally reserved for the next checkpoint.

## Fail-closed contract

RUST-020 mutation tests reject at least:

- a modified vendored source file;
- a missing vendored source file;
- an extra vendored source file;
- a source-file symlink substitution;
- a modified `.cargo-checksum.json` file hash;
- a modified package checksum;
- an unexpected extra package directory;
- a missing package directory.

The original vendor tree is verified again after the mutation suite.

## Explicit non-goals

RUST-020 does **not** publish artifacts, create a GitHub Release, enable OIDC, introduce a production signing key, create GitHub attestations, deploy code, change chain identity, install or route a production Rust implementation, or change consensus behavior.

Production consensus remains Python-authoritative. Full native rebuild consumption of the verified vendor/Maturin closure remains a later non-production checkpoint.
