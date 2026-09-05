# RUST-019 — Offline dependency archive closure

RUST-018 proves that an authenticated five-file native source closure can be rebuilt with Docker networking disabled and that the resulting wheel is byte-identical to the signed reference artifact. Its detached build still stages Maturin tooling and an already populated Cargo cache from the CI producer environment.

RUST-019 isolates that remaining trust boundary. It does **not** change production execution or the RUST-018 rebuild path. Instead, it creates and independently verifies the exact dependency archives that a future detached build may consume.

## Rust crate closure

The verifier parses `native/axven_native/Cargo.lock` itself with Python's standard-library TOML parser. Every package whose source is the crates.io registry must have:

- a non-empty package name and version;
- a lowercase 64-character SHA-256 checksum;
- exactly one supplied archive named `<name>-<version>.crate`;
- archive SHA-256 exactly equal to the checksum in `Cargo.lock`.

The supplied crate directory must contain exactly the registry package set from the lock file: missing, duplicate, renamed and extra archives fail closed.

Each `.crate` archive is also inspected as a gzip-compressed tar archive. Absolute paths, traversal components, backslashes, symlinks, hardlinks, device nodes and entries outside the package's canonical `<name>-<version>/` root are rejected. This prevents a checksum-validity check from being confused with a safe extraction policy.

## Python build-tool closure

The verifier independently parses `requirements-native-build.lock` and requires the current contract to remain a single exact requirement:

`maturin==1.15.0`

The lock must contain only lowercase SHA-256 hashes. The supplied Python-wheel directory must contain exactly one regular `.whl` file whose digest is one of those lock-file hashes and whose filename identifies Maturin 1.15.0.

The wheel is checked as a ZIP archive with unique safe member paths and no symlink members.

## Producer collection

A dedicated CI workflow may use the network **before** detached verification to populate candidate dependency archives:

- `cargo fetch --locked` obtains the crates named by `Cargo.lock`;
- `pip download --no-deps --only-binary=:all: --require-hashes` obtains the hash-locked Maturin wheel.

Only archive bytes are copied into the detached verification bundle. The verifier itself runs under `env -i`, imports no Axven production module, does not execute subprocesses, and has no Git, Docker, network-client or GitHub-environment dependency.

The workflow then runs verify → fail-closed selftest → verify again.

## What this proves

RUST-019 proves that the externally sourced native build dependencies available for a future offline rebuild are closed over the exact Rust lock checksums and the exact hash-locked Python build requirement.

It deliberately does **not** yet route RUST-018 through that closure. Consuming only these authenticated archives in a fresh Cargo/Python tool environment is a separate checkpoint so verification policy and build-mechanism changes do not land in one step.

## Explicit non-goals

RUST-019 does **not** upload or publish artifacts, create a GitHub Release, enable OIDC, introduce a production signing key, create GitHub attestations, push packages/containers, deploy code, change chain identity, or route production consensus through Rust.

Production consensus remains Python-authoritative. The RUST-014 Ed25519 key remains TEST-ONLY.
