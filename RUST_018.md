# RUST-018 — Detached authenticated source rebuild

RUST-018 closes a build-input-closure gap discovered after RUST-017.

RUST-014's signed `build_inputs` list authenticates eleven source/policy files, and RUST-017 proves those bytes are reachable from the signed Git commit. The native crate directory also contains two files that can influence a Maturin/Rust build but are not present in that legacy eleven-file list:

- `native/axven_native/pyproject.toml`
- `native/axven_native/rust-toolchain.toml`

The first contains the native package metadata and `[tool.maturin]` bindings/features. The second pins the Rust channel/profile/components. RUST-018 therefore does not pretend that the RUST-014 list was a complete build-source closure.

## Security construction

RUST-018 authenticates an exact five-file native rebuild source:

- `native/axven_native/Cargo.toml`
- `native/axven_native/Cargo.lock`
- `native/axven_native/src/lib.rs`
- `native/axven_native/pyproject.toml`
- `native/axven_native/rust-toolchain.toml`

The first three must be byte-identical to the SHA-256-authenticated RUST-016 source inputs. All five must independently match their Git blob identities under the RUST-017 detached commit/tree proof. Because the RUST-017 commit object is itself required to equal the Ed25519-authenticated RUST-014 `source.commit`, the two additional configuration files gain authenticated source identity through commit membership without changing the historical RUST-014 schema.

The detached rebuild source is a real directory with an exact path set. Symlinks, missing files, extra files, path relocation, and byte mutation fail closed.

## Clean rebuild

After source authentication succeeds, CI performs a third native wheel build from only the detached five-file native source tree.

The rebuild:

- has no repository checkout mount and no `.git` directory;
- mounts the detached source read-only;
- uses the same immutable `manylinux_2_28_x86_64` image;
- uses CPython 3.13.13, Rust 1.98.0, Maturin 1.15.0, PyO3 0.29.2 and Cargo `--locked`;
- preserves the RUST-013 deterministic environment and signed `SOURCE_DATE_EPOCH`;
- runs with Docker `--network none` and `CARGO_NET_OFFLINE=true`;
- uses a separately staged hash-locked Maturin tool directory and an already populated local Cargo cache rather than fetching during the rebuild;
- writes only target/output state outside the read-only source mount.

After the rebuild, the detached verifier requires the rebuilt wheel to match build A, build B, and the signed artifact claim byte-for-byte, SHA-256-for-SHA-256, and byte-length-for-byte-length. The existing ZIP/source-epoch policy is re-applied to the rebuilt wheel.

## What this proves

The resulting chain is:

`signed TEST-ONLY provenance -> signed source.commit -> detached Git tree/blob membership -> exact native source closure -> network-disabled clean rebuild -> byte-identical portable wheel`

This is stronger than merely checking an artifact hash: it proves that an independently staged, authenticated native source closure rebuilds to the exact candidate artifact under the pinned builder policy.

## Explicit non-goals

RUST-018 does **not** publish artifacts, create a GitHub Release, enable OIDC, introduce a production signing key, create GitHub attestations, push a package/container, deploy code, or route production consensus through Rust.

The RUST-014 Ed25519 key remains deliberately TEST-ONLY. Production consensus remains Python-authoritative. Any real release trust root, publication path, or production Rust routing remains a separate explicit approval gate.
