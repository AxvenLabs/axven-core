# RUST-016 — Hermetic native source-closure build rehearsal

RUST-016 narrows the native build input boundary after RUST-013 through RUST-015 established reproducible wheels, signed reproducibility evidence, and detached verification.

The existing reproducible build runs inside pinned manylinux containers but mounts the repository at `/work`. RUST-016 asks a stricter question: can the canonical native wheel be rebuilt from a minimal read-only native source closure without exposing the rest of the repository to the build container, and is that wheel still byte-for-byte identical to the ordinary reproducible build?

## Exact native source closure

The staged source tree contains exactly three regular files:

- `Cargo.toml`
- `Cargo.lock`
- `src/lib.rs`

They are copied from:

- `native/axven_native/Cargo.toml`
- `native/axven_native/Cargo.lock`
- `native/axven_native/src/lib.rs`

No symlinks, extra source files, `.git`, Python production modules, workflow files, documentation, wallet/P2P/RPC code, or other repository content is present in the staged native source tree.

A repository-side closure specification checks the exact path set and requires each staged file SHA-256 to match its canonical repository source before and after the container build.

## Repository-blind closure build

The closure build uses the same immutable environment policy as the portable reproducibility path:

- manylinux image `quay.io/pypa/manylinux_2_28_x86_64@sha256:443eabd378e140996780a772e12c1a1ef10551da933fe76d74a1bab61f68a7b7`;
- builder CPython `3.13.13`;
- Rust `1.98.0`;
- maturin `1.15.0`;
- PyO3 `0.29.2`;
- `SOURCE_DATE_EPOCH` derived from the exact checked-out source commit;
- `CARGO_INCREMENTAL=0`;
- `PYTHONHASHSEED=0`;
- `TZ=UTC`;
- `LC_ALL=C.UTF-8`;
- Cargo `--locked`;
- `manylinux_2_28` compatibility.

The source closure is mounted read-only at `/src`. The container does **not** receive the repository root at `/work` or any other full-repository mount. Separate writable mounts are provided only for the Cargo target directory, maturin tool installation directory, and wheel output. The hash-locked native build-tool requirements file is mounted separately read-only as a build-tool input, not as native source.

## Equality contract

After the repository-blind closure build:

1. the source-closure path set and hashes are rechecked;
2. RUST-013 compares ordinary reproducible build A with the source-closure wheel;
3. SHA-256 and byte length must match;
4. complete wheel archives must be byte-for-byte identical;
5. ZIP member order and metadata must match and remain source-epoch pinned;
6. all native/dist-info member payloads must match;
7. RUST-009 portable-wheel policy is rerun against the closure wheel.

Thus RUST-016 fails if repository ambient files alter the native output relative to the declared three-file native source closure.

## Scope limitation

The Cargo registry/toolchain caches and hash-locked maturin installation are external build dependencies; RUST-016 does not claim those bytes are derived from the three-file source closure. Their versions and image/toolchain policy remain pinned by the existing build contracts.

RUST-016 also does not add the closure result to the RUST-014 signed provenance schema. Binding source-closure proof into a future evidence schema is a separate checkpoint rather than a silent change to existing signed semantics.

## Publication and consensus boundary

RUST-016 does not upload or publish the closure wheel, create an Actions artifact or GitHub Release, request OIDC, write a GitHub attestation, use a production signing credential, push a package/container, deploy code, or enable production Rust routing.

Production remains Python-authoritative. No production file imports or routes to `axven_native`, and no chain identity, genesis, monetary rule, P2P protocol, SMT/PQ activation, ML-DSA behavior, wallet-key semantics, or transaction/block signature-acceptance rule changes in RUST-016.
