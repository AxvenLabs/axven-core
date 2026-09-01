# RUST-009 — Portable Linux native wheel gate

RUST-009 proves a portable Linux x86_64 wheel for the dormant `axven_native` extension without publishing or routing production consensus through Rust.

## Build baseline

The Linux wheel is built inside the official PyPA `manylinux_2_28_x86_64` image at an immutable repository digest:

`quay.io/pypa/manylinux_2_28_x86_64@sha256:443eabd378e140996780a772e12c1a1ef10551da933fe76d74a1bab61f68a7b7`

That digest was discovered from the official dated tag `2026.05.07-2` by a temporary read-only workflow that only pulled and inspected the image; it did not execute the image. The temporary discovery workflow is not part of the final RUST-009 branch.

`manylinux_2_28` is the intended compatibility floor for this checkpoint. The permanent gate refuses the previous host-built `manylinux_2_34_x86_64` diagnostic tag and requires the resulting wheel and native ELF symbol versions to remain compatible with glibc 2.28 or older.

## Locked inputs

- source checkout is exact and credentials are not persisted;
- CPython is exactly 3.13.15;
- Rust toolchain is exactly 1.98.0;
- PyO3 remains exactly 0.29.2 with `abi3-py313`;
- maturin remains exactly 1.15.0 from `requirements-native-build.lock` with `--require-hashes`;
- Cargo uses the committed lockfile with `--locked`;
- the manylinux build image is referenced only by the immutable digest above.

The host-installed Rust toolchain is mounted into the build container. Cargo's locked registry downloads remain checksum-verified by the committed `Cargo.lock`. Maturin is installed inside the container from the existing hash-locked binary-only requirements file.

## Required evidence

The gate must:

1. build exactly one release wheel with `--compatibility manylinux_2_28`;
2. require an `abi3` + `manylinux_2_28_x86_64` wheel tag;
3. inspect the wheel archive for duplicate/unsafe members and exact package metadata;
4. verify the embedded native extension exposes no required `GLIBC_x.y` symbol newer than 2.28;
5. clean-install the wheel into an isolated directory and re-run the native boundary, fixed Sparse-Merkle vector, and duplicate-outpoint fail-closed probe;
6. prove production Python modules still contain no `axven_native` import;
7. recheck canonical chain identity, genesis, and activation heights.

## Distribution boundary

The wheel remains ephemeral on the GitHub runner. RUST-009 contains no artifact upload, package publish, GitHub Release, deployment, canonical release-manifest change, or runtime-provenance installation step.

## Consensus boundary

Production `expected_state_root()`, `_transition()`, `_apply_forward()`, block validation, mining, reorg, replay, persistence, RPC, P2P, wallet behavior, ML-DSA, and signature acceptance remain Python-authoritative and unchanged.

No chain identity, genesis, reward/monetary rule, P2P protocol, SMT/PQ activation height, ML-DSA behavior, wallet-key semantics, or signature-acceptance semantics change in RUST-009.
