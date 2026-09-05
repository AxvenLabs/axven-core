# RUST-013 — Reproducible portable native build rehearsal

RUST-013 asks a narrower question than release publication: can the dormant `axven_native` portable wheel be rebuilt twice from the same source under the same immutable builder policy and produce byte-identical wheel files?

This checkpoint does **not** alter the RUST-011 provenance schema, the RUST-012 detached verifier format, production consensus routing, release publication, package upload, GitHub OIDC/attestation permissions, or the canonical Axven release manifest.

## Reproducibility contract

For one exact checked-out source SHA, CI derives `SOURCE_DATE_EPOCH` from that commit's recorded Unix timestamp. The timestamp is therefore source-bound rather than runner-wall-clock-bound.

Two separate `manylinux_2_28_x86_64` containers then build the same native crate with:

- immutable builder image `quay.io/pypa/manylinux_2_28_x86_64@sha256:443eabd378e140996780a772e12c1a1ef10551da933fe76d74a1bab61f68a7b7`;
- builder CPython `3.13.13`;
- Rust `1.98.0`;
- maturin `1.15.0` from the existing hash-locked native-build requirements;
- PyO3 `0.29.2` from the locked Cargo graph;
- Cargo `--locked`;
- `SOURCE_DATE_EPOCH` fixed to the exact source commit timestamp;
- `CARGO_INCREMENTAL=0`, `PYTHONHASHSEED=0`, `TZ=UTC`, and `LC_ALL=C.UTF-8`;
- distinct Cargo target directories, tool-install directories, and wheel output directories for build A and build B.

The two builds deliberately occur in separate container invocations and are separated by wall-clock time. They may share download caches for Cargo/Rust components, but they do not share compiled target directories or wheel output directories.

## Byte-for-byte evidence

`rust_013_reproducible_wheel_spec.py` requires both output directories to contain exactly one wheel with the canonical filename:

`axven_native-0.1.0-cp313-abi3-manylinux_2_28_x86_64.whl`

It then requires:

- identical wheel SHA-256 and file length;
- byte-for-byte equality of the complete wheel archive;
- identical ZIP member order and metadata;
- identical bytes for every ZIP member, including the native `.so`, metadata, WHEEL, and RECORD content;
- no duplicate, absolute, backslash, or `..` traversal member names;
- ZIP entry timestamps fixed to the source-derived reproducibility epoch rather than the runner's current time.

After the equality proof, each wheel is independently passed through the existing RUST-009 portable-wheel contract so both sides must retain the expected manylinux tag, ELF/glibc floor, clean-install behavior, and Python-authoritative production boundary.

## What this does and does not prove

RUST-013 proves deterministic output for two independent builds performed under one explicitly pinned Linux builder policy. It does not yet claim cross-provider, cross-architecture, or independently implemented toolchain reproducibility. It also does not retroactively change the RUST-011 provenance statement: binding the reproducibility epoch/evidence into a signed provenance schema is a separate future checkpoint.

## Privilege / publication boundary

The dedicated workflow uses `contents: read` only. It does not upload either wheel as an Actions artifact, publish to PyPI or another package registry, create a GitHub Release, request an OIDC token, write a GitHub attestation, push a container image, deploy anything, or write a transparency log.

## Consensus boundary

Production remains Python-authoritative. No production file imports or routes to `axven_native`, and no chain identity, genesis, reward/monetary rule, P2P protocol, SMT/PQ activation, ML-DSA behavior, wallet-key semantics, or transaction/block signature-acceptance rule changes in RUST-013.

Production Rust routing and production release signing/publication remain separate explicit approval gates.
