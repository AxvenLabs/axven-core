# RUST-011 — Portable attested native candidate gate

RUST-011 joins the previously separate portable-build and offline-attestation rehearsals into one read-only release-candidate evidence path. It builds the dormant `axven_native` wheel inside the immutable RUST-009 `manylinux_2_28_x86_64` image, verifies the portable wheel contract, generates a canonical portable provenance statement that explicitly binds the builder image and locked toolchain inputs, and seals that exact statement with a TEST-ONLY Ed25519 envelope.

This checkpoint does **not** publish a wheel, upload an artifact, create a GitHub Release, request an OIDC token, publish an attestation, modify the canonical Axven release manifest, or route production consensus through Rust.

## Why this checkpoint exists

RUST-009 proved portability. RUST-010 proved the envelope/trust-root/fail-closed policy using an unpublished host-built Linux wheel. RUST-011 closes the evidence gap between those checkpoints: the attested payload now describes the actual portable `manylinux_2_28` candidate and explicitly records the immutable container image used to build it.

## Portable provenance contract

The canonical `axven-native-portable-provenance-v1` statement binds:

- repository `AxvenLabs/axven-core` and the exact checked-out source SHA;
- immutable builder image `quay.io/pypa/manylinux_2_28_x86_64@sha256:443eabd378e140996780a772e12c1a1ef10551da933fe76d74a1bab61f68a7b7`;
- compatibility floor `manylinux_2_28` and architecture `x86_64`;
- the actual immutable-image builder CPython `3.13.13`, Rust `1.98.0`, maturin `1.15.0`, and PyO3 `0.29.2` policy pins;
- exact SHA-256/byte length/filename of the single portable wheel;
- SHA-256 of native source/build inputs and the permanent RUST-011 workflow;
- `production_consensus: python`.

The GitHub host verifier remains pinned separately to CPython `3.13.15`. Builder and verifier Python versions are intentionally distinguished: the immutable manylinux image currently contains CPython `3.13.13`, while the host-side policy/provenance/attestation verifier runs on `3.13.15`. The evidence must describe the environment that actually produced the wheel rather than silently substituting the host interpreter version.

The generator requires the portable wheel filename to end in `-cp313-abi3-manylinux_2_28_x86_64.whl` and requires the current checkout to equal `AXVEN_SOURCE_SHA`.

## Attestation contract

The TEST-ONLY envelope uses schema `axven-native-portable-attestation-envelope-v1`, algorithm `ed25519`, payload type `application/vnd.axven.native-portable-provenance.v1+json`, and key id `rust-011-test-only-ed25519-v1`.

Unlike the earlier rehearsal, RUST-011 signs both the exact canonical policy header and the exact canonical provenance bytes under a dedicated domain separator. The verifier pins the public key independently and rejects unexpected fields, non-canonical JSON/base64, policy substitution, payload mutation, signature mutation, and embedded attacker-supplied trust roots.

The committed private seed is deliberately TEST-ONLY. RUST-011 therefore remains a format/evidence rehearsal, not production release authentication.

## CI / publication boundary

The dedicated workflow:

- uses `permissions: contents: read` only;
- checks out the exact PR head/push SHA with credentials disabled;
- runs host-side verification on CPython `3.13.15`;
- pulls the immutable manylinux image and verifies the resolved digest before execution;
- verifies the builder image's actual CPython is exactly `3.13.13` before building;
- mounts the exact Rust 1.98.0 toolchain read-only into the container;
- installs maturin from the existing hash-locked requirements file;
- builds one unpublished portable wheel with Cargo `--locked`;
- reruns the RUST-009 portable wheel integrity/ABI/glibc/clean-install contract;
- generates, seals, verifies, and mutation-tests the RUST-011 evidence pair.

Forbidden in this checkpoint: `id-token: write`, `attestations: write`, `packages: write`, `contents: write`, artifact upload, package publish, release creation, deployment, or transparency-log writes.

## Consensus boundary

Production `expected_state_root()`, `_transition()`, `_apply_forward()`, block validation, mining, reorg, replay, persistence, RPC, P2P, wallet behavior, ML-DSA, and signature acceptance remain Python-authoritative and unchanged.

No chain identity, genesis, reward/monetary rule, P2P protocol, SMT/PQ activation height, ML-DSA behavior, wallet-key semantics, or transaction/block signature-acceptance semantics change in RUST-011. Production Rust routing remains a separate explicit approval gate.
