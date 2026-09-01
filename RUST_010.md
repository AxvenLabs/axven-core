# RUST-010 — Offline native attestation envelope policy gate

RUST-010 adds a cryptographic **policy rehearsal** around the canonical `native-provenance.json` candidate produced by RUST-008. It does not publish an artifact, publish an attestation, create a release, request a GitHub OIDC token, or route production consensus through Rust.

## Scope

The checkpoint takes one freshly built unpublished Linux native wheel, generates and re-verifies the existing RUST-008 canonical provenance candidate, then seals the exact canonical provenance bytes in an `axven-native-attestation-envelope-v1` envelope.

The envelope binds:

- schema `axven-native-attestation-envelope-v1`;
- algorithm `ed25519`;
- key id `rust-010-test-only-ed25519-v1`;
- payload type `application/vnd.axven.native-provenance.v1+json`;
- SHA-256 of the exact canonical provenance bytes;
- one Ed25519 signature over a domain-separated length-prefixed message.

The verifier does **not** trust a public key supplied by the envelope. Its trust root is pinned independently in the verifier, and unexpected envelope fields are rejected. Signature bytes must use canonical base64.

## Test-only trust root

The private seed used by this checkpoint is deliberately committed and labeled **TEST-ONLY**. Therefore RUST-010 is **not a production authentication mechanism** and the signature is not evidence that a release was produced by a secret Axven signing key.

That limitation is intentional. This checkpoint reviews and locks the envelope format, trust-root separation, domain separation, canonicalization, and fail-closed verifier behavior before any real keyless/OIDC or externally visible attestation mechanism is authorized.

A later checkpoint may replace this rehearsal key with a reviewed keyless or release-signing identity. Doing so will be a separate privilege and publication boundary.

## Fail-closed mutation contract

The dedicated self-test must reject all of the following while accepting the original pair:

1. canonical provenance payload tampering;
2. Ed25519 signature tampering;
3. key-id substitution;
4. algorithm substitution;
5. an attacker-supplied embedded `public_key` field;
6. a non-canonical envelope encoding.

The source provenance is also re-verified by the RUST-008 verifier before and after sealing.

## CI and publication boundary

The dedicated workflow:

- runs on Ubuntu 24.04;
- checks out the exact PR head / push SHA with credentials disabled;
- uses CPython 3.13.15 and Rust 1.98.0;
- installs maturin and runtime cryptography only from existing hash-locked requirement files;
- builds one unpublished release wheel with Cargo `--locked`;
- runs RUST-007 wheel integrity and RUST-008 provenance generation/verification;
- runs the RUST-010 static policy contract, seal/verify pair, and mutation suite;
- retains `permissions: contents: read`.

It does **not** request `id-token: write`, `attestations: write`, `packages: write`, or `contents: write`. It does not upload workflow artifacts, call GitHub artifact attestation APIs, write to a transparency log, publish a package, create a GitHub Release, or deploy anything.

## Consensus boundary

Production `expected_state_root()`, `_transition()`, `_apply_forward()`, block validation, mining, reorg, replay, persistence, RPC, P2P, wallet behavior, ML-DSA, and signature acceptance remain unchanged and Python-authoritative.

No chain identity, genesis, reward/monetary rule, P2P protocol, SMT/PQ activation height, ML-DSA behavior, wallet-key semantics, or transaction/block signature-acceptance semantics change in RUST-010.
