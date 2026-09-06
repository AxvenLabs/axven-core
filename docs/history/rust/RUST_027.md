# RUST-027 — Verification-only build-material consumer

RUST-026 proved that the complete upstream-authenticated, fully detached native build materials can be bound into a canonical TEST-ONLY Ed25519 attestation. Its combined producer/verifier module intentionally still contains the TEST-ONLY signing seed because it also generates mutation fixtures.

RUST-027 separates those roles.

## Verification-only consumer

A new detached consumer verifier independently pins the RUST-026 schemas, algorithm, key id, domain, public key, builder identity, upstream Rust distribution identity and expected native artifact name. It contains no TEST_SEED, Ed25519 private-key API, sealing code, producer-module import, repository import or Git dependency.

The workflow first reproduces the complete RUST-025 evidence and uses the RUST-026 producer only to generate and seal the canonical materials. The detached consumer then receives only:

- the RUST-027 verification-only script,
- `materials.json`,
- `attestation.json`.

The already detached RUST-025 evidence remains under `/tmp` and is passed as explicit verification input. The consumer runs under `env -i` outside the repository checkout.

The verifier recomputes and checks the final wheel identity, Rust distribution SHA-256, toolchain-manifest identity, Cargo/build lock hashes, dependency closure inventory and vendor closure inventory before accepting the signature-bound material statement.

## Fail-closed contract

The self-test rejects ten independent mutations/substitutions: source SHA, signature, non-canonical materials, wheel bytes, Rust archive substitution, toolchain-manifest substitution, dependency closure mutation, vendor closure mutation, Cargo.lock mutation and native-build lock mutation.

The pristine statement is re-verified after mutation testing.

## Boundary

This remains TEST-ONLY supply-chain hardening. RUST-027 does not upload or publish artifacts or attestations, enable OIDC, add a production signing key, create a release, deploy code, change chain/consensus semantics or route production execution through Rust.

Production consensus remains Python-authoritative. Production signing, publication and Rust routing remain separate explicit approval gates.
