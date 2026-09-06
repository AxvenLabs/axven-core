# RUST-028 — TEST-ONLY attestation trust-root rotation continuity

RUST-027 separated build-material verification from producer/sealing capability. RUST-028 exercises the next supply-chain trust boundary without introducing a production signing key: controlled transition from the existing RUST-026 TEST-ONLY attestation key to a second TEST-ONLY verifier key.

## Contract

The checkpoint composes the already-verified RUST-025/RUST-026/RUST-027 chain and then proves a fail-closed trust transition:

- The existing RUST-026 key remains the pinned old trust root:
  `rust-026-test-only-ed25519-v1`.
- A distinct TEST-ONLY successor is introduced:
  `rust-028-test-only-ed25519-v2`.
- The transition is a canonical JSON object with sequence `1`, explicit material-attestation scope, old/new key IDs and public keys, the activating source commit, and `production=false`.
- The transition itself is signed by the old TEST-ONLY key under a dedicated domain.
- The same canonical build-material payload is signed by both the old and new TEST-ONLY keys.
- A detached verification-only consumer pins the old root and expected successor independently. It accepts the new signature only after validating the old signature and old-signed transition.
- Rollback sequence, unknown old key, new-key substitution, old/new signature mutation, payload disagreement, non-canonical transition, source activation mismatch and material-source mutation are rejected.

Before the rotation proof, the workflow re-runs the RUST-025 upstream-authenticated fully detached build and RUST-027 verification-only material consumer so the transition is anchored to real build evidence rather than a synthetic payload.

## Key separation

The detached RUST-028 verifier contains no private seed, `Ed25519PrivateKey`, sealing function, Axven producer import, Git dependency or production signing credential. TEST-ONLY private seeds exist only in the producer-side workflow step used to exercise the transition contract.

This is a test of trust-root lifecycle mechanics, not a production key ceremony.

## Non-goals

RUST-028 does not publish artifacts or attestations, enable OIDC, create a GitHub Release, introduce a production signing key, deploy code, change chain identity or consensus semantics, or route production execution through Rust.

Production consensus remains Python-authoritative. Production signing, artifact publication and Rust production routing remain separate explicit approval gates.
