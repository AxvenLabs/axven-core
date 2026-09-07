# RUST-034 — TEST-ONLY 2-of-3 external-floor witness quorum

RUST-033 authenticates the RUST-032 external monotonic-floor record with one pinned TEST-ONLY Ed25519 witness key. That removes unauthenticated floor substitution, but a single witness identity remains a single availability and trust dependency.

RUST-034 adds a narrow **TEST-ONLY 2-of-3 witness quorum** over the exact canonical external-floor bytes. It does not introduce production key custody, a witness service, HSM/TPM state, a transparency log, OIDC, publication, or deployment.

## Contract

The detached verifier first re-applies the RUST-032 floor/state validation. It then accepts a canonical `axven-native-external-floor-witness-quorum-v1` object only when:

- `threshold` is exactly `2`;
- the payload digest binds the exact canonical external-floor bytes;
- `production=false`;
- witness key IDs are unique, sorted, and selected only from three verifier-pinned TEST identities;
- every supplied signature verifies under the pinned Ed25519 public key and the RUST-034 domain;
- at least two distinct pinned witnesses are present.

The first quorum member is the exact RUST-033 pinned witness identity. Two additional deterministic TEST identities are introduced only for this simulation. The quorum file cannot choose arbitrary public keys.

## Availability and fail-closed behavior

CI proves that all three valid 2-witness subsets are accepted: A+B, A+C, and B+C. It also proves 13 fail-closed mutations including threshold downgrade, duplicate/unknown/unsorted witness identities, signature mutation, payload substitution, production substitution, non-canonical encoding, floor downgrade, and activation-source mismatch.

The external floor and quorum evidence remain outside the detached consumer directory and are chmod `0444`. Verification runs under `env -i` and `/usr/bin/python3 -S`.

## Security boundary

RUST-034 reduces the TEST simulation's dependence on one witness identity. It does **not** make the witness producers operationally independent: CI still creates deterministic fixture keys in one test harness. A real production quorum would require independent administration, durable monotonic state, key custody, compromise/revocation procedures, and deployment architecture.

Those production decisions remain explicit future approval gates.

## Non-goals

No production signing, OIDC, artifact publication, release/deployment, consensus change, website/DNS change, production anti-rollback storage, or production Rust routing is introduced.

Production consensus remains Python-authoritative.
