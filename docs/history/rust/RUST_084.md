# RUST-084 — TEST-ONLY multi-step RUST-081 checkpoint monitor rotation

RUST-084 composes the exact reviewed RUST-083 monitor-set rotation and performs a second detached TEST-only monitor rotation.

## Contract

- predecessor monitor set: M2/M3/M4, threshold 2-of-3
- final monitor set: M3/M4/M5, threshold 2-of-3
- M1 remains revoked and M2 is newly revoked
- cumulative revoked monitor ids are exactly `[M1, M2]`
- the second rotation binds the exact SHA-256 of the RUST-083 first rotation, first authorization, and first successor monitor bundle
- all canonical RUST-081 checkpoint target fields remain bound through rotation and final monitoring
- all 3/3 predecessor two-monitor authorization subsets are accepted
- all 3/3 final two-monitor monitoring subsets are accepted
- revoked-monitor resurrection, first-successor replay, non-canonical evidence, signature/quorum failures, target mutation, and valid signed same-parent fork substitution are rejected fail-closed
- detached selftest targets 51/51 expected rejection cases

## Boundary

This remains TEST-only. Production consensus remains Python-authoritative. No production monitor administration/signing, global network publication, durable publication, key custody, HSM/TPM use, OIDC, release/deployment authority, consensus change, or production Rust routing is introduced.
