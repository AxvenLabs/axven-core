# RUST-091 — TEST-ONLY RUST-090 checkpoint monitor-set rotation

RUST-091 composes the exact reviewed RUST-090 detached checkpoint-monitor verifier and rotates its three TEST-only monitors from M1/M2/M3 to M2/M3/M4 while preserving a 2-of-3 quorum.

## Contract

- The exact RUST-090 predecessor monitor bundle SHA-256 is bound into the rotation.
- The predecessor monitor-set digest, successor monitor set, sequence and revocation list are canonical.
- M1 is revoked. M2 and M3 continue. M4 is introduced with a deterministic TEST-only public-key pin.
- Rotation authorization is signed by the predecessor set with a 2-of-3 threshold; all 3/3 valid two-monitor authorization subsets must verify.
- The successor monitor bundle is bound to a namespaced successor epoch and exact successor monitor-set digest; all 3/3 valid two-monitor successor subsets must verify.
- Every rotation and successor report preserves the exact 12-field RUST-090 canonical checkpoint target.
- A signed same-parent checkpoint fork can be represented as observed evidence, but it cannot substitute for the canonical successor bundle.
- The detached selftest is fail-closed for 50/50 mutation, replay and fork-substitution cases.

## Detached boundary

The verifier and selftest contain no private signing keys and no network capability. Deterministic private keys exist only in the producer fixture. CI uses a read-only workflow, chmod 0444 evidence, a fixed 159-path manifest and a 64-file verifier-only detached consumer executed with `env -i` and `/usr/bin/python3 -S`.

This checkpoint does not introduce global gossip, durable publication, production monitor administration, production signing, key custody, HSM/TPM integration, OIDC, release/deployment authority, consensus changes or production Rust routing.

Production consensus remains Python-authoritative.
