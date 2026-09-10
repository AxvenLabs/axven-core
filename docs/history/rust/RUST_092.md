# RUST-092 — TEST-ONLY second RUST-090 checkpoint monitor-set rotation

RUST-092 composes the exact reviewed RUST-091 monitor-set rotation verifier and performs the second TEST-only rotation for the RUST-090 checkpoint monitor family.

## Contract

- Monitor set rotates from M2/M3/M4 to M3/M4/M5 with a 2-of-3 threshold.
- M1 remains revoked and M2 is revoked, producing the cumulative revocation list `[M1, M2]`.
- The exact RUST-091 first rotation, rotation authorization and successor monitor bundle SHA-256 values are bound into the second rotation.
- The predecessor set digest, final set, sequence and cumulative revocation list are canonical.
- Second-rotation authorization uses the predecessor M2/M3/M4 set and accepts all 3/3 valid two-monitor subsets.
- Final monitoring uses M3/M4/M5 and accepts all 3/3 valid two-monitor subsets.
- Every rotation and final report preserves the exact 12-field RUST-090 canonical checkpoint target.
- Signed same-parent fork evidence cannot substitute for the canonical final bundle.
- The detached selftest rejects 53/53 mutation, replay, revocation-rollback and fork-substitution cases fail-closed.

## Detached boundary

Deterministic TEST private keys exist only in the producer fixture. The verifier and selftest contain no private signing keys or network capability. CI is read-only, makes evidence mode 0444, uses a fixed 162-path manifest, stages a 65-file verifier-only detached consumer and executes it with `env -i` and `/usr/bin/python3 -S`.

No production monitor administration/signing, global publication, key custody, HSM/TPM integration, OIDC, release/deployment authority, consensus change or production Rust routing is introduced.

Production consensus remains Python-authoritative.
