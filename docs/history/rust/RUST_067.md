# RUST-067 — TEST-ONLY monitor-set rotation for the RUST-066 checkpoint monitors

RUST-067 composes the exact reviewed RUST-066 monitor verifier and adds deterministic TEST-only monitor-set rotation/revocation continuity for the monitors observing the final RUST-065 monitor-rotation-journal observer-rotation-journal checkpoint.

The reviewed monitor history rotates `M1/M2/M3 -> M2/M3/M4`. M1 is explicitly revoked. The rotation binds the exact predecessor RUST-066 monitor bundle SHA-256, exact predecessor monitor-set digest, successor monitor-set bytes, activation source commit, and every field in the complete RUST-066 canonical checkpoint target. The rotation authorization is domain-separated Ed25519 and requires 2-of-3 signatures from the predecessor M1/M2/M3 set; all 3/3 valid two-monitor authorization subsets are accepted.

The successor bundle uses distinct v2 schemas/domain, carries monitor-set sequence 1 and the exact successor set digest, and requires 2-of-3 reports from M2/M3/M4. All 3/3 valid two-monitor successor subsets are accepted. Revoked M1 cannot appear in the successor set or reports.

A valid signed successor report for a distinct checkpoint with the same observer-set sequence and previous-checkpoint parent is rejected fail-closed as a same-parent split view. Replay, target-field substitution, predecessor-bundle substitution, set rollback, revocation omission, threshold downgrade, duplicate/unsorted signers, signature mutation, non-canonical evidence, and predecessor bundle replay are rejected.

The detached verifier and selftest contain no private signing or network capability. Deterministic TEST private Ed25519 seeds exist only in the producer fixture and are checked against pinned public keys. Evidence is made read-only before detached verification.

This TEST-only evidence does **not** create durable global gossip, production monitor administration, production signing, key custody, HSM/TPM use, OIDC, publication, release/deployment authority, anti-rollback policy, consensus change, or production Rust routing.

Production consensus remains Python-authoritative.
