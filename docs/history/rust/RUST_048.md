# RUST-048 — TEST-ONLY multi-step monitor-journal observer rotation

RUST-048 composes the exact reviewed RUST-047 journal-observer rotation verifier and extends the TEST-only administration history by one more authorized rotation.

The reviewed history becomes `J1/J2/J3 -> J2/J3/J4 -> J3/J4/J5`. J1 remains revoked, J2 is newly revoked, and deterministic TEST-only J5 is introduced. The second transition is authorized by a valid 2-of-3 quorum from the exact predecessor J2/J3/J4 set.

The second rotation binds the exact predecessor set digest, exact RUST-047 first-rotation SHA-256, exact RUST-047 successor-bundle SHA-256, cumulative revocation list `[J1, J2]`, exact canonical RUST-045 final monitor-journal checkpoint SHA-256 and checkpoint-statement SHA-256, activation source commit, final J3/J4/J5 set, and `production=false`.

Final observation uses distinct v3 schemas/domain and is bound to observer-set sequence 2 and the exact J3/J4/J5 set digest. All 3/3 valid predecessor two-observer authorization subsets and all 3/3 final two-observer reporting subsets are accepted. The RUST-047 v2 successor bundle cannot replay as final evidence.

A valid signed final report for a distinct checkpoint with the same monitor-set sequence and same previous-checkpoint parent is rejected fail-closed as a split view, even if two other final observers report the canonical checkpoint.

The detached verifier and selftest contain no private signing or network capability. Deterministic TEST private Ed25519 seeds exist only in the producer fixture.

This TEST-only evidence does **not** create global network gossip, production observer administration, production signing, key custody, HSM/TPM use, OIDC, publication, release/deployment authority, anti-rollback policy, consensus change, or production Rust routing.

Production consensus remains Python-authoritative.
