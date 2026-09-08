# RUST-056 — TEST-ONLY multi-step journal-monitor-journal observer rotation

RUST-056 composes the exact reviewed RUST-055 journal-monitor-journal observer-set rotation verifier and extends the TEST-only observer administration history by one more authorized rotation.

The reviewed history becomes `O1/O2/O3 -> O2/O3/O4 -> O3/O4/O5`. O1 remains revoked, O2 is newly revoked, and deterministic TEST-only O5 is introduced. The second transition is authorized by a valid 2-of-3 quorum from the exact predecessor O2/O3/O4 set.

The second rotation binds the exact predecessor set digest, exact RUST-055 first-rotation SHA-256, exact RUST-055 first-rotation authorization SHA-256, exact RUST-055 successor-bundle SHA-256, cumulative revocation list `[O1, O2]`, exact canonical RUST-053 final journal-monitor-journal checkpoint SHA-256 and checkpoint-statement SHA-256, activation source commit, final O3/O4/O5 set, and `production=false`.

Final observation uses distinct v3 schemas/domain and is bound to observer-set sequence 2 and the exact O3/O4/O5 set digest. All 3/3 valid predecessor two-observer authorization subsets and all 3/3 final two-observer reporting subsets are accepted. The RUST-055 v2 successor bundle cannot replay as final evidence.

A valid signed final report for a distinct checkpoint with the same monitor-set sequence and same previous-checkpoint parent is rejected fail-closed as a split view, even if two other final observers report the canonical checkpoint.

The detached verifier and selftest contain no private signing or network capability. Deterministic TEST private Ed25519 seeds exist only in the producer fixture and are checked against the pinned public keys.

This TEST-only evidence does **not** create global network gossip, production observer administration, production signing, key custody, HSM/TPM use, OIDC, publication, release/deployment authority, anti-rollback policy, consensus change, or production Rust routing.

Production consensus remains Python-authoritative.
