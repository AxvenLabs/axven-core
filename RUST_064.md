# RUST-064 — TEST-ONLY multi-step monitor-rotation-journal observer-set rotation continuity

RUST-064 composes the exact reviewed RUST-063 monitor-rotation-journal observer-set rotation verifier and extends that TEST-only observer administration history with a second authorized rotation.

The reviewed observer history becomes `O1/O2/O3 -> O2/O3/O4 -> O3/O4/O5`. O1 remains revoked, O2 is newly revoked, and deterministic TEST-only O5 is introduced. The second transition requires a valid 2-of-3 authorization quorum from the exact predecessor O2/O3/O4 set, and all 3/3 valid predecessor two-observer authorization subsets are exercised.

The second rotation binds the exact predecessor observer-set digest, the original RUST-062 observation-bundle SHA-256, the exact RUST-063 first-rotation SHA-256, exact RUST-063 rotation-authorization SHA-256, exact RUST-063 successor-bundle SHA-256, cumulative revocation `[O1, O2]`, the exact RUST-061 final monitor-rotation-journal checkpoint SHA-256 and checkpoint-statement SHA-256, the activation source commit, the final O3/O4/O5 set, and `production=false`.

Final observation uses distinct v3 schemas/domain and is bound to observer-set sequence 2 and the exact O3/O4/O5 set digest. Every report continues to bind the complete inherited RUST-062 canonical target: monitor-set sequence/digest, entry count, journal/head/parent digests, observer-rotation-journal checkpoint and checkpoint-statement digests, observed-target digest, final monitor-rotation-journal checkpoint and statement digests, activation source commit, and `production=false`. All 3/3 valid final two-observer reporting subsets are accepted. The RUST-063 v2 successor bundle cannot replay as final evidence.

A valid signed final report for a distinct checkpoint with the same monitor-set sequence and same previous-checkpoint parent is rejected fail-closed as a split view, even when two other final observers report the canonical checkpoint. Split-view safety remains stronger than availability.

The detached verifier and selftest contain no private signing or network capability. Deterministic TEST private Ed25519 seeds exist only in the producer fixture and are checked against reviewed public-key pins.

This TEST-only evidence does **not** create global network gossip, production observer administration, production signing, key custody, HSM/TPM use, OIDC, artifact publication, release/deployment authority, production anti-rollback, durable global state, consensus changes, or production Rust routing.

Production consensus remains Python-authoritative.
